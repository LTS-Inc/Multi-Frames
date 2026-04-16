# Multi-Frames Codebase Review

**Date:** 2026-04-16
**Branch:** `claude/codebase-review-testing-PWeko`
**Scope:** `multi_frames.py` (12,024 lines), `multi_frames/` package (~1,700 lines), `cloud/worker.js` (4,229 lines).

This document records bugs, conflicts, and risks discovered during a full codebase review, and defines a manual + automated testing process.

---

## 1. Critical

### 1.1 SSRF via proxy redirect handling (`multi_frames.py:9872-9885`)
The `/proxy/<iframe>/...` handler validates the initial target with `validate_local_ip`, but when the upstream returns a 3xx redirect the handler follows it (`while resp.status in (301, 302, 303, 307, 308)`) and reconnects to `redir_parsed.hostname` **without re-validating the host**. A local resource that redirects to `http://attacker.example.com/...` causes the server to fetch that external URL and return its body to an authenticated client. Protocol-relative redirects (`Location: //evil.com/`) additionally fall through the `else` branch (line 9885) and are assigned directly to `request_path`, which is also unsafe.

**Fix:** re-run `validate_local_ip(redirect_url)` (for absolute redirects) and reject protocol-relative URLs before continuing the loop.

### 1.2 JWT signature is cosmetic, not cryptographic (`cloud/worker.js:~64, ~45-54`)
`signature = btoa(env.JWT_SECRET + '.' + data)` is plain base64 of a concatenation — not HMAC-SHA256. Verification decodes the payload and trusts it. Any attacker who can reach the worker can forge session tokens.

**Fix:** sign with `crypto.subtle.sign('HMAC', key, data)` using SHA-256 and compare with `crypto.subtle.verify`. Reject tokens whose signature fails verification.

### 1.3 CORS allows any origin (`cloud/worker.js:~18`)
`Access-Control-Allow-Origin: *` on every response, including state-changing endpoints. Combined with session-bearing cookies/headers this enables cross-site request forgery against the admin portal.

**Fix:** allow-list explicit origins (the portal domain), and require a CSRF token or SameSite cookies for state-changing calls.

### 1.4 Modular package cannot run (`multi_frames/__main__.py`, `templates/__init__.py`)
`python -m multi_frames` fails immediately with `ModuleNotFoundError: No module named 'multi_frames.server'`. `multi_frames/templates/__init__.py` also imports `base`, `login`, `dashboard`, `help`, `widgets` — none of which exist. `multi_frames/handlers/__init__.py` is an empty stub. README and CLAUDE.md advertise `python -m multi_frames --port 8080` as a supported entry point.

**Fix options:** (a) remove the broken entry point and templates `__init__.py` imports until the refactor lands, or (b) add a thin `server.py` that re-exports `main` from the single-file distribution.

---

## 2. High

### 2.1 Password hashing uses unsalted SHA-256 (`multi_frames.py:3082-3084`)
CLAUDE.md advertises "SHA-256 + salt"; implementation is `hashlib.sha256(password.encode()).hexdigest()`. Vulnerable to rainbow-table / GPU attacks; two users with the same password share a hash.

**Fix:** `hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)` with a per-user random salt stored alongside the hash. Retain the old hash in a `legacy_password_hash` field and migrate on next successful login.

### 2.2 Shared state has no locking under a threaded server (`multi_frames.py:2983, 2986, 11773`)
`ThreadedTCPServer(ThreadingMixIn, TCPServer)` serves concurrent requests, yet `sessions`, `failed_login_attempts`, and the in-memory `config` dict are mutated from any handler thread without a `threading.Lock`. Symptoms: lost writes to config, inconsistent login-throttling counters, dropped sessions.

**Fix:** wrap reads/writes to `sessions`, `failed_login_attempts` in a module-level `threading.Lock`. For `save_config`, see 2.3.

### 2.3 `save_config` is not atomic (`multi_frames.py:3039-3060`)
Writes directly to `CONFIG_FILE`. A crash or concurrent writer can leave the file truncated/corrupt — causing a permanent config-load failure.

**Fix:** write to `CONFIG_FILE + '.tmp'` then `os.replace(tmp, CONFIG_FILE)` under a lock.

### 2.4 Unbounded growth of `sessions` and `failed_login_attempts` (`multi_frames.py:2986, 3095`)
Expired sessions are removed only on access (`get_session`). Failed-login entries are removed only when the same IP retries after lockout. A botnet rotating through thousands of source IPs grows both dicts indefinitely.

**Fix:** background thread (daemon, 5-minute interval) sweeps expired entries from both dicts.

### 2.5 Missing `await` on `logTunnelEvent` (`cloud/worker.js:1137, 1229, 1340, 1366`)
Fire-and-forget logging calls can be dropped when the worker instance terminates. For audit/compliance on tunnel sessions, this is a retention hole.

**Fix:** either `await logTunnelEvent(...)` or `ctx.waitUntil(logTunnelEvent(...))` so the runtime holds the request open until logging completes.

### 2.6 Unprotected `request.json()` parsing (`cloud/worker.js` — 13+ sites around lines 439, 481, 520, 633, 661, 693, 724, 792, 832, 859, 884, 935, 1095)
Malformed JSON rejects the promise and is caught only by the outer 500 handler. This masks real errors and leaks stack traces.

**Fix:** helper `async function readJson(request, fallback = {})` that try/catches and returns a 400.

### 2.7 Widget-template route order (`cloud/worker.js:~820-880`)
A regex matcher `^/api/widget-templates/[\w-]+` is tested before `/api/widget-templates/push`. A PUT to `/push` matches the regex first and the push handler is unreachable.

**Fix:** anchor the regex (`^/api/widget-templates/[\w-]+$`) **and** reorder so `/push` is checked first.

---

## 3. Medium

### 3.1 Bare `except: pass` masks errors (`multi_frames.py:1551, 1632, 1655, 1687, 1699, 2249`)
Six call sites swallow all exceptions (vcgencmd, resource, socket). Failures look like success.

**Fix:** narrow to the expected exception and log with `server_logger.debug(...)`.

### 3.2 `escape_html` does not escape apostrophes (`multi_frames.py:~3258`)
Values emitted inside single-quoted HTML attributes can break out. Today most attributes are double-quoted, so impact is limited — but fragile.

**Fix:** add `.replace("'", "&#39;")`.

### 3.3 Tunnel-proxy HTML injection (`cloud/worker.js:~1382-1420`)
The relay injects a nav script into proxied HTML. If the tunnel token ever reaches that template unescaped (or via a future refactor), it breaks out of the JS string.

**Fix:** base-path and token should be emitted via `JSON.stringify(...)`; better yet set a `Content-Security-Policy` on the rewritten document.

### 3.4 Open-redirect shape in OAuth callback (`cloud/worker.js:~405`)
Dashboard redirect carries the session token in the query string (`?token=...`). Tokens end up in referrer headers and browser history.

**Fix:** set a `Secure; HttpOnly; SameSite=Lax` cookie and redirect to a token-free URL.

### 3.5 Metrics array silently truncated (`cloud/worker.js:958-960`)
When metrics exceed 60/hour the oldest entries are spliced away without logging. An attacker (or a noisy device) can erase earlier data.

**Fix:** cap ingress rate per device-hour and log truncation events.

### 3.6 Missing `return` after `self.redirect()` (`multi_frames.py:10023`)
Works today because of `if/elif` structure, but a refactor could fall through and send a second response (raising `BrokenPipeError` in the handler).

**Fix:** explicit `return` after every `self.redirect(...)` call in POST handlers.

### 3.7 Missing `return` paths after `self.send_json({...}, 4xx)`
Several admin POST branches call `self.send_json({...}, 4xx)` and continue to `save_config` / `self.send_json(...)` a second time. Grep for `send_json(` followed by `save_config` within the same branch.

---

## 4. Low

- Inefficient daily-uptime cleanup (`multi_frames.py:669-681`) — O(n) rescan; use a sorted-key approach.
- Inconsistent auth-check placement between GET (`9726-9728`) and POST (`10155-10160`) handlers — maintenance risk.
- Session cookie lacks `Secure` flag (`multi_frames.py:9657`). Acceptable over local HTTP, but should be conditional on TLS being enabled.

---

## 5. Conflicts between sources

| Topic | Single-file (`multi_frames.py`) | Modular (`multi_frames/`) |
|-------|--------------------------------|---------------------------|
| Entry point | `main()` at L11897, `__main__` at L12023 | `__main__.py` imports from non-existent `.server` |
| Session timeout | `SESSION_TIMEOUT_HOURS = 24` (datetime-based) | `SESSION_TIMEOUT = 86400` (epoch seconds) |
| Credential check | inline in POST handler, uses `check_login_allowed` | standalone `validate_credentials()` helper, no rate limit |
| Templates | `render_login_page`, `render_main_page`, `render_help_page` all present | all referenced but missing (`templates/base.py` etc.) |
| Handlers | do_GET at L9676, do_POST at L9974 | `handlers/__init__.py` empty |

Net effect: the modular package is a scaffolding of a future refactor, not a runnable alternative. The single-file distribution is the only production artifact today.

---

## 6. Testing process

### 6.1 Automated suite (`tests/`)

Added a pytest-free, standard-library test runner so tests can run with the same "zero dependencies" promise as the project.

- `tests/run_tests.py` — discovers and runs all `test_*.py` files via `unittest`.
- `tests/test_unit.py` — exercises pure helpers (`hash_password`, `validate_local_ip`, `escape_html`, `parse_multipart`, rate-limiter state machine, config round-trip).
- `tests/test_server.py` — spins up the server on an ephemeral port and exercises login, session cookie, admin gating, and the `/proxy/` SSRF regression.
- `tests/test_worker.py` — lightweight JS syntax + route-table assertions for `cloud/worker.js` using Node if available, skipped otherwise.

Run:
```bash
python tests/run_tests.py          # full suite
python tests/run_tests.py -k proxy # filter
```

### 6.2 Manual smoke test (per release)

1. **Clean install.** Delete `~/.multi_frames_config.json`; start `python multi_frames.py --port 8080`; confirm default admin login `admin` / `admin123`, force password change, verify hash persists.
2. **iFrame CRUD.** Add a local URL; verify connectivity test passes; drag-reorder; delete; confirm `~/.multi_frames_config.json` persists after restart.
3. **SSRF regression.** Add an iFrame pointing at a local redirector that 302s to `http://example.com/`. Hit `/proxy/0/` — must return 403, not `example.com` content.
4. **Rate limit.** Submit 6 bad logins from one IP; 6th must be blocked for 15 min.
5. **Admin gating.** Create a non-admin user; ensure `/admin` returns 403 and `/admin/iframe/add` rejects with 403.
6. **Network command.** Use the admin console to send a `dummy` command; verify success. Send a `tcp` command to `127.0.0.1:65535`; verify graceful error.
7. **Raspberry Pi card** (if Pi available): verify temperature and throttling read; otherwise confirm the card shows "not detected" instead of crashing.
8. **Cloud sync** (if cloud configured): push a config, flip a value in the portal, pull, confirm applied.
9. **Tunnel relay**: open a tunnel, fetch a local page through it, terminate, confirm DO cleanup via `wrangler tail`.
10. **Crash restart:** `kill -9` the server mid-save; confirm `~/.multi_frames_config.json` still parses (will fail today — see §2.3).

### 6.3 CI integration

A minimal GitHub Actions workflow (`.github/workflows/tests.yml`) can be added later:
```yaml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: python tests/run_tests.py
```
Not added in this PR pending team decision on CI provider.

---

## 7. Recommended next steps (ordered)

1. Patch the SSRF proxy redirect (§1.1) and JWT signing (§1.2) — both are remotely exploitable.
2. Restrict worker CORS (§1.3).
3. Decide on modular-package direction (§1.4): delete the stubs or land the refactor.
4. Migrate password hashing to PBKDF2/Argon2 (§2.1) with a one-time on-login migration.
5. Add a `threading.Lock` around shared in-memory state and atomic config writes (§2.2, §2.3).
6. Add the `tests/` suite to CI.
