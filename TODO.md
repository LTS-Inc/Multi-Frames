# TODO - Multi-Frames

Tracking planned optimizations, security hardening, and improvements.
A deeper review with file:line references and severity grouping lives in
[REVIEW.md](REVIEW.md).

---

## Security

### Critical

- [x] **Upgrade password hashing** — done in v1.6.0. `hash_password()`/`verify_password()` use PBKDF2-HMAC-SHA256 with a per-hash 16-byte salt and 600k iterations; legacy SHA-256 hashes still verify and migrate to PBKDF2 on next login.

- [ ] **Strengthen password reset tokens** — `uuid.uuid4()[:8]` at `multi_frames.py:10045` gives only ~32 bits of entropy. Use `secrets.token_urlsafe(32)`, add expiration (e.g. 1 hour), and rate-limit reset attempts.

- [x] **Add CSRF protection** — done in v1.6.0. Session cookie is `SameSite=Strict` (never sent cross-site) and state-changing POSTs reject a mismatched `Origin`/`Referer` (`_csrf_ok`); tunnel-forwarded requests are exempt.

- [x] **Fix SSRF in proxy redirect handling** — done in v1.5.1. The `/proxy/` redirect loop re-runs `validate_local_ip()` on every absolute hop, rejects protocol-relative `Location`, and honors the redirect scheme.

### High

- [ ] **Authenticate info-leak endpoints** — `/api/client-info` and `/api/pi-status` require no auth and expose IP, server port, Pi model, temperature, hostname, memory, and network config. Gate behind authentication.

- [x] **Add security response headers** — done in v1.6.0. `send_html()` sets `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options: SAMEORIGIN` (omitted for tunnel-embedded pages), and a `Content-Security-Policy`.

- [x] **Harden session cookies** — done in v1.6.0. `HttpOnly` + `SameSite=Strict` on all session cookies, `Secure` when behind TLS (`X-Forwarded-Proto: https`), and logout invalidates the session server-side.

- [x] **Fix rate-limit bypass via header spoofing** — re-assessed as **not vulnerable**: login throttling keys on `self.client_address[0]` (the real socket peer), not on any client-settable header. The spoofable `X-Forwarded-For`/`X-Real-IP` parsing only feeds the informational `/api/client-info` display.

### Medium

- [ ] **Tighten proxy SSRF surface** — `validate_local_ip()` at `multi_frames.py:3099` allows `.local` and `.lan` hostnames which could resolve to unintended targets via DNS rebinding. Consider allowlist-only or resolve-then-check approach.

- [ ] **Avoid innerHTML for dynamic content** — JS in help/diagnostics page uses `innerHTML` with server responses (e.g. `multi_frames.py:5139`). Switch to `textContent` or DOM element creation to eliminate DOM XSS risk.

- [x] **Set config file permissions** — done in v1.6.0. `save_config()` writes atomically (temp + `os.replace`) and `chmod`s the file to `0600`.

- [ ] **Re-enable SSL cert verification in proxy** — Proxy disables certificate verification (`ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE` at `multi_frames.py:9848`), allowing MITM on proxied HTTPS connections. Use default verification or make it configurable.

- [x] **Escape single quotes in `escape_html()`** — done in v1.5.1. `escape_html()` now escapes `'` → `&#39;`, and a dedicated `escape_js_string()` handles values interpolated into inline JS handlers/scripts.

---

## Performance

### Critical

- [x] **Cache config in memory** — done in v1.6.1. `load_config()` caches the parsed dict keyed on the file's `(mtime, size)` and returns deep copies; `save_config()` refreshes the cache.

- [x] **Thread-safe session storage** — done in v1.6.0. `sessions`, `failed_login_attempts`, and `_soundtrack_cache` are guarded by module-level `threading.Lock`s; a background thread sweeps expired entries.

- [~] **Thread-safe config writes** — partial (v1.6.0). `save_config()` is now atomic and lock-serialized, so writes can't corrupt each other. Full load→modify→save atomicity across concurrent handlers is still open (deferred with the Phase 3 in-memory config cache).

### High

- [x] **Cache generated CSS** — done in v1.6.1. `generate_dynamic_styles()` caches its output keyed on the serialized `appearance` settings.

- [x] **Add gzip response compression** — done in v1.6.1. `send_html`/`send_json` gzip responses over 1 KB when `Accept-Encoding: gzip` is present, with `Vary: Accept-Encoding`.

- [x] **Serve images as separate cacheable assets** — done in v1.6.1. Logo/favicon/icons/background are served from `/static/<name>` with `Cache-Control: public, max-age=86400`, an `ETag` (304 on `If-None-Match`), and versioned URLs for cache-busting.

### Medium

- [x] **Add HTTP caching for static content** — done in v1.6.1 for branding assets (`/static/*` uses `Cache-Control: public, max-age=86400` + `ETag` + versioned URLs). Dynamic HTML/JSON stays `no-store` by design.

- [ ] **Connection pooling in proxy** — The `/proxy/` handler creates a new `HTTPConnection` per request (`multi_frames.py:9841`). Reuse connections for repeated requests to the same target.

- [ ] **Close proxy connections on error** — `conn.close()` at `multi_frames.py:9896` may not execute if an exception occurs. Wrap in try-finally.

---

## Code Quality

### High

- [ ] **Break up monolithic POST handler** — `_handle_post()` at `multi_frames.py:9987` is 1,783 lines with 50+ elif branches. Extract each route into a named function for readability and testability.

- [ ] **Deduplicate inline JavaScript** — `sendCommand()` JS function is copy-pasted in two places (`multi_frames.py:5882` and `:6103`). Extract to a single shared script block.

- [ ] **Replace broad exception handlers** — 81 try-except blocks, many catching bare `Exception` or using `except: pass` (e.g. `multi_frames.py:1187`). Use specific exceptions and log errors.

### Medium

- [ ] **Complete modular package** — `multi_frames/templates/` is marked TODO. Finish splitting the single-file source into the modular package for easier development.

- [x] **Add automated tests** — done in v1.4.8. `tests/` holds a zero-dependency stdlib runner and 39 tests covering `hash_password()`, `validate_local_ip()`, `escape_html()`, rate limiter, session lifecycle, config round-trip, iframe/widget ID backfill, per-user permission filtering, login flow, admin gating, proxy SSRF regression, and Node syntax check of `cloud/worker.js`. Run: `python tests/run_tests.py`.

- [ ] **Reduce render function size** — `render_main_page()` (450+ lines) and `render_admin_page()` (1,000+ lines) are hard to maintain. Break into composable helper functions.

---

## Features

- [ ] **Move images out of config JSON** — Branding images (logo up to 500KB, background up to 2MB) are base64-encoded inside the JSON config. Store as separate files, reference by path. Reduces config size and memory usage.

- [ ] **Persist logs to disk** — `ServerLogger` stores logs in an in-memory deque only (`multi_frames.py:347`). Add optional file-based logging with rotation for audit trails.

- [ ] **Add connectivity report rotation** — Reports stored in config (`multi_frames.py:10144`) grow unbounded. Cap at N reports or move to a separate file.
