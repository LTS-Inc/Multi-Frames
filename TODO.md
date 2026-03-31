# TODO - Multi-Frames

Tracking planned optimizations, security hardening, and improvements.

---

## Security

### Critical

- [ ] **Upgrade password hashing** — Replace bare SHA-256 (`hash_password()` in `multi_frames.py:3082`) with PBKDF2 (stdlib `hashlib.pbkdf2_hmac`) using a per-user salt and 600k+ iterations. Migrate existing hashes on next login.

- [ ] **Strengthen password reset tokens** — `uuid.uuid4()[:8]` at `multi_frames.py:10045` gives only ~32 bits of entropy. Use `secrets.token_urlsafe(32)`, add expiration (e.g. 1 hour), and rate-limit reset attempts.

- [ ] **Add CSRF protection** — No anti-CSRF tokens on any POST form. A malicious page can trigger admin actions (add user, change settings) through victim's session. Generate a per-session token, embed in forms, validate on POST.

- [ ] **Fix SSRF in proxy redirect handling** — The `/proxy/` handler follows HTTP redirects without re-validating the target against `validate_local_ip()` (`multi_frames.py:9869`). A local server can redirect to an external host, letting the proxy fetch arbitrary URLs. Re-validate each redirect target before following.

### High

- [ ] **Authenticate info-leak endpoints** — `/api/client-info` and `/api/pi-status` require no auth and expose IP, server port, Pi model, temperature, hostname, memory, and network config. Gate behind authentication.

- [ ] **Add security response headers** — `send_html()` at `multi_frames.py:9603` sets no security headers. Add `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a basic `Content-Security-Policy`.

- [ ] **Harden session cookies** — Ensure `HttpOnly`, `SameSite=Strict`, and `Secure` (when behind HTTPS) flags are set consistently on all Set-Cookie responses. Explicitly delete sessions on logout.

- [ ] **Fix rate-limit bypass via header spoofing** — Login rate limiting trusts `X-Forwarded-For` and `X-Real-IP` headers (`multi_frames.py:9771`), which any client can set. Only trust forwarded headers when behind a known reverse proxy, otherwise use the socket IP.

### Medium

- [ ] **Tighten proxy SSRF surface** — `validate_local_ip()` at `multi_frames.py:3099` allows `.local` and `.lan` hostnames which could resolve to unintended targets via DNS rebinding. Consider allowlist-only or resolve-then-check approach.

- [ ] **Avoid innerHTML for dynamic content** — JS in help/diagnostics page uses `innerHTML` with server responses (e.g. `multi_frames.py:5139`). Switch to `textContent` or DOM element creation to eliminate DOM XSS risk.

- [ ] **Set config file permissions** — `save_config()` doesn't restrict file permissions. Set `0600` on `~/.multi_frames_config.json` so only the owning user can read passwords/tokens.

- [ ] **Re-enable SSL cert verification in proxy** — Proxy disables certificate verification (`ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE` at `multi_frames.py:9848`), allowing MITM on proxied HTTPS connections. Use default verification or make it configurable.

- [ ] **Escape single quotes in `escape_html()`** — `escape_html()` at `multi_frames.py:3254` does not escape `'` to `&#39;`. While most attributes use double quotes, this is an incomplete mitigation. Add single-quote escaping for defense-in-depth.

---

## Performance

### Critical

- [ ] **Cache config in memory** — `load_config()` reads and parses JSON from disk on every HTTP request (`multi_frames.py:9692`, `:9990`). Load once at startup, keep in memory, and reload only when the file's mtime changes.

- [ ] **Thread-safe session storage** — `sessions = {}` (global dict at `multi_frames.py:2983`) is read/written from multiple request threads with no lock. Protect with `threading.Lock()`.

- [ ] **Thread-safe config writes** — Concurrent requests can load config, modify independently, and save — last write wins, losing the other's changes. Use a lock around read-modify-write cycles.

### High

- [ ] **Cache generated CSS** — `generate_dynamic_styles(config)` at `multi_frames.py:4744` rebuilds ~400 lines of CSS on every page render. Cache the output and invalidate only when appearance settings change.

- [ ] **Add gzip response compression** — No compression on any response. HTML pages with inline base64 images can be 10MB+. Check `Accept-Encoding` and gzip responses over 1KB.

- [ ] **Serve images as separate cacheable assets** — Logo, favicon, background are base64-embedded inline in every HTML response (`multi_frames.py:4676-4696`). Serve at `/static/logo.png` etc. with `Cache-Control` and `ETag` headers.

### Medium

- [ ] **Add HTTP caching for static content** — All responses set `Cache-Control: no-store`. CSS/JS/images should use `Cache-Control: public, max-age=86400` with content hashing for cache-busting.

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

- [ ] **Add automated tests** — Currently no tests. Start with unit tests for `hash_password()`, `validate_local_ip()`, `escape_html()`, session management, and config load/save.

- [ ] **Reduce render function size** — `render_main_page()` (450+ lines) and `render_admin_page()` (1,000+ lines) are hard to maintain. Break into composable helper functions.

---

## Features

- [ ] **Move images out of config JSON** — Branding images (logo up to 500KB, background up to 2MB) are base64-encoded inside the JSON config. Store as separate files, reference by path. Reduces config size and memory usage.

- [ ] **Persist logs to disk** — `ServerLogger` stores logs in an in-memory deque only (`multi_frames.py:347`). Add optional file-based logging with rotation for audit trails.

- [ ] **Add connectivity report rotation** — Reports stored in config (`multi_frames.py:10144`) grow unbounded. Cap at N reports or move to a separate file.
