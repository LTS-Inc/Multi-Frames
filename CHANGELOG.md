# Changelog

All notable changes to Multi-Frames will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.1] - 2026-07-07

Performance release. Behavior is unchanged; responses are smaller and faster.

### Performance
- **In-memory config cache.** `load_config()` no longer re-reads and re-parses the JSON config (which can carry multi-MB base64 images) on every request. The parsed config is cached and only re-read when the file's `(mtime, size)` fingerprint changes; `save_config()` refreshes the cache. Callers still receive an independent deep copy, so in-place mutation before saving never leaks into the cache or other request threads.
- **Cached generated CSS.** `generate_dynamic_styles()` rebuilt ~400 lines of CSS on every page render; the result is now cached and reused until the `appearance` settings change.
- **gzip compression.** HTML and JSON responses over 1 KB are gzip-compressed when the client sends `Accept-Encoding: gzip`, with a `Vary: Accept-Encoding` header. HTML pages with inline scripts/styles shrink substantially.
- **Branding images served as cacheable assets.** Logo, favicon, Apple/Android touch icons, and the background image are no longer base64-inlined into every HTML/CSS response. They are served once from `/static/<name>` with `Cache-Control: public, max-age=86400` and an `ETag` (honoring `If-None-Match` → 304), and referenced by a versioned URL (`/static/logo?v=<hash>`) so a changed image busts the cache. Admin-panel upload previews remain inline (admin-only, not on the hot path).

### Notes
- Fully backward-compatible: no config migration, no API changes. The config still stores the images as base64 (moving them out of the JSON entirely is tracked as a separate Phase 4 item); this release stops *re-embedding* them into every response.

## [1.6.0] - 2026-07-07

Security-hardening release. No user-facing feature changes; existing accounts
and configs keep working (password hashes migrate automatically on next login).

### Security
- **PBKDF2 password hashing.** `hash_password()` now uses PBKDF2-HMAC-SHA256 with a per-hash random 16-byte salt and 600,000 iterations (`pbkdf2_sha256$iterations$salt$hash`). `verify_password()` still accepts legacy bare-SHA-256 hashes, and a successful login transparently re-hashes to PBKDF2. Unknown-user logins run a dummy PBKDF2 pass to keep timing constant.
- **CSRF protection.** The session cookie is `SameSite=Strict` (never sent cross-site) and, as defense-in-depth, state-changing POSTs now reject requests whose `Origin`/`Referer` names a different host. Tunnel-forwarded requests are exempt.
- **Security response headers.** HTML responses set `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: SAMEORIGIN` (omitted for tunnel-embedded pages), and a `Content-Security-Policy`; JSON responses set `nosniff`.
- **Hardened session cookies.** `HttpOnly` + `SameSite=Strict` on all session cookies, with `Secure` added automatically when the request arrives over TLS (`X-Forwarded-Proto: https`). Logout now invalidates the session server-side, not just the cookie.
- **Config file permissions.** `~/…/multi_frames_config.json` is written with `0600` (owner-only) since it holds password hashes and API tokens.
- **Worker JSON parsing hardened.** All 13 `request.json()` sites now go through a `readJson()` helper that returns `{}` on malformed input instead of rejecting an un-awaited promise and leaking a stack trace through the 500 handler.

### Changed / Fixed
- **Atomic config writes.** `save_config()` writes to a temp file and `os.replace()`s it into place under a lock, so a crash or concurrent writer can no longer leave a truncated/corrupt config.
- **Thread-safety.** Access to the shared `sessions`, `failed_login_attempts`, and `_soundtrack_cache` dicts (and config writes) is now guarded by locks — the server is threaded, so these were racy before.
- **Background state sweeper.** A daemon thread prunes expired sessions and stale login-lockout entries every 5 minutes so those dicts can't grow unbounded under an IP-rotating attacker.

### Deferred
- **KV read-modify-write races (worker, C-5).** Concurrent widget-template/config/device-list updates can still lose a write because Cloudflare KV has no compare-and-swap. A correct fix needs a Durable Object or a per-key storage layout (each template under its own key); tracked for a later phase rather than shipping a racy half-guard.

### Notes
- The test suite runs slower (~13s vs ~1.5s) because PBKDF2 verification is intentionally expensive; this is expected.

## [1.5.1] - 2026-07-07

### Fixed
- **iFrame proxy is now addressed by stable id, not list index.** `render_main_page` renders the per-user *filtered* iframe list but `/proxy/` indexed the *unfiltered* list, so a restricted user's frame could load a different (hidden) iframe's content. The endpoint is now `/proxy/<id>` and resolves the target against the requesting user's permitted iframes — fixing both the wrong-content bug and a permission-bypass.
- **Fallback content now actually appears.** The configured fallback panel (image + text) was stored and configurable but never shown. Iframes now reveal their fallback panel on an `error` event or after a load timeout via a new `mfShowFallback` page script.
- **Requests/Errors log tabs show the newest entries.** They sliced `[:30]`/`[:20]` off chronological lists (the *oldest* rows); now `[-30:]`/`[-20:]`.
- **Notes widget renders line breaks.** It replaced the literal two-character string `\n` instead of real newlines, collapsing multi-line notes to one line.
- **Embed-code iframes can be saved without a URL.** The URL field was `required` even in embed mode (which ignores it); the add/edit embed toggles now clear `required` when embed mode is on.
- **Inline JS handlers and widget scripts are JS-escaped.** Values interpolated into `onclick`/`<script>` (weather location, countdown target, iframe test buttons) used HTML-escaping, which the parser decodes before JS runs — a name like `Bob's Camera` or city `St. John's` broke the handler. Added `escape_js_string()` and applied it at these sites. `escape_html()` now also escapes the single quote (`'` → `&#39;`).
- **Missing `.status-dot` CSS added.** Connectivity/test indicators and the firmware/restore "spinner" divs referenced `.status-dot`/`.connected`/`.loading`/`.error` classes that were never defined (invisible dots, no spinners). Added the classes plus a spin keyframe.
- **Proxy redirects honor scheme and re-validate the host.** The `/proxy/` redirect loop now re-runs `validate_local_ip()` on each absolute hop (blocking a local→external SSRF bounce), rejects protocol-relative `Location`, and reconnects over HTTPS (port 443) when a redirect target is `https://` instead of always plaintext port 80.
- **Cloud metrics averages use per-metric denominators.** The worker divided each running mean (cpu_temp, memory_pct, cpu_usage) by the total sample count, skewing values low when some samples omit a metric. Each metric now tracks its own non-null count.
- **Cloud CPU usage reports current load.** The device computed `cpu_usage` from cumulative `/proc/stat` counters (a near-constant since-boot average); it now samples twice and reports the delta.

### Changed
- CLAUDE.md corrected: iFrame reordering is via ▲/▼ move buttons (drag-and-drop was never implemented); documented the `/proxy/<id>` addressing and the now-functional fallback panel.

### Added
- Regression tests: proxy permission enforcement by id (`test_proxy_enforces_permissions_by_id`), updated SSRF/external proxy tests to the id scheme, and `escape_html`/`escape_js_string` unit tests. Suite is now 58 tests.

## [1.5.0] - 2026-07-07

### Security
- **Cloud JWT tokens are now signed and verified with HMAC-SHA256** (`crypto.subtle`). Previously the signature was `btoa(JWT_SECRET + '.' + data)` and `verifyToken()` never checked it at all, so anyone could forge an admin session and reach every authenticated worker route. Existing cloud sessions are invalidated and users must sign in again.
- **Stored XSS fixed in the cloud portal.** Device-reported fields (`name`, `hostname`, `ip_address`, `version`, and stat values) are now HTML-escaped before being inserted into the Devices/metrics/push views. A malicious or compromised device can no longer inject script into an admin's browser. Tunnel buttons pass only the device `id` and look the name up client-side, removing the `onclick` string-injection surface.
- **Tunnel routes are now bound to their initiating user.** Tunnel status, close, `admin-ws`, and the HTTP proxy verify `initiated_by` matches the caller, so one authenticated user can no longer drive, attach to, or close another user's tunnel by guessing a tunnel id.
- **Device WebSocket now requires `device_key`.** The relay's device end previously verified the device key only when present; it is now mandatory, so a tunnel-token holder can no longer impersonate the device end.
- **OAuth login now uses a `state` parameter** stored in an HttpOnly cookie and validated on callback, closing a login-CSRF vector.
- **Device keys and tunnel tokens now use a CSPRNG** (`crypto.getRandomValues`) instead of `Math.random()`.
- **`/api/send-command` is restricted to local/private hosts.** An authenticated user could previously make the server open TCP/UDP/Telnet connections to any host and port (internal services, cloud metadata). Real network protocols are now gated by `validate_local_ip()`.

### Fixed
- Socket file-descriptor leak in `send_network_command()`: sockets are now closed via `try/finally` on every path, so failed TCP/UDP/Telnet commands no longer leak descriptors (which could eventually exhaust the server).
- Proxy connection leak: the `/proxy/` upstream connection is now closed in a `finally` block so an exception mid-fetch no longer leaks a socket.
- Cloud tunnel session selection used a non-existent `role` field; it now checks `is_admin`, so the tunnel authenticates as an actual admin instead of falling back to an arbitrary user.

### Added
- Regression tests: `/api/send-command` host restriction (accept local, reject external), and worker static checks asserting HMAC signing/verification, CSPRNG credential generation, and OAuth `state` validation. Suite is now 55 tests.
- `ROADMAP.md` — review findings (UI + network bugs with file:line) and a phased improvement roadmap.

## [1.4.9] - 2026-05-25

### Added
- **Soundtrack Your Brand integration**: connect Multi-Frames to the Soundtrack Your Brand music API and control music zones from the dashboard.
  - New **Soundtrack** widget type — a full control panel showing now playing (track, artist, album art, sound-zone name), playback state, and controls (play/pause, skip, volume). Each widget targets its own sound zone, stored in the widget's `content` field.
  - Admin **Settings → Soundtrack Your Brand** section to enable the integration and store the API token. The token is held server-side only and is never rendered into any page (the inline config view redacts it, alongside the cloud device key).
  - Server-side proxy endpoints keep the token out of the browser: `GET /api/soundtrack/zones` (admin-only, lists sound zones for the widget editor), `GET /api/soundtrack/now-playing` (any logged-in user, short TTL cache per zone), and `POST /api/soundtrack/control` (any logged-in user; play/pause/skip/volume).
  - `soundtrack_graphql()` helper performs authenticated GraphQL calls to a fixed host using only the standard library.

### Security
- The inline (sanitized) admin config view now redacts `soundtrack.api_token` and `cloud.device_key` so secrets are not exposed in the rendered admin page.

## [1.4.8] - 2026-04-16

### Added
- **Per-user iframe/widget visibility**: admins can now restrict which iframes and widgets each non-admin user sees on their dashboard. A new **Permissions** button appears on every non-admin row in the admin Users list; it opens a panel with checkbox groups for iframes and widgets, plus a **Reset (see all)** action.
- **Stable IDs on iframes and widgets**: every iframe and widget now carries an 8-char hex `id` so permissions survive renames and list reordering. `load_config()` backfills IDs on upgrade and persists them exactly once.
- `filter_by_permissions(iframes, widgets, user_record)` helper applied in `render_main_page()`.
- `POST /admin/user/permissions` endpoint to save or reset an individual user's allow-lists. Unknown IDs are silently dropped (self-heals against deleted iframes/widgets).
- Multi-value form field exposure via `_multi` in `read_post_data()` (enables checkbox groups without changing single-value callers).
- Test suite under `tests/` (zero-dependency stdlib runner): `run_tests.py`, `test_unit.py`, `test_server.py`, `test_worker.py`. 39 tests cover password hashing, URL validation, HTML escaping, rate limiter, session lifecycle, config round-trip, ID backfill, permission filtering, login flow, admin gating, proxy rejection of external URLs, proxy SSRF regression, and Node syntax check of `cloud/worker.js`.
- `REVIEW.md` — full codebase review report (bugs, conflicts, risks) grouped by severity with file:line references and suggested fixes.

### Changed
- `render_main_page()` filters iframes and widgets per user. `is_admin=True` users always see everything, regardless of their own permission list.
- iframe add/edit handlers (`/admin/iframe/add`, `/admin/iframe/edit`) inject a new `id` on add and preserve the existing `id` on edit.
- Widget add/edit handlers (`/admin/widget/add`, `/admin/widget/edit`) inject a new `id` on add and preserve the existing `id` on edit.
- `load_config()` now runs a one-shot `_ensure_ids` migration on read and rewrites the config file when any IDs are backfilled.

### Backward compatibility
- User records without `allowed_iframes` / `allowed_widgets` continue to see every iframe and widget — no upgrade surprises.
- Pre-upgrade configs lacking iframe/widget IDs are migrated transparently on first load.

## [1.4.7] - 2026-03-31

### Fixed
- **iFrame proxy breaking local display**: The iframe reverse proxy (added in v1.4.6) was rewriting local iframe URLs to `/proxy/N` even for clients on the local network, where mixed content is not an issue. The server-side proxy cannot properly handle JavaScript-heavy pages, WebSockets, or cookies, causing iframes to display incorrectly. The proxy now checks the client IP and only activates for remote (public) clients accessing through tunnels.

### Changed
- `render_main_page()` now accepts `client_ip` parameter to determine proxy behavior
- Version bumped to 1.4.7

## [1.4.6] - 2026-03-08

### Fixed
- **Tunnel "Not found" on navigation**: Clicking Admin, Help, or any link inside the tunnel remote view navigated to the cloud worker domain instead of routing through the proxy. Injected a URL-rewriting script into HTML responses that intercepts link clicks, form submissions, `fetch()`, and `XMLHttpRequest` to rewrite absolute paths through the tunnel proxy.

### Added
- **POST support for tunnel proxy**: The proxy route now accepts POST requests, forwarding request body and Content-Type through the WebSocket relay to the device. Enables admin panel form submissions (settings, iframe management, etc.) through the tunnel.
- URL-rewriting script injection in `handleProxy()` response pipeline (worker.js)
- Request body forwarding in TunnelRelay DO `handleProxy()` (worker.js)
- POST body handling in `_handle_tunnel_request()` with Content-Length (multi_frames.py)

## [1.4.5] - 2026-03-05

### Fixed
- **Tunnel remote view black screen**: Tunnel proxy requests were made without authentication, causing the local server to redirect to `/login` instead of serving the dashboard. The tunnel now creates an authenticated session (first admin user) on connect and injects the session cookie into all proxy requests.

### Added
- `CloudAgent._tunnel_session_id` — session created via `create_session()` when tunnel starts, cleaned up on close
- Redirect following in `_handle_tunnel_request()` — follows up to 5 local redirects as a safety net

### Changed
- `_handle_tunnel_request()` injects `Cookie: session={id}` header into all proxy requests to the local webserver
- Tunnel worker now loads config and finds the first admin user to create a tunnel session
- Version bumped to 1.4.5

## [1.4.4] - 2026-03-05

### Fixed
- **Tunnel proxy "Connection refused"**: `_get_local_server_port()` was reading the port from the config file, which may not reflect the actual running port when using the `--port` CLI flag. Now uses the global `SERVER_PORT` variable set at startup, ensuring the tunnel always connects to the correct local webserver port.

### Changed
- Simplified `CloudAgent._get_local_server_port()` to a single `return SERVER_PORT` statement
- Version bumped to 1.4.4 across all files

## [1.4.3] - 2026-03-05

### Changed
- Updated ARCHITECTURE.md tunnel flow diagram to show TunnelRelay Durable Object as dedicated relay column
- Updated ARCHITECTURE.md cloud backend component diagram with TunnelRelay DO box
- Added TunnelRelay Durable Object section to CODEBASE.md with internal routes and state schema
- Updated CODEBASE.md tunnel route comments to note DO forwarding
- Updated cloud README architecture diagram to show TunnelRelay DO and WSS connections
- Added secure remote tunnels feature line to cloud README
- Updated wrangler.toml.example with Durable Objects binding and migration config
- Updated CHANGELOG.md with full v1.4.2 Fixed/Added/Changed/Technical breakdown
- Version bumped to 1.4.3 across all files

## [1.4.2] - 2026-03-05

### Fixed
- **Tunnel proxy disconnect**: Replaced in-memory `activeTunnels` Map with a Durable Object (`TunnelRelay`) for WebSocket relay. The per-isolate Map caused the proxy iframe to show "Tunnel Disconnected" because HTTP requests could hit a different Worker isolate than the one holding the device WebSocket.

### Added
- `TunnelRelay` Durable Object class — each tunnel gets its own DO instance guaranteeing a single execution context for device WebSocket, admin WebSocket, and HTTP proxy requests
- `getTunnelDO()` helper to obtain a Durable Object stub by tunnel ID
- Durable Object binding (`TUNNEL_RELAY`) and migration (`v1`) in `wrangler.toml`

### Changed
- Device-ws, admin-ws, and proxy tunnel routes now validate auth in the Worker fetch handler then forward to the `TunnelRelay` Durable Object
- Tunnel status check (`/api/tunnel/:id/status`) queries DO for live active state instead of in-memory Map
- Tunnel close (`/api/tunnel/:id/close`) delegates WebSocket teardown to DO
- Active tunnels list (`/api/tunnel/active`) queries recent KV sessions and verifies via DO
- Removed module-level `activeTunnels` Map from cloud worker (replaced by DO state)
- Updated `wrangler.toml.example` with Durable Objects binding and migration config
- Updated cloud README with Durable Objects requirement note and updated wrangler.toml example
- Updated ARCHITECTURE.md tunnel flow diagram to show Durable Object relay
- Updated CODEBASE.md cloud worker documentation to reflect DO architecture

### Technical
- Durable Objects require Cloudflare Workers Paid plan ($5/month)
- Each `TunnelRelay` instance maintains: `deviceWebSocket`, `adminWebSockets[]`, `pendingProxyRequests` Map
- DO handles `/device-ws`, `/admin-ws`, `/proxy/*`, `/status`, `/close` internal routes
- Proxy requests use a promise-based pattern: store pending request, send via device WS, resolve on matching `http_response`
- Device WebSocket close event automatically notifies all admin WebSockets and rejects pending proxy requests

## [1.4.1] - 2026-03-05

### Changed
- Updated all documentation to reflect v1.4.0 secure tunnel features
- Added tunnel API routes, session/log/WebSocket message schemas to CODEBASE.md
- Added secure tunnel flow diagram to ARCHITECTURE.md
- Updated CloudAgent class documentation with tunnel methods in CODEBASE.md
- Fixed tunnel connection timeout with lightweight `GET /api/tunnel/check` polling endpoint
- Device now polls for tunnel requests every 5 seconds between 60-second heartbeats
- Increased admin-side tunnel poll timeout from 60 to 120 seconds
- Updated version references across all Python files and documentation

## [1.4.0] - 2026-03-04

### Added
- **Secure Remote Tunnels**: Access device webservers remotely through encrypted WebSocket tunnels
  - New "Tunnels" page in cloud dashboard sidebar with full tunnel management
  - "Connect Remotely" button on each device card (enabled when device is online)
  - WebSocket-based tunnel relay through Cloudflare Worker for NAT traversal
  - Embedded iframe view of remote device webserver within the cloud portal
  - "Open in New Tab" option for full-screen remote access
  - Quick Connect section on Tunnels page for rapid device connections
  - `POST /api/tunnel/initiate` - Initiate tunnel session (user auth)
  - `GET /api/tunnel/{id}/status` - Check tunnel status (user auth)
  - `POST /api/tunnel/{id}/close` - Close active tunnel (user auth)
  - `GET /api/tunnel/logs` - Retrieve tunnel activity logs (user auth)
  - `GET /api/tunnel/active` - List active tunnels (user auth)
  - `GET /api/tunnel/proxy/{id}/` - HTTP proxy through active tunnel (user auth)
  - WebSocket endpoints for device and admin tunnel connections

- **Tunnel Security**: Multi-layer security for remote access
  - Time-limited tunnel tokens (5-minute validity for initial connection)
  - Maximum 1-hour tunnel session duration
  - Device key + tunnel token dual authentication for device WebSocket connections
  - Admin JWT authentication for tunnel initiation and proxy access
  - Per-tunnel unique IDs and cryptographic tokens
  - Device online status verification before tunnel initiation
  - Sandboxed iframe embedding for remote webserver view

- **Tunnel Activity Logging**: Complete audit trail for all tunnel sessions
  - Logs for: tunnel initiated, device connected, admin connected, tunnel closed
  - Tracks initiating user, device name, timestamps, and tunnel IDs
  - 90-day log retention with automatic expiration
  - Activity log table in Tunnels page with event badges and filtering
  - Stats cards showing active tunnels, total sessions, and available devices

- **Mobile-Friendly Tunnel UI**: Responsive design for tunnel management on mobile
  - Adaptive iframe height (70vh desktop, 50vh tablet, 40vh mobile)
  - Responsive tunnel log table with column hiding on small screens
  - Touch-friendly Connect Remotely buttons
  - Responsive tunnel status cards and connecting overlay

### Changed
- Cloud dashboard sidebar now includes "Tunnels" navigation item
- Device card actions row now includes "Connect Remotely" button (green, prominent)
- CloudAgent heartbeat response includes `tunnel_requested` field for tunnel signaling
- CloudAgent `get_status()` now returns `tunnel_active` boolean
- Device actions section now wraps on mobile for better touch targets
- Version bumped to 1.4.0

### Technical
- `CloudAgent._establish_tunnel()` - Starts tunnel WebSocket connection in background thread
- `CloudAgent._run_tunnel()` - Raw WebSocket client implementation (no external dependencies)
- `CloudAgent._handle_tunnel_request()` - Forwards HTTP requests to local webserver via `http.client`
- `CloudAgent._ws_read_frame()` / `_ws_send_frame()` - WebSocket frame encoding/decoding per RFC 6455
- `CloudAgent._recv_exact()` - Reliable socket read helper
- Tunnel tokens use `tun_` prefix + 48 random alphanumeric characters
- Tunnel IDs use 16 random lowercase alphanumeric characters
- `logTunnelEvent()` helper stores events in KV with indexed retrieval
- `getTunnelDisconnectedHTML()` helper for disconnected tunnel iframe content
- Active tunnels relayed via `TunnelRelay` Durable Object (one instance per tunnel session)
- Tunnel proxy supports both text and binary content forwarding (base64 encoding for binary)

## [1.3.0] - 2026-02-18

### Added
- **Cloud Portal Customization**: Full branding customization from within the cloud portal
  - Logo upload with base64 storage (recommended 200x200px+, max 2MB)
  - Logo displayed in sidebar header, login page, and mobile header
  - Fallback to URL-based logo if no file uploaded
- **iOS Home Screen Icon**: Upload Apple Touch Icon (180x180px PNG) for cloud portal
  - Enables "Add to Home Screen" on iOS with custom icon
  - Served via `/api/branding/apple-touch-icon`
- **Android Home Screen Icon**: Upload Android icon (192x192px PNG) for cloud portal
  - Auto-generates Web App Manifest for "Add to Home Screen"
  - Served via `/api/branding/android-icon`
- **Favicon Upload**: Custom browser tab icon for cloud portal
  - Supports ICO and PNG formats (max 512KB)
  - Served via `/api/branding/favicon`
- **Widget Template Management**: Create and manage widget templates from cloud portal
  - New "Widgets" page in cloud dashboard sidebar
  - Create templates for all 8 widget types (clock, date, weather, countdown, text, image, notes, buttons)
  - Configure size, colors, border radius, and type-specific JSON config
  - Push widget templates to selected devices (adds widget to device config)
  - `POST /api/widget-templates` - Create template
  - `PUT /api/widget-templates/{id}` - Update template
  - `DELETE /api/widget-templates/{id}` - Delete template
  - `POST /api/widget-templates/push` - Push template to devices
- **Historical Metrics Logging**: Device performance data tracking and visualization
  - New "Metrics" page in cloud dashboard with device selector
  - Devices auto-report metrics every 5 minutes (CPU temp, memory, disk, uptime, CPU usage)
  - Hourly data stored with 30-day retention (max 60 entries/hour)
  - Daily summaries with 90-day retention (avg/max temp, memory %, CPU %, hours online)
  - SVG-based responsive chart with 24h/7d/30d range selector
  - Metric selector: CPU Temp, Memory %, CPU Usage, Hours Online
  - `POST /api/metrics/record` - Device records metrics (device key auth)
  - `GET /api/metrics/{deviceId}?range=24h&metric=cpu_temp` - Query metrics (user auth)
  - `GET /api/metrics/{deviceId}/latest` - Get latest metrics (user auth)
- **Expanded Settings Page**: Tabbed interface with Branding, App Icons, and Colors & Theme sections
  - Drag-and-drop style upload zones for all image assets
  - Live preview of uploaded images with remove option
  - Color pickers with descriptive hints
  - Dark mode toggle with description

### Changed
- Cloud portal branding model expanded: `logoData`, `logoMime`, `faviconData`, `faviconMime`, `appleTouchIconData`, `appleTouchIconMime`, `androidIconData`, `androidIconMime`
- Cloud portal now includes `<meta>` tags for mobile web app support (iOS and Android)
- Cloud dashboard sidebar now includes Widgets and Metrics navigation items
- Settings page redesigned with tab navigation (Branding / App Icons / Colors & Theme)
- CloudAgent now sends device metrics every 5 heartbeats (5 minutes) to cloud
- CloudAgent background thread tracks metrics reporting cycle
- Branding PUT endpoint preserves existing fields when not provided in request

### Technical
- `CloudAgent._send_metrics()` method for periodic metric reporting
- `/api/branding/logo`, `/api/branding/favicon`, `/api/branding/apple-touch-icon`, `/api/branding/android-icon` serve binary assets
- Metrics use KV key format: `metrics:{deviceId}:{hourKey}` with TTL-based expiration
- Daily summaries use rolling average calculation for temperature, memory, and CPU
- Upload size validation: logos max 2MB, icons max 512KB
- SVG chart rendering with area fill, grid lines, axis labels, and data point circles

## [1.2.8] - 2026-02-14

### Fixed
- **Cloud Agent SSL Error**: Fixed `CERTIFICATE_VERIFY_FAILED` error when connecting to cloud
  - Added `_get_ssl_context()` helper to CloudAgent that detects available CA certificates
  - Falls back to unverified context on systems without CA bundle (Raspberry Pi, minimal installs)
  - Applied to all CloudAgent HTTPS calls: heartbeat, config pull, firmware download, config push

## [1.2.7] - 2026-02-14

### Added
- **Cloud Firmware Management**: Upload and deploy firmware to devices remotely
  - New Firmware page in cloud dashboard with upload, deploy, and status tracking
  - `POST /api/firmware/upload` - Upload firmware file with version auto-extraction
  - `GET /api/firmware` - Get firmware metadata (version, size, uploader, date)
  - `GET /api/firmware/download` - Device downloads firmware (device key auth)
  - `POST /api/firmware/deploy` - Queue firmware deployment to selected devices
  - Deploy modal with per-device selection and bulk deploy
  - Device firmware status table showing current version vs latest
  - Automatic firmware validation, backup, and server restart on device
- **Cloud Config Refresh**: Request devices to push their current config
  - `POST /api/config/{id}/request` - Request device to sync its config
  - "Refresh" button on device cards in cloud dashboard
  - "Refresh from Device" button in config view modal
  - Device auto-pushes config on next heartbeat when requested

### Changed
- Heartbeat response now includes `firmware_update_available` and `config_requested` flags
- Device cards show firmware update pending indicator
- Cloud dashboard sidebar now includes Firmware navigation item

## [1.2.6] - 2026-02-14

### Added
- **Typography Settings**: New appearance options under admin panel
  - Font family selection (System, Inter, Roboto, Monospace)
  - Base font size (12-24px)
  - Heading weight (Normal, Medium, Semibold, Bold)
- **Layout Settings**: Customizable layout parameters
  - Border radius (0-20px)
  - iFrame gap/spacing (8-32px)
  - Content padding (8-32px)
- **Animation Settings**: Control over UI animations
  - Enable/disable animations
  - Transition speed (Slow, Normal, Fast)
- **Android Home Screen Icon**: Support for Android "Add to Home Screen"
  - PNG upload (192x192px recommended)
  - Uses `<link rel="icon" sizes="192x192">` for Android devices

### Changed
- Empty text fields now allowed for all customization options
- Custom CSS icon updated from ✨ to 🎯 for better distinction
- Improved appearance settings organization in admin panel

## [1.2.5] - 2026-02-14

### Removed
- **Connectivity Test**: Removed server-side ping test and status dots from dashboard
  - Removed `/api/connectivity-test-url` endpoint
  - Removed status dot indicators from iframe cards
  - Removed connectivity test CSS (status-dot classes)
  - Help page test now uses iframe-based approach
- **Help Page for Users**: Help/diagnostics page now restricted to admin users only

### Added
- **Password Visibility Toggle**: Show/hide button on login password field
  - Toggle button displays "Show"/"Hide" text
  - Styled to match existing form design
- **Mobile Optimizations**: Improved responsive layout for small screens
  - Better header layout on phones (smaller logo, compact nav)
  - Responsive iframe cards with adjusted padding and font sizes
  - Optimized footer spacing on mobile
  - Better touch target sizes (min 36px on extra small screens)
  - Improved card heading sizes for 480px screens

## [1.2.4] - 2026-02-05

### Added
- **CLAUDE.md**: Project context document for AI assistants
  - Development guidelines and common patterns
  - API endpoint reference
  - Troubleshooting guide
- **ARCHITECTURE.md**: Comprehensive system architecture documentation
  - Component diagrams (local server, cloud backend)
  - Data flow diagrams (auth, sync, connectivity)
  - Security architecture
  - Deployment architecture (Raspberry Pi)
- **CODEBASE.md**: Detailed code documentation
  - Module-by-module function reference
  - Configuration schema
  - API reference with request/response examples
  - HTML templates and CSS classes
  - JavaScript function reference

## [1.2.3] - 2026-02-04

### Changed
- **Simplified Connectivity Test**: Completely redesigned for reliability
  - Server now returns simple `reachable: true/false` instead of complex status
  - Any HTTP response (including 4xx/5xx) = reachable
  - Only network errors (timeout, refused, DNS fail) = not reachable
  - Removed complex X-Frame-Options and CSP checking that caused false failures
  - Frontend JavaScript simplified to basic true/false status display

### Fixed
- Connectivity test no longer shows false failures for accessible iframes
- Help page connectivity test updated to use simplified API

## [1.2.2] - 2026-02-04

### Fixed
- **Connectivity Test Accuracy**: Fixed false negatives in iframe status indicators
  - HTTP 4xx/5xx responses now correctly show as "reachable" (server responded)
  - Only network-level errors (timeout, DNS, connection refused) show as failed
  - Added warning status for SSL certificate issues
- **Cloud Agent 403 Error**: Fixed Cloudflare blocking Python requests
  - Added proper User-Agent header (`Multi-Frames/{VERSION}`) to all cloud API calls
  - Heartbeat, config pull, and config push endpoints now work correctly

### Changed
- Connectivity test now uses HEAD requests instead of GET for faster response
- Reduced connectivity test timeout from 10s to 8s
- Improved error messages for different network failure types
- Help page and admin connectivity tests now show "Reachable" for HTTP errors

## [1.2.1] - 2026-02-04

### Added
- **Cloud Settings in Admin Panel**: Configure cloud connectivity from the Settings tab
  - Cloud URL field for Cloudflare Worker endpoint
  - Device Key field for device authentication
  - Enable/disable toggle for cloud sync
  - Live status indicator (Connected/Connecting/Off)
- **Cloud Status Indicator**: Shows real-time cloud connection status in admin dashboard
  - Green checkmark when connected
  - Orange dots when connecting
  - Gray X when disabled

### Changed
- Admin status dashboard now includes cloud connectivity status
- Cloud agent automatically starts/stops based on settings

## [1.2.0] - 2026-02-03

### Added
- **Modern Cloud Dashboard**: Completely redesigned cloud management interface
  - Inter font family with modern typography
  - Responsive sidebar navigation (collapses on mobile)
  - Stats cards showing total/online/offline device counts
  - Device cards with hover effects and status indicators
  - Toast notifications for user feedback
- **Branding Customization**: Customize the cloud dashboard appearance
  - Company name setting
  - Logo URL upload
  - Primary and accent color pickers
  - Dark mode toggle
  - Branding stored in Cloudflare KV
- **Branding API Endpoints**: `GET /api/branding` and `PUT /api/branding`

### Changed
- Cloud dashboard is now fully responsive for mobile devices
- Improved sidebar with hamburger menu for mobile navigation
- Settings page reorganized with branding section

## [1.1.15] - 2026-02-03

### Added
- **Cloud Remote Management**: Manage 50+ Multi-Frames devices from anywhere
  - Cloudflare Workers-based serverless backend
  - Google Workspace authentication for secure access
  - Real-time device status monitoring (online/offline, uptime, temp)
  - Full config mirror sync across all devices
  - Bulk config push to multiple devices
  - Device registration with secure API keys
- **Cloud Agent**: Background service in Multi-Frames for cloud connectivity
  - Automatic heartbeat every 60 seconds
  - Config pull/push synchronization
  - Auto-apply config updates from cloud
- **Cloud Dashboard**: Web-based management interface
  - View all registered devices
  - Monitor device health and status
  - Push configurations remotely
  - Device registration workflow

## [1.1.14] - 2026-02-03

### Changed
- **Simplified iFrame Connectivity Test**: Streamlined the connectivity status indicator
  - Simple green/red status: green = reachable, red = not reachable
  - Removed complex X-Frame-Options/CSP header checking (was causing false warnings)
  - More reliable and predictable connectivity detection
  - Cleaner, simpler codebase

### Fixed
- **User Add Error**: Fixed "cannot access local variable 're'" error when adding users
- **Server Uptime**: Fixed uptime not resetting after unexpected server stops

### Added
- **Status Icon Setting**: New option to hide/show connectivity status icon per iframe

## [1.1.13] - 2026-01-27

### Fixed
- **Throttle Alert Accuracy**: Fixed false "Throttling Active" warning that appeared even when `vcgencmd get_throttled` returned `0x0`
  - Now properly checks individual throttle flags (bits 0-3 for current, bits 16-19 for past issues)
  - Shows red warning only for active throttling issues
  - Shows orange warning for past issues (since boot)
  - No warning displayed when system is healthy (0x0)

## [1.1.12] - 2026-01-27

### Fixed
- **Raspberry Pi Health Widgets**: Fixed widgets showing 0% instead of real data
  - Memory widget now shows used/total in MB (e.g., `512/2048 MB`)
  - Disk widget now shows used/total in GB (e.g., `12.5/32.0 GB`)
  - Power widget now shows actual core voltage with color indicator
- **Server Reset Issue**: Removed `WatchdogSec=300` from systemd service to prevent 5-minute automatic restarts

### Added
- Real-time memory usage tracking (`memory_used`, `memory_free` fields)
- Real-time disk usage tracking (`disk_total`, `disk_used`, `disk_free` fields)
- Core voltage monitoring via `vcgencmd measure_volts core`

## [1.1.11] - 2026-01-26

### Added
- **Watchdog Tab**: New admin panel tab with 30-day server uptime tracking
  - 24-hour, 7-day, and 30-day uptime percentages
  - Visual uptime chart with daily breakdown
  - Crash and restart event logging
  - Session duration tracking

## [1.1.10] - 2025-01-26

### Added
- **Status Dashboard**: Modern health banner at top of admin page showing server status
- **Server Health Indicator**: Visual 🟢/🟡/🔴 status with uptime display
- **Raspberry Pi Card**: Dedicated section showing temperature, memory, disk, power status
- **Modern Logs Viewer**: Tabbed interface with Requests, Logs, and Errors tabs
- **Stats Cards**: Visual cards for requests, errors, memory, IP address
- **Quick Info Bar**: Hostname, port, Python version, mDNS status at a glance

### Changed
- Admin page now shows status dashboard at top (always visible)
- System panel reorganized into logical sections
- Logs use color-coded icons and modern styling
- Connectivity testing simplified with inline status indicators
- Overall cleaner admin UI with better information hierarchy

### Fixed
- Removed duplicate code sections in render_system_section
- Improved code organization and reduced redundancy

## [1.1.9] - 2025-01-26

### Added
- **Git Clone URL Field**: Paste any GitHub URL format to configure updates
  - HTTPS: `https://github.com/owner/repo.git`
  - HTTPS with auth: `https://user:token@github.com/owner/repo.git`
  - SSH: `git@github.com:owner/repo.git`
  - Short: `github.com/owner/repo` or `owner/repo`
- **URL Parser**: Automatically extracts owner/repo from pasted URLs
- **Configuration Status**: Shows "Configure Repository" prompt when not set
- **Repository Link**: Displays linked GitHub repo when configured

### Changed
- Update settings form auto-opens when repository not configured
- "Check for Updates" button disabled until repository is configured
- Cleaner UI with primary URL field and advanced options collapsed

### Fixed
- NoneType error in `render_update_section` when `last_result` is None
- Admin page 500 error on fresh installations
- Authenticated GitHub URLs now parsed correctly

## [1.1.8] - 2025-01-26

### Added - Enhanced Install Script for Raspberry Pi
- **Kiosk Mode** (`--kiosk`): Auto-start Chromium in fullscreen on boot
- **Screen Blanking** (`--disable-blanking`): Prevent screen from sleeping
- **WiFi Fix** (`--fix-wifi`): Disable power management to prevent dropouts
- **Hostname Setup** (`--hostname NAME`): Set Pi hostname during install
- **Status Command** (`--status`): Show service status + Pi temp/throttling
- **Live Logs** (`--logs`): Follow logs in real-time
- **Auto Dependencies** (`--install-deps`): Install zeroconf and git

### Changed - Systemd Service Improvements
- Watchdog timer for Pi (5 minute timeout, auto-restart if hung)
- Memory limits for Pi (256MB max, 192MB high watermark)
- Security hardening (NoNewPrivileges, ProtectSystem, PrivateTmp)
- UFW firewall auto-configuration when active
- Better service restart timing (10s for Pi, 5s for others)

### Technical
- 717-line install.sh with comprehensive Pi detection
- X11/LightDM screen blanking disable
- Chromium kiosk mode with error dialog suppression
- WiFi power management via systemd service
- Hostname validation (RFC 1123 compliant)

## [1.1.7] - 2025-01-26

### Added
- **Auto-Restart on Crash**: Server automatically restarts with exponential backoff (up to 10 attempts)
- **Server Health Alerts**: Track and display errors, crashes, and warnings in admin panel
- **Alert System**: Severity levels (critical, error, warning, info) with timestamps
- **Crash Counter**: Tracks server restarts and displays in System tab
- **Clear Alerts**: Button to clear all server health alerts
- **--no-auto-restart**: Command line flag to disable auto-restart for debugging

### Fixed
- **Request Error Handling**: Wrapped do_GET and do_POST in try/except blocks
- **Connection Errors**: Graceful handling of BrokenPipeError and ConnectionResetError
- **Regex Pattern**: Fixed HTML input pattern attributes for modern browser compatibility (v flag)

### Changed
- Server stability significantly improved - crashes now auto-recover
- Error messages are captured and displayed in admin panel
- Improved logging of request errors

### Technical
- `ServerAlerts` class for tracking server health
- `_handle_request_error()` method for graceful error handling
- `track_server_alert()` function for logging alerts
- Main loop now has crash recovery with backoff
- Alerts consolidate repeated errors within 60 seconds

## [1.1.6] - 2025-01-26

### Added
- **Firmware Update System**: Check for and install updates from GitHub
- **Check for Updates**: Button to check GitHub releases for new versions
- **Git Pull Updates**: One-click update when running from a git repository
- **Update Settings**: Configure GitHub owner/repo for update checks
- **Git Status Display**: Shows current branch, commit hash, and uncommitted changes
- **Version Comparison**: Smart comparison determines if update is available
- **Auto-detection**: Automatically detects GitHub repo from git remote URL

### Changed
- Reorganized System page with dedicated "Firmware Updates" section
- Manual firmware upload moved to its own collapsible section
- Update check results are saved and displayed on page load

### Technical
- `get_git_info()`: Gets current git repository status
- `check_for_updates()`: Checks GitHub API for latest release
- `is_newer_version()`: Compares semantic version strings
- `perform_git_pull()`: Executes git pull with error handling
- New POST handlers: `/admin/system/check-updates`, `/admin/system/git-pull`, `/admin/system/update-settings`

## [1.1.5] - 2025-01-25

### Added
- **Raspberry Pi Auto-Detection**: Automatically detects when running on a Raspberry Pi
- **Pi System Info Panel**: Shows model, temperature, memory, hostname, throttling status
- **Temperature Monitoring**: Color-coded temperature display with status indicators (Normal/Warm/Hot/Critical)
- **Throttling Warnings**: Shows under-voltage, frequency capping, and thermal throttling alerts
- **Change Hostname**: Change Raspberry Pi hostname directly from the web interface
- **Pi Reboot/Shutdown**: Reboot or shutdown the Pi from Admin → System panel
- **dhcpcd Support**: Network configuration via dhcpcd.conf (Raspberry Pi OS default)
- `/api/pi-status` endpoint: Get Pi info via JSON API
- `/api/ping` endpoint: Simple connectivity check endpoint
- Auto-reconnect after Pi reboot (polls for server return)

### Changed
- Network config detection now prioritizes dhcpcd for Raspberry Pi OS
- System Information section now shows Pi-specific hardware details when detected
- Linux network configuration uses dhcpcd when available

### Technical
- `get_raspberry_pi_info()`: Comprehensive Pi detection via /proc/device-tree, /proc/cpuinfo, vcgencmd
- `apply_pi_network_dhcpcd()`: Configure static IP via /etc/dhcpcd.conf
- `set_pi_hostname()`: Update /etc/hostname and /etc/hosts
- `render_raspberry_pi_section()`: Dedicated UI component for Pi info

## [1.1.4] - 2025-01-25

### Fixed
- Browser back button no longer navigates away from the main page when iframes are present
- Iframe navigation (clicking links, using back/forward) now stays within the iframe

### Added
- Enhanced sandbox attribute: `allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox`
- Browser history management to prevent accidental page departure
- Links clicked in iframes now open in new tabs instead of hijacking parent
- Automatic sandbox injection for embed code iframes (YouTube, Vimeo, etc.)

### Security
- Removed `allow-top-navigation` from sandbox to prevent iframe from navigating parent page
- Embed codes now receive sandbox attributes if not already present

## [1.1.3] - 2025-01-25

### Added
- Password change functionality in Admin → Users
- "Change Password" button for each user
- Password confirmation field (must match)
- Terminal banner now shows security status line
- Green indicator when admin password has been changed
- Admins can change any user's password

### Changed
- Terminal banner shows `Security: ● Password changed` (green) or `Security: ○ Default password` (yellow)
- User list now shows "(you)" indicator for current user

## [1.1.2] - 2025-01-25

### Added
- Comprehensive mobile CSS optimizations
- Safe-area-insets for notched phones (iPhone X+)
- Touch-friendly button sizes (min 44px targets)
- Admin tabs show icons-only on mobile with tooltips
- Login rate limiting (5 attempts, 15-minute lockout)
- Timing-attack resistant password comparison
- Print stylesheet
- Reduced motion support (`prefers-reduced-motion`)
- Touch feedback animations on buttons

### Changed
- Form inputs now use 16px font to prevent iOS zoom
- Improved mobile layouts for item lists and forms
- Better horizontal scrolling on admin tabs with fade indicator
- Color grid uses 2 columns on mobile, 1 on very small screens
- Widgets container responsive grid improvements

### Fixed
- Bare `except:` clauses replaced with specific exceptions
- Improved error messages for button widget configuration

### Security
- Added login attempt tracking and IP-based lockout
- Password comparison now uses `secrets.compare_digest()`
- Failed login attempts are logged with IP address

## [1.1.1] - 2025-01-25

### Fixed
- Config file permission error now shows user-friendly message instead of crashing
- Branding uploads (logo, favicon, iOS icon) now handle save errors gracefully

### Added
- Warning banner in System tab when config file is not writable
- Instructions shown to fix permissions (chmod commands)
- `check_config_writable()` function for permission detection

## [1.1.0] - 2025-01-25

### Added
- Configuration import/upload feature
- "Preserve users" option for config import
- Modernized terminal boot UI with colors
- `--no-color` flag for terminal output
- Terminal shows network IP, config stats, mDNS status
- Full config export (includes password hashes for backup)
- Deep merge on config import ensures all fields exist
- Enhanced Help page with device/network information
- Mobile-responsive Help page layout
- `/api/client-info` endpoint for IP detection
- Table of Contents in source code for navigation
- Modular package structure for development

### Fixed
- Firmware upload bug (empty file error)
- Connectivity report submission error
- Security warning only shows if default password in use

### Changed
- Help page now shows connection status cards
- Device info shows browser, OS, screen details
- Improved mobile layout for test results

## [1.0.0] - 2025-01-25

### Added
- Initial release
- iFrame management with URL/embed code support
- Dashboard widgets system (8 widget types):
  - Clock (12h/24h)
  - Date
  - Text/HTML
  - Image
  - Weather (Open-Meteo API, no key required)
  - Countdown
  - Notes
  - Command Buttons
- Command Buttons with network protocols (TCP/UDP/Telnet)
- User authentication and admin panel
- Customizable branding (logo, favicon, apple-touch-icon)
- Theme customization (colors, backgrounds, CSS)
- Network configuration (DHCP/static IP)
- mDNS/Bonjour support for .local hostnames
- Connectivity testing with browser/server tests
- User connectivity reports to admin
- Forgot password system with admin approval
- Footer hyperlinks configuration
- Fallback image for failed iFrames
- Tabbed admin navigation with mobile support
- Session-based authentication (24h timeout)
- Cross-platform support (Windows, macOS, Linux, Raspberry Pi)

### Security
- SHA-256 password hashing
- Secure session tokens (256-bit)
- HttpOnly, SameSite=Strict cookies
- Local IP validation for iFrames
- iFrame sandboxing

---

## Versioning

- **Major version (X.0.0)**: Breaking changes or major new features
- **Minor version (0.X.0)**: New features, backwards compatible
- **Patch version (0.0.X)**: Bug fixes, minor improvements
