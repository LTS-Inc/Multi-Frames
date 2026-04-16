# Multi-Frames - Project Context

This document provides context for AI assistants working on the Multi-Frames codebase.

## Project Overview

**Multi-Frames** is a zero-dependency Python web server for displaying configurable iFrames and dashboard widgets. Designed for home dashboards, kiosks, digital signage, and Raspberry Pi deployments.

- **Author**: Marco Longoria, LTS, Inc.
- **Version**: 1.4.8
- **License**: MIT
- **Python**: 3.6+

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system architecture.

### Key Components

| Component | Location | Description |
|-----------|----------|-------------|
| Main Server | `multi_frames.py` | Single-file distribution (~10k lines) |
| Modular Source | `multi_frames/` | Package with separated modules |
| Cloud Backend | `cloud/worker.js` | Cloudflare Worker for remote management |

### Technology Stack

- **Backend**: Python standard library only (no pip dependencies)
- **Frontend**: Vanilla JavaScript, CSS3
- **Cloud**: Cloudflare Workers + KV storage
- **Auth**: Session-based (local), Google OAuth (cloud)

## File Structure

```
Multi-Frames/
├── multi_frames.py          # Single-file distribution (main)
├── multi_frames/            # Modular package source
│   ├── __init__.py          # Version, metadata
│   ├── __main__.py          # Entry point
│   ├── config.py            # Configuration management
│   ├── auth.py              # Authentication
│   ├── logger.py            # Logging
│   ├── cli.py               # Terminal UI
│   ├── build.py             # Build script
│   ├── network/             # Network utilities
│   ├── utils/               # Helper functions
│   ├── templates/           # HTML templates (TODO)
│   └── handlers/            # HTTP handlers (TODO)
├── cloud/                   # Cloud management
│   ├── worker.js            # Cloudflare Worker
│   ├── wrangler.toml.example
│   └── README.md
├── ARCHITECTURE.md          # System architecture docs
├── CODEBASE.md              # Detailed code documentation
├── CHANGELOG.md             # Version history
└── README.md                # User documentation
```

## Development Guidelines

### Code Style

- **No external dependencies** - Use only Python standard library
- **Single-file deployable** - Build combines modules into one file
- **Embedded HTML/CSS/JS** - All frontend code in Python strings
- **Type hints** - Use where practical
- **Docstrings** - Document public functions

### Common Patterns

```python
# HTML escaping (always escape user input)
from multi_frames.utils.html import escape_html
safe_text = escape_html(user_input)

# Configuration access
config = load_config()
config["setting"] = value
save_config(config)

# Session validation
user = self.get_current_user()
if not user:
    self.redirect('/login')
    return

# Stable IDs on new iframes / widgets
import secrets
new_iframe = {"id": secrets.token_hex(4), "name": name, ...}

# Per-user visibility filter (applied in render_main_page)
iframes, widgets = filter_by_permissions(
    config.get("iframes", []),
    config.get("widgets", []),
    config.get("users", {}).get(user, {}),
)
```

### Building

```bash
# Build single-file distribution
python multi_frames/build.py

# Output: dist/multi_frames.py
```

### Running

```bash
# From single file
python multi_frames.py --port 8080

# From package
python -m multi_frames --port 8080
```

## Key Features to Understand

### 1. iFrame Management
- Add/edit/delete iFrames with URLs, dimensions, zoom
- Drag-and-drop reordering
- Connectivity testing (server-side ping)
- Fallback content for failed loads
- Stable 8-char hex `id` on every iframe (backfilled on upgrade) — permissions and future references should use `id`, not list index

### 2. Dashboard Widgets
- Clock, weather, buttons, text, images
- Command buttons (TCP/UDP/Telnet)
- Raspberry Pi monitoring card
- Stable 8-char hex `id` on every widget (backfilled on upgrade)

### 3. User Authentication & Permissions
- Session-based with secure tokens
- Admin vs regular users
- Password hashing — currently bare SHA-256 (no salt); PBKDF2 migration is tracked in `TODO.md`
- Rate limiting on login
- **Per-user allow-lists**: each user record may carry optional
  `allowed_iframes` / `allowed_widgets` fields (lists of stable IDs).
  `None` or missing = see all (backward compat); `[]` = see none; list
  of IDs = whitelist. Admins always bypass filtering. See
  `filter_by_permissions()` applied in `render_main_page()`.
- Admin UI: each non-admin user row in Admin → Users has a **Permissions**
  button opening checkbox groups for iframes and widgets, plus a
  **Reset (see all)** action. Posts to `/admin/user/permissions`.

### 4. Cloud Sync (Optional)
- Cloudflare Worker backend
- Google Workspace authentication
- Config push/pull to 50+ devices
- Real-time device status
- Portal branding: logo, favicon, iOS/Android icon uploads
- Widget template management and push-to-devices
- Historical metrics logging with 24h/7d/30d chart views
- Device performance tracking (CPU, memory, disk, uptime)
- Secure remote tunnels for accessing device webservers
- Tunnel relay via TunnelRelay Durable Object (one instance per tunnel)
- Tunnel activity logging with 90-day retention

### 5. Raspberry Pi Integration
- Auto-detection of Pi hardware
- Temperature, memory, disk monitoring
- Kiosk mode configuration
- GPIO controls (reboot, shutdown)

## API Endpoints

### Public
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/login` | GET/POST | User login |
| `/logout` | GET | User logout |

### Authenticated
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin` | GET | Admin panel |
| `/help` | GET | Help/diagnostics |
| `/api/send-command` | POST | Send network command |

### Admin Only
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/iframe/*` | POST | Manage iFrames (add, edit, delete, move) |
| `/admin/widget/*` | POST | Manage widgets (add, edit, delete, move) |
| `/admin/user/add` | POST | Create a user |
| `/admin/user/delete` | POST | Delete a user |
| `/admin/user/change-password` | POST | Change a user's password |
| `/admin/user/permissions` | POST | Set `allowed_iframes` / `allowed_widgets` for a user (or reset to see-all) |
| `/admin/settings/*` | POST | System settings |

## Testing

Automated tests live in `tests/` and use only the Python standard
library (zero dependencies, same constraint as the project).

```bash
python tests/run_tests.py              # full suite
python tests/run_tests.py -v           # verbose
python tests/run_tests.py -k perms     # filter
```

- `tests/test_unit.py` — password hashing, URL validation, HTML
  escaping, rate limiter, session lifecycle, config round-trip,
  `_ensure_ids` backfill, `filter_by_permissions` behavior.
- `tests/test_server.py` — boots the real server on an ephemeral
  port; exercises login, admin gating, proxy SSRF regression,
  and per-user permission filtering.
- `tests/test_worker.py` — `node --check` on `cloud/worker.js` and
  client/worker route parity.
- Manual release checklist: `tests/README.md`.

### Manual smoke test

1. Start server: `python multi_frames.py`
2. Open browser: `http://localhost:8080`
3. Login with admin/admin123
4. Test features in admin panel
5. Check connectivity tests
6. Test on Raspberry Pi if available

## Common Tasks

### Adding a New API Endpoint

1. Find POST handler section (~line 9000 in multi_frames.py)
2. Add new `elif path == '/api/your-endpoint':` block
3. Validate user authentication
4. Process request data
5. Return JSON response with `self.send_json()`

### Adding a New Admin Setting

1. Add form field in Settings tab HTML (~line 6400)
2. Add POST handler for saving (~line 9800)
3. Update `save_config()` call
4. Add to default config if needed

### Working with iframe/widget permissions

- Each iframe and widget has a stable `id` (8-char hex). When adding new
  ones in handlers, inject `"id": secrets.token_hex(4)`. When editing an
  existing one (full-replace pattern), preserve `existing.get("id")` or
  fall back to a new token.
- Per-user allow-lists live on the user record as `allowed_iframes` and
  `allowed_widgets`. `None` means "see all". Never store list indices —
  always store stable IDs.
- If you add a new content surface (e.g. "sections"), mirror the same
  id-backfill + filter pattern: extend `_ensure_ids()` and extend
  `filter_by_permissions()` with a matching `allowed_sections` field.

### Help Page

The help/diagnostics page is admin-only and includes:
- iframe connectivity tests (iframe-based load detection)
- Device information detection
- Server status and diagnostics

## Troubleshooting

### Port Already in Use
```bash
# Find process using port
lsof -i :8080
# Kill it or use different port
python multi_frames.py --port 8081
```

### Config File Errors
```bash
# Config location
~/.multi_frames_config.json

# Reset to defaults
rm ~/.multi_frames_config.json
```

### Cloud Connection Issues
- Check Cloud URL in Settings tab
- Verify Device Key is correct
- Check server logs for 403 errors
- Ensure User-Agent header is set

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

Current: **v1.4.8** (2026-04-16)
