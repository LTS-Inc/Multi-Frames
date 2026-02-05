# Multi-Frames - Project Context

This document provides context for AI assistants working on the Multi-Frames codebase.

## Project Overview

**Multi-Frames** is a zero-dependency Python web server for displaying configurable iFrames and dashboard widgets. Designed for home dashboards, kiosks, digital signage, and Raspberry Pi deployments.

- **Author**: Marco Longoria, LTS, Inc.
- **Version**: 1.2.4
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

### 2. Dashboard Widgets
- Clock, weather, buttons, text, images
- Command buttons (TCP/UDP/Telnet)
- Raspberry Pi monitoring card

### 3. User Authentication
- Session-based with secure tokens
- Admin vs regular users
- Password hashing (SHA-256 + salt)
- Rate limiting on login

### 4. Cloud Sync (Optional)
- Cloudflare Worker backend
- Google Workspace authentication
- Config push/pull to 50+ devices
- Real-time device status

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
| `/api/connectivity-test-url` | POST | Test URL reachability |
| `/api/send-command` | POST | Send network command |

### Admin Only
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/iframe/*` | POST | Manage iFrames |
| `/admin/widget/*` | POST | Manage widgets |
| `/admin/user/*` | POST | Manage users |
| `/admin/settings/*` | POST | System settings |

## Testing

Currently no automated tests. Manual testing workflow:

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

### Modifying Connectivity Test

The connectivity test is simple:
- Server makes HEAD request to URL
- Returns `{reachable: true}` if any HTTP response
- Returns `{reachable: false}` on network error
- Frontend displays green/red status dot

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

Current: **v1.2.4** (2026-02-05)
