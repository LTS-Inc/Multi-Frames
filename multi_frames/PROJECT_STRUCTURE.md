# Multi-Frames Project Structure

This document describes the modular architecture of Multi-Frames for easier maintenance and development.

## Directory Structure

```
multi_frames/
├── __init__.py           # Package metadata, version info
├── __main__.py           # Entry point: python -m multi_frames
├── config.py             # Configuration management
├── auth.py               # Authentication & sessions
├── logger.py             # Server logging
├── cli.py                # Terminal UI, argument parsing
├── server.py             # Main HTTP server (TODO: extract from single file)
│
├── network/              # Network-related functionality
│   ├── __init__.py
│   ├── interfaces.py     # Network interface detection
│   ├── mdns.py           # mDNS/Bonjour service
│   ├── commands.py       # TCP/UDP/Telnet commands
│   └── config.py         # Network config apply (TODO)
│
├── utils/                # Utility functions
│   ├── __init__.py
│   ├── html.py           # HTML escaping, formatting
│   ├── validation.py     # IP/URL validation
│   └── multipart.py      # Form data parsing
│
├── templates/            # HTML templates
│   ├── __init__.py
│   ├── base.py           # Base page template, CSS (TODO)
│   ├── login.py          # Login pages (TODO)
│   ├── dashboard.py      # Main dashboard (TODO)
│   ├── admin.py          # Admin panel (TODO)
│   ├── help.py           # Help page (TODO)
│   └── widgets.py        # Widget rendering (TODO)
│
└── handlers/             # HTTP request handlers
    ├── __init__.py
    ├── base.py           # Base handler class (TODO)
    ├── api.py            # API endpoints (TODO)
    └── admin.py          # Admin POST handlers (TODO)
```

## Module Descriptions

### Core Modules

| Module | Description |
|--------|-------------|
| `config.py` | Configuration loading, saving, defaults, password hashing |
| `auth.py` | Session management, credential validation |
| `logger.py` | In-memory logging with level support |
| `cli.py` | Terminal banner, color support, argument parsing |

### Network Package

| Module | Description |
|--------|-------------|
| `interfaces.py` | Cross-platform network interface detection |
| `mdns.py` | mDNS/Bonjour service using zeroconf |
| `commands.py` | Send commands via TCP, UDP, Telnet |

### Utils Package

| Module | Description |
|--------|-------------|
| `html.py` | HTML escaping, safe IDs, truncation |
| `validation.py` | IP address, URL, hostname validation |
| `multipart.py` | Multipart form data parsing |

## Development

### Running from Source

```bash
# Run as module
python -m multi_frames --port 8080

# Or directly
python multi_frames/server.py --port 8080
```

### Building Single-File Distribution

For easy deployment, combine modules into single file:

```bash
python build.py
# Creates: dist/multi_frames.py
```

### Adding New Features

1. **New utility function**: Add to `utils/` package
2. **New network feature**: Add to `network/` package
3. **New page template**: Add to `templates/` package
4. **New API endpoint**: Add to `handlers/api.py`

### Code Style

- Use type hints for function signatures
- Document all public functions with docstrings
- Keep modules focused and single-purpose
- Avoid circular imports

## Migration from Single File

The original `multi_frames.py` (7,400+ lines) is being refactored into this modular structure. To extract a section:

1. Identify related functions
2. Create new module in appropriate package
3. Move functions and their dependencies
4. Update imports in other modules
5. Test thoroughly

## Dependencies

**Required (Standard Library):**
- `http.server` - HTTP server
- `socketserver` - Threading support
- `json` - Configuration files
- `hashlib` - Password hashing
- `secrets` - Session tokens
- `socket` - Network operations
- `subprocess` - System commands

**Optional:**
- `zeroconf` - mDNS/Bonjour support

## Version History

See main README.md for version history.
