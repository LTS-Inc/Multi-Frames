# Multi-Frames System Architecture

This document describes the complete system architecture of Multi-Frames, including the local server, cloud backend, and their interactions.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLOUD LAYER                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Cloudflare Workers (Optional)                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │  │
│  │  │   worker.js │  │   DEVICES   │  │   CONFIGS   │  │  SESSIONS   │ │  │
│  │  │    (API)    │  │    (KV)     │  │    (KV)     │  │    (KV)     │ │  │
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────┘ │  │
│  └─────────┼────────────────────────────────────────────────────────────┘  │
│            │ HTTPS                                                          │
└────────────┼────────────────────────────────────────────────────────────────┘
             │
             │  Heartbeat (60s) / Config Sync / Status Updates
             │
┌────────────┼────────────────────────────────────────────────────────────────┐
│            │                    LOCAL NETWORK                                │
│            ▼                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Multi-Frames Server                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │  │
│  │  │   HTTP      │  │    Auth     │  │   Config    │  │   Cloud     │ │  │
│  │  │   Server    │  │   Manager   │  │   Manager   │  │   Agent     │ │  │
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────┘ │  │
│  │         │                                                             │  │
│  │  ┌──────┴──────────────────────────────────────────────────────────┐ │  │
│  │  │                    Request Handlers                              │ │  │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │ │  │
│  │  │  │Dashboard│  │  Admin  │  │   API   │  │  Static │            │ │  │
│  │  │  │  Pages  │  │  Panel  │  │Endpoints│  │  Files  │            │ │  │
│  │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │                          │                          │             │
│         ▼                          ▼                          ▼             │
│    ┌─────────┐               ┌─────────┐               ┌─────────┐         │
│    │ Browser │               │ Browser │               │  Kiosk  │         │
│    │ (Admin) │               │ (User)  │               │ Display │         │
│    └─────────┘               └─────────┘               └─────────┘         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Local Server (`multi_frames.py`)

The main server is a single-file Python application using only the standard library.

```
┌─────────────────────────────────────────────────────────────────┐
│                    MultiFramesHandler                            │
│  (Extends http.server.SimpleHTTPRequestHandler)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   do_GET()      │  │   do_POST()     │  │   do_HEAD()     │ │
│  │                 │  │                 │  │                 │ │
│  │ - Dashboard     │  │ - Login         │  │ - Connectivity  │ │
│  │ - Admin Panel   │  │ - Admin Actions │  │   Testing       │ │
│  │ - Help Page     │  │ - API Endpoints │  │                 │ │
│  │ - Static Files  │  │ - Settings      │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                    Support Classes                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ ServerLogger    │  │ CloudAgent      │  │ ThreadedServer  │ │
│  │                 │  │                 │  │                 │ │
│  │ - In-memory log │  │ - Heartbeat     │  │ - Multi-thread  │ │
│  │ - Level filter  │  │ - Config sync   │  │ - Graceful stop │ │
│  │ - Max entries   │  │ - Status report │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Cloud Backend (`cloud/worker.js`)

Cloudflare Worker providing centralized management.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cloudflare Worker                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Router                                │   │
│  │  /auth/*     → Authentication handlers                   │   │
│  │  /api/*      → API handlers                              │   │
│  │  /           → Dashboard HTML                            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Auth Handlers   │  │ Device Handlers │  │ Config Handlers │ │
│  │                 │  │                 │  │                 │ │
│  │ - Google OAuth  │  │ - Register      │  │ - Pull config   │ │
│  │ - JWT tokens    │  │ - Heartbeat     │  │ - Push config   │ │
│  │ - Session mgmt  │  │ - List/Delete   │  │ - Bulk push     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 KV Namespaces                            │   │
│  │  DEVICES  - Device registry (id, key, name, status)      │   │
│  │  CONFIGS  - Device configurations (JSON blobs)           │   │
│  │  SESSIONS - User auth sessions (JWT tokens)              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. User Authentication Flow

```
┌────────┐     ┌────────────┐     ┌────────────┐
│Browser │     │Multi-Frames│     │  Config    │
│        │     │  Server    │     │   File     │
└───┬────┘     └─────┬──────┘     └─────┬──────┘
    │                │                   │
    │  POST /login   │                   │
    │  user/pass     │                   │
    │───────────────>│                   │
    │                │  validate_user()  │
    │                │──────────────────>│
    │                │    user data      │
    │                │<──────────────────│
    │                │                   │
    │                │  create_session() │
    │                │                   │
    │  Set-Cookie    │                   │
    │  session_id    │                   │
    │<───────────────│                   │
    │                │                   │
    │  GET /admin    │                   │
    │  Cookie: sid   │                   │
    │───────────────>│                   │
    │                │  validate_session │
    │  Admin HTML    │                   │
    │<───────────────│                   │
```

### 2. Cloud Sync Flow

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│Multi-Frames│     │ Cloudflare │     │   Admin    │
│  Device    │     │   Worker   │     │  Browser   │
└─────┬──────┘     └─────┬──────┘     └─────┬──────┘
      │                  │                   │
      │  Heartbeat (60s) │                   │
      │  device_key      │                   │
      │  status/temp     │                   │
      │─────────────────>│                   │
      │                  │  Store in KV      │
      │  config_update   │                   │
      │  available?      │                   │
      │<─────────────────│                   │
      │                  │                   │
      │                  │  GET /api/devices │
      │                  │<──────────────────│
      │                  │  device list      │
      │                  │──────────────────>│
      │                  │                   │
      │                  │  PUT /api/config  │
      │                  │  new config       │
      │                  │<──────────────────│
      │                  │  Mark pending     │
      │                  │──────────────────>│
      │                  │                   │
      │  Next heartbeat  │                   │
      │─────────────────>│                   │
      │  config_update:  │                   │
      │  true            │                   │
      │<─────────────────│                   │
      │                  │                   │
      │  GET /api/config │                   │
      │  /pull           │                   │
      │─────────────────>│                   │
      │  new config JSON │                   │
      │<─────────────────│                   │
      │                  │                   │
      │  Apply config    │                   │
      │  locally         │                   │
```

### 3. Connectivity Test Flow

```
┌────────┐     ┌────────────┐     ┌────────────┐
│Browser │     │Multi-Frames│     │  Target    │
│        │     │  Server    │     │   URL      │
└───┬────┘     └─────┬──────┘     └─────┬──────┘
    │                │                   │
    │  POST /api/    │                   │
    │  connectivity  │                   │
    │  -test-url     │                   │
    │  {url: "..."}  │                   │
    │───────────────>│                   │
    │                │                   │
    │                │  HEAD request     │
    │                │──────────────────>│
    │                │                   │
    │                │  HTTP response    │
    │                │  (any status)     │
    │                │<──────────────────│
    │                │                   │
    │  {reachable:   │                   │
    │   true}        │                   │
    │<───────────────│                   │
    │                │                   │
    │  Update UI     │                   │
    │  (green dot)   │                   │
```

## Module Architecture

### Python Package Structure

```
multi_frames/
├── __init__.py         # Package metadata
│   - __version__       # Version string
│   - __author__        # Author info
│
├── __main__.py         # Entry point
│   - main()            # CLI entry
│
├── config.py           # Configuration
│   - DEFAULT_CONFIG    # Default settings
│   - load_config()     # Load from file
│   - save_config()     # Save to file
│   - hash_password()   # Password hashing
│
├── auth.py             # Authentication
│   - Session class     # Session management
│   - create_session()  # New session
│   - validate_session()# Check session
│
├── logger.py           # Logging
│   - ServerLogger      # In-memory logger
│   - log()             # Add entry
│   - get_logs()        # Retrieve logs
│
├── cli.py              # Terminal UI
│   - print_banner()    # Startup banner
│   - parse_args()      # CLI arguments
│
├── build.py            # Build script
│   - build()           # Combine modules
│
├── network/            # Network utilities
│   ├── interfaces.py   # Interface detection
│   ├── mdns.py         # mDNS/Bonjour
│   └── commands.py     # TCP/UDP/Telnet
│
├── utils/              # Helpers
│   ├── html.py         # HTML escaping
│   ├── validation.py   # Input validation
│   └── multipart.py    # Form parsing
│
├── templates/          # HTML templates (TODO)
│   └── (future)
│
└── handlers/           # HTTP handlers (TODO)
    └── (future)
```

## Security Architecture

### Authentication Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Model                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  LOCAL SERVER                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Session-Based Authentication                         │   │
│  │                                                      │   │
│  │ - 64-byte random session tokens (secrets module)     │   │
│  │ - SHA-256 password hashing with salt                 │   │
│  │ - Session stored in memory (lost on restart)         │   │
│  │ - Rate limiting: 5 attempts per 5 minutes            │   │
│  │ - Admin flag per user for privileged access          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  CLOUD BACKEND                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Google OAuth 2.0 + Device Keys                       │   │
│  │                                                      │   │
│  │ - Google Workspace domain restriction                │   │
│  │ - JWT tokens for user sessions                       │   │
│  │ - Unique device keys for API authentication          │   │
│  │ - HTTPS only (Cloudflare enforced)                   │   │
│  │ - No password storage (delegated to Google)          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  INPUT VALIDATION                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ - HTML escaping for all user content                 │   │
│  │ - URL validation for iFrame sources                  │   │
│  │ - IP address format validation                       │   │
│  │ - Integer bounds checking                            │   │
│  │ - String length limits                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Frontend Architecture

### Page Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Dashboard (/)                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Header (optional)                                    │   │
│  │ - Logo, title, navigation                            │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Widget Row (configurable)                            │   │
│  │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │   │
│  │ │  Clock  │ │ Weather │ │ Button  │ │  Text   │    │   │
│  │ └─────────┘ └─────────┘ └─────────┘ └─────────┘    │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ iFrame Grid                                          │   │
│  │ ┌───────────────────┐ ┌───────────────────┐         │   │
│  │ │    iFrame 1       │ │    iFrame 2       │         │   │
│  │ │  - Header         │ │  - Header         │         │   │
│  │ │  - Status dot     │ │  - Status dot     │         │   │
│  │ │  - Content        │ │  - Content        │         │   │
│  │ │  - URL bar        │ │  - URL bar        │         │   │
│  │ └───────────────────┘ └───────────────────┘         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Footer (optional)                                    │   │
│  │ - Copyright, version, links                          │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Admin Panel (/admin)                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Status Dashboard                                     │   │
│  │ - Server health, uptime, cloud status                │   │
│  │ - Raspberry Pi info (if applicable)                  │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Tab Navigation                                       │   │
│  │ [iFrames] [Widgets] [Users] [System] [Settings]      │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Tab Content                                          │   │
│  │ - Forms for adding/editing items                     │   │
│  │ - Lists with drag-drop reordering                    │   │
│  │ - Action buttons (edit, delete, etc.)                │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Logs Panel (collapsible)                             │   │
│  │ - Tabbed: Requests, Server Logs, Errors              │   │
│  │ - Auto-refresh, search, clear                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Deployment Architecture

### Raspberry Pi Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                    Raspberry Pi                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Systemd Service                                      │   │
│  │ /etc/systemd/system/multi-frames.service             │   │
│  │                                                      │   │
│  │ - Auto-start on boot                                 │   │
│  │ - Restart on crash (5 second delay)                  │   │
│  │ - Run as pi user                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Kiosk Mode (optional)                                │   │
│  │                                                      │   │
│  │ - Chromium in fullscreen                             │   │
│  │ - Auto-hide cursor                                   │   │
│  │ - Disable screen blanking                            │   │
│  │ - Point to http://localhost:8080                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Hardware Monitoring                                  │   │
│  │                                                      │   │
│  │ - vcgencmd for temperature, throttling               │   │
│  │ - /proc/meminfo for memory                           │   │
│  │ - df for disk usage                                  │   │
│  │ - Alerts for high temp/low memory                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Performance Considerations

### Server
- **Threading**: Each request handled in separate thread
- **In-memory sessions**: No database overhead
- **Embedded assets**: No file I/O for CSS/JS
- **Lazy imports**: Heavy modules loaded on demand

### Frontend
- **Vanilla JS**: No framework overhead
- **CSS-only animations**: GPU accelerated
- **Lazy iframe loading**: Content loads after page
- **Status polling**: 60 second intervals (configurable)

### Cloud
- **Edge computing**: Worker runs at nearest Cloudflare POP
- **KV storage**: Eventually consistent, fast reads
- **Minimal payload**: JSON only, no large files
- **Heartbeat batching**: Multiple status fields per request

## Scalability

| Component | Limit | Notes |
|-----------|-------|-------|
| iFrames per instance | ~50 | Browser memory limited |
| Users per instance | ~100 | In-memory sessions |
| Devices per cloud | ~50+ | KV storage limits |
| Concurrent connections | ~100 | Thread pool based |
| Config file size | ~1MB | JSON parsing limits |

## Future Architecture Considerations

1. **Database backend** - Replace JSON file with SQLite
2. **WebSocket updates** - Real-time instead of polling
3. **Plugin system** - Custom widgets/handlers
4. **Multi-instance** - Load balancing support
5. **Metrics export** - Prometheus/Grafana integration
