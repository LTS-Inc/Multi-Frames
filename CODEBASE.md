# Multi-Frames Codebase Documentation

Detailed documentation of the Multi-Frames codebase, including all modules, classes, functions, and API endpoints.

## Table of Contents

1. [Main Server (multi_frames.py)](#main-server)
2. [Package Modules (multi_frames/)](#package-modules)
3. [Cloud Backend (cloud/worker.js)](#cloud-backend)
4. [Configuration Schema](#configuration-schema)
5. [API Reference](#api-reference)
6. [HTML Templates](#html-templates)
7. [CSS Styling](#css-styling)
8. [JavaScript Functions](#javascript-functions)

---

## Main Server

### File: `multi_frames.py`

The main server file (~10,000 lines) contains all functionality in a single deployable file.

### Constants (Lines 196-200)

```python
VERSION = "1.2.7"           # Current version
VERSION_DATE = "2026-02-14" # Release date
DEFAULT_PORT = 8080         # Default HTTP port
DEFAULT_HOST = "0.0.0.0"    # Listen on all interfaces
```

### Class: ServerLogger (Lines ~220-280)

In-memory logging system with level filtering.

```python
class ServerLogger:
    """Thread-safe in-memory logger with level support."""

    def __init__(self, max_entries=1000):
        """Initialize logger with max entry limit."""

    def log(self, message, level="INFO"):
        """Add log entry with timestamp."""

    def get_logs(self, level=None, limit=100):
        """Retrieve logs, optionally filtered by level."""

    def clear(self):
        """Clear all log entries."""
```

**Log Levels**: DEBUG, INFO, WARNING, ERROR

### Class: CloudAgent (Lines ~700-900)

Background thread for cloud synchronization.

```python
class CloudAgent(threading.Thread):
    """Manages cloud connectivity and config sync."""

    def __init__(self, config):
        """Initialize with configuration."""

    def run(self):
        """Main loop: heartbeat every 60 seconds."""

    def send_heartbeat(self):
        """Send status to cloud, check for config updates."""

    def pull_config(self):
        """Download and apply new configuration."""

    def push_config(self):
        """Upload local configuration to cloud."""
```

**Headers**: Includes `User-Agent: Multi-Frames/{VERSION}` to avoid Cloudflare blocking.

### Class: MultiFramesHandler (Lines ~1000-9900)

Main HTTP request handler extending `SimpleHTTPRequestHandler`.

#### Key Methods

| Method | Line | Description |
|--------|------|-------------|
| `do_GET()` | ~1100 | Handle GET requests |
| `do_POST()` | ~8500 | Handle POST requests |
| `do_HEAD()` | ~9300 | Handle HEAD requests |
| `get_current_user()` | ~1050 | Get authenticated user from session |
| `send_json()` | ~1080 | Send JSON response |
| `redirect()` | ~1090 | Send redirect response |

#### GET Request Routing (Lines ~1100-5000)

| Path | Auth | Description |
|------|------|-------------|
| `/` | Optional | Main dashboard |
| `/login` | No | Login page |
| `/logout` | Yes | Logout and redirect |
| `/admin` | Admin | Admin panel |
| `/help` | Yes | Help/diagnostics page |
| `/favicon.ico` | No | Favicon image |

#### POST Request Routing (Lines ~8500-9900)

| Path | Auth | Description |
|------|------|-------------|
| `/login` | No | Process login |
| `/api/send-command` | Yes | Send network command |
| `/admin/iframe/*` | Admin | Manage iFrames |
| `/admin/widget/*` | Admin | Manage widgets |
| `/admin/user/*` | Admin | Manage users |
| `/admin/settings/*` | Admin | System settings |

### Function: load_config() (Lines ~300-400)

```python
def load_config():
    """Load configuration from JSON file.

    Returns:
        dict: Configuration dictionary with defaults applied.

    Location: ~/.multi_frames_config.json
    """
```

### Function: save_config() (Lines ~400-450)

```python
def save_config(config):
    """Save configuration to JSON file.

    Args:
        config: Configuration dictionary to save.
    """
```

### Function: hash_password() (Lines ~450-480)

```python
def hash_password(password, salt=None):
    """Hash password using SHA-256 with salt.

    Args:
        password: Plain text password.
        salt: Optional salt (generated if not provided).

    Returns:
        tuple: (hashed_password, salt)
    """
```

### Function: validate_user() (Lines ~480-520)

```python
def validate_user(username, password, config):
    """Validate user credentials.

    Args:
        username: Username to validate.
        password: Password to check.
        config: Configuration containing users.

    Returns:
        str or None: Username if valid, None otherwise.
    """
```

### Function: escape_html() (Lines ~550-570)

```python
def escape_html(text):
    """Escape HTML special characters.

    Args:
        text: Text to escape.

    Returns:
        str: Escaped text safe for HTML output.
    """
```

---

## Package Modules

### File: `multi_frames/__init__.py`

Package metadata and version information.

```python
__version__ = "1.2.7"
__author__ = "Marco Longoria"
__company__ = "LTS, Inc."
```

### File: `multi_frames/__main__.py`

Entry point for `python -m multi_frames`.

```python
def main():
    """Parse arguments and start server."""
```

### File: `multi_frames/config.py`

Configuration management.

```python
DEFAULT_CONFIG = {
    "users": {...},
    "iframes": [],
    "widgets": [],
    "appearance": {...},
    "settings": {...}
}

def load_config() -> dict:
    """Load config from file with defaults."""

def save_config(config: dict) -> None:
    """Save config to file."""

def get_config_path() -> str:
    """Get path to config file."""
```

### File: `multi_frames/auth.py`

Authentication and session management.

```python
class SessionManager:
    """Manage user sessions."""

    sessions: dict  # token -> user data

    def create_session(self, username: str) -> str:
        """Create new session, return token."""

    def validate_session(self, token: str) -> str | None:
        """Validate token, return username or None."""

    def destroy_session(self, token: str) -> None:
        """Remove session."""

def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with SHA-256."""

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash."""
```

### File: `multi_frames/logger.py`

Logging utilities.

```python
class ServerLogger:
    """In-memory log storage."""

    def log(self, message: str, level: str = "INFO"):
        """Add log entry."""

    def get_logs(self, level: str = None, limit: int = 100) -> list:
        """Get log entries."""
```

### File: `multi_frames/cli.py`

Command-line interface.

```python
def print_banner(version: str, port: int, host: str):
    """Print startup banner with ASCII art."""

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

def supports_color() -> bool:
    """Check if terminal supports ANSI colors."""
```

### File: `multi_frames/build.py`

Build script to combine modules into single file.

```python
def build(output_path: str, version: str):
    """Combine all modules into single distributable file.

    Args:
        output_path: Path for output file (default: dist/multi_frames.py)
        version: Version string to embed
    """
```

### File: `multi_frames/network/interfaces.py`

Network interface detection.

```python
def get_network_interfaces() -> list:
    """Get list of network interfaces with IPs.

    Returns:
        list: [{"name": "eth0", "ip": "192.168.1.100"}, ...]
    """

def get_primary_ip() -> str:
    """Get primary network IP address."""
```

### File: `multi_frames/network/mdns.py`

mDNS/Bonjour service discovery.

```python
def register_mdns_service(name: str, port: int):
    """Register mDNS service for local discovery.

    Args:
        name: Service name (e.g., "Multi-Frames")
        port: HTTP port number
    """

def unregister_mdns_service():
    """Unregister mDNS service on shutdown."""
```

### File: `multi_frames/network/commands.py`

Network command sending.

```python
def send_tcp_command(host: str, port: int, command: str) -> dict:
    """Send TCP command and get response.

    Returns:
        {"success": bool, "response": str, "error": str}
    """

def send_udp_command(host: str, port: int, command: str) -> dict:
    """Send UDP command (no response expected)."""

def send_telnet_command(host: str, port: int, command: str) -> dict:
    """Send command via Telnet protocol."""
```

### File: `multi_frames/utils/html.py`

HTML utilities.

```python
def escape_html(text: str) -> str:
    """Escape HTML special characters."""

def make_safe_id(text: str) -> str:
    """Convert text to safe HTML ID."""

def truncate(text: str, length: int) -> str:
    """Truncate text with ellipsis."""
```

### File: `multi_frames/utils/validation.py`

Input validation.

```python
def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IPv4 address."""

def is_valid_url(url: str) -> bool:
    """Check if string is valid URL."""

def is_valid_hostname(hostname: str) -> bool:
    """Check if string is valid hostname."""

def sanitize_filename(filename: str) -> str:
    """Remove unsafe characters from filename."""
```

### File: `multi_frames/utils/multipart.py`

Multipart form parsing.

```python
def parse_multipart(body: bytes, boundary: str) -> dict:
    """Parse multipart/form-data body.

    Returns:
        {"field_name": value, "file_field": {"filename": str, "data": bytes}}
    """
```

---

## Cloud Backend

### File: `cloud/worker.js`

Cloudflare Worker for remote device management.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret |
| `ALLOWED_DOMAIN` | Restrict to Google Workspace domain |
| `JWT_SECRET` | Secret for signing tokens |

### KV Namespaces

| Binding | Purpose |
|---------|---------|
| `DEVICES` | Device registry |
| `CONFIGS` | Device configurations |
| `SESSIONS` | User auth sessions |

### Route Handlers

```javascript
// Authentication
router.get('/auth/google/url', getGoogleAuthUrl);
router.get('/auth/google/callback', handleGoogleCallback);
router.get('/auth/verify', verifyAuth);

// Devices
router.get('/api/devices', listDevices);
router.post('/api/devices/register', registerDevice);
router.post('/api/devices/heartbeat', deviceHeartbeat);
router.get('/api/devices/:id', getDevice);
router.delete('/api/devices/:id', deleteDevice);

// Configuration
router.get('/api/config/pull', pullConfig);
router.post('/api/config/push', pushConfig);
router.get('/api/config/:id', getDeviceConfig);
router.put('/api/config/:id', updateDeviceConfig);
router.post('/api/config/bulk-push', bulkPushConfig);

// Branding
router.get('/api/branding', getBranding);
router.put('/api/branding', updateBranding);

// Dashboard
router.get('/', serveDashboard);
```

### Device Object Schema

```javascript
{
  "id": "uuid",
  "name": "Living Room Pi",
  "key": "device-api-key",
  "created_at": "2026-01-15T10:30:00Z",
  "last_seen": "2026-02-05T14:22:00Z",
  "status": "online",  // online, offline, unknown
  "info": {
    "version": "1.2.7",
    "ip": "192.168.1.100",
    "hostname": "raspberrypi",
    "temperature": 45.2,
    "memory_percent": 32,
    "disk_percent": 18,
    "uptime": 86400
  },
  "config_version": 5,
  "pending_config": false
}
```

---

## Configuration Schema

### Root Configuration Object

```javascript
{
  "users": {
    "admin": {
      "password": "hashed-password",
      "salt": "random-salt",
      "is_admin": true
    }
  },

  "iframes": [
    {
      "id": "uuid",
      "name": "Home Assistant",
      "url": "http://homeassistant.local:8123",
      "height": 400,
      "width": 50,        // percentage
      "zoom": 100,        // percentage
      "show_url": true,
      "show_header": true,
      "show_status": true,
      "header_text": "",  // custom header (optional)
      "border_style": "default",
      "border_color": "",
      "allow_external": false,
      "use_embed_code": false,
      "embed_code": ""
    }
  ],

  "widgets": [
    {
      "id": "uuid",
      "type": "clock",    // clock, weather, button, text, image, pi_info
      "name": "Clock",
      "config": {
        // Widget-specific config
      }
    }
  ],

  "appearance": {
    "header": {
      "enabled": true,
      "logo_url": "",
      "title": "Multi-Frames",
      "show_title": true,
      "show_nav": true
    },
    "footer": {
      "enabled": true,
      "text": "Multi-Frames v1.2.7 by LTS, Inc."
    },
    "theme": "dark",
    "background_color": "#1a1a2e",
    "accent_color": "#0078d4"
  },

  "settings": {
    "cloud": {
      "enabled": false,
      "url": "",
      "device_key": ""
    },
    "network": {
      "mdns_enabled": true,
      "mdns_name": "multi-frames"
    },
    "pi": {
      "kiosk_mode": false,
      "auto_update": false
    }
  },

  "watchdog": {
    "uptime_history": [],
    "downtime_events": []
  }
}
```

### Widget Type Configurations

#### Clock Widget
```javascript
{
  "type": "clock",
  "config": {
    "format": "12h",      // 12h or 24h
    "show_seconds": true,
    "show_date": true,
    "timezone": "local"
  }
}
```

#### Weather Widget
```javascript
{
  "type": "weather",
  "config": {
    "location": "New York",
    "units": "imperial",  // imperial or metric
    "api_key": ""
  }
}
```

#### Button Widget
```javascript
{
  "type": "button",
  "config": {
    "label": "Power On",
    "protocol": "tcp",    // tcp, udp, telnet
    "host": "192.168.1.50",
    "port": 4998,
    "command": "POWER ON"
  }
}
```

#### Text Widget
```javascript
{
  "type": "text",
  "config": {
    "content": "Welcome!",
    "font_size": 16,
    "color": "#ffffff",
    "align": "center"
  }
}
```

#### Pi Info Widget
```javascript
{
  "type": "pi_info",
  "config": {
    "show_temp": true,
    "show_memory": true,
    "show_disk": true,
    "show_voltage": true
  }
}
```

---

## API Reference

### Public Endpoints

#### POST /login

Authenticate user and create session.

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (success):**
```
Set-Cookie: session_id=<token>; HttpOnly; Path=/
Redirect: /
```

**Response (failure):**
```
Redirect: /login?error=1
```

### Authenticated Endpoints

#### POST /api/send-command

Send network command to device.

**Request:**
```json
{
  "protocol": "tcp",
  "host": "192.168.1.50",
  "port": 4998,
  "command": "POWER ON"
}
```

**Response:**
```json
{
  "success": true,
  "response": "OK"
}
```

### Admin Endpoints

#### POST /admin/iframe/add

Add new iFrame.

**Request:**
```json
{
  "name": "Home Assistant",
  "url": "http://homeassistant.local:8123",
  "height": 400,
  "width": 50,
  "zoom": 100,
  "show_url": "1",
  "show_header": "1",
  "show_status": "1"
}
```

#### POST /admin/iframe/edit

Edit existing iFrame.

**Request:**
```json
{
  "id": "iframe-uuid",
  "name": "Updated Name",
  "url": "http://new-url.com"
}
```

#### POST /admin/iframe/delete

Delete iFrame.

**Request:**
```json
{
  "id": "iframe-uuid"
}
```

#### POST /admin/iframe/reorder

Reorder iFrames via drag-drop.

**Request:**
```json
{
  "order": ["uuid1", "uuid2", "uuid3"]
}
```

#### POST /admin/settings/cloud

Update cloud settings.

**Request:**
```json
{
  "enabled": "1",
  "url": "https://worker.example.com",
  "device_key": "key-123"
}
```

---

## HTML Templates

### Base Page Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{css}</style>
</head>
<body>
    {header}
    {content}
    {footer}
    <script>{javascript}</script>
</body>
</html>
```

### Key Template Functions

| Function | Line | Description |
|----------|------|-------------|
| `render_dashboard()` | ~1200 | Main dashboard page |
| `render_admin()` | ~2500 | Admin panel page |
| `render_login()` | ~1150 | Login page |
| `render_help()` | ~4200 | Help/diagnostics page |
| `render_iframe()` | ~1500 | Single iFrame card |
| `render_widget()` | ~1700 | Single widget |

---

## CSS Styling

### CSS Variables (Theme)

```css
:root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --bg-card: #1f2937;
    --text-primary: #ffffff;
    --text-secondary: #9ca3af;
    --accent: #0078d4;
    --success: #22c55e;
    --warning: #f59e0b;
    --error: #ef4444;
    --border: #374151;
    --radius: 8px;
}
```

### Key CSS Classes

| Class | Purpose |
|-------|---------|
| `.card` | Card container with shadow |
| `.btn` | Button styling |
| `.btn-primary` | Primary action button |
| `.btn-secondary` | Secondary action button |
| `.btn-danger` | Destructive action button |
| `.form-group` | Form field container |
| `.status-dot` | Connectivity indicator |
| `.status-dot.connected` | Green status |
| `.status-dot.error` | Red status |
| `.status-dot.loading` | Pulsing animation |
| `.tab-nav` | Tab navigation |
| `.tab-content` | Tab content area |
| `.iframe-card` | iFrame container |
| `.widget-card` | Widget container |

---

## JavaScript Functions

### Dashboard (Main Page)

```javascript
// Back button prevention for iframes
(function() {
    // Prevents iframe navigation from hijacking browser back button
})();
```

### Admin Panel

```javascript
// Tab navigation
function showTab(tabId) {
    // Switch visible tab content
}

// Drag-drop reordering
function initDragDrop() {
    // Initialize drag-drop for iframe/widget lists
}

function saveOrder(type) {
    // POST new order to server
}

// Form handling
function submitForm(formId, url) {
    // Submit form via AJAX
}

// Log viewer
function refreshLogs() {
    // Fetch and display server logs
}

function filterLogs(level) {
    // Filter logs by level
}
```

### Help Page

```javascript
// Diagnostics
function helpTestUrl(idx, url, name) {
    // Test URL connectivity
}

function helpTestAll() {
    // Run all connectivity tests
}

function showHelpSummary() {
    // Display test results summary
}

function sendReport() {
    // Send diagnostic report
}

// Device detection
function detectDevice() {
    // Detect browser, OS, screen info
}
```

---

## Error Handling

### HTTP Error Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful request |
| 302 | Redirect | After login/logout |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Not logged in |
| 403 | Forbidden | Not admin |
| 404 | Not Found | Invalid path |
| 500 | Server Error | Unexpected error |

### Error Response Format

```json
{
  "success": false,
  "error": "Error message here"
}
```

### Logging Errors

```python
# Log error with stack trace
server_logger.log(f"Error in {path}: {str(e)}", "ERROR")

# Log warning
server_logger.log(f"Rate limit exceeded for {ip}", "WARNING")
```

---

## Testing Checklist

### Unit Test Areas (TODO)

- [ ] Password hashing/verification
- [ ] Session creation/validation
- [ ] Configuration loading/saving
- [ ] HTML escaping
- [ ] IP/URL validation
- [ ] Multipart parsing

### Integration Test Areas

- [ ] Login flow
- [ ] iFrame CRUD operations
- [ ] Widget CRUD operations
- [ ] User management
- [ ] Cloud sync
- [ ] Network commands

### Manual Test Scenarios

1. Fresh install with default config
2. Add/edit/delete iFrames
3. Drag-drop reorder
4. Connectivity test accuracy
5. Cloud connection setup
6. Multi-user access
7. Raspberry Pi detection
8. Mobile responsive layout
