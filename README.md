# Multi-Frames

**Dashboard & iFrame Display Server**

*Designed and Developed by Marco Longoria, LTS, Inc.*

A lightweight, zero-dependency Python web server for displaying configurable iFrames and dashboard widgets. Designed to run 24/7 with minimal resource usage.

---

## File Structure

Multi-Frames is available in two formats:

### Single-File Distribution (Recommended for Deployment)
```
multi_frames.py          # Complete server in one file (~7,400 lines)
```

### Modular Package (For Development)
```
multi_frames/
├── __init__.py          # Version info
├── __main__.py          # Entry point
├── config.py            # Configuration management
├── auth.py              # Authentication & sessions
├── logger.py            # Server logging
├── cli.py               # Terminal UI
├── network/
│   ├── interfaces.py    # Network detection
│   ├── mdns.py          # mDNS/Bonjour
│   └── commands.py      # TCP/UDP/Telnet
├── utils/
│   ├── html.py          # HTML utilities
│   ├── validation.py    # IP/URL validation
│   └── multipart.py     # Form parsing
└── templates/           # HTML templates (TODO)
```

See `PROJECT_STRUCTURE.md` for detailed documentation.

---

## Features

- **Zero external dependencies** - Uses only Python standard library
- **Dashboard widgets** - Clock, weather, countdown, notes, command buttons, and more
- **iFrame management** - Display local services, embed codes, external URLs
- **User authentication** - Session-based login with admin privileges
- **Custom branding** - Logo, favicon, iOS icons, colors, backgrounds
- **Network configuration** - DHCP/static IP settings across platforms
- **mDNS/Bonjour** - Access via friendly `.local` hostnames
- **Connectivity testing** - Built-in diagnostics with user reporting
- **Responsive design** - Works on desktop, tablet, and mobile
- **Config import/export** - Backup and restore your settings

---

## Version History

### v1.1.0 (2025-01-25)
- Added configuration import/upload feature
- Added "preserve users" option for config import
- Fixed firmware upload bug (empty file error)
- Fixed connectivity report submission error
- Modernized terminal boot UI with colors
- Added `--no-color` flag for terminal output
- Terminal now shows network IP, config stats, mDNS status
- Security warning only shows if default password in use
- Full config export (includes password hashes for backup)
- Deep merge on config import ensures all fields exist

### v1.0.0 (2025-01-25) - Initial Release
- iFrame management with URL/embed code support
- Dashboard widgets system (8 widget types)
- Command Buttons with network protocols (TCP/UDP/Telnet)
- Weather widget with Open-Meteo API (no API key required)
- User authentication and admin panel
- Customizable branding (logo, favicon, colors)
- Network configuration (DHCP/static IP)
- Connectivity testing and user reports
- Forgot password system with admin approval
- Footer hyperlinks
- mDNS/Bonjour support

---

## Requirements

- Python 3.6+ (no additional packages needed)
- **Supported platforms:** Windows, macOS, Linux, Raspberry Pi

---

## Quick Start

```bash
# Run with default settings (port 8080)
python multi_frames.py

# Run on a custom port
python multi_frames.py --port 9000

# Bind to specific interface
python multi_frames.py --host 127.0.0.1 --port 8080

# Disable colored terminal output
python multi_frames.py --no-color
```

Then open http://localhost:8080 in your browser.

---

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin    | admin123 | Admin |

⚠️ **IMPORTANT:** Change the default password immediately in production!

---

## Terminal Output

When you start the server, you'll see a colorful status display:

```
  MULTI-FRAMES v1.1.0
  Dashboard & iFrame Display Server
  Designed by Marco Longoria, LTS, Inc.

  ────────────────────────────────────────────

  ● Server running

    Local:      http://0.0.0.0:8080
    Network:    http://192.168.1.100:8080
    Bonjour:    http://multi-frames.local:8080

  ◆ Configuration

    Config:     multi_frames_config.json
    iFrames:    3 configured
    Widgets:    5 configured
    Users:      2 registered
    mDNS:       ● Active (multi-frames.local)

  ⚠  Security Warning
    Default password in use: admin / admin123
    Change in Admin → Users

  ────────────────────────────────────────────
  Press Ctrl+C to stop
```

---

## Configuration

All configuration is stored in `multi_frames_config.json`:

```json
{
  "users": {
    "admin": {
      "password_hash": "...",
      "is_admin": true
    }
  },
  "iframes": [
    {
      "name": "Local Service",
      "url": "http://192.168.1.100:8000",
      "height": 400
    }
  ],
  "widgets": [
    {
      "type": "clock",
      "enabled": true,
      "size": "medium"
    }
  ],
  "settings": {
    "page_title": "Dashboard",
    "refresh_interval": 0,
    "grid_columns": 2
  }
}
```

### Configuration Import/Export

**Export:** Admin → System → Download (creates timestamped JSON backup)

**Import:** Admin → System → Configuration Import
- Upload a previously exported `.json` file
- Option to preserve current users and passwords
- Deep merges with defaults to ensure all fields exist

---

## Dashboard Widgets

Multi-Frames includes 8 widget types:

| Widget | Description |
|--------|-------------|
| **Clock** | Digital clock with customizable format |
| **Date** | Current date display |
| **Text/HTML** | Custom text or HTML content |
| **Image** | Display images from URL |
| **Weather** | Current weather (Open-Meteo API, no key required) |
| **Countdown** | Count down to a specific date/time |
| **Notes** | Editable text notes |
| **Command Buttons** | Network control buttons (TCP/UDP/Telnet) |

### Command Buttons

Send network commands to devices on your network:

- **Protocols:** TCP, UDP, Telnet
- **Visual feedback:** Pulse animation, success/error states
- **Configuration:** JSON-based or visual builder UI

---

## Admin Panel Tabs

| Tab | Features |
|-----|----------|
| 📺 **iFrames** | Add, edit, reorder, delete iFrames |
| 🎨 **Appearance** | Colors, backgrounds, header/footer |
| ✨ **Branding** | Logo, favicon, iOS icon uploads |
| 👥 **Users** | User management, forgot password requests |
| 🌐 **Network** | DHCP/static IP, mDNS settings |
| ⚙️ **Settings** | Page title, grid layout, refresh interval |
| 🔧 **System** | Diagnostics, firmware, config export/import |

---

## iFrame Features

### Per-iFrame Settings
- **Size & Zoom:** Height, width (%), zoom level (25-200%)
- **Display:** Show/hide header and URL bar
- **Border:** Style (default, none, thin, thick, rounded) and custom color
- **External URLs:** Toggle to allow loading websites from the internet

### Embed Code Support
Paste raw iframe/HTML embed codes for:
- YouTube/Vimeo videos
- Google Maps
- Weather widgets
- Social media embeds

---

## Branding & Appearance

### Custom Branding
- **Logo:** Header logo (PNG, JPG, GIF, SVG, WebP - max 500KB)
- **Favicon:** Browser tab icon (PNG, ICO, SVG - max 500KB)
- **Apple Touch Icon:** iOS home screen icon (PNG - max 500KB)

### Theme Customization
- Background colors (primary, secondary, tertiary)
- Text colors (primary, secondary)
- Accent colors (links, buttons, hover states)
- Custom CSS injection

### Background Options
- **Solid:** Single color
- **Gradient:** Two-color gradient with direction control
- **Image:** Upload with size/opacity options

---

## Network Configuration

Cross-platform network settings (requires admin/root privileges):

| Platform | Method | Requirements |
|----------|--------|--------------|
| **Windows** | `netsh` commands | Run as Administrator |
| **macOS** | `networksetup` commands | Run with `sudo` |
| **Linux** | netplan or interfaces | Run with `sudo` |

### mDNS / Bonjour

Access your server via friendly hostname:

```bash
# Install zeroconf (optional)
pip install zeroconf

# Access via
http://multi-frames.local:8080
```

---

## Help & Diagnostics

Built-in help page (click **?** in header):

- **Connectivity Test:** Test all iFrame URLs from browser and server
- **Quick Tips:** Status indicators, X-Frame-Options info
- **Your Connection:** Online status, connection type, speed
- **Send Report:** Submit failed tests to admin for review

---

## Running as a Service

### Linux (systemd)

1. **Copy files:**
```bash
sudo mkdir -p /opt/multi-frames
sudo cp multi_frames.py /opt/multi-frames/
sudo chmod +x /opt/multi-frames/multi_frames.py
```

2. **Create service file** `/etc/systemd/system/multi-frames.service`:
```ini
[Unit]
Description=Multi-Frames Dashboard Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/multi-frames
ExecStart=/usr/bin/python3 /opt/multi-frames/multi_frames.py --host 0.0.0.0 --port 80
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

3. **Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable multi-frames
sudo systemctl start multi-frames
```

### Service Commands

```bash
sudo systemctl status multi-frames    # Check status
sudo systemctl restart multi-frames   # Restart
sudo journalctl -u multi-frames -f    # View logs
```

### macOS (launchd)

Create `~/Library/LaunchAgents/com.lts.multi-frames.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.lts.multi-frames</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/multi_frames.py</string>
        <string>--port</string>
        <string>8080</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load with: `launchctl load ~/Library/LaunchAgents/com.lts.multi-frames.plist`

### Windows (Task Scheduler)

1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task → "Multi-Frames Server"
3. Trigger: When the computer starts
4. Action: Start a program
   - Program: `python`
   - Arguments: `C:\path\to\multi_frames.py --port 8080`
5. Enable "Run with highest privileges"

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY multi_frames.py .
EXPOSE 8080
CMD ["python", "multi_frames.py", "--host", "0.0.0.0", "--port", "8080"]
```

```bash
docker build -t multi-frames .
docker run -d -p 8080:8080 -v $(pwd)/config:/app multi-frames
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main dashboard |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate |
| GET | `/logout` | End session |
| GET | `/admin` | Admin panel |
| GET | `/help` | Help & diagnostics |
| POST | `/api/send-command` | Send network command |
| POST | `/api/submit-connectivity-report` | Submit test report |

---

## Security Features

1. **Session Security:** 256-bit tokens, HttpOnly cookies, SameSite=Strict
2. **iFrame Sandboxing:** Restricted permissions by default
3. **Local IP Validation:** Optional restriction to private networks
4. **Password Hashing:** SHA-256

---

## Troubleshooting

**Port already in use:**
```bash
lsof -i :8080           # Linux/Mac
netstat -ano | findstr :8080  # Windows
```

**Permission denied on port 80:**
```bash
sudo python3 multi_frames.py --port 80
```

**Config file errors:**
Delete `multi_frames_config.json` to reset to defaults.

**mDNS not working:**
```bash
pip install zeroconf    # Install the library
# Windows: Install Bonjour Print Services
# Linux: sudo apt install avahi-daemon
```

---

## License

MIT License - Use freely for any purpose.

---

## Credits

**Designed and Developed by:** Marco Longoria  
**Company:** LTS, Inc.  
**Version:** 1.1.0  
**Website:** [multi-frames.local](http://multi-frames.local:8080)
