<div align="center">

# Multi-Frames

**Dashboard & iFrame Display Server**

*Zero dependencies. Maximum flexibility.*

<br>

[![Version](https://img.shields.io/badge/v1.4.7-2026--03--31-0078D4?style=flat-square&labelColor=000000)](#)
[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=000000)](#)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square&labelColor=000000)](#)
[![Platform](https://img.shields.io/badge/Platform-Win%20%7C%20Mac%20%7C%20Linux%20%7C%20Pi-888888?style=flat-square&labelColor=000000)](#)

<br>

**A lightweight Python web server for iFrames and dashboard widgets**
<br>
Built for home dashboards, kiosks, and digital signage

<br>

*Designed and Developed by Marco Longoria, LTS, Inc.*

<br>

[Features](#-features) • [Quick Start](#-quick-start) • [What's New](#-whats-new-in-v140) • [Documentation](#-configuration)

</div>

<br>

---

<br>

## ⚡ Features

<table>
<tr>
<td width="50%" valign="top">

### Core

- **Single file deployment** — Just run `multi_frames.py`
- **Zero dependencies** — Python standard library only
- **Cross-platform** — Windows, macOS, Linux, Raspberry Pi
- **24/7 ready** — Systemd service support included

</td>
<td width="50%" valign="top">

### Security

- **Session authentication** — Secure token-based login
- **Password hashing** — SHA-256 encryption
- **Role-based access** — Admin and user accounts
- **Rate limiting** — Login attempt protection
- **Sandboxed iFrames** — Isolated content display

</td>
</tr>
</table>

<br>

---

<br>

## 🧩 Dashboard Widgets

Display dynamic content alongside your iFrames:

<table>
<tr>
<td align="center" width="12.5%">
<br>
<b>🕐</b><br>
<sub>Clock</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>📅</b><br>
<sub>Date</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>🌤️</b><br>
<sub>Weather</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>⏱️</b><br>
<sub>Countdown</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>📝</b><br>
<sub>Text</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>🖼️</b><br>
<sub>Image</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>📋</b><br>
<sub>Notes</sub>
</td>
<td align="center" width="12.5%">
<br>
<b>🎮</b><br>
<sub>Buttons</sub>
</td>
</tr>
</table>

> **Weather Widget** uses the free Open-Meteo API — no API key required!

<br>

---

<br>

## 🎮 Command Buttons

Control network devices directly from your dashboard:

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│    ┌──────────┐   ┌──────────┐   ┌──────────┐              │
│    │  Power   │   │  Input   │   │  Volume  │              │
│    │   On     │   │  HDMI 1  │   │    Up    │              │
│    └──────────┘   └──────────┘   └──────────┘              │
│                                                            │
│    Protocols: TCP  •  UDP  •  Telnet                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

- Visual feedback with pulse animations
- Success/error state indicators
- JSON config or visual button builder

<br>

---

<br>

## 🎨 Customization

<table>
<tr>
<td width="33%" valign="top">

**Branding**

- Logo upload (file or URL)
- Custom favicon
- iOS home screen icon
- Android home screen icon
- Header text

</td>
<td width="33%" valign="top">

**Appearance**

- Color theme editor
- Gradient backgrounds
- Background images
- Custom CSS

</td>
<td width="33%" valign="top">

**Layout**

- Grid columns (1-6)
- Sticky header
- Footer links
- Auto-refresh

</td>
</tr>
</table>

<br>

---

<br>

## 📱 Admin Panel

Seven organized sections with mobile-friendly navigation:

| | Tab | What you can do |
|:---:|:---|:---|
| 📺 | **iFrames** | Add, edit, reorder, delete frames |
| 🎨 | **Appearance** | Colors, backgrounds, header/footer |
| ✨ | **Branding** | Upload logos, favicons, icons |
| 👥 | **Users** | Manage accounts, change passwords |
| 🌐 | **Network** | Configure IP settings, enable mDNS |
| ⚙️ | **Settings** | Page title, grid layout, refresh |
| 🔧 | **System** | Logs, diagnostics, Pi controls, backup/restore |

<br>

---

<br>

## 🚀 Quick Start

```bash
# Download and run
python multi_frames.py

# Custom port
python multi_frames.py --port 8080

# Open browser
http://localhost:8080
```

**Default credentials:** `admin` / `admin123`

> ⚠️ Change the default password in Admin → Users

<br>

---

<br>

## 🆕 What's New in v1.4.0

<table>
<tr>
<td>

### 🔒 Secure Remote Tunnels

- **Connect Remotely** button on each device card
- Access device webservers through encrypted WebSocket tunnels
- Embedded iframe view within the cloud portal
- Open in new tab for full-screen remote access
- NAT traversal — works with devices behind firewalls

</td>
<td>

### 🛡️ Tunnel Security

- Time-limited tunnel tokens (5-minute validity)
- 1-hour maximum session duration
- Dual authentication (device key + tunnel token)
- Admin JWT verification for all tunnel operations
- Device online status verification before connection

</td>
</tr>
<tr>
<td>

### 📋 Tunnel Activity Logging

- Complete audit trail for all tunnel sessions
- Event tracking: initiated, connected, closed
- 90-day log retention with auto-expiration
- Activity log table with event badges
- Stats: active tunnels, total sessions, available devices

</td>
<td>

### 📱 Mobile-Friendly Tunnels

- Responsive tunnel management UI
- Adaptive iframe sizing (desktop/tablet/mobile)
- Touch-friendly Connect Remotely buttons
- Quick Connect section for rapid device access
- Responsive log table with smart column hiding

</td>
</tr>
</table>

<br>

---

<br>

## 🖥️ Platform Support

| Platform | Status | Installation |
|:---------|:------:|:-------------|
| Windows | ✅ | `python multi_frames.py` |
| macOS | ✅ | `python3 multi_frames.py` |
| Linux | ✅ | `sudo ./install.sh` |
| Raspberry Pi | ✅ | Auto-detected, systemd service included |
| Docker | ✅ | Dockerfile provided |

<br>

---

<br>

## 📂 File Structure

Multi-Frames is available in two formats:

### Single-File Distribution (Recommended)
```
multi_frames.py          # Complete server in one file (~8,600 lines)
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
└── templates/           # HTML templates
```

<br>

---

<br>

## 📖 Configuration

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

<br>

---

<br>

## 🌐 Network Configuration

Cross-platform network settings (requires admin/root privileges):

| Platform | Method | Requirements |
|----------|--------|--------------|
| **Windows** | `netsh` commands | Run as Administrator |
| **macOS** | `networksetup` commands | Run with `sudo` |
| **Linux** | netplan or interfaces | Run with `sudo` |
| **Raspberry Pi** | dhcpcd.conf | Run with `sudo` |

### mDNS / Bonjour

Access your server via friendly hostname:

```bash
# Install zeroconf (optional)
pip install zeroconf

# Access via
http://multi-frames.local:8080
```

<br>

---

<br>

## 🔧 Running as a Service

### Linux / Raspberry Pi (systemd)

Use the included installer:

```bash
sudo ./install.sh --port 80
```

Or manually create `/etc/systemd/system/multi-frames.service`:

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

<br>

---

<br>

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main dashboard |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate |
| GET | `/logout` | End session |
| GET | `/admin` | Admin panel |
| GET | `/help` | Help & diagnostics |
| GET | `/api/ping` | Connectivity check |
| GET | `/api/pi-status` | Raspberry Pi info |
| POST | `/api/send-command` | Send network command |

<br>

---

<br>

## 🛠️ Troubleshooting

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

<br>

---

<br>

## 📋 Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

| Version | Date | Highlights |
|---------|------|------------|
| **1.4.7** | 2026-03-31 | Fix iframe proxy breaking local display, proxy only for remote clients |
| **1.4.6** | 2026-03-08 | Fix tunnel navigation (Admin/Help links), add POST proxy support |
| **1.4.5** | 2026-03-05 | Fix tunnel black screen, inject auth session into proxy requests |
| **1.4.4** | 2026-03-05 | Fix tunnel proxy connection refused, use actual server port |
| **1.4.3** | 2026-03-05 | Documentation updates for Durable Objects tunnel relay |
| **1.4.2** | 2026-03-05 | Fix tunnel proxy disconnect with Durable Objects relay |
| **1.4.1** | 2026-03-05 | Documentation updates, tunnel timeout fix, fast tunnel polling |
| **1.4.0** | 2026-03-04 | Secure remote tunnels, tunnel activity logging, mobile tunnel UI |
| **1.3.0** | 2026-02-18 | Cloud portal customization, widget templates, historical metrics |
| **1.2.8** | 2026-02-14 | Fix cloud agent SSL certificate verification error |
| **1.2.7** | 2026-02-14 | Cloud firmware deployment and config refresh |
| **1.2.6** | 2026-02-14 | Typography, layout, animation settings; Android icon support |
| **1.2.5** | 2026-02-14 | Mobile optimization, password toggle, removed connectivity test |
| **1.2.4** | 2026-02-05 | Documentation: CLAUDE.md, ARCHITECTURE.md, CODEBASE.md |
| **1.2.3** | 2026-02-04 | Simplified connectivity test to basic ping check |
| **1.2.2** | 2026-02-04 | Improved connectivity test accuracy, fixed false negatives |
| **1.2.1** | 2026-02-04 | Cloud settings in admin panel, connection status indicator |
| **1.2.0** | 2026-02-03 | Modern cloud dashboard, branding customization, responsive UI |
| **1.1.15** | 2026-02-03 | Cloud remote management, Google Workspace auth, config sync |
| **1.1.14** | 2026-02-03 | Simplified connectivity test, status icon toggle, bug fixes |
| **1.1.13** | 2026-01-27 | Fixed false throttle alerts, accurate vcgencmd integration |
| **1.1.12** | 2026-01-27 | Real-time Pi health widgets (MB/GB), core voltage display, server reset fix |
| **1.1.11** | 2026-01-26 | Watchdog tab with 30-day uptime tracking |
| **1.1.10** | 2025-01-26 | Modern status dashboard, Pi monitoring card, tabbed logs viewer |
| **1.1.9** | 2025-01-26 | Git clone URL field, auto-parse GitHub URLs, improved update UI |
| **1.1.8** | 2025-01-26 | Enhanced Pi install script, kiosk mode, WiFi fix, screen blanking |
| **1.1.7** | 2025-01-26 | Auto-restart on crash, server health alerts, reliability improvements |
| **1.1.6** | 2025-01-26 | GitHub update system, git pull support, version checking |
| **1.1.5** | 2025-01-25 | Raspberry Pi auto-detection, temperature monitoring, Pi controls |
| **1.1.4** | 2025-01-25 | Fixed iframe back button navigation |
| **1.1.3** | 2025-01-25 | Password change functionality |
| **1.1.2** | 2025-01-25 | Mobile CSS optimization, login rate limiting |
| **1.1.1** | 2025-01-25 | Config permission error handling |
| **1.1.0** | 2025-01-25 | Config import/export, modern terminal UI |
| **1.0.0** | 2025-01-25 | Initial release |

<br>

---

<br>

<div align="center">

**Designed & Developed by Marco Longoria**

LTS, Inc. • MIT License • 2025

<br>

*Built for home automation enthusiasts, makers, and tinkerers*

</div>
