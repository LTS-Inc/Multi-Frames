<div align="center">

# Multi-Frames

**Dashboard & iFrame Display Server**

*Zero dependencies. Maximum flexibility.*

<br>

[![Version](https://img.shields.io/badge/v1.1.2-2025--01--25-0078D4?style=flat-square&labelColor=000000)](#)
[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=000000)](#)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square&labelColor=000000)](#)
[![Platform](https://img.shields.io/badge/Platform-Win%20%7C%20Mac%20%7C%20Linux-888888?style=flat-square&labelColor=000000)](#)

<br>

**A lightweight Python web server for iFrames and dashboard widgets**
<br>
Built for home dashboards, kiosks, and digital signage

<br>

[Features](#-features) • [Quick Start](#-quick-start) • [What's New](#-whats-new-in-v110) • [Screenshots](#-admin-panel)

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
│    ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│    │  Power   │   │  Input   │   │  Volume  │            │
│    │   On     │   │  HDMI 1  │   │    Up    │            │
│    └──────────┘   └──────────┘   └──────────┘            │
│                                                            │
│    Protocols: TCP  •  UDP  •  Telnet                      │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

- Visual feedback with pulse animations
- Success/error state indicators
- JSON config or visual button builder
- Built-in test modes for development

<br>

---

<br>

## 🎨 Customization

<table>
<tr>
<td width="33%" valign="top">

**Branding**

- Logo upload
- Custom favicon
- iOS home screen icon
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
| 👥 | **Users** | Manage accounts, approve password resets |
| 🌐 | **Network** | Configure IP settings, enable mDNS |
| ⚙️ | **Settings** | Page title, grid layout, refresh |
| 🔧 | **System** | Logs, diagnostics, backup/restore |

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

## 🆕 What's New in v1.1.2

<table>
<tr>
<td>

### 📱 Mobile First

- Touch-friendly 44px button targets
- Safe-area-insets for notched phones
- Admin tabs: icon-only on mobile
- 16px fonts prevent iOS zoom
- Touch feedback animations

</td>
<td>

### 🔒 Security

- Login rate limiting (5 attempts)
- 15-minute IP lockout
- Timing-attack resistant auth
- Failed attempts logged

### ♿ Accessibility

- Reduced motion support
- Print stylesheet added

</td>
</tr>
</table>

<br>

---

<br>

## 🆕 What's New in v1.1.1

<table>
<tr>
<td>

### Fixed

- ✅ Config permission errors now show friendly message
- ✅ Branding uploads handle save errors gracefully
- ✅ No more crashes on read-only config files

</td>
<td>

### Added

- ⚠️ Warning banner when config not writable
- 🔧 Fix instructions shown in System tab
- 📋 `check_config_writable()` function

</td>
</tr>
</table>

<br>

---

<br>

## 🆕 What's New in v1.1.0

<table>
<tr>
<td>

### Added

- 📦 Configuration import/export with backup
- 👥 Preserve users option during import
- 🖥️ Modern terminal UI with colors
- 📊 Enhanced help page with device diagnostics
- 📱 Mobile-responsive help layout
- 🎨 `--no-color` terminal flag

</td>
<td>

### Fixed

- ✅ Firmware upload empty file error
- ✅ Connectivity report submission
- ✅ Security warning logic

### Improved

- 📈 Terminal shows network info at startup
- 🔒 Smarter default password detection
- 📁 Modular codebase structure

</td>
</tr>
</table>

<br>

---

<br>

## 📋 v1.0.0 — Foundation Release

<details>
<summary><b>View all initial features</b></summary>

<br>

### iFrame Management
- URL and embed code support
- External URL toggle per frame
- Height, width, zoom controls (25-200%)
- Border styles and colors
- Show/hide headers and URL bars

### Network Features
- Static IP / DHCP configuration
- mDNS / Bonjour support (`.local` hostnames)
- Cross-platform interface detection
- Connectivity testing (browser + server)
- User report submission

### User Management
- Admin and regular user roles
- Secure session authentication
- Forgot password workflow
- Password reset queue for admins

### Security
- SHA-256 password hashing
- 256-bit session tokens
- HttpOnly + SameSite cookies
- iFrame sandboxing
- Local IP validation

</details>

<br>

---

<br>

## 🖥️ Platform Support

| Platform | Status | Installation |
|:---------|:------:|:-------------|
| Windows | ✅ | `python multi_frames.py` |
| macOS | ✅ | `python3 multi_frames.py` |
| Linux | ✅ | `sudo ./install.sh` |
| Raspberry Pi | ✅ | Systemd service included |
| Docker | ✅ | Dockerfile provided |

<br>

---

<br>

## 📂 Files

```
multi_frames.py      →  Main server (deploy this)
install.sh           →  Linux service installer
README.md            →  Documentation
CHANGELOG.md         →  Version history
multi_frames/        →  Modular source code
```

<br>

---

<br>

<div align="center">

**Designed & Developed by Marco Longoria**

LTS, Inc. • MIT License • 2025

<br>

*Built for home automation enthusiasts, makers, and tinkerers*

</div>
