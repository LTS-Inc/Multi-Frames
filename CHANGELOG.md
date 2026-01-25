# Changelog

All notable changes to Multi-Frames will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
