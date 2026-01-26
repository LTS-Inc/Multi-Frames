# Changelog

All notable changes to Multi-Frames will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
