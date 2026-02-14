# Changelog

All notable changes to Multi-Frames will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.8] - 2026-02-14

### Fixed
- **Cloud Agent SSL Error**: Fixed `CERTIFICATE_VERIFY_FAILED` error when connecting to cloud
  - Added `_get_ssl_context()` helper to CloudAgent that detects available CA certificates
  - Falls back to unverified context on systems without CA bundle (Raspberry Pi, minimal installs)
  - Applied to all CloudAgent HTTPS calls: heartbeat, config pull, firmware download, config push

## [1.2.7] - 2026-02-14

### Added
- **Cloud Firmware Management**: Upload and deploy firmware to devices remotely
  - New Firmware page in cloud dashboard with upload, deploy, and status tracking
  - `POST /api/firmware/upload` - Upload firmware file with version auto-extraction
  - `GET /api/firmware` - Get firmware metadata (version, size, uploader, date)
  - `GET /api/firmware/download` - Device downloads firmware (device key auth)
  - `POST /api/firmware/deploy` - Queue firmware deployment to selected devices
  - Deploy modal with per-device selection and bulk deploy
  - Device firmware status table showing current version vs latest
  - Automatic firmware validation, backup, and server restart on device
- **Cloud Config Refresh**: Request devices to push their current config
  - `POST /api/config/{id}/request` - Request device to sync its config
  - "Refresh" button on device cards in cloud dashboard
  - "Refresh from Device" button in config view modal
  - Device auto-pushes config on next heartbeat when requested

### Changed
- Heartbeat response now includes `firmware_update_available` and `config_requested` flags
- Device cards show firmware update pending indicator
- Cloud dashboard sidebar now includes Firmware navigation item

## [1.2.6] - 2026-02-14

### Added
- **Typography Settings**: New appearance options under admin panel
  - Font family selection (System, Inter, Roboto, Monospace)
  - Base font size (12-24px)
  - Heading weight (Normal, Medium, Semibold, Bold)
- **Layout Settings**: Customizable layout parameters
  - Border radius (0-20px)
  - iFrame gap/spacing (8-32px)
  - Content padding (8-32px)
- **Animation Settings**: Control over UI animations
  - Enable/disable animations
  - Transition speed (Slow, Normal, Fast)
- **Android Home Screen Icon**: Support for Android "Add to Home Screen"
  - PNG upload (192x192px recommended)
  - Uses `<link rel="icon" sizes="192x192">` for Android devices

### Changed
- Empty text fields now allowed for all customization options
- Custom CSS icon updated from ✨ to 🎯 for better distinction
- Improved appearance settings organization in admin panel

## [1.2.5] - 2026-02-14

### Removed
- **Connectivity Test**: Removed server-side ping test and status dots from dashboard
  - Removed `/api/connectivity-test-url` endpoint
  - Removed status dot indicators from iframe cards
  - Removed connectivity test CSS (status-dot classes)
  - Help page test now uses iframe-based approach
- **Help Page for Users**: Help/diagnostics page now restricted to admin users only

### Added
- **Password Visibility Toggle**: Show/hide button on login password field
  - Toggle button displays "Show"/"Hide" text
  - Styled to match existing form design
- **Mobile Optimizations**: Improved responsive layout for small screens
  - Better header layout on phones (smaller logo, compact nav)
  - Responsive iframe cards with adjusted padding and font sizes
  - Optimized footer spacing on mobile
  - Better touch target sizes (min 36px on extra small screens)
  - Improved card heading sizes for 480px screens

## [1.2.4] - 2026-02-05

### Added
- **CLAUDE.md**: Project context document for AI assistants
  - Development guidelines and common patterns
  - API endpoint reference
  - Troubleshooting guide
- **ARCHITECTURE.md**: Comprehensive system architecture documentation
  - Component diagrams (local server, cloud backend)
  - Data flow diagrams (auth, sync, connectivity)
  - Security architecture
  - Deployment architecture (Raspberry Pi)
- **CODEBASE.md**: Detailed code documentation
  - Module-by-module function reference
  - Configuration schema
  - API reference with request/response examples
  - HTML templates and CSS classes
  - JavaScript function reference

## [1.2.3] - 2026-02-04

### Changed
- **Simplified Connectivity Test**: Completely redesigned for reliability
  - Server now returns simple `reachable: true/false` instead of complex status
  - Any HTTP response (including 4xx/5xx) = reachable
  - Only network errors (timeout, refused, DNS fail) = not reachable
  - Removed complex X-Frame-Options and CSP checking that caused false failures
  - Frontend JavaScript simplified to basic true/false status display

### Fixed
- Connectivity test no longer shows false failures for accessible iframes
- Help page connectivity test updated to use simplified API

## [1.2.2] - 2026-02-04

### Fixed
- **Connectivity Test Accuracy**: Fixed false negatives in iframe status indicators
  - HTTP 4xx/5xx responses now correctly show as "reachable" (server responded)
  - Only network-level errors (timeout, DNS, connection refused) show as failed
  - Added warning status for SSL certificate issues
- **Cloud Agent 403 Error**: Fixed Cloudflare blocking Python requests
  - Added proper User-Agent header (`Multi-Frames/{VERSION}`) to all cloud API calls
  - Heartbeat, config pull, and config push endpoints now work correctly

### Changed
- Connectivity test now uses HEAD requests instead of GET for faster response
- Reduced connectivity test timeout from 10s to 8s
- Improved error messages for different network failure types
- Help page and admin connectivity tests now show "Reachable" for HTTP errors

## [1.2.1] - 2026-02-04

### Added
- **Cloud Settings in Admin Panel**: Configure cloud connectivity from the Settings tab
  - Cloud URL field for Cloudflare Worker endpoint
  - Device Key field for device authentication
  - Enable/disable toggle for cloud sync
  - Live status indicator (Connected/Connecting/Off)
- **Cloud Status Indicator**: Shows real-time cloud connection status in admin dashboard
  - Green checkmark when connected
  - Orange dots when connecting
  - Gray X when disabled

### Changed
- Admin status dashboard now includes cloud connectivity status
- Cloud agent automatically starts/stops based on settings

## [1.2.0] - 2026-02-03

### Added
- **Modern Cloud Dashboard**: Completely redesigned cloud management interface
  - Inter font family with modern typography
  - Responsive sidebar navigation (collapses on mobile)
  - Stats cards showing total/online/offline device counts
  - Device cards with hover effects and status indicators
  - Toast notifications for user feedback
- **Branding Customization**: Customize the cloud dashboard appearance
  - Company name setting
  - Logo URL upload
  - Primary and accent color pickers
  - Dark mode toggle
  - Branding stored in Cloudflare KV
- **Branding API Endpoints**: `GET /api/branding` and `PUT /api/branding`

### Changed
- Cloud dashboard is now fully responsive for mobile devices
- Improved sidebar with hamburger menu for mobile navigation
- Settings page reorganized with branding section

## [1.1.15] - 2026-02-03

### Added
- **Cloud Remote Management**: Manage 50+ Multi-Frames devices from anywhere
  - Cloudflare Workers-based serverless backend
  - Google Workspace authentication for secure access
  - Real-time device status monitoring (online/offline, uptime, temp)
  - Full config mirror sync across all devices
  - Bulk config push to multiple devices
  - Device registration with secure API keys
- **Cloud Agent**: Background service in Multi-Frames for cloud connectivity
  - Automatic heartbeat every 60 seconds
  - Config pull/push synchronization
  - Auto-apply config updates from cloud
- **Cloud Dashboard**: Web-based management interface
  - View all registered devices
  - Monitor device health and status
  - Push configurations remotely
  - Device registration workflow

## [1.1.14] - 2026-02-03

### Changed
- **Simplified iFrame Connectivity Test**: Streamlined the connectivity status indicator
  - Simple green/red status: green = reachable, red = not reachable
  - Removed complex X-Frame-Options/CSP header checking (was causing false warnings)
  - More reliable and predictable connectivity detection
  - Cleaner, simpler codebase

### Fixed
- **User Add Error**: Fixed "cannot access local variable 're'" error when adding users
- **Server Uptime**: Fixed uptime not resetting after unexpected server stops

### Added
- **Status Icon Setting**: New option to hide/show connectivity status icon per iframe

## [1.1.13] - 2026-01-27

### Fixed
- **Throttle Alert Accuracy**: Fixed false "Throttling Active" warning that appeared even when `vcgencmd get_throttled` returned `0x0`
  - Now properly checks individual throttle flags (bits 0-3 for current, bits 16-19 for past issues)
  - Shows red warning only for active throttling issues
  - Shows orange warning for past issues (since boot)
  - No warning displayed when system is healthy (0x0)

## [1.1.12] - 2026-01-27

### Fixed
- **Raspberry Pi Health Widgets**: Fixed widgets showing 0% instead of real data
  - Memory widget now shows used/total in MB (e.g., `512/2048 MB`)
  - Disk widget now shows used/total in GB (e.g., `12.5/32.0 GB`)
  - Power widget now shows actual core voltage with color indicator
- **Server Reset Issue**: Removed `WatchdogSec=300` from systemd service to prevent 5-minute automatic restarts

### Added
- Real-time memory usage tracking (`memory_used`, `memory_free` fields)
- Real-time disk usage tracking (`disk_total`, `disk_used`, `disk_free` fields)
- Core voltage monitoring via `vcgencmd measure_volts core`

## [1.1.11] - 2026-01-26

### Added
- **Watchdog Tab**: New admin panel tab with 30-day server uptime tracking
  - 24-hour, 7-day, and 30-day uptime percentages
  - Visual uptime chart with daily breakdown
  - Crash and restart event logging
  - Session duration tracking

## [1.1.10] - 2025-01-26

### Added
- **Status Dashboard**: Modern health banner at top of admin page showing server status
- **Server Health Indicator**: Visual 🟢/🟡/🔴 status with uptime display
- **Raspberry Pi Card**: Dedicated section showing temperature, memory, disk, power status
- **Modern Logs Viewer**: Tabbed interface with Requests, Logs, and Errors tabs
- **Stats Cards**: Visual cards for requests, errors, memory, IP address
- **Quick Info Bar**: Hostname, port, Python version, mDNS status at a glance

### Changed
- Admin page now shows status dashboard at top (always visible)
- System panel reorganized into logical sections
- Logs use color-coded icons and modern styling
- Connectivity testing simplified with inline status indicators
- Overall cleaner admin UI with better information hierarchy

### Fixed
- Removed duplicate code sections in render_system_section
- Improved code organization and reduced redundancy

## [1.1.9] - 2025-01-26

### Added
- **Git Clone URL Field**: Paste any GitHub URL format to configure updates
  - HTTPS: `https://github.com/owner/repo.git`
  - HTTPS with auth: `https://user:token@github.com/owner/repo.git`
  - SSH: `git@github.com:owner/repo.git`
  - Short: `github.com/owner/repo` or `owner/repo`
- **URL Parser**: Automatically extracts owner/repo from pasted URLs
- **Configuration Status**: Shows "Configure Repository" prompt when not set
- **Repository Link**: Displays linked GitHub repo when configured

### Changed
- Update settings form auto-opens when repository not configured
- "Check for Updates" button disabled until repository is configured
- Cleaner UI with primary URL field and advanced options collapsed

### Fixed
- NoneType error in `render_update_section` when `last_result` is None
- Admin page 500 error on fresh installations
- Authenticated GitHub URLs now parsed correctly

## [1.1.8] - 2025-01-26

### Added - Enhanced Install Script for Raspberry Pi
- **Kiosk Mode** (`--kiosk`): Auto-start Chromium in fullscreen on boot
- **Screen Blanking** (`--disable-blanking`): Prevent screen from sleeping
- **WiFi Fix** (`--fix-wifi`): Disable power management to prevent dropouts
- **Hostname Setup** (`--hostname NAME`): Set Pi hostname during install
- **Status Command** (`--status`): Show service status + Pi temp/throttling
- **Live Logs** (`--logs`): Follow logs in real-time
- **Auto Dependencies** (`--install-deps`): Install zeroconf and git

### Changed - Systemd Service Improvements
- Watchdog timer for Pi (5 minute timeout, auto-restart if hung)
- Memory limits for Pi (256MB max, 192MB high watermark)
- Security hardening (NoNewPrivileges, ProtectSystem, PrivateTmp)
- UFW firewall auto-configuration when active
- Better service restart timing (10s for Pi, 5s for others)

### Technical
- 717-line install.sh with comprehensive Pi detection
- X11/LightDM screen blanking disable
- Chromium kiosk mode with error dialog suppression
- WiFi power management via systemd service
- Hostname validation (RFC 1123 compliant)

## [1.1.7] - 2025-01-26

### Added
- **Auto-Restart on Crash**: Server automatically restarts with exponential backoff (up to 10 attempts)
- **Server Health Alerts**: Track and display errors, crashes, and warnings in admin panel
- **Alert System**: Severity levels (critical, error, warning, info) with timestamps
- **Crash Counter**: Tracks server restarts and displays in System tab
- **Clear Alerts**: Button to clear all server health alerts
- **--no-auto-restart**: Command line flag to disable auto-restart for debugging

### Fixed
- **Request Error Handling**: Wrapped do_GET and do_POST in try/except blocks
- **Connection Errors**: Graceful handling of BrokenPipeError and ConnectionResetError
- **Regex Pattern**: Fixed HTML input pattern attributes for modern browser compatibility (v flag)

### Changed
- Server stability significantly improved - crashes now auto-recover
- Error messages are captured and displayed in admin panel
- Improved logging of request errors

### Technical
- `ServerAlerts` class for tracking server health
- `_handle_request_error()` method for graceful error handling
- `track_server_alert()` function for logging alerts
- Main loop now has crash recovery with backoff
- Alerts consolidate repeated errors within 60 seconds

## [1.1.6] - 2025-01-26

### Added
- **Firmware Update System**: Check for and install updates from GitHub
- **Check for Updates**: Button to check GitHub releases for new versions
- **Git Pull Updates**: One-click update when running from a git repository
- **Update Settings**: Configure GitHub owner/repo for update checks
- **Git Status Display**: Shows current branch, commit hash, and uncommitted changes
- **Version Comparison**: Smart comparison determines if update is available
- **Auto-detection**: Automatically detects GitHub repo from git remote URL

### Changed
- Reorganized System page with dedicated "Firmware Updates" section
- Manual firmware upload moved to its own collapsible section
- Update check results are saved and displayed on page load

### Technical
- `get_git_info()`: Gets current git repository status
- `check_for_updates()`: Checks GitHub API for latest release
- `is_newer_version()`: Compares semantic version strings
- `perform_git_pull()`: Executes git pull with error handling
- New POST handlers: `/admin/system/check-updates`, `/admin/system/git-pull`, `/admin/system/update-settings`

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
