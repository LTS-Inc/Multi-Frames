#!/usr/bin/env python3
"""
Multi-Frames v1.1.10
===================
A lightweight, dependency-free web server for displaying configurable iFrames
and dashboard widgets. Uses only Python standard library.

Designed and Developed by: Marco Longoria
Company: LTS, Inc.

Features:
- User authentication with admin privileges
- Admin panel to manage iFrames and users
- Dashboard widgets (clock, weather, buttons, etc.)
- Network command buttons (TCP/UDP/Telnet)
- Customizable appearance and branding
- mDNS/Bonjour local network discovery
- Session-based authentication
- Responsive design
- Raspberry Pi auto-detection and management
- GitHub integration for firmware updates
- Auto-restart on crash with alerts

Usage:
    python multi_frames.py [--port PORT] [--host HOST]
    
Default: http://localhost:8080
Default admin credentials: admin / admin123 (CHANGE THIS!)

Version History:
    v1.1.11 (2026-01-26)
        - Added Watchdog tab in admin portal
        - 30-day server uptime tracking and history
        - Uptime percentage calculations and visualizations
        - Persistent uptime data across server restarts
        - Downtime event logging and tracking
        - Real-time server health monitoring dashboard

    v1.1.10 (2025-01-26)
        - Modern status dashboard at top of admin page
        - Server health banner with uptime and status
        - Raspberry Pi info card (temp, memory, disk, power)
        - Modern tabbed logs viewer (Requests, Logs, Errors)
        - Streamlined System panel with collapsible sections
        - Connectivity testing with visual status indicators
        - Improved overall admin UI organization

    v1.1.9 (2025-01-26)
        - Git clone URL field for easy repository configuration
        - Auto-parse GitHub URLs (HTTPS, SSH, authenticated, short formats)
        - Improved update settings UI with auto-open when unconfigured
        - Repository configuration status display
        - Fixed NoneType error in render_update_section
        - Check for Updates button disabled until configured

    v1.1.8 (2025-01-26)
        - Enhanced install.sh optimized for Raspberry Pi
        - Kiosk mode support (--kiosk flag)
        - Screen blanking disable option (--disable-blanking)
        - WiFi power management fix (--fix-wifi)
        - Hostname configuration during install (--hostname)
        - Service status command (--status)
        - Live log viewing (--logs)
        - Automatic dependency installation (--install-deps)
        - Systemd watchdog for Pi (5 min timeout)
        - Memory limits for Pi (256MB max)
        - Security hardening in systemd service
        - UFW firewall auto-configuration

    v1.1.7 (2025-01-26)
        - Server reliability improvements
        - Auto-restart on crash with exponential backoff
        - Server health alert system
        - Request error handling wrapper for do_GET/do_POST
        - Connection reset and broken pipe handling
        - Alert tracking with severity levels
        - Crash counter and restart logging
        - Clear alerts button in admin panel
        - Fixed HTML pattern attribute regex for modern browsers
        - --no-auto-restart flag for debugging

    v1.1.6 (2025-01-26)
        - Added firmware update system with GitHub integration
        - Check for updates from GitHub releases or raw file
        - Git pull support for automatic updates (when running from git repo)
        - Update settings configuration (GitHub owner/repo)
        - Shows git status (branch, commit, changes)
        - Auto-detection of GitHub repo from git remote
        - Version comparison with update notifications

    v1.1.5 (2025-01-25)
        - Automatic Raspberry Pi detection
        - Pi-specific system info (model, temperature, throttling status)
        - Change Pi hostname from web interface
        - Reboot/Shutdown Pi from Admin panel
        - dhcpcd network configuration support for Pi OS
        - Temperature monitoring with status indicators
        - Throttling and under-voltage warnings
        - /api/pi-status endpoint for Pi info
        - /api/ping endpoint for connectivity checks

    v1.1.4 (2025-01-25)
        - Fixed browser back button affecting parent page when in iframes
        - Added sandbox attribute to prevent iframe top-level navigation
        - History management prevents accidental page departure
        - Embed code iframes now get sandbox injection for security
        - Added allow-popups so links open in new tabs

    v1.1.3 (2025-01-25)
        - Added password change functionality for all users
        - Users can now change their own password in Admin → Users
        - Admins can change any user's password
        - Terminal banner shows security status (green when password changed)
        - Password confirmation required when changing passwords

    v1.1.2 (2025-01-25)
        - Comprehensive mobile optimization (touch targets, layouts)
        - Added safe-area-insets for notched phones
        - Admin tabs now show icons-only on small screens
        - Login rate limiting (5 attempts, 15 min lockout)
        - Timing-attack resistant password comparison
        - Improved error handling throughout
        - Better touch feedback on buttons
        - Reduced motion support for accessibility
        - Print styles added

    v1.1.1 (2025-01-25)
        - Fixed config file permission error (now shows friendly message)
        - Branding uploads handle save errors gracefully
        - Added warning banner when config not writable
        - Added fix instructions in System tab

    v1.1.0 (2025-01-25)
        - Added configuration import/upload feature
        - Added "preserve users" option for config import
        - Fixed firmware upload bug (empty file error)
        - Fixed connectivity report submission error
        - Modernized terminal boot UI with colors
        - Added --no-color flag for terminal output
        - Terminal now shows network IP, config stats, mDNS status
        - Security warning only shows if default password in use
        - Full config export (includes password hashes for backup)
        - Deep merge on config import ensures all fields exist
        
    v1.0.0 (2025-01-25) - Initial release
        - iFrame management with URL/embed code support
        - Dashboard widgets system (8 widget types)
        - Command Buttons with network protocols
        - Weather widget with Open-Meteo API
        - User authentication and admin panel
        - Customizable branding (logo, favicon, colors)
        - Network configuration (DHCP/static IP)
        - Connectivity testing and user reports
        - Forgot password system with admin approval
        - Footer hyperlinks
        - mDNS/Bonjour support
"""

# =============================================================================
# TABLE OF CONTENTS
# =============================================================================
#
# Line    Section
# ----    -------
# 97      VERSION & CONSTANTS
# 140     LOGGING SYSTEM (ServerLogger class)
# 254     SYSTEM DIAGNOSTICS
# 363     MDNS/BONJOUR SERVICE
# 476     NETWORK CONFIGURATION
# 955     CONFIGURATION MANAGEMENT (load/save config, sessions)
# 1225    DEFAULT CONFIGURATION
# 1800    CSS & DYNAMIC STYLES
# 2060    BASE PAGE TEMPLATE (render_page)
# 2180    LOGIN PAGES
# 2250    HELP & DIAGNOSTICS PAGE
# 2925    DASHBOARD WIDGETS
# 3215    MAIN DASHBOARD PAGE
# 3695    ADMIN PANEL
# 4385    WIDGET EDITOR
# 4765    PASSWORD RESET REQUESTS
# 4830    CONNECTIVITY REPORTS
# 4910    FIRMWARE MANAGEMENT
# 5045    FOOTER LINKS EDITOR
# 5090    NETWORK SETTINGS UI
# 5315    SYSTEM SETTINGS UI
# 5865    HTTP REQUEST HANDLER (IFrameHandler class)
# 7280    TCP SERVER
# 7290    TERMINAL UI (TermColors, banner)
# 7400    MAIN ENTRY POINT
#
# =============================================================================

# =============================================================================
# Version Information
# =============================================================================
VERSION = "1.2.2"
VERSION_DATE = "2026-02-04"
VERSION_NAME = "Multi-Frames"
VERSION_AUTHOR = "Marco Longoria"
VERSION_COMPANY = "LTS, Inc."

# GitHub repository for updates (user should configure this)
GITHUB_REPO_OWNER = ""  # e.g., "username"
GITHUB_REPO_NAME = ""   # e.g., "multi-frames"
GITHUB_BRANCH = "main"

import http.server
import socketserver
import json
import hashlib
import secrets
import os
import sys
import re
import argparse
import ipaddress
import base64
import socket
import urllib.request
import urllib.error
from urllib.parse import parse_qs, urlparse
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from functools import partial

# Optional mDNS support via zeroconf
ZEROCONF_AVAILABLE = False
try:
    from zeroconf import ServiceInfo, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    pass

# Global mDNS service instance
mdns_service = None
# Global server port
SERVER_PORT = 8080
# Global server start time
SERVER_START_TIME = None
# Firmware/update settings
FIRMWARE_BACKUP_DIR = None  # Set in main() based on script location
FIRMWARE_MAX_BACKUPS = 5
FIRMWARE_RESTART_DELAY = 2  # Seconds to wait before restart

# =============================================================================
# Logging System
# =============================================================================

from collections import deque
import traceback
import time as time_module

class ServerLogger:
    """Simple in-memory logging system with size limits."""
    
    LOG_LEVELS = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3}
    
    def __init__(self, max_entries=500, max_requests=200):
        self.logs = deque(maxlen=max_entries)
        self.requests = deque(maxlen=max_requests)
        self.errors = deque(maxlen=100)
        self.log_level = 'INFO'
        self.stats = {
            'total_requests': 0, 'total_errors': 0,
            'requests_by_path': {},
            'requests_by_method': {'GET': 0, 'POST': 0},
            'status_codes': {}
        }
    
    def _should_log(self, level):
        return self.LOG_LEVELS.get(level, 1) >= self.LOG_LEVELS.get(self.log_level, 1)
    
    def _entry(self, level, message, extra=None):
        return {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                'level': level, 'message': message, 'extra': extra}
    
    def debug(self, message, extra=None):
        if self._should_log('DEBUG'): self.logs.append(self._entry('DEBUG', message, extra))
    
    def info(self, message, extra=None):
        if self._should_log('INFO'): self.logs.append(self._entry('INFO', message, extra))
    
    def warning(self, message, extra=None):
        if self._should_log('WARNING'): self.logs.append(self._entry('WARNING', message, extra))
    
    def error(self, message, extra=None):
        entry = self._entry('ERROR', message, extra)
        if self._should_log('ERROR'): self.logs.append(entry)
        self.errors.append(entry)
        self.stats['total_errors'] += 1
    
    def log_request(self, method, path, status_code, duration_ms, client_ip, user=None):
        self.stats['total_requests'] += 1
        self.stats['requests_by_method'][method] = self.stats['requests_by_method'].get(method, 0) + 1
        simple_path = path.split('?')[0]
        self.stats['requests_by_path'][simple_path] = self.stats['requests_by_path'].get(simple_path, 0) + 1
        self.stats['status_codes'][str(status_code)] = self.stats['status_codes'].get(str(status_code), 0) + 1
        self.requests.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': method, 'path': path, 'status': status_code,
            'duration_ms': round(duration_ms, 2), 'client_ip': client_ip, 'user': user
        })
    
    def get_logs(self, limit=100): return list(self.logs)[-limit:]
    def get_requests(self, limit=50): return list(self.requests)[-limit:]
    def get_errors(self, limit=50): return list(self.errors)[-limit:]
    def get_stats(self): return self.stats.copy()
    def clear_logs(self): self.logs.clear(); self.requests.clear(); self.errors.clear()
    def clear_stats(self):
        self.stats = {'total_requests': 0, 'total_errors': 0, 'requests_by_path': {},
                      'requests_by_method': {'GET': 0, 'POST': 0}, 'status_codes': {}}
    def set_level(self, level):
        if level in self.LOG_LEVELS: self.log_level = level; return True
        return False

# Global logger instance
server_logger = ServerLogger()

# =============================================================================
# Server Alert System
# =============================================================================

class ServerAlerts:
    """Track server alerts and errors for display in admin panel."""
    
    def __init__(self, max_alerts=100):
        self.alerts = []
        self.max_alerts = max_alerts
        self.crash_count = 0
        self.last_crash = None
        self.error_counts = {}  # Track error frequency
    
    def add_alert(self, alert_type, message, severity='warning'):
        """Add an alert. Severity: 'info', 'warning', 'error', 'critical'"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message[:500],  # Limit message length
            'severity': severity,
            'count': 1
        }
        
        # Check if same error occurred recently (within 60s) - consolidate
        for existing in self.alerts[-10:]:
            if (existing['type'] == alert_type and 
                existing['message'] == alert['message'] and
                existing['severity'] == severity):
                existing['count'] = existing.get('count', 1) + 1
                existing['timestamp'] = alert['timestamp']
                return
        
        self.alerts.append(alert)
        
        # Track error frequency
        self.error_counts[alert_type] = self.error_counts.get(alert_type, 0) + 1
        
        # Trim old alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
    
    def record_crash(self, error_msg=None):
        """Record a server crash/restart."""
        self.crash_count += 1
        self.last_crash = datetime.now().isoformat()
        self.add_alert('crash', error_msg or 'Server crashed and restarted', 'critical')
    
    def get_alerts(self, limit=50, severity=None):
        """Get recent alerts, optionally filtered by severity."""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        return list(reversed(alerts[-limit:]))
    
    def get_stats(self):
        """Get alert statistics."""
        return {
            'total_alerts': len(self.alerts),
            'crash_count': self.crash_count,
            'last_crash': self.last_crash,
            'error_counts': dict(self.error_counts),
            'critical_count': len([a for a in self.alerts if a['severity'] == 'critical']),
            'error_count': len([a for a in self.alerts if a['severity'] == 'error']),
            'warning_count': len([a for a in self.alerts if a['severity'] == 'warning'])
        }
    
    def clear(self):
        """Clear all alerts."""
        self.alerts = []
        self.error_counts = {}

server_alerts = ServerAlerts()

def track_server_alert(alert_type, message, severity='error'):
    """Convenience function to track server alerts."""
    server_alerts.add_alert(alert_type, message, severity)

# =============================================================================
# Uptime Tracking System (30-day history)
# =============================================================================

class UptimeTracker:
    """Track server uptime with 30-day history, persisted to config."""

    MAX_HISTORY_DAYS = 30
    CHECK_INTERVAL_SECONDS = 60  # Record uptime every minute

    def __init__(self):
        self.current_session_start = None
        self.last_check = None
        self._initialized = False

    def initialize(self, config):
        """Initialize tracker when server starts."""
        self.current_session_start = datetime.now()
        self.last_check = datetime.now()
        self._initialized = True

        # Check for unexpected shutdown from previous session
        watchdog_data = config.get('watchdog', {})
        last_shutdown = watchdog_data.get('last_shutdown')
        last_update = watchdog_data.get('last_update')
        prev_session_start = watchdog_data.get('current_session_start')

        # Detect unexpected shutdown: last_update exists but no last_shutdown after it
        # This means the server was killed without graceful shutdown
        unexpected_shutdown = False
        downtime_start = None

        if last_update:
            try:
                last_update_dt = datetime.fromisoformat(last_update)

                if last_shutdown:
                    last_shutdown_dt = datetime.fromisoformat(last_shutdown)
                    # If last_update is after last_shutdown, server crashed after restart
                    if last_update_dt > last_shutdown_dt:
                        unexpected_shutdown = True
                        downtime_start = last_update_dt
                else:
                    # No shutdown recorded but we have last_update - unexpected shutdown
                    unexpected_shutdown = True
                    downtime_start = last_update_dt
            except:
                pass

        # Record unexpected shutdown event
        if unexpected_shutdown and downtime_start:
            downtime_seconds = (self.current_session_start - downtime_start).total_seconds()
            if downtime_seconds > 0 and downtime_seconds < 86400 * 30:  # Less than 30 days
                self._record_event(config, 'crash', 'Server stopped unexpectedly', severity='critical')
                self._record_event(config, 'downtime', f'Server was down for {self._format_duration(int(downtime_seconds))}',
                                  extra={'downtime_seconds': int(downtime_seconds)})
                # Record crash in daily stats
                today = datetime.now().strftime('%Y-%m-%d')
                config.setdefault('watchdog', {})
                daily_uptime = config['watchdog'].setdefault('daily_uptime', {})
                if today not in daily_uptime:
                    daily_uptime[today] = {'uptime_seconds': 0, 'downtime_seconds': 0, 'crashes': 0, 'restarts': 0}
                daily_uptime[today]['crashes'] = daily_uptime[today].get('crashes', 0) + 1
                daily_uptime[today]['downtime_seconds'] = daily_uptime[today].get('downtime_seconds', 0) + int(downtime_seconds)

        # If graceful shutdown was recorded, calculate downtime from that
        elif last_shutdown and not unexpected_shutdown:
            try:
                last_shutdown_dt = datetime.fromisoformat(last_shutdown)
                downtime_seconds = (self.current_session_start - last_shutdown_dt).total_seconds()
                if downtime_seconds > 0 and downtime_seconds < 86400 * 30:  # Less than 30 days
                    self._record_event(config, 'downtime', f'Server was down for {self._format_duration(int(downtime_seconds))}',
                                      extra={'downtime_seconds': int(downtime_seconds)})
            except:
                pass

        # Record server start event
        self._record_event(config, 'start', 'Server started')

        # Clear last_shutdown so we can detect future unexpected shutdowns
        config.setdefault('watchdog', {})
        config['watchdog']['last_shutdown'] = None

    def record_shutdown(self, config):
        """Record graceful shutdown."""
        if not self._initialized:
            return

        config.setdefault('watchdog', {})
        config['watchdog']['last_shutdown'] = datetime.now().isoformat()
        self._record_event(config, 'stop', 'Server stopped gracefully')
        self._update_session_uptime(config)

    def record_crash(self, config, error_msg=None):
        """Record a crash event."""
        if not self._initialized:
            return
        self._record_event(config, 'crash', error_msg or 'Server crashed', severity='critical')

    def periodic_update(self, config):
        """Called periodically to update uptime stats."""
        if not self._initialized:
            return

        now = datetime.now()
        if self.last_check and (now - self.last_check).total_seconds() >= self.CHECK_INTERVAL_SECONDS:
            self.last_check = now
            self._update_session_uptime(config)

    def _update_session_uptime(self, config):
        """Update the current session's uptime in config."""
        if not self.current_session_start:
            return

        config.setdefault('watchdog', {})
        watchdog = config['watchdog']

        # Update current session info
        session_duration = int((datetime.now() - self.current_session_start).total_seconds())
        watchdog['current_session_start'] = self.current_session_start.isoformat()
        watchdog['current_session_duration'] = session_duration
        watchdog['last_update'] = datetime.now().isoformat()

        # Update daily uptime tracking
        today = datetime.now().strftime('%Y-%m-%d')
        daily_uptime = watchdog.setdefault('daily_uptime', {})

        # Initialize or update today's uptime
        if today not in daily_uptime:
            daily_uptime[today] = {'uptime_seconds': 0, 'downtime_seconds': 0, 'crashes': 0, 'restarts': 0}

        # Calculate uptime for today's portion of this session
        session_start_date = self.current_session_start.strftime('%Y-%m-%d')
        if session_start_date == today:
            # Session started today - full duration counts
            daily_uptime[today]['uptime_seconds'] = session_duration
        else:
            # Session started before today - only count from midnight
            midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_duration = int((datetime.now() - midnight).total_seconds())
            daily_uptime[today]['uptime_seconds'] = today_duration

        # Cleanup old entries (keep only 30 days)
        self._cleanup_old_data(watchdog)

    def _record_event(self, config, event_type, message, severity='info', extra=None):
        """Record a watchdog event."""
        config.setdefault('watchdog', {})
        events = config['watchdog'].setdefault('events', [])

        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'message': message[:500],
            'severity': severity
        }
        if extra:
            event['extra'] = extra

        events.append(event)

        # Keep only last 500 events
        if len(events) > 500:
            config['watchdog']['events'] = events[-500:]

        # Update daily stats for crashes/restarts
        today = datetime.now().strftime('%Y-%m-%d')
        daily_uptime = config['watchdog'].setdefault('daily_uptime', {})
        if today not in daily_uptime:
            daily_uptime[today] = {'uptime_seconds': 0, 'downtime_seconds': 0, 'crashes': 0, 'restarts': 0}

        if event_type == 'crash':
            daily_uptime[today]['crashes'] = daily_uptime[today].get('crashes', 0) + 1
        elif event_type == 'start':
            daily_uptime[today]['restarts'] = daily_uptime[today].get('restarts', 0) + 1
        elif event_type == 'downtime' and extra:
            daily_uptime[today]['downtime_seconds'] = daily_uptime[today].get('downtime_seconds', 0) + extra.get('downtime_seconds', 0)

    def _cleanup_old_data(self, watchdog):
        """Remove data older than MAX_HISTORY_DAYS."""
        cutoff = (datetime.now() - timedelta(days=self.MAX_HISTORY_DAYS)).strftime('%Y-%m-%d')

        # Cleanup daily uptime
        daily_uptime = watchdog.get('daily_uptime', {})
        old_dates = [d for d in daily_uptime if d < cutoff]
        for d in old_dates:
            del daily_uptime[d]

        # Cleanup old events
        events = watchdog.get('events', [])
        cutoff_dt = datetime.now() - timedelta(days=self.MAX_HISTORY_DAYS)
        watchdog['events'] = [e for e in events if datetime.fromisoformat(e['timestamp']) > cutoff_dt]

    def get_stats(self, config):
        """Get comprehensive uptime statistics."""
        watchdog = config.get('watchdog', {})
        daily_uptime = watchdog.get('daily_uptime', {})
        events = watchdog.get('events', [])

        # Calculate totals for the period
        total_uptime_seconds = 0
        total_downtime_seconds = 0
        total_crashes = 0
        total_restarts = 0
        days_tracked = 0

        for date, data in daily_uptime.items():
            total_uptime_seconds += data.get('uptime_seconds', 0)
            total_downtime_seconds += data.get('downtime_seconds', 0)
            total_crashes += data.get('crashes', 0)
            total_restarts += data.get('restarts', 0)
            days_tracked += 1

        # Calculate uptime percentage
        total_time = total_uptime_seconds + total_downtime_seconds
        uptime_percentage = (total_uptime_seconds / total_time * 100) if total_time > 0 else 100.0

        # Current session info
        current_session_duration = 0
        if self.current_session_start:
            current_session_duration = int((datetime.now() - self.current_session_start).total_seconds())

        # Get recent events
        recent_events = sorted(events, key=lambda x: x['timestamp'], reverse=True)[:20]

        # Last 7 days daily breakdown
        last_7_days = {}
        for i in range(7):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            if date in daily_uptime:
                last_7_days[date] = daily_uptime[date]
            else:
                last_7_days[date] = {'uptime_seconds': 0, 'downtime_seconds': 0, 'crashes': 0, 'restarts': 0}

        # Calculate 24h, 7d, 30d uptime percentages
        def calc_period_uptime(days):
            up = down = 0
            for i in range(days):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                if date in daily_uptime:
                    up += daily_uptime[date].get('uptime_seconds', 0)
                    down += daily_uptime[date].get('downtime_seconds', 0)
            total = up + down
            return (up / total * 100) if total > 0 else 100.0

        return {
            'current_session_start': self.current_session_start.isoformat() if self.current_session_start else None,
            'current_session_duration': current_session_duration,
            'current_session_formatted': self._format_duration(current_session_duration),
            'total_uptime_seconds': total_uptime_seconds,
            'total_uptime_formatted': self._format_duration(total_uptime_seconds),
            'total_downtime_seconds': total_downtime_seconds,
            'total_downtime_formatted': self._format_duration(total_downtime_seconds),
            'uptime_percentage': round(uptime_percentage, 3),
            'uptime_24h': round(calc_period_uptime(1), 3),
            'uptime_7d': round(calc_period_uptime(7), 3),
            'uptime_30d': round(calc_period_uptime(30), 3),
            'total_crashes': total_crashes,
            'total_restarts': total_restarts,
            'days_tracked': days_tracked,
            'recent_events': recent_events,
            'last_7_days': last_7_days,
            'daily_uptime': daily_uptime
        }

    def _format_duration(self, seconds):
        """Format duration in human readable format."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            mins = seconds // 60
            secs = seconds % 60
            return f"{mins}m {secs}s"
        elif seconds < 86400:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hours}h {mins}m"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d {hours}h"

# Global uptime tracker instance
uptime_tracker = UptimeTracker()

# =============================================================================
# Cloud Agent - Remote Management & Config Sync
# =============================================================================

class CloudAgent:
    """Background agent for cloud connectivity, config sync, and remote management."""

    HEARTBEAT_INTERVAL = 60  # seconds

    def __init__(self):
        self.enabled = False
        self.cloud_url = None
        self.device_key = None
        self.config_version = 0
        self._thread = None
        self._stop_event = None
        self._last_heartbeat = None
        self._last_error = None
        self._connected = False

    def initialize(self, config):
        """Initialize cloud agent from config."""
        cloud_config = config.get('cloud', {})
        self.enabled = cloud_config.get('enabled', False)
        self.cloud_url = cloud_config.get('url', '').rstrip('/')
        self.device_key = cloud_config.get('device_key', '')
        self.config_version = cloud_config.get('config_version', 0)

        if self.enabled and self.cloud_url and self.device_key:
            self.start()

    def start(self):
        """Start the background sync thread."""
        if self._thread and self._thread.is_alive():
            return

        import threading
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        server_logger.info(f"Cloud agent started, connecting to {self.cloud_url}")

    def stop(self):
        """Stop the background sync thread."""
        if self._stop_event:
            self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._connected = False

    def _run(self):
        """Background thread main loop."""
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
                self._check_config_update()
            except Exception as e:
                self._last_error = str(e)
                self._connected = False
                server_logger.error(f"Cloud agent error: {e}")

            # Wait for next interval or stop signal
            self._stop_event.wait(self.HEARTBEAT_INTERVAL)

    def _send_heartbeat(self):
        """Send heartbeat to cloud server."""
        if not self.cloud_url or not self.device_key:
            return

        import urllib.request
        import json
        import socket

        # Gather device info
        pi_info = get_raspberry_pi_info()
        sys_info = get_system_info()

        heartbeat_data = {
            'hostname': socket.gethostname(),
            'ip_address': self._get_local_ip(),
            'version': VERSION,
            'config_version': self.config_version,
            'uptime': sys_info.get('server_uptime_formatted', ''),
            'memory_used': f"{pi_info.get('memory_used', 0)}/{pi_info.get('memory_total', 0)} MB" if pi_info else '',
            'cpu_temp': pi_info.get('temperature') if pi_info else None
        }

        try:
            req = urllib.request.Request(
                f"{self.cloud_url}/api/devices/heartbeat",
                data=json.dumps(heartbeat_data).encode('utf-8'),
                headers={
                    'Content-Type': 'application/json',
                    'X-Device-Key': self.device_key,
                    'User-Agent': f'Multi-Frames/{VERSION}'
                },
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                self._connected = True
                self._last_heartbeat = datetime.now()
                self._last_error = None

                # Check if config update available
                if result.get('config_update_available'):
                    self._pull_config()

        except Exception as e:
            self._connected = False
            self._last_error = str(e)
            raise

    def _check_config_update(self):
        """Check for and apply config updates from cloud."""
        pass  # Handled in heartbeat response

    def _pull_config(self):
        """Pull config from cloud and apply it."""
        if not self.cloud_url or not self.device_key:
            return

        import urllib.request
        import json

        try:
            req = urllib.request.Request(
                f"{self.cloud_url}/api/config/pull",
                headers={
                    'X-Device-Key': self.device_key,
                    'User-Agent': f'Multi-Frames/{VERSION}'
                },
                method='GET'
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))

                if result.get('config') and result.get('version', 0) > self.config_version:
                    # Apply new config
                    self._apply_config(result['config'], result['version'])

        except Exception as e:
            server_logger.error(f"Cloud config pull failed: {e}")

    def _apply_config(self, new_config, version):
        """Apply config received from cloud."""
        try:
            config = load_config()

            # Merge cloud config (preserve local cloud settings)
            cloud_settings = config.get('cloud', {})

            # Update config with cloud data
            for key, value in new_config.items():
                if key != 'cloud':  # Don't overwrite cloud settings
                    config[key] = value

            # Restore cloud settings and update version
            config['cloud'] = cloud_settings
            config['cloud']['config_version'] = version
            self.config_version = version

            save_config(config)
            server_logger.info(f"Cloud config applied, version {version}")

        except Exception as e:
            server_logger.error(f"Failed to apply cloud config: {e}")

    def push_config(self, config):
        """Push current config to cloud."""
        if not self.enabled or not self.cloud_url or not self.device_key:
            return False, "Cloud sync not enabled"

        import urllib.request
        import json

        # Prepare config for upload (exclude sensitive data)
        upload_config = {k: v for k, v in config.items() if k not in ['cloud']}

        try:
            req = urllib.request.Request(
                f"{self.cloud_url}/api/config/push",
                data=json.dumps({'config': upload_config}).encode('utf-8'),
                headers={
                    'Content-Type': 'application/json',
                    'X-Device-Key': self.device_key,
                    'User-Agent': f'Multi-Frames/{VERSION}'
                },
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                if result.get('success'):
                    self.config_version = result.get('version', self.config_version)
                    config['cloud']['config_version'] = self.config_version
                    return True, f"Config synced to cloud (version {self.config_version})"
                return False, result.get('error', 'Unknown error')

        except Exception as e:
            return False, str(e)

    def _get_local_ip(self):
        """Get local IP address."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'

    def get_status(self):
        """Get cloud agent status."""
        return {
            'enabled': self.enabled,
            'connected': self._connected,
            'cloud_url': self.cloud_url,
            'config_version': self.config_version,
            'last_heartbeat': self._last_heartbeat.isoformat() if self._last_heartbeat else None,
            'last_error': self._last_error
        }


# Global cloud agent instance
cloud_agent = CloudAgent()

def get_system_info():
    """Get system information for debugging."""
    import sys
    import platform
    info = {
        'python_version': sys.version.split()[0],
        'platform': platform.platform(),
        'server_port': SERVER_PORT,
        'config_file': CONFIG_FILE,
        'zeroconf_available': ZEROCONF_AVAILABLE,
        'mdns_running': mdns_service.running if mdns_service else False,
        'server_uptime': None, 'memory_mb': 'N/A',
        'is_raspberry_pi': False,
        'pi_info': None
    }
    if SERVER_START_TIME:
        uptime = datetime.now() - SERVER_START_TIME
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        info['server_uptime'] = f"{hours}h {minutes}m {seconds}s"
    try:
        import resource
        info['memory_mb'] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
    except: pass
    
    # Check for Raspberry Pi
    pi_info = get_raspberry_pi_info()
    if pi_info:
        info['is_raspberry_pi'] = True
        info['pi_info'] = pi_info
    
    return info

def get_raspberry_pi_info():
    """
    Detect if running on a Raspberry Pi and return device info.
    Returns None if not a Pi, or dict with Pi details.
    """
    pi_info = None
    
    try:
        # Method 1: Check /proc/device-tree/model (most reliable)
        if os.path.exists('/proc/device-tree/model'):
            with open('/proc/device-tree/model', 'r') as f:
                model = f.read().strip().replace('\x00', '')
                if 'raspberry pi' in model.lower():
                    pi_info = {'model': model, 'detection_method': 'device-tree'}
        
        # Method 2: Check /proc/cpuinfo for Pi-specific hardware
        if not pi_info and os.path.exists('/proc/cpuinfo'):
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                if 'BCM' in cpuinfo or 'Raspberry' in cpuinfo:
                    # Extract model from cpuinfo
                    for line in cpuinfo.split('\n'):
                        if line.startswith('Model'):
                            model = line.split(':')[1].strip() if ':' in line else 'Raspberry Pi'
                            pi_info = {'model': model, 'detection_method': 'cpuinfo'}
                            break
                        elif line.startswith('Hardware'):
                            hardware = line.split(':')[1].strip() if ':' in line else ''
                            if 'BCM' in hardware:
                                pi_info = {'model': f'Raspberry Pi ({hardware})', 'detection_method': 'cpuinfo'}
        
        # Method 3: Check for Pi-specific files
        if not pi_info:
            pi_indicators = [
                '/opt/vc/bin/vcgencmd',  # VideoCore tools
                '/boot/config.txt',       # Pi boot config (older)
                '/boot/firmware/config.txt'  # Pi boot config (newer)
            ]
            for indicator in pi_indicators:
                if os.path.exists(indicator):
                    pi_info = {'model': 'Raspberry Pi (detected)', 'detection_method': 'filesystem'}
                    break
        
        if pi_info:
            # Get additional Pi info
            pi_info['serial'] = None
            pi_info['revision'] = None
            pi_info['temperature'] = None
            pi_info['throttled'] = None
            pi_info['memory_total'] = None
            pi_info['boot_config'] = None
            
            # Get serial and revision from cpuinfo
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('Serial'):
                            pi_info['serial'] = line.split(':')[1].strip() if ':' in line else None
                        elif line.startswith('Revision'):
                            pi_info['revision'] = line.split(':')[1].strip() if ':' in line else None
            
            # Get temperature using vcgencmd
            try:
                result = subprocess.run(['vcgencmd', 'measure_temp'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Output: temp=42.0'C
                    temp_str = result.stdout.strip()
                    if 'temp=' in temp_str:
                        temp = temp_str.split('=')[1].replace("'C", "").strip()
                        pi_info['temperature'] = float(temp)
            except: pass
            
            # Get throttling status
            try:
                result = subprocess.run(['vcgencmd', 'get_throttled'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Output: throttled=0x0
                    throttle_str = result.stdout.strip()
                    if 'throttled=' in throttle_str:
                        throttle_hex = throttle_str.split('=')[1].strip()
                        throttle_val = int(throttle_hex, 16)
                        pi_info['throttled'] = {
                            'value': throttle_hex,
                            'under_voltage': bool(throttle_val & 0x1),
                            'freq_capped': bool(throttle_val & 0x2),
                            'throttled': bool(throttle_val & 0x4),
                            'soft_temp_limit': bool(throttle_val & 0x8),
                            'under_voltage_occurred': bool(throttle_val & 0x10000),
                            'freq_capped_occurred': bool(throttle_val & 0x20000),
                            'throttled_occurred': bool(throttle_val & 0x40000),
                            'soft_temp_occurred': bool(throttle_val & 0x80000)
                        }
            except: pass
            
            # Get memory info (used/total in MB)
            if os.path.exists('/proc/meminfo'):
                mem_total_kb = 0
                mem_available_kb = 0
                mem_free_kb = 0
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            mem_total_kb = int(line.split()[1])
                        elif line.startswith('MemAvailable:'):
                            mem_available_kb = int(line.split()[1])
                        elif line.startswith('MemFree:'):
                            mem_free_kb = int(line.split()[1])

                if mem_total_kb > 0:
                    pi_info['memory_total'] = round(mem_total_kb / 1024)  # MB
                    # Use MemAvailable if present (more accurate), otherwise use MemFree
                    available_kb = mem_available_kb if mem_available_kb > 0 else mem_free_kb
                    pi_info['memory_used'] = round((mem_total_kb - available_kb) / 1024)  # MB
                    pi_info['memory_free'] = round(available_kb / 1024)  # MB

            # Get disk usage info (in GB)
            try:
                statvfs = os.statvfs('/')
                disk_total_bytes = statvfs.f_frsize * statvfs.f_blocks
                disk_free_bytes = statvfs.f_frsize * statvfs.f_bavail
                disk_used_bytes = disk_total_bytes - disk_free_bytes
                pi_info['disk_total'] = round(disk_total_bytes / (1024**3), 1)  # GB
                pi_info['disk_used'] = round(disk_used_bytes / (1024**3), 1)  # GB
                pi_info['disk_free'] = round(disk_free_bytes / (1024**3), 1)  # GB
            except: pass

            # Get voltage info using vcgencmd
            try:
                result = subprocess.run(['vcgencmd', 'measure_volts', 'core'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Output: volt=1.2000V
                    volt_str = result.stdout.strip()
                    if 'volt=' in volt_str:
                        volt = volt_str.split('=')[1].replace('V', '').strip()
                        pi_info['voltage_core'] = float(volt)
            except: pass
            
            # Determine boot config file location
            if os.path.exists('/boot/firmware/config.txt'):
                pi_info['boot_config'] = '/boot/firmware/config.txt'
            elif os.path.exists('/boot/config.txt'):
                pi_info['boot_config'] = '/boot/config.txt'
            
            # Check which network config method is used
            pi_info['network_config'] = 'unknown'
            if os.path.exists('/etc/dhcpcd.conf'):
                pi_info['network_config'] = 'dhcpcd'
            elif os.path.exists('/etc/netplan'):
                pi_info['network_config'] = 'netplan'
            elif os.path.exists('/etc/network/interfaces'):
                pi_info['network_config'] = 'interfaces'
            
            # Get hostname
            try:
                pi_info['hostname'] = socket.gethostname()
            except:
                pi_info['hostname'] = 'unknown'
    
    except Exception as e:
        # If anything fails, just return None
        pass
    
    return pi_info

def get_pi_config_settings():
    """Read current Raspberry Pi config.txt settings."""
    settings = {}
    
    # Find config file
    config_file = None
    if os.path.exists('/boot/firmware/config.txt'):
        config_file = '/boot/firmware/config.txt'
    elif os.path.exists('/boot/config.txt'):
        config_file = '/boot/config.txt'
    
    if not config_file:
        return settings
    
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    settings[key.strip()] = value.strip()
    except:
        pass
    
    return settings

def set_pi_hostname(new_hostname):
    """Set Raspberry Pi hostname. Returns (success, message)."""
    if not new_hostname or not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', new_hostname):
        return False, "Invalid hostname. Use only letters, numbers, and hyphens."
    
    try:
        # Update /etc/hostname
        with open('/etc/hostname', 'w') as f:
            f.write(new_hostname + '\n')
        
        # Update /etc/hosts
        hosts_content = ""
        with open('/etc/hosts', 'r') as f:
            for line in f:
                if '127.0.1.1' in line:
                    hosts_content += f"127.0.1.1\t{new_hostname}\n"
                else:
                    hosts_content += line
        
        with open('/etc/hosts', 'w') as f:
            f.write(hosts_content)
        
        # Apply hostname immediately
        subprocess.run(['hostnamectl', 'set-hostname', new_hostname], 
                      capture_output=True, timeout=10)
        
        return True, f"Hostname changed to '{new_hostname}'. Reboot recommended."
    except PermissionError:
        return False, "Permission denied. Run as root to change hostname."
    except Exception as e:
        return False, f"Error: {str(e)}"

def apply_pi_network_dhcpcd(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Apply network configuration using dhcpcd (Raspberry Pi OS default)."""
    dhcpcd_conf = '/etc/dhcpcd.conf'
    
    try:
        # Read existing config
        existing_content = ""
        if os.path.exists(dhcpcd_conf):
            with open(dhcpcd_conf, 'r') as f:
                existing_content = f.read()
        
        # Remove any existing static IP config for this interface
        lines = existing_content.split('\n')
        new_lines = []
        skip_until_blank = False
        
        for line in lines:
            if line.strip().startswith(f'interface {interface}'):
                skip_until_blank = True
                continue
            if skip_until_blank:
                if line.strip() == '' or line.strip().startswith('interface '):
                    skip_until_blank = False
                    if line.strip().startswith('interface '):
                        new_lines.append(line)
                continue
            new_lines.append(line)
        
        # Build new config
        new_content = '\n'.join(new_lines).strip()
        
        if mode == 'static':
            # Convert subnet mask to CIDR notation
            cidr = subnet_to_cidr(subnet) if subnet else '24'
            
            static_config = f"""

# Multi-Frames static IP configuration
interface {interface}
static ip_address={ip_addr}/{cidr}"""
            
            if gateway:
                static_config += f"\nstatic routers={gateway}"
            
            dns_servers = []
            if dns_primary:
                dns_servers.append(dns_primary)
            if dns_secondary:
                dns_servers.append(dns_secondary)
            if dns_servers:
                static_config += f"\nstatic domain_name_servers={' '.join(dns_servers)}"
            
            new_content += static_config
        
        new_content += '\n'
        
        # Backup existing config
        if os.path.exists(dhcpcd_conf):
            backup_file = dhcpcd_conf + '.backup'
            with open(backup_file, 'w') as f:
                f.write(existing_content)
        
        # Write new config
        with open(dhcpcd_conf, 'w') as f:
            f.write(new_content)
        
        # Restart dhcpcd service
        result = subprocess.run(['systemctl', 'restart', 'dhcpcd'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            # Restore backup
            if os.path.exists(dhcpcd_conf + '.backup'):
                with open(dhcpcd_conf + '.backup', 'r') as f:
                    with open(dhcpcd_conf, 'w') as wf:
                        wf.write(f.read())
                subprocess.run(['systemctl', 'restart', 'dhcpcd'], capture_output=True, timeout=30)
            return False, f"Failed to apply: {result.stderr}"
        
        return True, "Network configured via dhcpcd. Changes applied."
        
    except PermissionError:
        return False, "Permission denied. Run as root to change network settings."
    except subprocess.TimeoutExpired:
        return False, "Network configuration timed out."
    except Exception as e:
        return False, f"Error: {str(e)}"

def subnet_to_cidr(subnet):
    """Convert subnet mask (255.255.255.0) to CIDR notation (24)."""
    try:
        octets = subnet.split('.')
        binary = ''.join([bin(int(x))[2:].zfill(8) for x in octets])
        return str(binary.count('1'))
    except:
        return '24'

# =============================================================================
# Firmware Update Functions
# =============================================================================

def get_git_info():
    """Get information about the current git repository."""
    info = {
        'is_git_repo': False,
        'current_branch': None,
        'current_commit': None,
        'commit_short': None,
        'commit_date': None,
        'remote_url': None,
        'has_changes': False,
        'repo_owner': None,
        'repo_name': None
    }
    
    # Check if we're in a git repository
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    try:
        # Check if .git directory exists
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode != 0:
            return info
        
        info['is_git_repo'] = True
        
        # Get current branch
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode == 0:
            info['current_branch'] = result.stdout.strip()
        
        # Get current commit hash
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode == 0:
            info['current_commit'] = result.stdout.strip()
            info['commit_short'] = info['current_commit'][:7]
        
        # Get commit date
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%ci'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode == 0:
            info['commit_date'] = result.stdout.strip()
        
        # Get remote URL
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode == 0:
            remote_url = result.stdout.strip()
            info['remote_url'] = remote_url
            
            # Parse owner/repo from URL
            # Handles: https://github.com/owner/repo.git or git@github.com:owner/repo.git
            match = re.search(r'github\.com[:/]([^/]+)/([^/\.]+)', remote_url)
            if match:
                info['repo_owner'] = match.group(1)
                info['repo_name'] = match.group(2).replace('.git', '')
        
        # Check for uncommitted changes
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            capture_output=True, text=True, timeout=5,
            cwd=script_dir
        )
        if result.returncode == 0:
            info['has_changes'] = bool(result.stdout.strip())
        
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # Git not installed
        pass
    except Exception as e:
        info['error'] = str(e)
    
    return info

def check_for_updates(config):
    """
    Check GitHub for available updates.
    Returns dict with update info.
    """
    result = {
        'update_available': False,
        'current_version': VERSION,
        'latest_version': None,
        'latest_date': None,
        'release_notes': None,
        'error': None,
        'checked_at': datetime.now().isoformat()
    }
    
    # Get repo info from config or git
    update_settings = config.get('update_settings', {})
    repo_owner = update_settings.get('github_owner', '').strip()
    repo_name = update_settings.get('github_repo', '').strip()
    
    # If not configured, try to get from git remote
    if not repo_owner or not repo_name:
        git_info = get_git_info()
        if git_info.get('repo_owner') and git_info.get('repo_name'):
            repo_owner = git_info['repo_owner']
            repo_name = git_info['repo_name']
    
    if not repo_owner or not repo_name:
        result['error'] = 'GitHub repository not configured. Set in Admin → System → Update Settings.'
        return result
    
    try:
        # Try GitHub API first (for releases)
        api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"
        
        req = urllib.request.Request(api_url, headers={
            'User-Agent': f'Multi-Frames/{VERSION}',
            'Accept': 'application/vnd.github.v3+json'
        })
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                tag_name = data.get('tag_name', '')
                # Remove 'v' prefix if present
                latest_version = tag_name.lstrip('v')
                
                result['latest_version'] = latest_version
                result['latest_date'] = data.get('published_at', '')[:10]
                result['release_notes'] = data.get('body', '')[:500]
                result['release_url'] = data.get('html_url', '')
                
                # Compare versions
                if latest_version and latest_version != VERSION:
                    # Simple version comparison
                    result['update_available'] = is_newer_version(latest_version, VERSION)
                
                return result
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # No releases, try checking raw file
                pass
            else:
                raise
        
        # Fallback: Check raw file for VERSION
        raw_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/multi_frames.py"
        
        req = urllib.request.Request(raw_url, headers={
            'User-Agent': f'Multi-Frames/{VERSION}'
        })
        
        with urllib.request.urlopen(req, timeout=15) as response:
            # Read first 2KB to find VERSION
            content = response.read(2048).decode('utf-8', errors='ignore')
            
            # Extract VERSION from file
            version_match = re.search(r'VERSION\s*=\s*["\']([^"\']+)["\']', content)
            date_match = re.search(r'VERSION_DATE\s*=\s*["\']([^"\']+)["\']', content)
            
            if version_match:
                latest_version = version_match.group(1)
                result['latest_version'] = latest_version
                
                if date_match:
                    result['latest_date'] = date_match.group(1)
                
                if latest_version != VERSION:
                    result['update_available'] = is_newer_version(latest_version, VERSION)
    
    except urllib.error.URLError as e:
        result['error'] = f"Network error: {str(e.reason)}"
    except urllib.error.HTTPError as e:
        result['error'] = f"HTTP error {e.code}: {e.reason}"
    except Exception as e:
        result['error'] = f"Error checking updates: {str(e)}"
    
    return result

def is_newer_version(latest, current):
    """Compare version strings. Returns True if latest > current."""
    try:
        def parse_version(v):
            # Handle versions like "1.1.5" or "1.1.5-beta"
            parts = re.split(r'[-+]', v)[0]  # Remove pre-release suffix
            return [int(x) for x in parts.split('.')]
        
        latest_parts = parse_version(latest)
        current_parts = parse_version(current)
        
        # Pad with zeros
        max_len = max(len(latest_parts), len(current_parts))
        latest_parts.extend([0] * (max_len - len(latest_parts)))
        current_parts.extend([0] * (max_len - len(current_parts)))
        
        return latest_parts > current_parts
    except:
        # If parsing fails, do string comparison
        return latest > current

def perform_git_pull():
    """
    Perform git pull to update the firmware.
    Returns (success, message, details).
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    details = {
        'before_commit': None,
        'after_commit': None,
        'files_changed': [],
        'output': ''
    }
    
    try:
        # Check if git repo
        git_info = get_git_info()
        if not git_info['is_git_repo']:
            return False, "Not a git repository. Use firmware upload instead.", details
        
        if git_info['has_changes']:
            return False, "Local changes detected. Commit or stash changes first.", details
        
        details['before_commit'] = git_info.get('commit_short')
        
        # Perform git fetch first
        result = subprocess.run(
            ['git', 'fetch', 'origin'],
            capture_output=True, text=True, timeout=30,
            cwd=script_dir
        )
        
        if result.returncode != 0:
            return False, f"Git fetch failed: {result.stderr}", details
        
        # Get current branch
        branch = git_info.get('current_branch', 'main')
        
        # Perform git pull
        result = subprocess.run(
            ['git', 'pull', 'origin', branch],
            capture_output=True, text=True, timeout=60,
            cwd=script_dir
        )
        
        details['output'] = result.stdout + result.stderr
        
        if result.returncode != 0:
            return False, f"Git pull failed: {result.stderr}", details
        
        # Check if already up to date
        if 'Already up to date' in result.stdout or 'Already up-to-date' in result.stdout:
            return True, "Already up to date.", details
        
        # Get new commit
        new_git_info = get_git_info()
        details['after_commit'] = new_git_info.get('commit_short')
        
        # Get list of changed files
        if details['before_commit'] and details['after_commit']:
            diff_result = subprocess.run(
                ['git', 'diff', '--name-only', details['before_commit'], details['after_commit']],
                capture_output=True, text=True, timeout=10,
                cwd=script_dir
            )
            if diff_result.returncode == 0:
                details['files_changed'] = [f.strip() for f in diff_result.stdout.strip().split('\n') if f.strip()]
        
        return True, f"Updated from {details['before_commit']} to {details['after_commit']}", details
    
    except subprocess.TimeoutExpired:
        return False, "Git operation timed out.", details
    except FileNotFoundError:
        return False, "Git is not installed on this system.", details
    except Exception as e:
        return False, f"Error: {str(e)}", details

def get_update_settings(config):
    """Get update settings from config."""
    return config.get('update_settings', {
        'github_owner': '',
        'github_repo': '',
        'github_url': '',
        'auto_check': False,
        'last_check': None,
        'last_result': None
    })

def parse_git_url(url):
    """Parse a git clone URL to extract owner and repo name.
    
    Supports:
    - https://github.com/owner/repo.git
    - https://github.com/owner/repo
    - https://user:token@github.com/owner/repo.git (authenticated)
    - git@github.com:owner/repo.git
    - github.com/owner/repo
    - owner/repo
    """
    if not url:
        return None, None
    
    url = url.strip()
    
    # Remove .git suffix
    if url.endswith('.git'):
        url = url[:-4]
    
    # Handle authenticated HTTPS: https://user:token@github.com/owner/repo
    auth_match = re.match(r'https?://[^@]+@github\.com/([^/]+)/([^/]+)/?', url)
    if auth_match:
        return auth_match.group(1), auth_match.group(2)
    
    # Handle SSH format: git@github.com:owner/repo
    ssh_match = re.match(r'git@github\.com:([^/]+)/(.+)', url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)
    
    # Handle HTTPS format: https://github.com/owner/repo
    https_match = re.match(r'https?://github\.com/([^/]+)/([^/]+)/?', url)
    if https_match:
        return https_match.group(1), https_match.group(2)
    
    # Handle short format: github.com/owner/repo
    short_match = re.match(r'github\.com/([^/]+)/([^/]+)/?', url)
    if short_match:
        return short_match.group(1), short_match.group(2)
    
    # Handle owner/repo format directly
    direct_match = re.match(r'^([^/]+)/([^/]+)$', url)
    if direct_match:
        return direct_match.group(1), direct_match.group(2)
    
    return None, None

def save_update_settings(config, settings):
    """Save update settings to config."""
    config['update_settings'] = settings
    return save_config(config)

def get_network_diagnostics():
    """Get network diagnostic information."""
    diagnostics = {'hostname': socket.gethostname(), 'local_ip': '127.0.0.1', 'dns_resolution': 'Unknown', 'interfaces': []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        diagnostics['local_ip'] = s.getsockname()[0]
        s.close()
    except: pass
    try:
        socket.gethostbyname('google.com')
        diagnostics['dns_resolution'] = 'OK'
    except:
        diagnostics['dns_resolution'] = 'FAILED'
    return diagnostics

# =============================================================================
# Configuration
# =============================================================================

CONFIG_FILE = "multi_frames_config.json"
SESSION_TIMEOUT_HOURS = 24

DEFAULT_CONFIG = {
    "users": {
        "admin": {
            "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
            "is_admin": True
        }
    },
    "password_reset_requests": [],  # List of {"username": "...", "timestamp": "...", "id": "..."}
    "connectivity_reports": [],  # List of {"id": "...", "username": "...", "timestamp": "...", "results": [...]}
    "iframes": [],
    "settings": {
        "page_title": "Dashboard",
        "tab_title": "",  # Custom browser tab title (empty = use page_title)
        "tab_suffix": "Multi-Frames",  # Suffix after page title (empty = no suffix)
        "refresh_interval": 0,
        "grid_columns": 2,
        "auto_fullscreen": False
    },
    "branding": {
        "logo": None,  # Base64 encoded logo
        "logo_mime": None,  # MIME type of logo
        "favicon": None,  # Base64 encoded favicon
        "favicon_mime": None,
        "apple_touch_icon": None,  # Base64 encoded apple touch icon
        "apple_touch_icon_mime": None
    },
    "appearance": {
        "colors": {
            "bg_primary": "#0a0a0b",
            "bg_secondary": "#141416",
            "bg_tertiary": "#1c1c1f",
            "border": "#2a2a2d",
            "text_primary": "#e8e8e8",
            "text_secondary": "#888888",
            "accent": "#3b82f6",
            "accent_hover": "#2563eb",
            "danger": "#ef4444",
            "success": "#22c55e"
        },
        "background": {
            "type": "solid",  # solid, gradient, image
            "gradient_start": "#0a0a0b",
            "gradient_end": "#1a1a2e",
            "gradient_direction": "to bottom",
            "image": None,  # Base64 encoded
            "image_mime": None,
            "image_size": "cover",  # cover, contain, repeat
            "image_opacity": 100
        },
        "header": {
            "show": True,
            "sticky": True,
            "custom_text": "",
            "bg_color": "",  # Empty = use bg_secondary
            "text_color": ""  # Empty = use text_primary
        },
        "footer": {
            "show": True,
            "text": "Multi-Frames v1.1.10 by LTS, Inc.",
            "show_python_version": True,
            "links": []  # List of {"label": "...", "url": "..."}
        },
        "custom_css": ""
    },
    "network": {
        "mode": "dhcp",  # dhcp or static
        "interface": "eth0",
        "ip_address": "",
        "subnet_mask": "24",
        "gateway": "",
        "dns_primary": "8.8.8.8",
        "dns_secondary": "8.8.4.4",
        "mdns": {
            "enabled": False,
            "hostname": "multi-frames",  # Will be accessible as hostname.local
            "service_name": "iFrame Dashboard"  # Friendly name for service discovery
        }
    },
    "widgets": [],  # Dashboard widgets
    "fallback_image": {
        "enabled": False,
        "image": None,  # Base64 encoded
        "image_mime": None,
        "text": "Content Unavailable"
    }
}

# Maximum logo file size (500KB)
MAX_LOGO_SIZE = 500 * 1024
# Maximum background image size (2MB)
MAX_BG_SIZE = 2 * 1024 * 1024
# Maximum fallback image size (500KB)
MAX_FALLBACK_SIZE = 500 * 1024
ALLOWED_IMAGE_TYPES = {
    'image/png': 'png',
    'image/jpeg': 'jpg', 
    'image/gif': 'gif',
    'image/svg+xml': 'svg',
    'image/x-icon': 'ico',
    'image/webp': 'webp'
}

# =============================================================================
# mDNS Service Functions
# =============================================================================

class MDNSService:
    """Manages mDNS service registration for local network discovery."""
    
    def __init__(self):
        self.zeroconf = None
        self.service_info = None
        self.running = False
    
    def get_local_ip(self):
        """Get the local IP address of this machine."""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def start(self, hostname, service_name, port):
        """Start the mDNS service."""
        if not ZEROCONF_AVAILABLE:
            print("[mDNS] zeroconf library not installed. Run: pip install zeroconf")
            return False
        
        if self.running:
            self.stop()
        
        try:
            local_ip = self.get_local_ip()
            
            # Sanitize hostname (only alphanumeric and hyphens)
            hostname = re.sub(r'[^a-zA-Z0-9-]', '-', hostname).strip('-').lower()
            if not hostname:
                hostname = "multi-frames"
            
            # Create service info for HTTP service
            self.service_info = ServiceInfo(
                "_http._tcp.local.",
                f"{service_name}._http._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=port,
                properties={
                    'path': '/',
                    'version': '1.0',
                    'server': 'Multi-Frames'
                },
                server=f"{hostname}.local."
            )
            
            self.zeroconf = Zeroconf()
            self.zeroconf.register_service(self.service_info)
            self.running = True
            print(f"[mDNS] Service registered: http://{hostname}.local:{port}")
            print(f"[mDNS] Service name: {service_name}")
            print(f"[mDNS] Local IP: {local_ip}")
            return True
            
        except Exception as e:
            print(f"[mDNS] Failed to start: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop the mDNS service."""
        if self.zeroconf and self.service_info:
            try:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()
                print("[mDNS] Service unregistered")
            except Exception as e:
                print(f"[mDNS] Error stopping: {e}")
        
        self.zeroconf = None
        self.service_info = None
        self.running = False
    
    def restart(self, hostname, service_name, port):
        """Restart the mDNS service with new settings."""
        self.stop()
        return self.start(hostname, service_name, port)


def start_mdns_service(config, port):
    """Start mDNS service based on config."""
    global mdns_service
    
    mdns_config = config.get("network", {}).get("mdns", {})
    if not mdns_config.get("enabled", False):
        if mdns_service:
            mdns_service.stop()
        return
    
    if not mdns_service:
        mdns_service = MDNSService()
    
    hostname = mdns_config.get("hostname", "multi-frames")
    service_name = mdns_config.get("service_name", "iFrame Dashboard")
    mdns_service.start(hostname, service_name, port)


def stop_mdns_service():
    """Stop mDNS service."""
    global mdns_service
    if mdns_service:
        mdns_service.stop()


# =============================================================================
# Network Configuration Functions (Cross-Platform)
# =============================================================================

import platform
import subprocess

PLATFORM = platform.system().lower()  # 'linux', 'darwin' (macOS), 'windows'

def get_network_interfaces():
    """Get list of available network interfaces (cross-platform)."""
    interfaces = []
    
    try:
        if PLATFORM == 'windows':
            # Windows: Use netsh to get interfaces
            result = subprocess.run(
                ['netsh', 'interface', 'show', 'interface'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[3:]:  # Skip header lines
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = ' '.join(parts[3:])  # Interface name might have spaces
                        if iface_name and 'Loopback' not in iface_name:
                            interfaces.append(iface_name)
            if not interfaces:
                interfaces = ['Ethernet', 'Wi-Fi', 'Ethernet 2']
                
        elif PLATFORM == 'darwin':  # macOS
            # macOS: Use networksetup to list services
            result = subprocess.run(
                ['networksetup', '-listallnetworkservices'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    line = line.strip()
                    if line and not line.startswith('*'):
                        interfaces.append(line)
            if not interfaces:
                interfaces = ['Ethernet', 'Wi-Fi', 'Thunderbolt Ethernet']
                
        else:  # Linux
            net_path = "/sys/class/net"
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    if iface != 'lo':
                        interfaces.append(iface)
            if not interfaces:
                interfaces = ['eth0', 'ens33', 'enp0s3']
                
    except Exception:
        if PLATFORM == 'windows':
            interfaces = ['Ethernet', 'Wi-Fi']
        elif PLATFORM == 'darwin':
            interfaces = ['Ethernet', 'Wi-Fi']
        else:
            interfaces = ['eth0']
    
    return sorted(interfaces) if interfaces else ['eth0']

def get_current_network_info():
    """Get current network configuration (cross-platform)."""
    info = {
        'interfaces': get_network_interfaces(),
        'current_ip': 'Unknown',
        'current_gateway': 'Unknown',
        'current_dns': [],
        'config_method': PLATFORM,
        'platform': PLATFORM
    }
    
    try:
        if PLATFORM == 'windows':
            # Get IP configuration
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'IPv4 Address' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            info['current_ip'] = parts[1].strip()
                            break
                    elif 'IP Address' in line and 'IPv6' not in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if ip and not ip.startswith('127.'):
                                info['current_ip'] = ip
                                break
                
                for line in lines:
                    if 'Default Gateway' in line:
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1].strip():
                            info['current_gateway'] = parts[1].strip()
                            break
            
            # Get DNS
            result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'dns'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    # Look for IP addresses in DNS output
                    if line and line[0].isdigit():
                        parts = line.split()
                        if parts and validate_ip_address(parts[0]):
                            if parts[0] not in info['current_dns']:
                                info['current_dns'].append(parts[0])
                                
        elif PLATFORM == 'darwin':  # macOS
            # Get IP using ifconfig
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            info['current_ip'] = parts[1]
                            break
            
            # Get gateway
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            info['current_gateway'] = parts[1].strip()
                            break
            
            # Get DNS from scutil
            result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            dns = parts[1].strip()
                            if dns and dns not in info['current_dns']:
                                info['current_dns'].append(dns)
                                
        else:  # Linux
            # Get IP
            result = subprocess.run(['ip', '-4', 'addr', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            info['current_ip'] = parts[1]
                            break
            
            # Get gateway
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if 'via' in parts:
                    idx = parts.index('via')
                    if idx + 1 < len(parts):
                        info['current_gateway'] = parts[idx + 1]
            
            # Get DNS
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.strip().startswith('nameserver'):
                            dns = line.strip().split()[1]
                            if dns not in info['current_dns']:
                                info['current_dns'].append(dns)
            
            # Detect config method - check dhcpcd first (Raspberry Pi OS)
            if os.path.exists('/etc/dhcpcd.conf'):
                info['config_method'] = 'dhcpcd'
            elif os.path.exists('/etc/netplan'):
                info['config_method'] = 'netplan'
            elif os.path.exists('/etc/network/interfaces'):
                info['config_method'] = 'interfaces'
            elif os.path.exists('/etc/NetworkManager'):
                info['config_method'] = 'networkmanager'
                
    except Exception as e:
        info['error'] = str(e)
    
    return info

def validate_ip_address(ip):
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_subnet_mask(mask):
    """Validate subnet mask (CIDR notation, 1-32)."""
    try:
        mask_int = int(mask)
        return 1 <= mask_int <= 32
    except ValueError:
        return False

def cidr_to_netmask(cidr):
    """Convert CIDR notation to dotted decimal netmask."""
    netmask_map = {
        '8': '255.0.0.0', '9': '255.128.0.0', '10': '255.192.0.0',
        '11': '255.224.0.0', '12': '255.240.0.0', '13': '255.248.0.0',
        '14': '255.252.0.0', '15': '255.254.0.0', '16': '255.255.0.0',
        '17': '255.255.128.0', '18': '255.255.192.0', '19': '255.255.224.0',
        '20': '255.255.240.0', '21': '255.255.248.0', '22': '255.255.252.0',
        '23': '255.255.254.0', '24': '255.255.255.0', '25': '255.255.255.128',
        '26': '255.255.255.192', '27': '255.255.255.224', '28': '255.255.255.240',
        '29': '255.255.255.248', '30': '255.255.255.252', '31': '255.255.255.254',
        '32': '255.255.255.255'
    }
    return netmask_map.get(str(cidr), '255.255.255.0')

def generate_netplan_config(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Generate netplan YAML configuration."""
    if mode == 'dhcp':
        config = f"""# Generated by Multi-Frames
network:
  version: 2
  renderer: networkd
  ethernets:
    {interface}:
      dhcp4: true
"""
    else:
        dns_list = []
        if dns_primary:
            dns_list.append(dns_primary)
        if dns_secondary:
            dns_list.append(dns_secondary)
        dns_str = ', '.join(dns_list) if dns_list else '8.8.8.8'
        
        config = f"""# Generated by Multi-Frames
network:
  version: 2
  renderer: networkd
  ethernets:
    {interface}:
      dhcp4: false
      addresses:
        - {ip_addr}/{subnet}
      routes:
        - to: default
          via: {gateway}
      nameservers:
        addresses: [{dns_str}]
"""
    return config

def generate_interfaces_config(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Generate /etc/network/interfaces configuration."""
    netmask = cidr_to_netmask(subnet)
    
    if mode == 'dhcp':
        config = f"""# Generated by Multi-Frames
auto lo
iface lo inet loopback

auto {interface}
iface {interface} inet dhcp
"""
    else:
        dns_line = ""
        if dns_primary:
            dns_line = f"    dns-nameservers {dns_primary}"
            if dns_secondary:
                dns_line += f" {dns_secondary}"
        
        config = f"""# Generated by Multi-Frames
auto lo
iface lo inet loopback

auto {interface}
iface {interface} inet static
    address {ip_addr}
    netmask {netmask}
    gateway {gateway}
{dns_line}
"""
    return config

def apply_network_windows(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Apply network configuration on Windows using netsh."""
    try:
        if mode == 'dhcp':
            # Set interface to DHCP
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'set', 'address', interface, 'dhcp'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return False, f"Failed to set DHCP: {result.stderr}"
            
            # Set DNS to DHCP
            subprocess.run(
                ['netsh', 'interface', 'ip', 'set', 'dns', interface, 'dhcp'],
                capture_output=True, text=True, timeout=30
            )
            
            return True, "Network set to DHCP. Changes may take a moment to apply."
        else:
            # Set static IP
            netmask = cidr_to_netmask(subnet)
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'set', 'address', interface, 'static', ip_addr, netmask, gateway],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return False, f"Failed to set static IP: {result.stderr}"
            
            # Set primary DNS
            if dns_primary:
                subprocess.run(
                    ['netsh', 'interface', 'ip', 'set', 'dns', interface, 'static', dns_primary],
                    capture_output=True, text=True, timeout=30
                )
            
            # Add secondary DNS
            if dns_secondary:
                subprocess.run(
                    ['netsh', 'interface', 'ip', 'add', 'dns', interface, dns_secondary, 'index=2'],
                    capture_output=True, text=True, timeout=30
                )
            
            return True, "Static IP configured. Changes may take a moment to apply."
            
    except subprocess.TimeoutExpired:
        return False, "Network configuration timed out."
    except Exception as e:
        return False, f"Error: {str(e)}"

def apply_network_macos(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Apply network configuration on macOS using networksetup."""
    try:
        if mode == 'dhcp':
            # Set to DHCP
            result = subprocess.run(
                ['networksetup', '-setdhcp', interface],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return False, f"Failed to set DHCP: {result.stderr}"
            
            return True, "Network set to DHCP. Changes may take a moment to apply."
        else:
            # Set static IP (networksetup uses dotted netmask)
            netmask = cidr_to_netmask(subnet)
            result = subprocess.run(
                ['networksetup', '-setmanual', interface, ip_addr, netmask, gateway],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return False, f"Failed to set static IP: {result.stderr}"
            
            # Set DNS servers
            dns_servers = []
            if dns_primary:
                dns_servers.append(dns_primary)
            if dns_secondary:
                dns_servers.append(dns_secondary)
            
            if dns_servers:
                result = subprocess.run(
                    ['networksetup', '-setdnsservers', interface] + dns_servers,
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    return False, f"IP set but DNS failed: {result.stderr}"
            
            return True, "Static IP configured. Changes may take a moment to apply."
            
    except subprocess.TimeoutExpired:
        return False, "Network configuration timed out."
    except Exception as e:
        return False, f"Error: {str(e)}"

def apply_network_linux(interface, mode, ip_addr=None, subnet=None, gateway=None, dns_primary=None, dns_secondary=None):
    """Apply network configuration on Linux (including Raspberry Pi)."""
    net_info = get_current_network_info()
    config_method = net_info.get('config_method', 'unknown')
    
    # Check if this is a Raspberry Pi and use dhcpcd if available
    pi_info = get_raspberry_pi_info()
    if pi_info and pi_info.get('network_config') == 'dhcpcd':
        return apply_pi_network_dhcpcd(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
    
    try:
        if config_method == 'netplan':
            netplan_dir = '/etc/netplan'
            config_file = f'{netplan_dir}/01-multi-frames.yaml'
            
            netplan_config = generate_netplan_config(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
            
            with open(config_file, 'w') as f:
                f.write(netplan_config)
            
            result = subprocess.run(['netplan', 'apply'], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return False, f"Netplan apply failed: {result.stderr}"
            
            return True, "Network configured via netplan."
        
        elif config_method == 'dhcpcd':
            # Fallback: use dhcpcd directly
            return apply_pi_network_dhcpcd(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
            
        elif config_method == 'interfaces':
            config_file = '/etc/network/interfaces'
            backup_file = '/etc/network/interfaces.backup'
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    with open(backup_file, 'w') as bf:
                        bf.write(f.read())
            
            interfaces_config = generate_interfaces_config(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
            
            with open(config_file, 'w') as f:
                f.write(interfaces_config)
            
            subprocess.run(['ifdown', interface], capture_output=True, timeout=10)
            result = subprocess.run(['ifup', interface], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                if os.path.exists(backup_file):
                    with open(backup_file, 'r') as bf:
                        with open(config_file, 'w') as f:
                            f.write(bf.read())
                    subprocess.run(['ifup', interface], capture_output=True, timeout=30)
                return False, f"Failed: {result.stderr}. Backup restored."
            
            return True, "Network configured via interfaces."
            
        else:
            return False, f"Unsupported config method: {config_method}"
            
    except subprocess.TimeoutExpired:
        return False, "Network configuration timed out."
    except Exception as e:
        return False, f"Error: {str(e)}"

def check_admin_privileges():
    """Check if running with admin/root privileges."""
    if PLATFORM == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def apply_network_config(config, network_settings):
    """Apply network configuration (cross-platform). Returns (success, message)."""
    interface = network_settings.get('interface', 'eth0')
    mode = network_settings.get('mode', 'dhcp')
    ip_addr = network_settings.get('ip_address', '')
    subnet = network_settings.get('subnet_mask', '24')
    gateway = network_settings.get('gateway', '')
    dns_primary = network_settings.get('dns_primary', '8.8.8.8')
    dns_secondary = network_settings.get('dns_secondary', '')
    
    # Check for admin privileges
    if not check_admin_privileges():
        if PLATFORM == 'windows':
            return False, "Network changes require Administrator privileges. Run as Administrator."
        else:
            return False, "Network changes require root privileges. Run with sudo."
    
    if PLATFORM == 'windows':
        return apply_network_windows(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
    elif PLATFORM == 'darwin':
        return apply_network_macos(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)
    else:
        return apply_network_linux(interface, mode, ip_addr, subnet, gateway, dns_primary, dns_secondary)

# In-memory session storage
sessions = {}

# Login rate limiting
failed_login_attempts = {}  # IP -> {'count': int, 'lockout_until': datetime}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

def check_login_allowed(client_ip):
    """Check if login attempts are allowed from this IP."""
    if client_ip not in failed_login_attempts:
        return True, None
    
    attempt_data = failed_login_attempts[client_ip]
    lockout_until = attempt_data.get('lockout_until')
    
    if lockout_until and datetime.now() < lockout_until:
        remaining = (lockout_until - datetime.now()).seconds // 60 + 1
        return False, f"Too many failed attempts. Try again in {remaining} minute(s)."
    
    # Lockout expired, reset
    if lockout_until and datetime.now() >= lockout_until:
        del failed_login_attempts[client_ip]
    
    return True, None

def record_failed_login(client_ip):
    """Record a failed login attempt."""
    if client_ip not in failed_login_attempts:
        failed_login_attempts[client_ip] = {'count': 0, 'lockout_until': None}
    
    failed_login_attempts[client_ip]['count'] += 1
    
    if failed_login_attempts[client_ip]['count'] >= MAX_LOGIN_ATTEMPTS:
        failed_login_attempts[client_ip]['lockout_until'] = datetime.now() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        server_logger.warning(f"IP {client_ip} locked out after {MAX_LOGIN_ATTEMPTS} failed login attempts")

def clear_failed_logins(client_ip):
    """Clear failed login attempts after successful login."""
    if client_ip in failed_login_attempts:
        del failed_login_attempts[client_ip]

# =============================================================================
# Utility Functions
# =============================================================================

def load_config():
    """Load configuration from JSON file or create default."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()

def save_config(config):
    """
    Save configuration to JSON file.
    Returns tuple: (success: bool, error_message: str or None)
    For backward compatibility, also works if return value is ignored.
    """
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True, None
    except PermissionError:
        error_msg = f"Permission denied: Cannot write to '{CONFIG_FILE}'. Check file permissions or run: chmod 666 {CONFIG_FILE}"
        server_logger.error(error_msg)
        return False, error_msg
    except IOError as e:
        error_msg = f"IO Error saving config: {str(e)}"
        server_logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error saving config: {str(e)}"
        server_logger.error(error_msg)
        return False, error_msg

def save_config_safe(config):
    """
    Save configuration, returning error message or None on success.
    Use this when you want to show error to user.
    """
    success, error = save_config(config)
    return error

def check_config_writable():
    """Check if config file is writable."""
    try:
        # If file exists, check if we can write to it
        if os.path.exists(CONFIG_FILE):
            return os.access(CONFIG_FILE, os.W_OK)
        # If file doesn't exist, check if directory is writable
        config_dir = os.path.dirname(CONFIG_FILE) or '.'
        return os.access(config_dir, os.W_OK)
    except Exception:
        return False

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(username):
    """Create a new session for a user."""
    session_id = secrets.token_hex(32)
    sessions[session_id] = {
        "username": username,
        "expires": datetime.now() + timedelta(hours=SESSION_TIMEOUT_HOURS)
    }
    return session_id

def get_session(session_id):
    """Get session data if valid."""
    if session_id in sessions:
        session = sessions[session_id]
        if datetime.now() < session["expires"]:
            return session
        del sessions[session_id]
    return None

def validate_local_ip(url):
    """Validate that a URL points to a local/private IP address."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Allow localhost
        if hostname in ('localhost', '127.0.0.1', '::1'):
            return True
        
        # Check if it's a private IP
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback
        except ValueError:
            # It's a hostname - only allow localhost variants
            return hostname.endswith('.local') or hostname.endswith('.lan')
    except Exception:
        return False


def send_network_command(protocol, host, port, command, timeout=5):
    """
    Send a command to a remote device via TCP, UDP, or Telnet.
    Also supports 'dummy' protocol for UI testing (no actual network call).
    
    Returns dict with 'success' bool and 'response' or 'error' string.
    """
    import socket
    import time
    
    result = {'success': False, 'response': '', 'error': ''}
    
    try:
        if protocol == 'dummy':
            # Dummy - simulate success after brief delay (for UI testing)
            time.sleep(0.3)  # Simulate network latency
            result['success'] = True
            result['response'] = f'[DUMMY] Command simulated: {command}'
            
        elif protocol == 'dummy_fail':
            # Dummy fail - simulate failure (for UI testing)
            time.sleep(0.3)
            result['success'] = False
            result['error'] = '[DUMMY] Simulated connection failure'
            
        elif protocol == 'dummy_random':
            # Dummy random - 70% success, 30% fail (for UI testing)
            import random
            time.sleep(0.3)
            if random.random() < 0.7:
                result['success'] = True
                result['response'] = f'[DUMMY] Random success: {command}'
            else:
                result['success'] = False
                result['error'] = '[DUMMY] Random failure'
        
        elif protocol == 'udp':
            # UDP - fire and forget (no response expected)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(command.encode('utf-8'), (host, port))
            sock.close()
            result['success'] = True
            result['response'] = 'UDP packet sent'
            
        elif protocol == 'tcp':
            # TCP - send and optionally receive response
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send command (add newline if not present for many protocols)
            cmd_to_send = command if command.endswith('\n') or command.endswith('\r\n') else command + '\r\n'
            sock.sendall(cmd_to_send.encode('utf-8'))
            
            # Try to receive response (non-blocking after short delay)
            try:
                sock.settimeout(1)
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                result['response'] = response.strip()
            except socket.timeout:
                result['response'] = 'Command sent (no response)'
            
            sock.close()
            result['success'] = True
            
        elif protocol == 'telnet':
            # Telnet - use telnetlib for proper telnet protocol handling
            try:
                import telnetlib
                tn = telnetlib.Telnet(host, port, timeout=timeout)
                
                # Send command
                cmd_to_send = command if command.endswith('\n') else command + '\n'
                tn.write(cmd_to_send.encode('utf-8'))
                
                # Read response with short timeout
                try:
                    response = tn.read_until(b'\n', timeout=2).decode('utf-8', errors='ignore')
                    result['response'] = response.strip()
                except:
                    result['response'] = 'Command sent'
                
                tn.close()
                result['success'] = True
            except ImportError:
                # telnetlib removed in Python 3.13+, fall back to raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                
                # Read initial telnet negotiation (if any)
                try:
                    sock.settimeout(0.5)
                    sock.recv(1024)  # Discard telnet negotiation
                except:
                    pass
                
                cmd_to_send = command if command.endswith('\n') else command + '\n'
                sock.sendall(cmd_to_send.encode('utf-8'))
                
                try:
                    sock.settimeout(1)
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    result['response'] = response.strip()
                except socket.timeout:
                    result['response'] = 'Command sent'
                
                sock.close()
                result['success'] = True
        else:
            result['error'] = f'Unknown protocol: {protocol}'
            
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except socket.gaierror as e:
        result['error'] = f'DNS/hostname error: {str(e)}'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except OSError as e:
        result['error'] = f'Network error: {str(e)}'
    except Exception as e:
        result['error'] = f'Error: {str(e)}'
    
    return result


def escape_html(text):
    """Escape HTML special characters."""
    if text is None:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def parse_multipart(content_type, body):
    """Parse multipart/form-data for file uploads."""
    result = {'fields': {}, 'files': {}}
    
    # Extract boundary from content-type
    boundary = None
    for part in content_type.split(';'):
        part = part.strip()
        if part.startswith('boundary='):
            boundary = part[9:].strip('"')
            break
    
    if not boundary:
        return result
    
    # Split body by boundary
    boundary_bytes = ('--' + boundary).encode()
    parts = body.split(boundary_bytes)
    
    for part in parts[1:]:  # Skip first empty part
        if part.startswith(b'--') or part.strip() == b'':
            continue
        
        # Split headers from content
        try:
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                continue
            
            headers_raw = part[:header_end].decode('utf-8', errors='ignore')
            content = part[header_end + 4:]
            
            # Remove trailing \r\n
            if content.endswith(b'\r\n'):
                content = content[:-2]
            
            # Parse headers
            headers = {}
            for line in headers_raw.split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Parse Content-Disposition
            disposition = headers.get('content-disposition', '')
            name = None
            filename = None
            
            for item in disposition.split(';'):
                item = item.strip()
                if item.startswith('name='):
                    name = item[5:].strip('"')
                elif item.startswith('filename='):
                    filename = item[9:].strip('"')
            
            if name:
                if filename:
                    # It's a file
                    content_type_header = headers.get('content-type', 'application/octet-stream')
                    result['files'][name] = {
                        'filename': filename,
                        'content_type': content_type_header,
                        'data': content
                    }
                else:
                    # It's a regular field
                    result['fields'][name] = content.decode('utf-8', errors='ignore')
        except Exception:
            continue
    
    return result

# =============================================================================
# HTML Templates
# =============================================================================

CSS_STYLES = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    line-height: 1.5;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1.5rem;
}

/* Header */
header {
    background: var(--header-bg, var(--bg-secondary));
    border-bottom: 1px solid var(--border);
    padding: 1rem 0;
    z-index: 100;
}

header.sticky { position: sticky; top: 0; }

header .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 0;
    padding-bottom: 0;
}

.logo {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--header-text, var(--text-primary));
    letter-spacing: -0.5px;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}

.logo img {
    height: 32px;
    width: auto;
    max-width: 120px;
    object-fit: contain;
}

.logo span { color: var(--accent); }

.header-subtitle {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-left: 1rem;
    padding-left: 1rem;
    border-left: 1px solid var(--border);
}

nav { display: flex; gap: 1rem; align-items: center; }
nav a, nav span {
    font-size: 0.85rem;
    color: var(--text-secondary);
    padding: 0.4rem 0.8rem;
    border-radius: var(--radius);
    transition: all 0.15s;
}
nav a:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
    text-decoration: none;
}

/* Forms */
.card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 2rem;
    max-width: 400px;
    margin: 4rem auto;
}

.card h2 {
    font-size: 1.2rem;
    margin-bottom: 1.5rem;
    font-weight: 500;
}

.form-group { margin-bottom: 1rem; }

label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-bottom: 0.4rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

input, select, textarea {
    width: 100%;
    padding: 0.7rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 0.9rem;
}

input[type="color"] {
    padding: 0.2rem;
    height: 40px;
    cursor: pointer;
}

textarea {
    min-height: 80px;
    resize: vertical;
}

input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--accent);
}

button, .btn {
    display: inline-block;
    padding: 0.7rem 1.2rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: var(--radius);
    font-family: inherit;
    font-size: 0.85rem;
    cursor: pointer;
    transition: background 0.15s;
}

button:hover, .btn:hover {
    background: var(--accent-hover);
    text-decoration: none;
}

.btn-secondary {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
}
.btn-secondary:hover { background: var(--border); }

.btn-danger { background: var(--danger); }
.btn-danger:hover { background: #dc2626; }

.btn-sm { padding: 0.4rem 0.8rem; font-size: 0.8rem; }

/* Messages */
.message {
    padding: 0.8rem 1rem;
    border-radius: var(--radius);
    margin-bottom: 1rem;
    font-size: 0.85rem;
}
.message.error { background: rgba(239,68,68,0.15); border: 1px solid var(--danger); }
.message.success { background: rgba(34,197,94,0.15); border: 1px solid var(--success); }

/* iFrame Grid */
.iframe-grid {
    display: grid;
    gap: 1rem;
    grid-template-columns: repeat(var(--cols, 2), 1fr);
}

@media (max-width: 900px) { .iframe-grid { grid-template-columns: 1fr; } }

.iframe-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}

.iframe-card h3 {
    padding: 0.8rem 1rem;
    font-size: 0.85rem;
    font-weight: 500;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.iframe-card h3 .title-left {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.iframe-card h3 span {
    color: var(--text-secondary);
    font-weight: 400;
    font-size: 0.75rem;
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #888;
    flex-shrink: 0;
    transition: background 0.3s;
}

.status-dot.loading {
    background: #f59e0b;
    animation: pulse 1s ease-in-out infinite;
}

.status-dot.connected {
    background: #22c55e;
}

.status-dot.error {
    background: #ef4444;
}

.status-dot.warning {
    background: #f59e0b;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.iframe-card iframe {
    width: 100%;
    height: 400px;
    border: none;
    background: var(--bg-primary);
}

.iframe-wrapper {
    overflow: hidden;
    position: relative;
}

.iframe-wrapper iframe {
    border: none;
    background: var(--bg-primary);
}

.embed-container {
    width: 100%;
    background: var(--bg-primary);
}

.embed-container iframe {
    max-width: 100%;
    border: none;
}

/* Admin Panel */
.admin-tabs {
    display: flex;
    gap: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1.5rem;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
}

.admin-tab {
    padding: 1rem 1.5rem;
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-family: inherit;
    font-size: 0.85rem;
    font-weight: 500;
    white-space: nowrap;
    transition: all 0.15s;
    border-bottom: 2px solid transparent;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.admin-tab:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
}

.admin-tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    background: var(--bg-tertiary);
}

.admin-tab-icon {
    font-size: 1rem;
}

.tab-panel {
    display: none;
}

.tab-panel.active {
    display: block;
}

.admin-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1.5rem;
}

.admin-section h3 {
    padding: 1rem 1.5rem;
    font-size: 0.9rem;
    font-weight: 500;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border);
}

.admin-content { padding: 1.5rem; }

.admin-subsection {
    margin-bottom: 1.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
}

.admin-subsection:last-child {
    margin-bottom: 0;
    padding-bottom: 0;
    border-bottom: none;
}

.admin-subsection h4 {
    font-size: 0.85rem;
    margin-bottom: 1rem;
    color: var(--text-secondary);
    font-weight: 500;
}

.item-list { list-style: none; }

.item-list li {
    padding: 0.8rem 0;
    border-bottom: 1px solid var(--border);
}

.item-list li:last-child { border-bottom: none; }

.item-list .item-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.item-order {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-right: 1rem;
}

.btn-icon {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    width: 24px;
    height: 20px;
    padding: 0;
    font-size: 0.7rem;
    cursor: pointer;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
}

.btn-icon:hover:not(:disabled) {
    background: var(--accent);
    color: white;
    border-color: var(--accent);
}

.item-info { flex: 1; }
.item-info strong { font-weight: 500; }
.item-info small { color: var(--text-secondary); display: block; font-size: 0.8rem; }

.item-actions { display: flex; gap: 0.5rem; }

.edit-panel {
    margin-top: 1rem;
    padding: 1rem;
    background: var(--bg-primary);
    border-radius: var(--radius);
    border: 1px solid var(--border);
}

.edit-panel .inline-form {
    margin: 0;
}

.edit-section {
    margin-bottom: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
}

.edit-section:last-of-type {
    border-bottom: none;
    margin-bottom: 0;
    padding-bottom: 0;
}

.edit-section h5 {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-bottom: 0.8rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.inline-form { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; }
.inline-form .form-group { margin-bottom: 0; flex: 1; min-width: 150px; }

.color-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 0.8rem;
}

.color-grid .form-group { min-width: 0; }

.empty-state {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
}

/* Details/Summary styling */
details summary {
    list-style: none;
    user-select: none;
}

details summary::-webkit-details-marker {
    display: none;
}

details[open] summary {
    margin-bottom: 0.5rem;
}

/* Preview box */
.preview-box {
    padding: 1rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1rem;
}

.preview-box img {
    max-height: 60px;
    max-width: 200px;
    object-fit: contain;
}

/* Toggle switch */
.toggle-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.6rem 0;
}

.toggle-row label {
    margin-bottom: 0;
    text-transform: none;
    font-size: 0.9rem;
    color: var(--text-primary);
}

/* Status indicator */
.status {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 0.5rem;
}
.status.online { background: var(--success); }
.status.offline { background: var(--danger); }

/* Background overlay for images */
.bg-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
    pointer-events: none;
}

footer {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
    font-size: 0.75rem;
}

footer a {
    color: var(--accent);
    text-decoration: none;
    transition: opacity 0.15s;
}

footer a:hover {
    opacity: 0.8;
    text-decoration: underline;
}

/* Tabs */
.tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1.5rem;
}

.tab {
    padding: 0.8rem 1.2rem;
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
}

.tab:hover { color: var(--text-primary); }
.tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
}

/* ==========================================================================
   MOBILE OPTIMIZATIONS
   ========================================================================== */

/* Safe area insets for notched phones */
@supports (padding: max(0px)) {
    body {
        padding-left: max(0px, env(safe-area-inset-left));
        padding-right: max(0px, env(safe-area-inset-right));
    }
    header {
        padding-left: max(1rem, env(safe-area-inset-left));
        padding-right: max(1rem, env(safe-area-inset-right));
    }
    footer {
        padding-bottom: max(2rem, env(safe-area-inset-bottom));
    }
}

/* Touch-friendly improvements */
@media (hover: none) and (pointer: coarse) {
    /* Larger touch targets */
    .btn, button {
        min-height: 44px;
        min-width: 44px;
    }
    
    .btn-sm {
        min-height: 36px;
        padding: 0.5rem 1rem;
    }
    
    .btn-icon {
        width: 36px;
        height: 36px;
        font-size: 0.9rem;
    }
    
    input, select, textarea {
        min-height: 44px;
        font-size: 16px; /* Prevents zoom on iOS */
    }
    
    input[type="checkbox"], input[type="radio"] {
        width: 22px;
        height: 22px;
        min-height: 22px;
    }
    
    /* Prevent text selection on buttons */
    button, .btn {
        -webkit-user-select: none;
        user-select: none;
        -webkit-tap-highlight-color: transparent;
    }
    
    /* Active states for touch feedback */
    button:active, .btn:active {
        transform: scale(0.97);
        opacity: 0.9;
    }
    
    /* Larger clickable areas for links in nav */
    nav a {
        padding: 0.6rem 0.8rem;
        min-height: 44px;
        display: inline-flex;
        align-items: center;
    }
}

/* Mobile breakpoint styles */
@media (max-width: 768px) {
    /* Base font size adjustment */
    html {
        font-size: 15px;
    }
    
    /* Container padding */
    .container {
        padding: 0 1rem;
    }
    
    /* Header improvements */
    header .container {
        padding: 0.75rem 1rem;
    }
    
    header .logo {
        font-size: 1rem;
        gap: 0.5rem;
    }
    
    header .logo img {
        max-height: 28px;
    }
    
    header nav {
        gap: 0.25rem;
    }
    
    header nav a {
        padding: 0.5rem 0.6rem;
        font-size: 0.8rem;
    }
    
    /* Cards and sections */
    .card {
        padding: 1.5rem;
        margin: 2rem auto;
    }
    
    .admin-section h3 {
        padding: 0.875rem 1rem;
        font-size: 0.85rem;
    }
    
    .admin-content {
        padding: 1rem;
    }
    
    /* Admin tabs - horizontal scroll with indicators */
    .admin-tabs {
        position: relative;
        margin-bottom: 1rem;
    }
    
    .admin-tabs::after {
        content: '';
        position: absolute;
        right: 0;
        top: 0;
        bottom: 0;
        width: 30px;
        background: linear-gradient(to right, transparent, var(--bg-secondary));
        pointer-events: none;
    }
    
    .admin-tab {
        padding: 0.875rem 1rem;
        font-size: 0.8rem;
    }
    
    .admin-tab-icon {
        font-size: 1.1rem;
    }
    
    /* Hide tab text on small screens, show icons */
    .admin-tab-text {
        display: none;
    }
    
    /* Form improvements */
    .form-group {
        margin-bottom: 1.25rem;
    }
    
    label {
        font-size: 0.75rem;
        margin-bottom: 0.5rem;
    }
    
    input, select, textarea {
        padding: 0.875rem;
        font-size: 16px;
    }
    
    .inline-form {
        flex-direction: column;
    }
    
    .inline-form .form-group {
        width: 100%;
        min-width: unset;
    }
    
    .inline-form button {
        width: 100%;
        margin-top: 0.5rem;
    }
    
    /* Color grid - 2 columns on mobile */
    .color-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 0.75rem;
    }
    
    /* Item list improvements */
    .item-list li {
        padding: 1rem 0;
    }
    
    .item-list .item-row {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.75rem;
    }
    
    .item-order {
        flex-direction: row;
        margin-right: 0;
        margin-bottom: 0.5rem;
    }
    
    .item-info {
        width: 100%;
    }
    
    .item-actions {
        width: 100%;
        justify-content: flex-start;
    }
    
    .item-actions .btn {
        flex: 1;
        text-align: center;
    }
    
    /* Button groups stack on mobile */
    .btn-group {
        flex-direction: column;
        width: 100%;
    }
    
    .btn-group .btn {
        width: 100%;
    }
    
    /* Tables become cards on mobile */
    .info-table {
        display: block;
    }
    
    .info-table tr {
        display: flex;
        flex-direction: column;
        padding: 0.75rem 0;
        border-bottom: 1px solid var(--border);
    }
    
    .info-table td:first-child {
        font-weight: 500;
        color: var(--text-secondary);
        font-size: 0.75rem;
        text-transform: uppercase;
        margin-bottom: 0.25rem;
    }
    
    /* Widget adjustments */
    .widgets-container {
        grid-template-columns: repeat(2, 1fr);
        gap: 0.75rem;
    }
    
    .widget {
        padding: 0.75rem;
    }
    
    .widget-clock {
        font-size: 1.5rem;
    }
    
    .widget-header {
        font-size: 0.65rem;
    }
    
    /* Command buttons grid */
    .cmd-btn-grid {
        grid-template-columns: repeat(2, 1fr) !important;
    }
    
    /* Footer */
    footer {
        padding: 1.5rem 1rem;
        font-size: 0.7rem;
    }
    
    /* Edit panel improvements */
    .edit-panel {
        padding: 0.875rem;
    }
    
    /* Messages */
    .message {
        padding: 0.75rem;
        font-size: 0.8rem;
    }
    
    /* Preview box */
    .preview-box {
        padding: 0.75rem;
    }
    
    .preview-box img {
        max-height: 50px;
    }
    
    /* Stats grid */
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

/* Extra small screens */
@media (max-width: 480px) {
    html {
        font-size: 14px;
    }
    
    .container {
        padding: 0 0.75rem;
    }
    
    header .logo span:not(:first-child) {
        display: none;
    }
    
    .card {
        padding: 1.25rem;
        margin: 1.5rem 0.5rem;
        border-radius: 0.5rem;
    }
    
    .widgets-container {
        grid-template-columns: 1fr;
    }
    
    .color-grid {
        grid-template-columns: 1fr;
    }
    
    /* Stack all form buttons */
    form button, form .btn {
        width: 100%;
    }
    
    /* Admin tabs - icon only */
    .admin-tab {
        padding: 0.75rem;
    }
    
    .admin-tab-icon {
        font-size: 1.2rem;
    }
}

/* Landscape phone */
@media (max-width: 900px) and (orientation: landscape) {
    .card {
        max-width: 500px;
    }
    
    .widgets-container {
        grid-template-columns: repeat(4, 1fr);
    }
}

/* Print styles */
@media print {
    header, footer, nav, .btn, button, form {
        display: none !important;
    }
    
    body {
        background: white;
        color: black;
    }
    
    .iframe-card {
        break-inside: avoid;
    }
}

/* Reduced motion preference */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}

/* Dark mode enhancements for OLED screens */
@media (prefers-color-scheme: dark) {
    .pure-black {
        --bg-primary: #000000;
        --bg-secondary: #0a0a0a;
    }
}
"""

def generate_dynamic_styles(config):
    """Generate CSS variables from config."""
    appearance = config.get("appearance", {})
    colors = appearance.get("colors", {})
    bg = appearance.get("background", {})
    header = appearance.get("header", {})
    
    # Default colors
    defaults = DEFAULT_CONFIG["appearance"]["colors"]
    
    css_vars = f"""
    :root {{
        --bg-primary: {colors.get('bg_primary', defaults['bg_primary'])};
        --bg-secondary: {colors.get('bg_secondary', defaults['bg_secondary'])};
        --bg-tertiary: {colors.get('bg_tertiary', defaults['bg_tertiary'])};
        --border: {colors.get('border', defaults['border'])};
        --text-primary: {colors.get('text_primary', defaults['text_primary'])};
        --text-secondary: {colors.get('text_secondary', defaults['text_secondary'])};
        --accent: {colors.get('accent', defaults['accent'])};
        --accent-hover: {colors.get('accent_hover', defaults['accent_hover'])};
        --danger: {colors.get('danger', defaults['danger'])};
        --success: {colors.get('success', defaults['success'])};
        --radius: 6px;
        --header-bg: {header.get('bg_color') or colors.get('bg_secondary', defaults['bg_secondary'])};
        --header-text: {header.get('text_color') or colors.get('text_primary', defaults['text_primary'])};
    }}
    """
    
    # Background styles
    bg_type = bg.get("type", "solid")
    if bg_type == "gradient":
        direction = bg.get("gradient_direction", "to bottom")
        start = bg.get("gradient_start", "#0a0a0b")
        end = bg.get("gradient_end", "#1a1a2e")
        css_vars += f"""
        body {{
            background: linear-gradient({direction}, {start}, {end});
            background-attachment: fixed;
        }}
        """
    elif bg_type == "image" and bg.get("image"):
        size = bg.get("image_size", "cover")
        opacity = bg.get("image_opacity", 100) / 100
        css_vars += f"""
        .bg-overlay {{
            background-image: url('data:{bg.get("image_mime", "image/png")};base64,{bg["image"]}');
            background-size: {size};
            background-position: center;
            background-repeat: {'repeat' if size == 'repeat' else 'no-repeat'};
            background-attachment: fixed;
            opacity: {opacity};
        }}
        """
    
    # Widget and Fallback CSS
    css_vars += """
    /* Widgets Container */
    .widgets-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .widget {
        padding: 1rem;
        border: 1px solid var(--border);
        overflow: hidden;
    }
    
    .widget-small { grid-column: span 1; }
    .widget-medium { grid-column: span 2; }
    .widget-large { grid-column: 1 / -1; }
    
    @media (max-width: 600px) {
        .widget-small, .widget-medium { grid-column: span 1; }
    }
    
    .widget-header {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.7;
        margin-bottom: 0.5rem;
    }
    
    .widget-body {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 60px;
    }
    
    .widget-clock {
        font-size: 2rem;
        font-weight: 600;
        font-family: monospace;
        letter-spacing: 0.05em;
    }
    
    .widget-date {
        font-size: 1.1rem;
        text-align: center;
    }
    
    .widget-countdown .countdown-label {
        font-size: 0.85rem;
        opacity: 0.8;
        margin-bottom: 0.5rem;
    }
    
    .widget-countdown .countdown-time {
        font-size: 1.5rem;
        font-weight: 600;
        font-family: monospace;
    }
    
    .widget-countdown .cd-num {
        font-size: 1.8rem;
    }
    
    .widget-countdown .cd-label {
        font-size: 0.9rem;
        opacity: 0.7;
        margin-right: 0.5rem;
    }
    
    .widget-image {
        max-width: 100%;
        max-height: 200px;
        object-fit: contain;
        border-radius: 4px;
    }
    
    .widget-weather {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .widget-weather .weather-icon {
        font-size: 2.5rem;
    }
    
    .widget-weather .weather-location {
        font-size: 0.9rem;
        opacity: 0.8;
    }
    
    .widget-weather .weather-temp {
        font-size: 1.5rem;
        font-weight: 600;
    }
    
    .widget-notes {
        font-size: 0.9rem;
        line-height: 1.5;
        text-align: left;
        width: 100%;
    }
    
    .widget-text {
        font-size: 0.95rem;
        line-height: 1.5;
        width: 100%;
    }
    
    .widget-placeholder {
        color: var(--text-secondary);
        font-style: italic;
    }
    
    /* Button Widget Styles */
    .widget-buttons {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        justify-content: center;
        width: 100%;
    }
    
    .cmd-button {
        padding: 0.6rem 1.2rem;
        border: none;
        border-radius: var(--radius);
        color: white;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s ease;
        font-size: 0.9rem;
        min-width: 80px;
    }
    
    .cmd-button:hover {
        filter: brightness(1.1);
        transform: translateY(-1px);
    }
    
    .cmd-button:active {
        transform: translateY(0);
    }
    
    .cmd-button:disabled {
        opacity: 0.7;
        cursor: wait;
    }
    
    .cmd-button.sending {
        animation: pulse 0.5s ease infinite;
    }
    
    .cmd-button.success {
        background: var(--success) !important;
    }
    
    .cmd-button.error {
        background: var(--danger) !important;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    
    /* Fallback Styles */
    .iframe-content-wrapper {
        position: relative;
    }
    
    .iframe-fallback {
        display: none;
        align-items: center;
        justify-content: center;
        background: var(--bg-tertiary);
        border-radius: var(--radius);
    }
    
    .fallback-content {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 1rem;
        padding: 2rem;
        text-align: center;
    }
    
    .fallback-content img {
        max-width: 80%;
        max-height: 60%;
        object-fit: contain;
        border-radius: var(--radius);
        opacity: 0.9;
    }
    
    .fallback-text {
        color: var(--text-secondary);
        font-size: 1rem;
    }
    """
    
    # Custom CSS
    custom_css = appearance.get("custom_css", "")
    if custom_css:
        css_vars += f"\n/* Custom CSS */\n{custom_css}\n"
    
    return css_vars

def render_page(title, content, user=None, config=None):
    """Render a full HTML page."""
    if config is None:
        config = load_config()
    
    appearance = config.get("appearance", {})
    header_cfg = appearance.get("header", {})
    footer_cfg = appearance.get("footer", {})
    bg_cfg = appearance.get("background", {})
    
    nav_items = ""
    if user:
        is_admin = config["users"].get(user, {}).get("is_admin", False)
        nav_items = ""
        if is_admin:
            nav_items += '<a href="/admin">Admin</a>'
        nav_items += '<a href="/help" title="Help & Diagnostics" style="width:28px;height:28px;padding:0;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;font-weight:600;">?</a>'
        nav_items += '<a href="/logout">Logout</a>'
    else:
        nav_items = '<a href="/login">Login</a>'
    
    # Build logo HTML
    branding = config.get("branding", {})
    logo_html = ""
    if branding.get("logo") and branding.get("logo_mime"):
        logo_html = f'<img src="data:{branding["logo_mime"]};base64,{branding["logo"]}" alt="Logo">'
    else:
        logo_html = '<span>◈</span>'
    
    # Build favicon HTML
    favicon_html = ""
    if branding.get("favicon") and branding.get("favicon_mime"):
        favicon_html = f'<link rel="icon" type="{branding["favicon_mime"]}" href="data:{branding["favicon_mime"]};base64,{branding["favicon"]}">'
    else:
        favicon_html = '<link rel="icon" href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'><text y=\'.9em\' font-size=\'90\'>◈</text></svg>">'
    
    # Build Apple Touch Icon HTML (for iOS "Add to Home Screen")
    apple_touch_icon_html = ""
    if branding.get("apple_touch_icon") and branding.get("apple_touch_icon_mime"):
        apple_touch_icon_html = f'<link rel="apple-touch-icon" href="data:{branding["apple_touch_icon_mime"]};base64,{branding["apple_touch_icon"]}">'
    
    # Header custom text
    header_subtitle = ""
    if header_cfg.get("custom_text"):
        header_subtitle = f'<span class="header-subtitle">{escape_html(header_cfg["custom_text"])}</span>'
    
    # Header HTML
    header_class = "sticky" if header_cfg.get("sticky", True) else ""
    header_html = ""
    if header_cfg.get("show", True):
        header_html = f"""
        <header class="{header_class}">
            <div class="container">
                <a href="/" class="logo">{logo_html} {escape_html(config['settings']['page_title'])}{header_subtitle}</a>
                <nav>{nav_items}</nav>
            </div>
        </header>
        """
    
    # Footer HTML
    footer_html = ""
    if footer_cfg.get("show", True):
        footer_text = escape_html(footer_cfg.get("text", "Multi-Frames v1.1.10 by LTS, Inc."))
        if footer_cfg.get("show_python_version", True):
            footer_text += f" • Python {'.'.join(map(str, __import__('sys').version_info[:2]))}"
        
        # Build footer links
        footer_links = footer_cfg.get("links", [])
        links_html = ""
        if footer_links:
            link_items = []
            for link in footer_links:
                label = escape_html(link.get("label", ""))
                url = escape_html(link.get("url", ""))
                if label and url:
                    link_items.append(f'<a href="{url}" target="_blank" rel="noopener">{label}</a>')
            if link_items:
                links_html = " • " + " • ".join(link_items)
        
        footer_html = f'<footer>{footer_text}{links_html}</footer>'
    
    # Background overlay (for image backgrounds)
    bg_overlay = ""
    if bg_cfg.get("type") == "image" and bg_cfg.get("image"):
        bg_overlay = '<div class="bg-overlay"></div>'
    
    # Generate dynamic styles
    dynamic_styles = generate_dynamic_styles(config)
    
    # Build browser tab title
    settings = config.get("settings", {})
    tab_title = settings.get("tab_title", "").strip()
    if not tab_title:
        tab_title = title  # Use page title if no custom tab title
    tab_suffix = settings.get("tab_suffix", "Multi-Frames")
    if tab_suffix:
        full_tab_title = f"{escape_html(tab_title)} | {escape_html(tab_suffix)}"
    else:
        full_tab_title = escape_html(tab_title)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>{full_tab_title}</title>
    {favicon_html}
    {apple_touch_icon_html}
    <style>{dynamic_styles}{CSS_STYLES}</style>
</head>
<body>
    {bg_overlay}
    {header_html}
    <main class="container">
        {content}
    </main>
    {footer_html}
</body>
</html>"""

def render_login_page(error=None, message=None):
    """Render the login page."""
    error_html = f'<div class="message error">{escape_html(error)}</div>' if error else ""
    message_html = f'<div class="message success">{escape_html(message)}</div>' if message else ""
    content = f"""
    <div class="card">
        <h2>Login</h2>
        {error_html}
        {message_html}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" style="width:100%;margin-top:0.5rem;">Login</button>
        </form>
        <div style="text-align:center;margin-top:1rem;">
            <a href="/forgot-password" style="color:var(--text-secondary);font-size:0.85rem;">Forgot Password?</a>
        </div>
    </div>
    """
    return render_page("Login", content)


def render_forgot_password_page(error=None, success=False):
    """Render the forgot password page."""
    if success:
        content = """
        <div class="card">
            <h2>Request Submitted</h2>
            <div class="message success">Your password reset request has been sent to the administrator.</div>
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-top:1rem;">
                Please contact your administrator to complete the password reset.
            </p>
            <a href="/login" style="display:block;text-align:center;margin-top:1.5rem;color:var(--accent);">← Back to Login</a>
        </div>
        """
    else:
        error_html = f'<div class="message error">{escape_html(error)}</div>' if error else ""
        content = f"""
        <div class="card">
            <h2>Forgot Password</h2>
            {error_html}
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">
                Enter your username to request a password reset. An administrator will need to approve your request.
            </p>
            <form method="POST" action="/forgot-password">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autocomplete="username">
                </div>
                <button type="submit" style="width:100%;margin-top:0.5rem;">Request Password Reset</button>
            </form>
            <a href="/login" style="display:block;text-align:center;margin-top:1rem;color:var(--text-secondary);font-size:0.85rem;">← Back to Login</a>
        </div>
        """
    return render_page("Forgot Password", content)


def render_help_page(user, config):
    """Render the help/diagnostics page for users."""
    
    # Build iFrame connectivity test list
    iframes = config.get('iframes', [])
    iframe_test_rows = ""

    for i, iframe in enumerate(iframes):
        name = escape_html(iframe.get('name', f'Frame {i+1}'))
        name_js_escaped = name.replace("'", "\\'")  # Escape for JS string
        url = iframe.get('url', '')
        url_escaped = escape_html(url).replace("'", "&#39;")
        enabled = iframe.get('enabled', True)

        if not enabled:
            continue  # Skip disabled iframes for user view
        
        if iframe.get('use_embed_code'):
            iframe_test_rows += f'''
            <tr>
                <td data-label=""><span class="status-dot connected">✓</span> <strong style="margin-left:0.5rem;">{name}</strong></td>
                <td data-label="Source" style="color:var(--text-secondary);font-size:0.85rem;">Embed Code</td>
                <td data-label="Time" style="text-align:center;">—</td>
                <td data-label="">—</td>
            </tr>'''
        else:
            # Parse URL for display
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.netloc or url[:30]
                is_https = parsed.scheme == 'https'
            except:
                host = url[:30]
                is_https = False
            
            iframe_test_rows += f'''
            <tr id="help-test-row-{i}">
                <td data-label=""><span class="status-dot" id="help-test-{i}">●</span> <strong style="margin-left:0.5rem;">{name}</strong></td>
                <td data-label="Source">
                    <span style="font-size:0.75rem;padding:0.15rem 0.4rem;background:{'#22c55e20' if is_https else '#f59e0b20'};color:{'#22c55e' if is_https else '#f59e0b'};border-radius:3px;">{'🔒' if is_https else 'HTTP'}</span>
                    <span style="color:var(--text-secondary);font-size:0.8rem;margin-left:0.5rem;word-break:break-all;">{escape_html(host[:25])}</span>
                </td>
                <td data-label="Time" style="text-align:center;font-family:monospace;" id="help-time-{i}">—</td>
                <td data-label="">
                    <button class="btn btn-sm btn-secondary" onclick="helpTestUrl({i}, '{url_escaped}', '{name_js_escaped}')">Test</button>
                </td>
            </tr>'''
    
    if not iframe_test_rows:
        iframe_test_rows = '<tr><td colspan="4" style="padding:2rem;text-align:center;color:var(--text-secondary);">No iFrames configured</td></tr>'
    
    content = f'''
    <style>
        .help-section {{
            background: var(--bg-secondary);
            border-radius: var(--radius);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .help-section h3 {{
            margin: 0 0 1rem 0;
            font-size: 1.1rem;
        }}
        .help-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .help-table th {{
            text-align: left;
            padding: 0.75rem;
            border-bottom: 2px solid var(--border);
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
        }}
        .help-table td {{
            padding: 0.75rem;
        }}
        .help-table tr {{
            border-bottom: 1px solid var(--border);
        }}
        .help-table tr:last-child {{
            border-bottom: none;
        }}
        .help-summary {{
            display: flex;
            gap: 1.5rem;
            padding: 1rem;
            background: var(--bg-primary);
            border-radius: var(--radius);
            margin-top: 1rem;
        }}
        .help-stat {{
            text-align: center;
        }}
        .help-stat-value {{
            font-size: 1.5rem;
            font-weight: 600;
        }}
        .help-stat-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .test-metric {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
        }}
        .test-metric.good {{ background: #22c55e20; color: #22c55e; }}
        .test-metric.warning {{ background: #f59e0b20; color: #f59e0b; }}
        .test-metric.error {{ background: #ef444420; color: #ef4444; }}
        
        /* Mobile card layout for test table */
        @media (max-width: 640px) {{
            .help-section {{
                padding: 1rem;
                margin-bottom: 1rem;
            }}
            .help-section h3 {{
                font-size: 1rem;
            }}
            .help-table thead {{
                display: none;
            }}
            .help-table, .help-table tbody, .help-table tr, .help-table td {{
                display: block;
                width: 100%;
            }}
            .help-table tr {{
                padding: 0.75rem 0;
                margin-bottom: 0.5rem;
                border-bottom: 1px solid var(--border);
            }}
            .help-table td {{
                padding: 0.25rem 0;
                text-align: left !important;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .help-table td:before {{
                content: attr(data-label);
                font-weight: 500;
                font-size: 0.75rem;
                color: var(--text-secondary);
                text-transform: uppercase;
                margin-right: 0.5rem;
            }}
            .help-table td:first-child {{
                justify-content: flex-start;
                gap: 0.75rem;
            }}
            .help-table td:first-child:before {{
                display: none;
            }}
            .help-table td:last-child {{
                margin-top: 0.5rem;
            }}
            .help-table td:last-child .btn {{
                width: 100%;
            }}
            .help-actions {{
                flex-direction: column;
            }}
            .help-actions .btn {{
                width: 100%;
            }}
            .help-actions #help-summary {{
                margin-left: 0;
                margin-top: 0.5rem;
                text-align: center;
            }}
            .help-tips li {{
                margin-bottom: 0.75rem;
            }}
            /* Info card grids on mobile */
            #connection-info > div:first-child,
            #device-info > div:first-child {{
                grid-template-columns: repeat(2, 1fr) !important;
            }}
        }}
    </style>
    
    <div style="max-width: 900px; margin: 0 auto; padding: 1rem;">
        <h2 style="margin-bottom: 1.5rem;">Help & Diagnostics</h2>
        
        <div class="help-section">
            <h3>🧪 iFrame Connectivity Test</h3>
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">
                Test if your configured content sources are reachable from your browser.
            </p>
            
            <div style="overflow-x:auto;">
                <table class="help-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Source</th>
                            <th style="width:100px;text-align:center;">Load Time</th>
                            <th style="width:80px;text-align:center;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {iframe_test_rows}
                    </tbody>
                </table>
            </div>
            
            <div class="help-actions" style="margin-top:1rem;display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
                <button class="btn" onclick="helpTestAll()">🧪 Test All</button>
                <button class="btn btn-secondary" onclick="helpReset()">Reset</button>
                <button class="btn btn-secondary" id="send-report-btn" onclick="sendReportToAdmin()" style="display:none;">📤 Send Report</button>
                <div id="help-summary" style="margin-left:auto;font-size:0.9rem;display:none;"></div>
            </div>
            <div id="report-status" style="margin-top:0.5rem;font-size:0.85rem;display:none;"></div>
        </div>
        
        <div class="help-section">
            <h3>ℹ️ Quick Tips</h3>
            <ul class="help-tips" style="color:var(--text-secondary);line-height:1.8;padding-left:1.25rem;font-size:0.9rem;">
                <li><strong>Red status (✗)</strong> — Content failed to load. Check if the URL is correct and the server is online.</li>
                <li><strong>Yellow/slow</strong> — Content loads but slowly. May indicate network issues.</li>
                <li><strong>Green status (✓)</strong> — Content loaded successfully!</li>
                <li><strong>X-Frame-Options</strong> — Some websites block embedding in iframes.</li>
                <li><strong>Mixed content</strong> — HTTPS pages cannot load HTTP iframes.</li>
            </ul>
        </div>
        
        <div class="help-section">
            <h3>🌐 Your Connection</h3>
            <div id="connection-info" style="font-size:0.9rem;">
                <p style="color:var(--text-secondary);">Gathering network info...</p>
            </div>
            <div style="margin-top:1rem;padding:0.75rem;background:var(--bg-primary);border-radius:6px;font-size:0.8rem;color:var(--text-secondary);">
                <strong>Note:</strong> WiFi network name (SSID) is not accessible via web browsers for security reasons.
            </div>
        </div>
        
        <div class="help-section">
            <h3>📱 Device Information</h3>
            <div id="device-info" style="font-size:0.9rem;">
                <p style="color:var(--text-secondary);">Detecting device...</p>
            </div>
        </div>
        
        <div style="text-align:center;margin-top:2rem;">
            <a href="/" class="btn btn-secondary">← Back to Dashboard</a>
        </div>
    </div>
    
    <script>
    var helpTestResults = {{}};
    var helpTestCount = 0;
    var apiBase = window.location.origin;  // Get correct protocol, host, and port

    function helpTestUrl(idx, url, name) {{
        var dot = document.getElementById('help-test-' + idx);
        var timeCell = document.getElementById('help-time-' + idx);
        if (!dot) return;

        dot.className = 'status-dot loading';
        dot.textContent = '●';
        if (timeCell) timeCell.textContent = '...';

        var startTime = performance.now();

        // Use server-side proxy test for accurate HTTP status checking
        // This avoids false positives from iframe.onload firing on error pages
        fetch(apiBase + '/api/connectivity-test-url', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ url: url, index: idx }})
        }})
        .then(function(response) {{ return response.json(); }})
        .then(function(data) {{
            var elapsed = Math.round(performance.now() - startTime);
            var result = data.result || {{}};

            // Determine success based on actual HTTP response
            var isSuccess = result.status === 'success';
            var isBlocked = false;
            var reason = '';

            // Check for X-Frame-Options that would block embedding
            if (result.x_frame_options) {{
                var xfo = result.x_frame_options.toUpperCase();
                if (xfo === 'DENY' || xfo === 'SAMEORIGIN') {{
                    isSuccess = false;
                    isBlocked = true;
                    reason = 'Blocked by X-Frame-Options';
                }}
            }}

            // Check for CSP frame-ancestors that would block embedding
            if (result.csp_frame_ancestors) {{
                var csp = result.csp_frame_ancestors.toLowerCase();
                if (csp.includes("'none'") || (csp.includes("'self'") && !csp.includes('*'))) {{
                    isSuccess = false;
                    isBlocked = true;
                    reason = 'Blocked by Content-Security-Policy';
                }}
            }}

            // Handle error cases - note: 'success' status includes HTTP 4xx/5xx (server reachable)
            if (result.status === 'error') {{
                isSuccess = false;
                reason = result.error || 'Not reachable';
            }} else if (result.status === 'warning') {{
                // SSL issues - server reachable but with certificate problems
                isBlocked = true;
                reason = result.error || 'SSL certificate issue';
            }}

            // Update UI
            dot.className = 'status-dot ' + (isSuccess ? 'connected' : (isBlocked ? 'warning' : 'error'));
            dot.textContent = isSuccess ? '✓' : (isBlocked ? '⚠' : '✗');

            if (timeCell) {{
                var displayTime = result.response_time || (elapsed + ' ms');
                // Parse the time for color coding
                var timeMs = parseInt(displayTime);
                if (isSuccess) {{
                    var cls = timeMs < 1000 ? 'good' : (timeMs < 3000 ? 'warning' : 'error');
                    timeCell.innerHTML = '<span class="test-metric ' + cls + '">' + displayTime + '</span>';
                }} else if (isBlocked) {{
                    timeCell.innerHTML = '<span class="test-metric warning">Blocked</span>';
                }} else {{
                    timeCell.innerHTML = '<span class="test-metric error">Failed</span>';
                }}
            }}

            // Store result with additional details
            helpTestResults[idx] = {{
                success: isSuccess,
                blocked: isBlocked,
                time: elapsed,
                name: name || 'Unknown',
                reason: reason,
                httpStatus: result.http_status
            }};

            checkForFailures();
        }})
        .catch(function(err) {{
            // Fallback: if server test fails, use iframe-based test
            helpTestUrlFallback(idx, url, name, startTime);
        }});
    }}

    function helpTestUrlFallback(idx, url, name, startTime) {{
        var dot = document.getElementById('help-test-' + idx);
        var timeCell = document.getElementById('help-time-' + idx);
        if (!dot) return;

        var done = false;
        var f = document.createElement('iframe');
        f.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0;pointer-events:none;';

        function finish(success, reason) {{
            if (done) return;
            done = true;
            var elapsed = Math.round(performance.now() - startTime);

            dot.className = 'status-dot ' + (success ? 'connected' : 'error');
            dot.textContent = success ? '✓' : '✗';

            if (timeCell) {{
                if (success) {{
                    var cls = elapsed < 1000 ? 'good' : (elapsed < 3000 ? 'warning' : 'error');
                    timeCell.innerHTML = '<span class="test-metric ' + cls + '">' + elapsed + ' ms</span>';
                }} else {{
                    timeCell.innerHTML = '<span class="test-metric error">' + (reason || 'Failed') + '</span>';
                }}
            }}

            helpTestResults[idx] = {{ success: success, time: elapsed, name: name || 'Unknown', reason: reason }};
            try {{ document.body.removeChild(f); }} catch(e) {{}}
            checkForFailures();
        }}

        f.onload = function() {{
            // onload fires even for error pages - try to detect actual content
            try {{
                var doc = f.contentDocument || f.contentWindow.document;
                if (doc && doc.body && doc.body.innerHTML && doc.body.innerHTML.length > 50) {{
                    finish(true);
                }} else {{
                    finish(false, 'Empty page');
                }}
            }} catch(e) {{
                // Cross-origin - assume success but note it's unverified
                finish(true, 'Unverified');
            }}
        }};
        f.onerror = function() {{ finish(false, 'Network error'); }};
        setTimeout(function() {{ if (!done) finish(false, 'Timeout'); }}, 10000);

        f.src = url;
        document.body.appendChild(f);
    }}
    
    function checkForFailures() {{
        var keys = Object.keys(helpTestResults);
        if (keys.length === 0) return;
        
        var hasFailures = false;
        keys.forEach(function(k) {{
            if (!helpTestResults[k].success) hasFailures = true;
        }});
        
        var sendBtn = document.getElementById('send-report-btn');
        if (sendBtn) {{
            sendBtn.style.display = hasFailures ? 'inline-block' : 'none';
        }}
    }}
    
    function helpTestAll() {{
        helpTestResults = {{}};
        var btns = document.querySelectorAll('[onclick^="helpTestUrl"]');
        var total = btns.length;
        var current = 0;
        var expectedTests = total;

        if (total === 0) return;

        // Track completion by checking helpTestResults periodically
        var checkInterval = setInterval(function() {{
            var completedTests = Object.keys(helpTestResults).length;
            if (completedTests >= expectedTests) {{
                clearInterval(checkInterval);
                showHelpSummary();
            }}
        }}, 500);

        // Also set a max timeout in case tests hang
        setTimeout(function() {{
            clearInterval(checkInterval);
            showHelpSummary();
        }}, (expectedTests * 12000) + 2000);

        // Run tests with slight stagger to avoid overwhelming the server
        function runNext() {{
            if (current < total) {{
                btns[current].click();
                current++;
                setTimeout(runNext, 400);
            }}
        }}
        runNext();
    }}
    
    function showHelpSummary() {{
        var keys = Object.keys(helpTestResults);
        if (keys.length === 0) return;
        
        var passed = 0, failed = 0, totalTime = 0;
        keys.forEach(function(k) {{
            if (helpTestResults[k].success) passed++;
            else failed++;
            totalTime += helpTestResults[k].time || 0;
        }});
        
        var avgTime = Math.round(totalTime / keys.length);
        var summary = document.getElementById('help-summary');
        var sendBtn = document.getElementById('send-report-btn');
        var reportStatus = document.getElementById('report-status');
        
        if (summary) {{
            summary.innerHTML = '<span style="color:#22c55e;">✓ ' + passed + ' passed</span> · ' +
                '<span style="color:' + (failed > 0 ? '#ef4444' : 'var(--text-secondary)') + ';">' + (failed > 0 ? '✗ ' : '') + failed + ' failed</span> · ' +
                '<span>Avg: ' + avgTime + ' ms</span>';
            summary.style.display = 'block';
        }}
        
        // Show send report button if there are failures
        if (sendBtn) {{
            sendBtn.style.display = failed > 0 ? 'inline-block' : 'none';
        }}
        if (reportStatus) {{
            reportStatus.style.display = 'none';
        }}
    }}
    
    function helpReset() {{
        helpTestResults = {{}};
        document.querySelectorAll('[id^="help-test-"]').forEach(function(el) {{
            if (el.id.match(/help-test-\\d+$/)) {{
                el.className = 'status-dot';
                el.textContent = '●';
            }}
        }});
        document.querySelectorAll('[id^="help-time-"]').forEach(function(el) {{
            el.textContent = '—';
        }});
        var summary = document.getElementById('help-summary');
        if (summary) summary.style.display = 'none';
        var sendBtn = document.getElementById('send-report-btn');
        if (sendBtn) sendBtn.style.display = 'none';
        var reportStatus = document.getElementById('report-status');
        if (reportStatus) reportStatus.style.display = 'none';
    }}
    
    function sendReportToAdmin() {{
        var sendBtn = document.getElementById('send-report-btn');
        var reportStatus = document.getElementById('report-status');
        
        if (sendBtn) sendBtn.disabled = true;
        if (reportStatus) {{
            reportStatus.innerHTML = '<span style="color:var(--text-secondary);">Sending report...</span>';
            reportStatus.style.display = 'block';
        }}
        
        // Build report data
        var results = [];
        Object.keys(helpTestResults).forEach(function(k) {{
            results.push({{
                index: parseInt(k),
                name: helpTestResults[k].name || 'Unknown',
                success: helpTestResults[k].success,
                time: helpTestResults[k].time
            }});
        }});
        
        fetch(apiBase + '/api/submit-connectivity-report', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                results: results,
                userAgent: navigator.userAgent,
                online: navigator.onLine,
                connectionType: navigator.connection ? navigator.connection.effectiveType : null
            }})
        }})
        .then(function(r) {{ return r.json(); }})
        .then(function(data) {{
            if (data.success) {{
                if (reportStatus) {{
                    reportStatus.innerHTML = '<span style="color:#22c55e;">✓ Report sent to administrator</span>';
                }}
                if (sendBtn) sendBtn.style.display = 'none';
            }} else {{
                if (reportStatus) {{
                    reportStatus.innerHTML = '<span style="color:#ef4444;">✗ Failed to send: ' + (data.error || 'Unknown error') + '</span>';
                }}
                if (sendBtn) sendBtn.disabled = false;
            }}
        }})
        .catch(function(e) {{
            if (reportStatus) {{
                reportStatus.innerHTML = '<span style="color:#ef4444;">✗ Error: ' + e.message + '</span>';
            }}
            if (sendBtn) sendBtn.disabled = false;
        }});
    }}
    
    // Check connection info
    (function() {{
        var info = document.getElementById('connection-info');
        
        // Start with summary cards at top
        var html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:0.75rem;margin-bottom:1rem;">';
        
        // Online status card
        var onlineStatus = navigator.onLine;
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.5rem;">' + (onlineStatus ? '🟢' : '🔴') + '</div>';
        html += '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem;">' + (onlineStatus ? 'Online' : 'Offline') + '</div>';
        html += '</div>';
        
        // Connection type card
        var connType = 'Unknown';
        var connIcon = '🌐';
        if (navigator.connection) {{
            var conn = navigator.connection;
            if (conn.type) {{
                connType = conn.type;
                if (connType === 'wifi') connIcon = '📶';
                else if (connType === 'cellular') connIcon = '📱';
                else if (connType === 'ethernet') connIcon = '🔌';
                else if (connType === 'bluetooth') connIcon = '🔵';
                else if (connType === 'none') connIcon = '❌';
            }} else if (conn.effectiveType) {{
                connType = conn.effectiveType.toUpperCase();
                connIcon = '📡';
            }}
        }}
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.5rem;">' + connIcon + '</div>';
        html += '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem;">' + connType.charAt(0).toUpperCase() + connType.slice(1).toLowerCase() + '</div>';
        html += '</div>';
        
        // Speed card
        var speed = '—';
        if (navigator.connection && navigator.connection.downlink) {{
            speed = navigator.connection.downlink + ' Mbps';
        }}
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.25rem;font-weight:600;">' + speed + '</div>';
        html += '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem;">Bandwidth</div>';
        html += '</div>';
        
        // Latency card
        var latency = '—';
        var latencyColor = 'inherit';
        if (navigator.connection && navigator.connection.rtt) {{
            latency = navigator.connection.rtt + ' ms';
            latencyColor = navigator.connection.rtt < 100 ? '#22c55e' : (navigator.connection.rtt < 300 ? '#f59e0b' : '#ef4444');
        }}
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.25rem;font-weight:600;color:' + latencyColor + ';">' + latency + '</div>';
        html += '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem;">Latency</div>';
        html += '</div>';
        
        html += '</div>';
        
        // Details table
        html += '<table style="width:100%;">';
        
        // IP will be inserted here via fetch
        html += '<tr id="ip-row" style="display:none;"><td style="padding:0.5rem 0;color:var(--text-secondary);width:45%;">Your IP Address</td><td id="ip-value" style="font-family:monospace;">—</td></tr>';
        
        // Server
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Server Address</td>';
        html += '<td style="font-family:monospace;font-size:0.9rem;">' + location.host + '</td></tr>';
        
        // Protocol
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Protocol</td>';
        html += '<td>' + (location.protocol === 'https:' ? '🔒 Secure (HTTPS)' : '⚠️ Unencrypted (HTTP)') + '</td></tr>';
        
        // Data saver
        if (navigator.connection && navigator.connection.saveData !== undefined) {{
            html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Data Saver</td>';
            html += '<td>' + (navigator.connection.saveData ? '✓ Enabled' : 'Disabled') + '</td></tr>';
        }}
        
        html += '</table>';
        info.innerHTML = html;
        
        // Fetch client IP from server
        fetch('/api/client-info')
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{
                if (data.ip) {{
                    var ipRow = document.getElementById('ip-row');
                    var ipValue = document.getElementById('ip-value');
                    if (ipRow && ipValue) {{
                        ipValue.textContent = data.ip;
                        ipRow.style.display = '';
                    }}
                }}
            }})
            .catch(function() {{}});
    }})();
    
    // Device information
    (function() {{
        var info = document.getElementById('device-info');
        var ua = navigator.userAgent;
        
        // Detect browser
        var browser = 'Unknown';
        var browserIcon = '🌐';
        var browserVersion = '';
        if (ua.indexOf('Firefox') > -1) {{ browser = 'Firefox'; browserIcon = '🦊'; }}
        else if (ua.indexOf('Edg/') > -1) {{ browser = 'Edge'; browserIcon = '🌀'; }}
        else if (ua.indexOf('Chrome') > -1) {{ browser = 'Chrome'; browserIcon = '🟢'; }}
        else if (ua.indexOf('Safari') > -1) {{ browser = 'Safari'; browserIcon = '🧭'; }}
        else if (ua.indexOf('Opera') > -1 || ua.indexOf('OPR') > -1) {{ browser = 'Opera'; browserIcon = '🔴'; }}
        
        var versionMatch = ua.match(/(Firefox|Edg|Chrome|Safari|OPR|Opera)[\\/ ]([\\d.]+)/i);
        if (versionMatch) browserVersion = versionMatch[2].split('.')[0];
        
        // Detect OS
        var os = 'Unknown';
        var osIcon = '💻';
        if (ua.indexOf('Windows NT 10') > -1 || ua.indexOf('Windows NT 11') > -1) {{ os = 'Windows'; osIcon = '🪟'; }}
        else if (ua.indexOf('Windows') > -1) {{ os = 'Windows'; osIcon = '🪟'; }}
        else if (ua.indexOf('Mac OS') > -1) {{ os = 'macOS'; osIcon = '🍎'; }}
        else if (ua.indexOf('Android') > -1) {{ os = 'Android'; osIcon = '🤖'; }}
        else if (ua.indexOf('iPhone') > -1) {{ os = 'iOS'; osIcon = '📱'; }}
        else if (ua.indexOf('iPad') > -1) {{ os = 'iPadOS'; osIcon = '📱'; }}
        else if (ua.indexOf('Linux') > -1) {{ os = 'Linux'; osIcon = '🐧'; }}
        else if (ua.indexOf('CrOS') > -1) {{ os = 'Chrome OS'; osIcon = '💻'; }}
        
        // Detect device type
        var device = 'Desktop';
        var deviceIcon = '🖥️';
        if (/iPad/i.test(ua)) {{
            device = 'Tablet';
            deviceIcon = '📱';
        }} else if (/Mobi|Android/i.test(ua)) {{
            device = 'Mobile';
            deviceIcon = '📱';
        }}
        
        // Summary cards
        var html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:0.75rem;margin-bottom:1rem;">';
        
        // Browser card
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.5rem;">' + browserIcon + '</div>';
        html += '<div style="font-weight:500;font-size:0.9rem;">' + browser + '</div>';
        html += '<div style="font-size:0.7rem;color:var(--text-secondary);">v' + browserVersion + '</div>';
        html += '</div>';
        
        // OS card
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.5rem;">' + osIcon + '</div>';
        html += '<div style="font-weight:500;font-size:0.9rem;">' + os + '</div>';
        html += '<div style="font-size:0.7rem;color:var(--text-secondary);">OS</div>';
        html += '</div>';
        
        // Device card
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.5rem;">' + deviceIcon + '</div>';
        html += '<div style="font-weight:500;font-size:0.9rem;">' + device + '</div>';
        html += '<div style="font-size:0.7rem;color:var(--text-secondary);">Device</div>';
        html += '</div>';
        
        // Screen card
        html += '<div style="background:var(--bg-primary);padding:0.75rem;border-radius:6px;text-align:center;">';
        html += '<div style="font-size:1.1rem;font-weight:600;">' + screen.width + '×' + screen.height + '</div>';
        html += '<div style="font-size:0.7rem;color:var(--text-secondary);margin-top:0.25rem;">Screen</div>';
        html += '</div>';
        
        html += '</div>';
        
        // Details table
        html += '<table style="width:100%;">';
        
        // Viewport
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);width:45%;">Viewport Size</td>';
        html += '<td>' + window.innerWidth + ' × ' + window.innerHeight + ' px</td></tr>';
        
        // Pixel ratio
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Pixel Ratio</td>';
        html += '<td>' + (window.devicePixelRatio || 1) + 'x</td></tr>';
        
        // Touch support
        var hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Touch Support</td>';
        html += '<td>' + (hasTouch ? '✓ Yes (' + navigator.maxTouchPoints + ' points)' : 'No') + '</td></tr>';
        
        // Cookies
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Cookies</td>';
        html += '<td>' + (navigator.cookieEnabled ? '✓ Enabled' : '✗ Disabled') + '</td></tr>';
        
        // Language
        var lang = navigator.language || navigator.userLanguage || 'Unknown';
        html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Language</td>';
        html += '<td>' + lang + '</td></tr>';
        
        // Timezone
        try {{
            var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
            var offset = new Date().getTimezoneOffset();
            var offsetHrs = Math.abs(Math.floor(offset / 60));
            var offsetMins = Math.abs(offset % 60);
            var offsetStr = (offset <= 0 ? '+' : '-') + (offsetHrs < 10 ? '0' : '') + offsetHrs + ':' + (offsetMins < 10 ? '0' : '') + offsetMins;
            html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Timezone</td>';
            html += '<td style="font-size:0.85rem;">' + tz + ' (UTC' + offsetStr + ')</td></tr>';
        }} catch(e) {{}}
        
        // Hardware concurrency (CPU cores)
        if (navigator.hardwareConcurrency) {{
            html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">CPU Cores</td>';
            html += '<td>' + navigator.hardwareConcurrency + '</td></tr>';
        }}
        
        // Memory (if available)
        if (navigator.deviceMemory) {{
            html += '<tr><td style="padding:0.5rem 0;color:var(--text-secondary);">Device Memory</td>';
            html += '<td>~' + navigator.deviceMemory + ' GB</td></tr>';
        }}
        
        html += '</table>';
        
        // User agent (collapsible)
        html += '<details style="margin-top:1rem;">';
        html += '<summary style="cursor:pointer;color:var(--text-secondary);font-size:0.85rem;">📋 Full User Agent String</summary>';
        html += '<div style="margin-top:0.5rem;padding:0.75rem;background:var(--bg-primary);border-radius:6px;font-family:monospace;font-size:0.7rem;word-break:break-all;color:var(--text-secondary);line-height:1.5;">' + ua + '</div>';
        html += '</details>';
        
        info.innerHTML = html;
    }})();
    </script>
    '''
    
    return render_page("Help & Diagnostics", content, user, config)


def render_widget(widget, config):
    """Render a single widget for the dashboard."""
    wtype = widget.get('type', 'text')
    name = escape_html(widget.get('name', 'Widget'))
    content = widget.get('content', '')
    size = widget.get('size', 'medium')
    bg_color = widget.get('bg_color', '#141416')
    text_color = widget.get('text_color', '#e8e8e8')
    border_radius = widget.get('border_radius', 8)
    
    # Size classes
    size_class = {'small': 'widget-small', 'medium': 'widget-medium', 'large': 'widget-large'}.get(size, 'widget-medium')
    
    # Generate widget content based on type
    if wtype == 'clock':
        fmt = '12h' if '12' in content else '24h'
        inner = f'''
        <div class="widget-clock" id="widget-clock-{id(widget)}">--:--:--</div>
        <script>
        (function() {{
            function updateClock() {{
                var now = new Date();
                var h = now.getHours(), m = now.getMinutes(), s = now.getSeconds();
                {'var ampm = h >= 12 ? "PM" : "AM"; h = h % 12; h = h ? h : 12;' if fmt == '12h' else ''}
                var time = (h < 10 ? "0" + h : h) + ":" + (m < 10 ? "0" + m : m) + ":" + (s < 10 ? "0" + s : s) {'+ " " + ampm' if fmt == '12h' else ''};
                document.getElementById('widget-clock-{id(widget)}').textContent = time;
            }}
            updateClock();
            setInterval(updateClock, 1000);
        }})();
        </script>
        '''
    elif wtype == 'date':
        inner = f'''
        <div class="widget-date" id="widget-date-{id(widget)}">Loading...</div>
        <script>
        (function() {{
            function updateDate() {{
                var now = new Date();
                var options = {{ weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }};
                document.getElementById('widget-date-{id(widget)}').textContent = now.toLocaleDateString(undefined, options);
            }}
            updateDate();
            setInterval(updateDate, 60000);
        }})();
        </script>
        '''
    elif wtype == 'countdown':
        target = escape_html(content) if content else '2025-01-01 00:00'
        inner = f'''
        <div class="widget-countdown">
            <div class="countdown-label">{name}</div>
            <div class="countdown-time" id="widget-countdown-{id(widget)}">Calculating...</div>
        </div>
        <script>
        (function() {{
            var target = new Date('{target}').getTime();
            function updateCountdown() {{
                var now = new Date().getTime();
                var diff = target - now;
                if (diff < 0) {{
                    document.getElementById('widget-countdown-{id(widget)}').textContent = 'Event passed!';
                    return;
                }}
                var days = Math.floor(diff / (1000 * 60 * 60 * 24));
                var hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                var mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                var secs = Math.floor((diff % (1000 * 60)) / 1000);
                document.getElementById('widget-countdown-{id(widget)}').innerHTML = 
                    '<span class="cd-num">' + days + '</span><span class="cd-label">d</span> ' +
                    '<span class="cd-num">' + hours + '</span><span class="cd-label">h</span> ' +
                    '<span class="cd-num">' + mins + '</span><span class="cd-label">m</span> ' +
                    '<span class="cd-num">' + secs + '</span><span class="cd-label">s</span>';
            }}
            updateCountdown();
            setInterval(updateCountdown, 1000);
        }})();
        </script>
        '''
    elif wtype == 'image':
        img_src = escape_html(content) if content else ''
        inner = f'<img src="{img_src}" alt="{name}" class="widget-image">' if img_src else '<div class="widget-placeholder">No image set</div>'
    elif wtype == 'weather':
        # Parse location and units from content (format: "City" or "City,C" or "lat,lon,F")
        raw_content = content.strip() if content else ''
        use_celsius = False
        location = raw_content
        
        # Check for unit suffix
        if raw_content.upper().endswith(',C') or raw_content.upper().endswith(',CELSIUS'):
            use_celsius = True
            location = raw_content.rsplit(',', 1)[0].strip()
        elif raw_content.upper().endswith(',F') or raw_content.upper().endswith(',FAHRENHEIT'):
            use_celsius = False
            location = raw_content.rsplit(',', 1)[0].strip()
        
        location_escaped = escape_html(location)
        widget_id = f"weather-{id(widget)}"
        temp_unit = 'celsius' if use_celsius else 'fahrenheit'
        temp_symbol = '°C' if use_celsius else '°F'
        wind_unit = 'kmh' if use_celsius else 'mph'
        wind_label = 'km/h' if use_celsius else 'mph'
        
        inner = f'''
        <div class="widget-weather" id="{widget_id}">
            <div class="weather-icon" id="{widget_id}-icon">⏳</div>
            <div class="weather-info">
                <div class="weather-location" id="{widget_id}-location">{location_escaped if location_escaped else 'Loading...'}</div>
                <div class="weather-temp" id="{widget_id}-temp">--°</div>
                <div class="weather-desc" id="{widget_id}-desc" style="font-size:0.8rem;opacity:0.8;"></div>
            </div>
        </div>
        <div class="weather-details" id="{widget_id}-details" style="display:flex;gap:1rem;margin-top:0.5rem;font-size:0.75rem;opacity:0.7;justify-content:center;"></div>
        <script>
        (function() {{
            var widgetId = '{widget_id}';
            var locationInput = '{location_escaped}';
            var tempUnit = '{temp_unit}';
            var tempSymbol = '{temp_symbol}';
            var windUnit = '{wind_unit}';
            var windLabel = '{wind_label}';
            
            var weatherCodes = {{
                0: ['☀️', 'Clear sky'],
                1: ['🌤️', 'Mainly clear'],
                2: ['⛅', 'Partly cloudy'],
                3: ['☁️', 'Overcast'],
                45: ['🌫️', 'Foggy'],
                48: ['🌫️', 'Icy fog'],
                51: ['🌧️', 'Light drizzle'],
                53: ['🌧️', 'Drizzle'],
                55: ['🌧️', 'Heavy drizzle'],
                61: ['🌧️', 'Light rain'],
                63: ['🌧️', 'Rain'],
                65: ['🌧️', 'Heavy rain'],
                66: ['🌨️', 'Freezing rain'],
                67: ['🌨️', 'Heavy freezing rain'],
                71: ['🌨️', 'Light snow'],
                73: ['🌨️', 'Snow'],
                75: ['🌨️', 'Heavy snow'],
                77: ['🌨️', 'Snow grains'],
                80: ['🌦️', 'Light showers'],
                81: ['🌦️', 'Showers'],
                82: ['🌦️', 'Heavy showers'],
                85: ['🌨️', 'Light snow showers'],
                86: ['🌨️', 'Snow showers'],
                95: ['⛈️', 'Thunderstorm'],
                96: ['⛈️', 'Thunderstorm with hail'],
                99: ['⛈️', 'Heavy thunderstorm']
            }};
            
            function setError(msg) {{
                document.getElementById(widgetId + '-icon').textContent = '⚠️';
                document.getElementById(widgetId + '-temp').textContent = '--°';
                document.getElementById(widgetId + '-desc').textContent = msg;
            }}
            
            function fetchWeather(lat, lon, locationName) {{
                var url = 'https://api.open-meteo.com/v1/forecast?latitude=' + lat + '&longitude=' + lon + 
                    '&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&temperature_unit=' + tempUnit + '&wind_speed_unit=' + windUnit;
                
                fetch(url)
                    .then(function(r) {{ return r.json(); }})
                    .then(function(data) {{
                        if (data.current) {{
                            var temp = Math.round(data.current.temperature_2m);
                            var code = data.current.weather_code;
                            var humidity = data.current.relative_humidity_2m;
                            var wind = Math.round(data.current.wind_speed_10m);
                            var weather = weatherCodes[code] || ['🌡️', 'Unknown'];
                            
                            document.getElementById(widgetId + '-icon').textContent = weather[0];
                            document.getElementById(widgetId + '-temp').textContent = temp + tempSymbol;
                            document.getElementById(widgetId + '-desc').textContent = weather[1];
                            document.getElementById(widgetId + '-location').textContent = locationName;
                            document.getElementById(widgetId + '-details').innerHTML = 
                                '<span>💧 ' + humidity + '%</span><span>💨 ' + wind + ' ' + windLabel + '</span>';
                        }} else {{
                            setError('No data');
                        }}
                    }})
                    .catch(function(e) {{ setError('API error'); }});
            }}
            
            function geocodeAndFetch(query) {{
                var url = 'https://geocoding-api.open-meteo.com/v1/search?name=' + encodeURIComponent(query) + '&count=1';
                fetch(url)
                    .then(function(r) {{ return r.json(); }})
                    .then(function(data) {{
                        if (data.results && data.results.length > 0) {{
                            var loc = data.results[0];
                            var locationName = loc.name + (loc.admin1 ? ', ' + loc.admin1 : '') + (loc.country_code ? ' ' + loc.country_code : '');
                            fetchWeather(loc.latitude, loc.longitude, locationName);
                        }} else {{
                            setError('Location not found');
                        }}
                    }})
                    .catch(function(e) {{ setError('Geocoding error'); }});
            }}
            
            // Parse location input
            if (!locationInput) {{
                // Try browser geolocation
                if (navigator.geolocation) {{
                    navigator.geolocation.getCurrentPosition(
                        function(pos) {{
                            fetchWeather(pos.coords.latitude, pos.coords.longitude, 'Current Location');
                        }},
                        function() {{ setError('Enter a location'); }}
                    );
                }} else {{
                    setError('Enter a location');
                }}
            }} else if (locationInput.match(/^-?\\d+\\.?\\d*\\s*,\\s*-?\\d+\\.?\\d*$/)) {{
                // Coordinates format: lat,lon
                var parts = locationInput.split(',');
                fetchWeather(parseFloat(parts[0].trim()), parseFloat(parts[1].trim()), 'Custom Location');
            }} else {{
                // City name - geocode first
                geocodeAndFetch(locationInput);
            }}
            
            // Refresh every 15 minutes
            setInterval(function() {{
                if (locationInput) {{
                    if (locationInput.match(/^-?\\d+\\.?\\d*\\s*,\\s*-?\\d+\\.?\\d*$/)) {{
                        var parts = locationInput.split(',');
                        fetchWeather(parseFloat(parts[0].trim()), parseFloat(parts[1].trim()), 'Custom Location');
                    }} else {{
                        geocodeAndFetch(locationInput);
                    }}
                }}
            }}, 900000);
        }})();
        </script>
        '''
    elif wtype == 'notes':
        notes_text = escape_html(content).replace('\\n', '<br>') if content else 'No notes'
        inner = f'<div class="widget-notes">{notes_text}</div>'
    elif wtype == 'buttons':
        # Parse buttons from content (JSON format)
        buttons_html = ""
        try:
            import json as json_module
            buttons_data = json_module.loads(content) if content else []
            if isinstance(buttons_data, list):
                for idx, btn in enumerate(buttons_data):
                    btn_label = escape_html(btn.get('label', 'Button'))
                    btn_protocol = escape_html(btn.get('protocol', 'tcp'))
                    btn_host = escape_html(btn.get('host', ''))
                    btn_port = int(btn.get('port', 23))
                    btn_command = btn.get('command', '')
                    btn_color = escape_html(btn.get('color', '#3b82f6'))
                    btn_id = f"cmd-btn-{id(widget)}-{idx}"
                    
                    # Encode command for safe transfer
                    cmd_encoded = base64.b64encode(btn_command.encode()).decode()
                    
                    buttons_html += f'''
                    <button class="cmd-button" id="{btn_id}" 
                            data-protocol="{btn_protocol}" 
                            data-host="{btn_host}" 
                            data-port="{btn_port}" 
                            data-command="{cmd_encoded}"
                            style="background:{btn_color};"
                            onclick="sendCommand(this)">
                        {btn_label}
                    </button>
                    '''
        except (json.JSONDecodeError, ValueError, TypeError, KeyError):
            buttons_html = '<div class="widget-placeholder">Invalid button configuration</div>'
        
        if not buttons_html:
            buttons_html = '<div class="widget-placeholder">No buttons configured</div>'
        
        inner = f'<div class="widget-buttons">{buttons_html}</div>'
    else:  # text/html
        # For text type, allow HTML
        inner = f'<div class="widget-text">{content}</div>'
    
    return f'''
    <div class="widget {size_class}" style="background:{bg_color};color:{text_color};border-radius:{border_radius}px;">
        <div class="widget-header">{name}</div>
        <div class="widget-body">{inner}</div>
    </div>
    '''


def render_main_page(user, config):
    """Render the main iFrame display page."""
    iframes = config.get("iframes", [])
    widgets = config.get("widgets", [])
    cols = config["settings"].get("grid_columns", 2)
    refresh = config["settings"].get("refresh_interval", 0)
    fallback_config = config.get("fallback_image", {})
    
    # Render widgets
    widgets_html = ""
    for widget in widgets:
        if not widget.get('enabled', True):
            continue
        widgets_html += render_widget(widget, config)
    
    if widgets_html:
        widgets_html = f'<div class="widgets-container">{widgets_html}</div>'
    
    # Build fallback image data for JavaScript
    fallback_enabled = fallback_config.get('enabled', False)
    fallback_text = escape_html(fallback_config.get('text', 'Content Unavailable'))
    fallback_image = fallback_config.get('image', '')
    fallback_mime = fallback_config.get('image_mime', 'image/png')
    
    if not iframes and not widgets:
        content = """
        <div class="empty-state" style="margin-top:4rem;">
            <h2 style="margin-bottom:1rem;">No Content Configured</h2>
            <p>Ask an administrator to add iFrames or widgets.</p>
        </div>
        """
    elif not iframes:
        # Widgets only - add command script for button widgets
        command_script = """
        <script>
        function sendCommand(btn) {
            var protocol = btn.dataset.protocol;
            var host = btn.dataset.host;
            var port = btn.dataset.port;
            var command = btn.dataset.command;
            
            btn.disabled = true;
            btn.classList.add('sending');
            var originalText = btn.textContent;
            btn.textContent = 'Sending...';
            
            fetch('/api/send-command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    protocol: protocol,
                    host: host,
                    port: parseInt(port),
                    command: command
                })
            })
            .then(response => response.json())
            .then(data => {
                btn.disabled = false;
                btn.classList.remove('sending');
                if (data.success) {
                    btn.classList.add('success');
                    btn.textContent = '✓ Sent';
                    setTimeout(() => {
                        btn.classList.remove('success');
                        btn.textContent = originalText;
                    }, 1500);
                } else {
                    btn.classList.add('error');
                    btn.textContent = '✗ Failed';
                    setTimeout(() => {
                        btn.classList.remove('error');
                        btn.textContent = originalText;
                    }, 2000);
                }
            })
            .catch(err => {
                btn.disabled = false;
                btn.classList.remove('sending');
                btn.classList.add('error');
                btn.textContent = '✗ Error';
                setTimeout(() => {
                    btn.classList.remove('error');
                    btn.textContent = originalText;
                }, 2000);
            });
        }
        </script>
        """
        content = f'{widgets_html}{command_script}'
    else:
        iframe_html = ""
        for i, iframe in enumerate(iframes):
            name = escape_html(iframe.get("name", f"Frame {i+1}"))
            url = escape_html(iframe.get("url", ""))
            height = iframe.get("height", 400)
            width = iframe.get("width", 100)  # percentage
            show_url = iframe.get("show_url", True)
            show_header = iframe.get("show_header", True)
            show_status = iframe.get("show_status", True)  # Show connectivity status icon
            header_text = escape_html(iframe.get("header_text", ""))  # Custom header text, empty = use name
            border_style = iframe.get("border_style", "default")  # default, none, thin, thick, rounded
            border_color = iframe.get("border_color", "")
            zoom = iframe.get("zoom", 100)  # percentage, 100 = normal
            use_embed_code = iframe.get("use_embed_code", False)
            embed_code = iframe.get("embed_code", "")
            
            # Display title - use header_text if set, otherwise use name
            display_title = header_text if header_text else name
            
            # URL display - show "Embed" for embed code iframes
            if use_embed_code:
                url_display = '<span style="opacity:0.6;">📋 Embed Code</span>' if show_url else ''
            else:
                url_display = f'<span>{url}</span>' if show_url else ''
            
            # Build border styles
            card_styles = []
            iframe_styles = []
            wrapper_styles = []
            
            if width != 100:
                card_styles.append(f"max-width:{width}%")
            
            if border_style == "none":
                card_styles.append("border:none")
            elif border_style == "thin":
                card_styles.append("border-width:1px")
            elif border_style == "thick":
                card_styles.append("border-width:3px")
            elif border_style == "rounded":
                card_styles.append("border-radius:12px;overflow:hidden")
            
            if border_color:
                card_styles.append(f"border-color:{escape_html(border_color)}")
            
            # Zoom/scale handling
            if zoom != 100:
                scale = zoom / 100
                # Scale the iframe and adjust container
                inverse_scale = 100 / zoom
                iframe_styles.append(f"transform:scale({scale})")
                iframe_styles.append("transform-origin:0 0")
                iframe_styles.append(f"width:{inverse_scale * 100}%")
                iframe_styles.append(f"height:{int(height * inverse_scale)}px")
                wrapper_styles.append(f"height:{height}px")
                wrapper_styles.append("overflow:hidden")
            else:
                iframe_styles.append(f"height:{height}px")
                iframe_styles.append("width:100%")
            
            card_style_str = ';'.join(card_styles) if card_styles else ''
            iframe_style_str = ';'.join(iframe_styles)
            wrapper_style_str = ';'.join(wrapper_styles) if wrapper_styles else ''
            
            # Header visibility with optional status dot
            if show_header:
                status_dot_html = f'<span class="status-dot {"connected" if use_embed_code else "loading"}" id="status-{i}" title="{"Embed Code" if use_embed_code else "Connecting..."}"></span>' if show_status else ''
                header_html = f'<h3><span class="title-left">{status_dot_html}{display_title}</span> {url_display}</h3>'
            else:
                header_html = ''
                if 'border-radius' not in card_style_str:
                    card_style_str += ';border-radius:var(--radius)'
            
            # Sandbox attribute - allows functionality but blocks parent navigation
            # - allow-scripts: JavaScript
            # - allow-same-origin: treat content as same origin
            # - allow-forms: form submission
            # - allow-popups: open links in new tabs/windows
            # - allow-popups-to-escape-sandbox: new windows aren't sandboxed
            # NOT included: allow-top-navigation (prevents iframe from navigating parent)
            sandbox_attr = 'sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox"'
            
            # Generate iframe content - embed code or regular iframe
            if use_embed_code and embed_code:
                # Render embed code directly in a container
                # Embed codes (YouTube, Vimeo, etc.) come with their own iframe attributes
                # We wrap in a container for sizing but don't add another iframe layer
                embed_wrapper_style = f"height:{height}px;overflow:hidden;position:relative;"
                if zoom != 100:
                    scale = zoom / 100
                    embed_wrapper_style = f"height:{height}px;overflow:hidden;position:relative;transform:scale({scale});transform-origin:0 0;"
                
                # Inject sandbox attribute into any iframes in the embed code (if not already present)
                # This adds security without breaking the embed
                if 'sandbox=' not in embed_code.lower():
                    sandboxed_embed = re.sub(
                        r'<iframe\s',
                        '<iframe sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox" ',
                        embed_code,
                        flags=re.IGNORECASE
                    )
                else:
                    sandboxed_embed = embed_code
                
                iframe_inner = f'<div class="embed-container" style="{embed_wrapper_style}">{sandboxed_embed}</div>'
            else:
                # Regular iframe with URL
                if wrapper_style_str:
                    iframe_inner = f'<div class="iframe-wrapper" style="{wrapper_style_str}"><iframe id="iframe-{i}" src="{url}" style="{iframe_style_str}" loading="lazy" {sandbox_attr}></iframe></div>'
                else:
                    iframe_inner = f'<iframe id="iframe-{i}" src="{url}" style="{iframe_style_str}" loading="lazy" {sandbox_attr}></iframe>'
            
            # Fallback placeholder (hidden by default)
            fallback_div = f'<div id="fallback-{i}" class="iframe-fallback" style="display:none;height:{height}px;"></div>'
            
            iframe_html += f"""
            <div class="iframe-card" style="{card_style_str}">
                {header_html}
                <div class="iframe-content-wrapper">
                    {iframe_inner}
                    {fallback_div}
                </div>
            </div>
            """
        
        # Add status monitoring script
        # Fallback configuration for JavaScript
        fallback_js = ""
        if fallback_enabled and fallback_image:
            fallback_js = f"""
            var fallbackConfig = {{
                enabled: true,
                image: 'data:{fallback_mime};base64,{fallback_image}',
                text: '{fallback_text}'
            }};
            """
        else:
            fallback_js = """
            var fallbackConfig = { enabled: false };
            """

        # Build iframe URL list for connectivity testing
        iframe_test_data = []
        for i, iframe in enumerate(iframes):
            if not iframe.get("use_embed_code", False) and iframe.get("url"):
                iframe_test_data.append({
                    "index": i,
                    "url": iframe.get("url", "")
                })

        import json as json_module
        iframe_test_json = json_module.dumps(iframe_test_data)

        status_script = f"""
        <script>
        {fallback_js}

        // Iframe URLs to test for connectivity
        var iframeTestData = {iframe_test_json};
        var apiBase = window.location.origin;
        var iframeLoadState = {{}};  // Track load state per iframe
        var LOAD_TIMEOUT = 15000;  // 15 seconds timeout

        // Prevent browser back button from navigating away when iframes are present
        (function() {{
            if (document.querySelectorAll('iframe').length > 0) {{
                if (!history.state || !history.state.iframePage) {{
                    history.pushState({{ iframePage: true }}, '', window.location.href);
                }}
                window.addEventListener('popstate', function(e) {{
                    if (!e.state || !e.state.iframePage) {{
                        history.pushState({{ iframePage: true }}, '', window.location.href);
                    }}
                }});
            }}
        }})();

        function showFallback(index) {{
            if (!fallbackConfig.enabled) return;
            var iframe = document.getElementById('iframe-' + index);
            var fallback = document.getElementById('fallback-' + index);
            if (iframe && fallback) {{
                iframe.style.display = 'none';
                if (iframe.parentElement) iframe.parentElement.style.display = 'none';
                fallback.style.display = 'flex';
                fallback.innerHTML = '<div class="fallback-content">' +
                    (fallbackConfig.image ? '<img src="' + fallbackConfig.image + '" alt="Fallback">' : '') +
                    '<span class="fallback-text">' + fallbackConfig.text + '</span></div>';
            }}
        }}

        function hideFallback(index) {{
            var iframe = document.getElementById('iframe-' + index);
            var fallback = document.getElementById('fallback-' + index);
            if (iframe && fallback) {{
                iframe.style.display = '';
                if (iframe.parentElement && iframe.parentElement.classList.contains('iframe-wrapper')) {{
                    iframe.parentElement.style.display = '';
                }}
                fallback.style.display = 'none';
            }}
        }}

        function setIframeStatus(index, status, reason) {{
            var dot = document.getElementById('status-' + index);
            if (dot) {{
                dot.classList.remove('loading', 'connected', 'error', 'warning');
                if (status === 'connected') {{
                    dot.classList.add('connected');
                    dot.title = reason || 'Loaded';
                    hideFallback(index);
                }} else if (status === 'warning') {{
                    dot.classList.add('warning');
                    dot.title = reason || 'Slow';
                    hideFallback(index);
                }} else if (status === 'loading') {{
                    dot.classList.add('loading');
                    dot.title = reason || 'Loading...';
                }} else {{
                    dot.classList.add('error');
                    dot.title = reason || 'Failed to load';
                    showFallback(index);
                }}
            }}
        }}

        // Monitor iframe load using actual iframe events
        function monitorIframe(index) {{
            var iframe = document.getElementById('iframe-' + index);
            if (!iframe) return;

            // Initialize state
            iframeLoadState[index] = {{
                loaded: false,
                startTime: Date.now(),
                timeoutId: null
            }};

            // Check if iframe might have already loaded (page load complete)
            // For cross-origin iframes, we can't check content, but we can check if
            // the iframe has a contentWindow which indicates it has loaded something
            var alreadyLoaded = false;
            try {{
                // If we can access contentWindow, the iframe has loaded
                // (even if cross-origin, contentWindow exists after load)
                if (iframe.contentWindow && iframe.contentWindow.document) {{
                    alreadyLoaded = true;
                }}
            }} catch (e) {{
                // Cross-origin - contentWindow exists but document throws
                // This means the iframe has loaded cross-origin content
                if (iframe.contentWindow) {{
                    alreadyLoaded = true;
                }}
            }}

            if (alreadyLoaded) {{
                iframeLoadState[index].loaded = true;
                setIframeStatus(index, 'connected', 'Loaded');
                return;
            }}

            // Set loading status
            setIframeStatus(index, 'loading', 'Loading...');

            // Set timeout for slow/hanging pages
            iframeLoadState[index].timeoutId = setTimeout(function() {{
                if (!iframeLoadState[index].loaded) {{
                    setIframeStatus(index, 'error', 'Timeout - page not responding');
                }}
            }}, LOAD_TIMEOUT);

            // Listen for load event
            iframe.addEventListener('load', function onLoad() {{
                if (iframeLoadState[index].timeoutId) {{
                    clearTimeout(iframeLoadState[index].timeoutId);
                }}
                iframeLoadState[index].loaded = true;
                var loadTime = Date.now() - iframeLoadState[index].startTime;
                if (loadTime > 5000) {{
                    setIframeStatus(index, 'connected', 'Loaded (slow: ' + Math.round(loadTime/1000) + 's)');
                }} else {{
                    setIframeStatus(index, 'connected', 'Loaded (' + loadTime + 'ms)');
                }}
                iframe.removeEventListener('load', onLoad);
            }});

            // Listen for error event
            iframe.addEventListener('error', function onError() {{
                if (iframeLoadState[index].timeoutId) {{
                    clearTimeout(iframeLoadState[index].timeoutId);
                }}
                if (!iframeLoadState[index].loaded) {{
                    setIframeStatus(index, 'error', 'Failed to load');
                }}
                iframe.removeEventListener('error', onError);
            }});

            // If page already loaded but iframe hasn't, force reload to catch event
            if (document.readyState === 'complete') {{
                var src = iframe.src;
                if (src) {{
                    iframe.src = '';
                    setTimeout(function() {{ iframe.src = src; }}, 10);
                }}
            }}
        }}

        // Initialize monitoring for all iframes on page load
        function initIframeMonitoring() {{
            iframeTestData.forEach(function(item) {{
                monitorIframe(item.index);
            }});
        }}

        // Run on page load
        if (document.readyState === 'complete') {{
            initIframeMonitoring();
        }} else {{
            window.addEventListener('load', initIframeMonitoring);
        }}

        // Periodic re-check every 60 seconds (reload iframes that failed)
        setInterval(function() {{
            iframeTestData.forEach(function(item) {{
                var state = iframeLoadState[item.index];
                // Only retry failed iframes
                if (state && !state.loaded) {{
                    var iframe = document.getElementById('iframe-' + item.index);
                    if (iframe && iframe.src) {{
                        // Reset and retry
                        iframeLoadState[item.index].startTime = Date.now();
                        iframeLoadState[item.index].loaded = false;
                        setIframeStatus(item.index, 'loading', 'Retrying...');

                        // Clear old timeout
                        if (state.timeoutId) clearTimeout(state.timeoutId);

                        // Set new timeout
                        iframeLoadState[item.index].timeoutId = setTimeout(function() {{
                            if (!iframeLoadState[item.index].loaded) {{
                                setIframeStatus(item.index, 'error', 'Timeout - page not responding');
                            }}
                        }}, LOAD_TIMEOUT);

                        // Force reload by resetting src
                        var src = iframe.src;
                        iframe.src = '';
                        iframe.src = src;
                    }}
                }}
            }});
        }}, 60000);
        </script>
        """

        # Command button script (for button widgets)
        command_script = """
        <script>
        function sendCommand(btn) {
            var protocol = btn.dataset.protocol;
            var host = btn.dataset.host;
            var port = btn.dataset.port;
            var command = btn.dataset.command;
            
            btn.disabled = true;
            btn.classList.add('sending');
            var originalText = btn.textContent;
            btn.textContent = 'Sending...';
            
            fetch('/api/send-command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    protocol: protocol,
                    host: host,
                    port: parseInt(port),
                    command: command
                })
            })
            .then(response => response.json())
            .then(data => {
                btn.disabled = false;
                btn.classList.remove('sending');
                if (data.success) {
                    btn.classList.add('success');
                    btn.textContent = '✓ Sent';
                    setTimeout(() => {
                        btn.classList.remove('success');
                        btn.textContent = originalText;
                    }, 1500);
                } else {
                    btn.classList.add('error');
                    btn.textContent = '✗ Failed';
                    console.error('Command error:', data.error);
                    setTimeout(() => {
                        btn.classList.remove('error');
                        btn.textContent = originalText;
                    }, 2000);
                }
            })
            .catch(err => {
                btn.disabled = false;
                btn.classList.remove('sending');
                btn.classList.add('error');
                btn.textContent = '✗ Error';
                console.error('Network error:', err);
                setTimeout(() => {
                    btn.classList.remove('error');
                    btn.textContent = originalText;
                }, 2000);
            });
        }
        </script>
        """
        
        content = f'{widgets_html}<div class="iframe-grid" style="--cols:{cols};">{iframe_html}</div>{status_script}{command_script}'
    
    # Add auto-refresh if configured
    refresh_script = ""
    if refresh > 0:
        refresh_script = f'<script>setTimeout(()=>location.reload(),{refresh * 1000});</script>'
    
    # Fullscreen functionality (only show when auto_fullscreen is enabled)
    auto_fullscreen = config["settings"].get("auto_fullscreen", False)
    fullscreen_script = ""
    fullscreen_prompt = ""
    
    if auto_fullscreen:
        fullscreen_script = """
    <style>
    .fullscreen-btn {
        position: fixed;
        bottom: 1rem;
        right: 1rem;
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        color: var(--text-primary);
        padding: 0.5rem 1rem;
        border-radius: var(--radius);
        cursor: pointer;
        font-family: inherit;
        font-size: 0.8rem;
        z-index: 1000;
        transition: all 0.15s;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .fullscreen-btn:hover {
        background: var(--accent);
        border-color: var(--accent);
    }
    .fullscreen-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.9);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        z-index: 9999;
        cursor: pointer;
    }
    .fullscreen-overlay h2 {
        color: white;
        margin-bottom: 1rem;
        font-size: 1.5rem;
    }
    .fullscreen-overlay p {
        color: #888;
        margin-bottom: 2rem;
    }
    .fullscreen-overlay .btn-enter {
        background: var(--accent);
        color: white;
        border: none;
        padding: 1rem 2rem;
        font-size: 1.1rem;
        border-radius: var(--radius);
        cursor: pointer;
    }
    .fullscreen-overlay .btn-skip {
        margin-top: 1rem;
        background: none;
        border: 1px solid #444;
        color: #888;
        padding: 0.5rem 1rem;
        border-radius: var(--radius);
        cursor: pointer;
    }
    </style>
    <button class="fullscreen-btn" onclick="toggleFullscreen()" title="Toggle Fullscreen">
        <span id="fs-icon">⛶</span> <span id="fs-text">Fullscreen</span>
    </button>
    <script>
    function toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(err => {
                console.log('Fullscreen error:', err);
            });
        } else {
            document.exitFullscreen();
        }
    }
    
    document.addEventListener('fullscreenchange', function() {
        var icon = document.getElementById('fs-icon');
        var text = document.getElementById('fs-text');
        if (document.fullscreenElement) {
            icon.textContent = '⛶';
            text.textContent = 'Exit';
        } else {
            icon.textContent = '⛶';
            text.textContent = 'Fullscreen';
        }
    });
    </script>
    """
    
        # Auto-fullscreen overlay prompt
        fullscreen_prompt = """
        <div class="fullscreen-overlay" id="fs-overlay" onclick="enterFullscreenAndClose(event)">
            <h2>⛶ Dashboard</h2>
            <p>Click anywhere or press the button to enter fullscreen mode</p>
            <button class="btn-enter" onclick="enterFullscreenAndClose(event)">Enter Fullscreen</button>
            <button class="btn-skip" onclick="closeOverlay(event)">Skip</button>
        </div>
        <script>
        function enterFullscreenAndClose(e) {
            e.stopPropagation();
            document.documentElement.requestFullscreen().then(function() {
                document.getElementById('fs-overlay').style.display = 'none';
            }).catch(function(err) {
                document.getElementById('fs-overlay').style.display = 'none';
            });
        }
        function closeOverlay(e) {
            e.stopPropagation();
            document.getElementById('fs-overlay').style.display = 'none';
        }
        // Also close on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                var overlay = document.getElementById('fs-overlay');
                if (overlay) overlay.style.display = 'none';
            }
        });
        </script>
        """
    
    return render_page(config["settings"]["page_title"], content + refresh_script + fullscreen_script + fullscreen_prompt, user, config)

def render_admin_page(user, config, message=None, error=None):
    """Render the admin panel."""
    msg_html = ""
    if message:
        msg_html = f'<div class="message success">{escape_html(message)}</div>'
    if error:
        msg_html = f'<div class="message error">{escape_html(error)}</div>'
    
    # Get appearance settings with defaults
    appearance = config.get("appearance", DEFAULT_CONFIG["appearance"])
    colors = appearance.get("colors", DEFAULT_CONFIG["appearance"]["colors"])
    bg = appearance.get("background", DEFAULT_CONFIG["appearance"]["background"])
    header_cfg = appearance.get("header", DEFAULT_CONFIG["appearance"]["header"])
    footer_cfg = appearance.get("footer", DEFAULT_CONFIG["appearance"]["footer"])
    
    # iFrames section
    iframes_list = ""
    total_iframes = len(config.get("iframes", []))
    for i, iframe in enumerate(config.get("iframes", [])):
        name = escape_html(iframe.get("name", ""))
        url = escape_html(iframe.get("url", ""))
        height = iframe.get("height", 400)
        width = iframe.get("width", 100)
        zoom = iframe.get("zoom", 100)
        show_url = iframe.get("show_url", True)
        show_header = iframe.get("show_header", True)
        show_status = iframe.get("show_status", True)
        header_text = escape_html(iframe.get("header_text", ""))
        border_style = iframe.get("border_style", "default")
        border_color = escape_html(iframe.get("border_color", ""))
        allow_external = iframe.get("allow_external", False)
        use_embed_code = iframe.get("use_embed_code", False)
        embed_code = escape_html(iframe.get("embed_code", ""))
        
        # Display URL or embed code indicator
        url_display = "📋 Embed Code" if use_embed_code else url
        
        # Move buttons (disable at boundaries)
        move_up_disabled = 'disabled style="opacity:0.3;cursor:not-allowed;"' if i == 0 else ''
        move_down_disabled = 'disabled style="opacity:0.3;cursor:not-allowed;"' if i == total_iframes - 1 else ''
        
        # Status indicators
        status_items = [f"{height}px"]
        if width != 100:
            status_items.append(f"{width}%w")
        if zoom != 100:
            status_items.append(f"{zoom}% zoom")
        if not show_url:
            status_items.append("URL hidden")
        if not show_header:
            status_items.append("No header")
        if header_text:
            status_items.append("Custom title")
        if border_style != "default":
            status_items.append(f"Border: {border_style}")
        if use_embed_code:
            status_items.append("📋 Embed")
        elif allow_external:
            status_items.append("🌐 External")
        status_str = " • ".join(status_items)
        
        iframes_list += f"""
        <li class="iframe-item" id="iframe-item-{i}">
            <div class="item-row">
                <div class="item-order">
                    <form method="POST" action="/admin/iframe/move" style="display:inline;">
                        <input type="hidden" name="index" value="{i}">
                        <input type="hidden" name="direction" value="up">
                        <button type="submit" class="btn-icon" title="Move up" {move_up_disabled}>▲</button>
                    </form>
                    <form method="POST" action="/admin/iframe/move" style="display:inline;">
                        <input type="hidden" name="index" value="{i}">
                        <input type="hidden" name="direction" value="down">
                        <button type="submit" class="btn-icon" title="Move down" {move_down_disabled}>▼</button>
                    </form>
                </div>
                <div class="item-info">
                    <strong>{name}</strong>
                    <small>{url_display}</small>
                    <small style="color:var(--text-secondary);opacity:0.7;">{status_str}</small>
                </div>
                <div class="item-actions">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="toggleEditIframe({i})">Edit</button>
                    <form method="POST" action="/admin/iframe/delete" style="display:inline;">
                        <input type="hidden" name="index" value="{i}">
                        <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this iFrame?')">Delete</button>
                    </form>
                </div>
            </div>
            <div class="edit-panel" id="edit-iframe-{i}" style="display:none;">
                <form method="POST" action="/admin/iframe/edit">
                    <input type="hidden" name="index" value="{i}">
                    
                    <div class="edit-section">
                        <h5>Basic Settings</h5>
                        <div class="inline-form">
                            <div class="form-group" style="flex:1.5;">
                                <label>Name</label>
                                <input type="text" name="name" value="{name}" required>
                            </div>
                            <div class="form-group" style="flex:2;">
                                <label>URL {"" if allow_external else "(Local IPs only)"}</label>
                                <input type="url" name="url" value="{url}" required>
                            </div>
                        </div>
                    </div>
                    
                    <div class="edit-section">
                        <h5>Size & Zoom</h5>
                        <div class="inline-form">
                            <div class="form-group">
                                <label>Height (px)</label>
                                <input type="number" name="height" value="{height}" min="100" max="2000">
                            </div>
                            <div class="form-group">
                                <label>Width (%)</label>
                                <input type="number" name="width" value="{width}" min="20" max="100">
                            </div>
                            <div class="form-group">
                                <label>Zoom (%)</label>
                                <input type="number" name="zoom" value="{zoom}" min="25" max="200" step="5">
                            </div>
                        </div>
                        <small style="color:var(--text-secondary);display:block;margin-top:0.5rem;">Zoom: 100% = normal, &lt;100% = zoom out (see more), &gt;100% = zoom in (larger content)</small>
                    </div>
                    
                    <div class="edit-section">
                        <h5>Display Options</h5>
                        <div class="inline-form" style="margin-bottom:0.75rem;">
                            <div class="form-group">
                                <label>Show Header</label>
                                <select name="show_header">
                                    <option value="1" {"selected" if show_header else ""}>Yes</option>
                                    <option value="0" {"selected" if not show_header else ""}>No</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Show URL</label>
                                <select name="show_url">
                                    <option value="1" {"selected" if show_url else ""}>Yes</option>
                                    <option value="0" {"selected" if not show_url else ""}>No (hide IP)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Status Icon</label>
                                <select name="show_status">
                                    <option value="1" {"selected" if show_status else ""}>Show</option>
                                    <option value="0" {"selected" if not show_status else ""}>Hide</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Header Text (leave empty to use Name)</label>
                            <input type="text" name="header_text" value="{header_text}" placeholder="Custom title for the header bar">
                        </div>
                    </div>
                    
                    <div class="edit-section">
                        <h5>Border Style</h5>
                        <div class="inline-form">
                            <div class="form-group">
                                <label>Border Style</label>
                                <select name="border_style">
                                    <option value="default" {"selected" if border_style == "default" else ""}>Default</option>
                                    <option value="none" {"selected" if border_style == "none" else ""}>None</option>
                                    <option value="thin" {"selected" if border_style == "thin" else ""}>Thin</option>
                                    <option value="thick" {"selected" if border_style == "thick" else ""}>Thick</option>
                                    <option value="rounded" {"selected" if border_style == "rounded" else ""}>Rounded</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Border Color (optional)</label>
                                <input type="text" name="border_color" value="{border_color}" placeholder="#3b82f6 or empty for default">
                            </div>
                        </div>
                    </div>
                    
                    <div class="edit-section">
                        <h5>🌐 Advanced</h5>
                        <div class="toggle-row" style="padding:0.75rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:0.75rem;">
                            <div>
                                <label style="margin-bottom:0;">Allow External URLs</label>
                                <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Enable to load websites from the internet (not just local IPs)</small>
                            </div>
                            <select name="allow_external" style="width:auto;">
                                <option value="0" {"selected" if not allow_external else ""}>Off (Local only)</option>
                                <option value="1" {"selected" if allow_external else ""}>On (Any URL)</option>
                            </select>
                        </div>
                        
                        <div class="toggle-row" style="padding:0.75rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:0.75rem;">
                            <div>
                                <label style="margin-bottom:0;">📋 Use Embed Code</label>
                                <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Paste an iframe/HTML snippet instead of a URL</small>
                            </div>
                            <select name="use_embed_code" style="width:auto;" onchange="toggleEmbedCode{i}(this.value)">
                                <option value="0" {"selected" if not use_embed_code else ""}>Off (Use URL)</option>
                                <option value="1" {"selected" if use_embed_code else ""}>On (Use Code)</option>
                            </select>
                        </div>
                        
                        <div id="embed-code-edit-{i}" style="display:{"block" if use_embed_code else "none"};">
                            <div class="form-group">
                                <label>Embed Code</label>
                                <textarea name="embed_code" rows="4" placeholder='<iframe src="..." width="100%" height="400"></iframe>' style="font-family:monospace;font-size:0.85rem;">{embed_code}</textarea>
                            </div>
                            <small style="color:var(--text-secondary);display:block;margin-top:0.5rem;">Paste the full embed code from widgets, videos, maps, etc. The code will be rendered directly.</small>
                        </div>
                        
                        <small style="color:var(--danger);display:block;margin-top:0.5rem;">⚠️ Note: Many websites block being loaded in iframes (X-Frame-Options). External URLs and embed codes work best with sites that explicitly allow embedding.</small>
                        
                        <script>
                        function toggleEmbedCode{i}(val) {{
                            document.getElementById('embed-code-edit-{i}').style.display = val === '1' ? 'block' : 'none';
                        }}
                        </script>
                    </div>
                    
                    <div style="margin-top:1rem;display:flex;gap:0.5rem;">
                        <button type="submit">Save Changes</button>
                        <button type="button" class="btn btn-secondary" onclick="toggleEditIframe({i})">Cancel</button>
                    </div>
                </form>
            </div>
        </li>
        """
    if not iframes_list:
        iframes_list = '<li class="empty-state">No iFrames configured</li>'
    
    # Users section
    users_list = ""
    for username, udata in config.get("users", {}).items():
        is_admin_badge = "Admin" if udata.get("is_admin") else "User"
        is_current_user = username == user
        user_id = f"user-{abs(hash(username)) % 100000}"
        
        users_list += f"""
        <li>
            <div class="item-row">
                <div class="item-info">
                    <strong>{escape_html(username)}</strong> {' <span style="color:var(--accent);font-size:0.75rem;">(you)</span>' if is_current_user else ''}
                    <small>{is_admin_badge}</small>
                </div>
                <div class="item-actions">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="togglePasswordChange('{user_id}')">Change Password</button>
                    {"" if is_current_user else f'''
                    <form method="POST" action="/admin/user/delete" style="display:inline;">
                        <input type="hidden" name="username" value="{escape_html(username)}">
                        <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete user {escape_html(username)}?')">Delete</button>
                    </form>
                    '''}
                </div>
            </div>
            <div class="edit-panel" id="{user_id}-password" style="display:none;">
                <form method="POST" action="/admin/user/change-password">
                    <input type="hidden" name="username" value="{escape_html(username)}">
                    <div class="inline-form">
                        <div class="form-group">
                            <label>New Password</label>
                            <input type="password" name="new_password" required minlength="6" placeholder="Minimum 6 characters">
                        </div>
                        <div class="form-group">
                            <label>Confirm Password</label>
                            <input type="password" name="confirm_password" required minlength="6" placeholder="Repeat password">
                        </div>
                    </div>
                    <div style="display:flex;gap:0.5rem;margin-top:1rem;">
                        <button type="submit">Update Password</button>
                        <button type="button" class="btn btn-secondary" onclick="togglePasswordChange('{user_id}')">Cancel</button>
                    </div>
                </form>
            </div>
        </li>
        """
    if not users_list:
        users_list = '<li class="empty-state">No users configured</li>'
    
    # Branding section
    branding = config.get("branding", {})
    logo_preview = ""
    if branding.get("logo") and branding.get("logo_mime"):
        logo_preview = f'''
        <div class="preview-box" style="display:flex;align-items:center;gap:1rem;">
            <img src="data:{branding["logo_mime"]};base64,{branding["logo"]}" style="height:48px;max-width:200px;object-fit:contain;" alt="Current logo">
            <div style="flex:1;"><strong>Current Logo</strong><small style="display:block;color:var(--text-secondary);">{branding.get("logo_mime", "unknown")}</small></div>
            <form method="POST" action="/admin/branding/logo/delete" style="display:inline;"><button type="submit" class="btn btn-danger btn-sm">Remove</button></form>
        </div>
        '''
    else:
        logo_preview = '<p style="color:var(--text-secondary);margin-bottom:1rem;">No logo uploaded.</p>'
    
    favicon_preview = ""
    if branding.get("favicon") and branding.get("favicon_mime"):
        favicon_preview = f'''
        <div class="preview-box" style="display:flex;align-items:center;gap:1rem;">
            <img src="data:{branding["favicon_mime"]};base64,{branding["favicon"]}" style="height:32px;width:32px;object-fit:contain;" alt="Current favicon">
            <div style="flex:1;"><strong>Current Favicon</strong><small style="display:block;color:var(--text-secondary);">{branding.get("favicon_mime", "unknown")}</small></div>
            <form method="POST" action="/admin/branding/favicon/delete" style="display:inline;"><button type="submit" class="btn btn-danger btn-sm">Remove</button></form>
        </div>
        '''
    else:
        favicon_preview = '<p style="color:var(--text-secondary);margin-bottom:1rem;">No favicon uploaded.</p>'
    
    # Apple Touch Icon preview (for iOS Add to Home Screen)
    apple_touch_icon_preview = ""
    if branding.get("apple_touch_icon") and branding.get("apple_touch_icon_mime"):
        apple_touch_icon_preview = f'''
        <div class="preview-box" style="display:flex;align-items:center;gap:1rem;">
            <img src="data:{branding["apple_touch_icon_mime"]};base64,{branding["apple_touch_icon"]}" style="height:60px;width:60px;object-fit:contain;border-radius:12px;" alt="Current Apple Touch Icon">
            <div style="flex:1;"><strong>Current Icon</strong><small style="display:block;color:var(--text-secondary);">{branding.get("apple_touch_icon_mime", "unknown")}</small></div>
            <form method="POST" action="/admin/branding/apple-touch-icon/delete" style="display:inline;"><button type="submit" class="btn btn-danger btn-sm">Remove</button></form>
        </div>
        '''
    else:
        apple_touch_icon_preview = '<p style="color:var(--text-secondary);margin-bottom:1rem;">No icon uploaded. iOS will use a screenshot.</p>'
    
    # Background preview
    bg_preview = ""
    if bg.get("type") == "image" and bg.get("image"):
        bg_preview = f'''
        <div class="preview-box" style="display:flex;align-items:center;gap:1rem;">
            <img src="data:{bg.get("image_mime", "image/png")};base64,{bg["image"]}" style="height:60px;max-width:120px;object-fit:cover;border-radius:4px;" alt="Background">
            <div style="flex:1;"><strong>Background Image</strong><small style="display:block;color:var(--text-secondary);">Opacity: {bg.get("image_opacity", 100)}%</small></div>
            <form method="POST" action="/admin/appearance/bg/delete" style="display:inline;"><button type="submit" class="btn btn-danger btn-sm">Remove</button></form>
        </div>
        '''
    
    content = f"""
    {msg_html}

    <!-- Server Status Dashboard (Always visible) -->
    {render_status_dashboard(config)}

    <!-- Admin Alert Banners -->
    {render_admin_alerts(config)}

    <script>
    function toggleEditIframe(index) {{
        var panel = document.getElementById('edit-iframe-' + index);
        if (panel.style.display === 'none') {{
            // Close all other edit panels first
            document.querySelectorAll('.edit-panel').forEach(function(p) {{
                p.style.display = 'none';
            }});
            panel.style.display = 'block';
        }} else {{
            panel.style.display = 'none';
        }}
    }}
    
    function togglePasswordChange(userId) {{
        var panel = document.getElementById(userId + '-password');
        if (!panel) {{
            console.error('Password panel not found for:', userId);
            alert('Error: Could not find password change panel');
            return;
        }}
        if (panel.style.display === 'none' || panel.style.display === '') {{
            // Close all other password panels first
            document.querySelectorAll('[id$="-password"].edit-panel').forEach(function(p) {{
                p.style.display = 'none';
            }});
            panel.style.display = 'block';
            var input = panel.querySelector('input[name="new_password"]');
            if (input) input.focus();
        }} else {{
            panel.style.display = 'none';
            // Clear the form
            var form = panel.querySelector('form');
            if (form) form.reset();
        }}
    }}
    
    function switchTab(tabId) {{
        // Hide all panels
        document.querySelectorAll('.tab-panel').forEach(function(panel) {{
            panel.classList.remove('active');
        }});
        // Deactivate all tabs
        document.querySelectorAll('.admin-tab').forEach(function(tab) {{
            tab.classList.remove('active');
        }});
        // Show selected panel
        document.getElementById('panel-' + tabId).classList.add('active');
        // Activate selected tab
        document.getElementById('tab-' + tabId).classList.add('active');
        // Save to localStorage
        localStorage.setItem('adminTab', tabId);
    }}
    
    // Restore last tab on load
    document.addEventListener('DOMContentLoaded', function() {{
        var savedTab = localStorage.getItem('adminTab') || 'iframes';
        switchTab(savedTab);
    }});
    </script>
    
    <div class="admin-tabs">
        <button class="admin-tab active" id="tab-iframes" onclick="switchTab('iframes')" title="iFrames">
            <span class="admin-tab-icon">📺</span><span class="admin-tab-text">iFrames</span>
        </button>
        <button class="admin-tab" id="tab-widgets" onclick="switchTab('widgets')" title="Widgets">
            <span class="admin-tab-icon">🧩</span><span class="admin-tab-text">Widgets</span>
        </button>
        <button class="admin-tab" id="tab-appearance" onclick="switchTab('appearance')" title="Appearance">
            <span class="admin-tab-icon">🎨</span><span class="admin-tab-text">Appearance</span>
        </button>
        <button class="admin-tab" id="tab-branding" onclick="switchTab('branding')" title="Branding">
            <span class="admin-tab-icon">✨</span><span class="admin-tab-text">Branding</span>
        </button>
        <button class="admin-tab" id="tab-users" onclick="switchTab('users')" title="Users">
            <span class="admin-tab-icon">👥</span><span class="admin-tab-text">Users</span>
        </button>
        <button class="admin-tab" id="tab-network" onclick="switchTab('network')" title="Network">
            <span class="admin-tab-icon">🌐</span><span class="admin-tab-text">Network</span>
        </button>
        <button class="admin-tab" id="tab-settings" onclick="switchTab('settings')" title="Settings">
            <span class="admin-tab-icon">⚙️</span><span class="admin-tab-text">Settings</span>
        </button>
        <button class="admin-tab" id="tab-watchdog" onclick="switchTab('watchdog')" title="Watchdog">
            <span class="admin-tab-icon">🐕</span><span class="admin-tab-text">Watchdog</span>
        </button>
        <button class="admin-tab" id="tab-system" onclick="switchTab('system')" title="System">
            <span class="admin-tab-icon">🔧</span><span class="admin-tab-text">System</span>
        </button>
    </div>
    
    <!-- iFrames Panel -->
    <div class="tab-panel active" id="panel-iframes">
        <div class="admin-section">
            <h3>📺 iFrames</h3>
            <div class="admin-content">
                <ul class="item-list">{iframes_list}</ul>
                <hr style="border:none;border-top:1px solid var(--border);margin:1.5rem 0;">
                <h4 style="font-size:0.85rem;margin-bottom:1rem;color:var(--text-secondary);">Add New iFrame</h4>
                <form method="POST" action="/admin/iframe/add">
                    <div class="inline-form" style="margin-bottom:1rem;">
                        <div class="form-group"><label>Name</label><input type="text" name="name" placeholder="Display name" required></div>
                        <div class="form-group" style="flex:2;"><label>URL</label><input type="url" name="url" placeholder="http://192.168.1.100:8000" required></div>
                        <div class="form-group" style="flex:0.5;"><label>Height (px)</label><input type="number" name="height" value="400" min="100" max="2000"></div>
                    </div>
                    <details style="margin-bottom:1rem;">
                        <summary style="cursor:pointer;color:var(--accent);font-size:0.85rem;margin-bottom:0.5rem;">+ Advanced Options</summary>
                        <div style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-top:0.5rem;">
                            <div class="inline-form" style="margin-bottom:1rem;">
                                <div class="form-group"><label>Width (%)</label><input type="number" name="width" value="100" min="20" max="100"></div>
                                <div class="form-group"><label>Zoom (%)</label><input type="number" name="zoom" value="100" min="25" max="200" step="5"></div>
                                <div class="form-group"><label>Show Header</label><select name="show_header"><option value="1" selected>Yes</option><option value="0">No</option></select></div>
                                <div class="form-group"><label>Show URL</label><select name="show_url"><option value="1" selected>Yes</option><option value="0">No (hide IP)</option></select></div>
                                <div class="form-group"><label>Status Icon</label><select name="show_status"><option value="1" selected>Show</option><option value="0">Hide</option></select></div>
                            </div>
                            <div class="form-group" style="margin-bottom:1rem;">
                                <label>Header Text (leave empty to use Name)</label>
                                <input type="text" name="header_text" placeholder="Custom title for the header bar">
                            </div>
                            <div class="inline-form" style="margin-bottom:1rem;">
                                <div class="form-group"><label>Border Style</label><select name="border_style"><option value="default">Default</option><option value="none">None</option><option value="thin">Thin</option><option value="thick">Thick</option><option value="rounded">Rounded</option></select></div>
                                <div class="form-group"><label>Border Color</label><input type="text" name="border_color" placeholder="#3b82f6 or empty"></div>
                            </div>
                            <div class="toggle-row" style="padding:0.75rem;background:var(--bg-secondary);border-radius:var(--radius);margin-bottom:0.8rem;">
                                <div>
                                    <label style="margin-bottom:0;">🌐 Allow External URLs</label>
                                    <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Load websites from the internet</small>
                                </div>
                                <select name="allow_external" style="width:auto;">
                                    <option value="0" selected>Off (Local only)</option>
                                    <option value="1">On (Any URL)</option>
                                </select>
                            </div>
                            <div class="toggle-row" style="padding:0.75rem;background:var(--bg-secondary);border-radius:var(--radius);margin-bottom:0.8rem;">
                                <div>
                                    <label style="margin-bottom:0;">📋 Use Embed Code</label>
                                    <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Paste an iframe/HTML snippet instead of a URL</small>
                                </div>
                                <select name="use_embed_code" style="width:auto;" onchange="toggleAddEmbedCode(this.value)">
                                    <option value="0" selected>Off (Use URL)</option>
                                    <option value="1">On (Use Code)</option>
                                </select>
                            </div>
                            <div id="embed-code-add" style="display:none;margin-bottom:0.8rem;">
                                <div class="form-group">
                                    <label>Embed Code</label>
                                    <textarea name="embed_code" rows="4" placeholder='<iframe src="..." width="100%" height="400"></iframe>' style="font-family:monospace;font-size:0.85rem;"></textarea>
                                </div>
                                <small style="color:var(--text-secondary);display:block;margin-top:0.5rem;">Paste the full embed code from widgets, videos, maps, etc.</small>
                            </div>
                            <small style="color:var(--text-secondary);display:block;">Zoom: 100% = normal, &lt;100% = zoom out, &gt;100% = zoom in</small>
                            <small style="color:var(--danger);display:block;margin-top:0.5rem;">⚠️ Many websites block iframe embedding. External URLs and embed codes work best with sites that allow it.</small>
                            <script>
                            function toggleAddEmbedCode(val) {{
                                document.getElementById('embed-code-add').style.display = val === '1' ? 'block' : 'none';
                            }}
                            </script>
                        </div>
                    </details>
                    <button type="submit">Add iFrame</button>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Widgets Panel -->
    <div class="tab-panel" id="panel-widgets">
        {render_widgets_section(config)}
    </div>
    
    <!-- Appearance Panel -->
    <div class="tab-panel" id="panel-appearance">
        <div class="admin-section">
            <h3>🎨 Appearance</h3>
        <div class="admin-content">
            <div class="admin-subsection">
                <h4>🎨 Theme Colors</h4>
                <form method="POST" action="/admin/appearance/colors">
                    <div class="color-grid">
                        <div class="form-group"><label>Background Primary</label><input type="color" name="bg_primary" value="{colors.get('bg_primary', '#0a0a0b')}"></div>
                        <div class="form-group"><label>Background Secondary</label><input type="color" name="bg_secondary" value="{colors.get('bg_secondary', '#141416')}"></div>
                        <div class="form-group"><label>Background Tertiary</label><input type="color" name="bg_tertiary" value="{colors.get('bg_tertiary', '#1c1c1f')}"></div>
                        <div class="form-group"><label>Border Color</label><input type="color" name="border" value="{colors.get('border', '#2a2a2d')}"></div>
                        <div class="form-group"><label>Text Primary</label><input type="color" name="text_primary" value="{colors.get('text_primary', '#e8e8e8')}"></div>
                        <div class="form-group"><label>Text Secondary</label><input type="color" name="text_secondary" value="{colors.get('text_secondary', '#888888')}"></div>
                        <div class="form-group"><label>Accent Color</label><input type="color" name="accent" value="{colors.get('accent', '#3b82f6')}"></div>
                        <div class="form-group"><label>Accent Hover</label><input type="color" name="accent_hover" value="{colors.get('accent_hover', '#2563eb')}"></div>
                        <div class="form-group"><label>Success Color</label><input type="color" name="success" value="{colors.get('success', '#22c55e')}"></div>
                        <div class="form-group"><label>Danger Color</label><input type="color" name="danger" value="{colors.get('danger', '#ef4444')}"></div>
                    </div>
                    <div style="margin-top:1rem;display:flex;gap:0.5rem;">
                        <button type="submit">Save Colors</button>
                        <button type="submit" name="reset" value="1" class="btn btn-secondary">Reset to Defaults</button>
                    </div>
                </form>
            </div>
            
            <div class="admin-subsection">
                <h4>🖼️ Background</h4>
                {bg_preview}
                <form method="POST" action="/admin/appearance/background" enctype="multipart/form-data">
                    <div class="inline-form" style="margin-bottom:1rem;">
                        <div class="form-group"><label>Background Type</label>
                            <select name="bg_type" id="bg-type-select" onchange="toggleBgOptions()">
                                <option value="solid" {"selected" if bg.get("type") == "solid" else ""}>Solid Color</option>
                                <option value="gradient" {"selected" if bg.get("type") == "gradient" else ""}>Gradient</option>
                                <option value="image" {"selected" if bg.get("type") == "image" else ""}>Image</option>
                            </select>
                        </div>
                    </div>
                    <div id="gradient-options" style="display:{"flex" if bg.get("type") == "gradient" else "none"};" class="inline-form">
                        <div class="form-group"><label>Start Color</label><input type="color" name="gradient_start" value="{bg.get('gradient_start', '#0a0a0b')}"></div>
                        <div class="form-group"><label>End Color</label><input type="color" name="gradient_end" value="{bg.get('gradient_end', '#1a1a2e')}"></div>
                        <div class="form-group"><label>Direction</label>
                            <select name="gradient_direction">
                                <option value="to bottom" {"selected" if bg.get("gradient_direction") == "to bottom" else ""}>Top → Bottom</option>
                                <option value="to right" {"selected" if bg.get("gradient_direction") == "to right" else ""}>Left → Right</option>
                                <option value="to bottom right" {"selected" if bg.get("gradient_direction") == "to bottom right" else ""}>Diagonal ↘</option>
                                <option value="to bottom left" {"selected" if bg.get("gradient_direction") == "to bottom left" else ""}>Diagonal ↙</option>
                            </select>
                        </div>
                    </div>
                    <div id="image-options" style="display:{"block" if bg.get("type") == "image" else "none"};">
                        <div class="inline-form">
                            <div class="form-group" style="flex:2;"><label>Upload Image (max 2MB)</label><input type="file" name="bg_image" accept="image/*" style="padding:0.5rem;"></div>
                            <div class="form-group"><label>Size</label>
                                <select name="image_size">
                                    <option value="cover" {"selected" if bg.get("image_size") == "cover" else ""}>Cover</option>
                                    <option value="contain" {"selected" if bg.get("image_size") == "contain" else ""}>Contain</option>
                                    <option value="repeat" {"selected" if bg.get("image_size") == "repeat" else ""}>Tile</option>
                                </select>
                            </div>
                            <div class="form-group"><label>Opacity %</label><input type="number" name="image_opacity" value="{bg.get('image_opacity', 100)}" min="10" max="100"></div>
                        </div>
                    </div>
                    <button type="submit" style="margin-top:1rem;">Save Background</button>
                </form>
                <script>function toggleBgOptions(){{var t=document.getElementById('bg-type-select').value;document.getElementById('gradient-options').style.display=t==='gradient'?'flex':'none';document.getElementById('image-options').style.display=t==='image'?'block':'none';}}</script>
            </div>
            
            <div class="admin-subsection">
                <h4>📌 Header Settings</h4>
                <form method="POST" action="/admin/appearance/header">
                    <div class="toggle-row"><label>Show Header</label><select name="show" style="width:auto;"><option value="1" {"selected" if header_cfg.get("show", True) else ""}>Yes</option><option value="0" {"selected" if not header_cfg.get("show", True) else ""}>No</option></select></div>
                    <div class="toggle-row"><label>Sticky Header</label><select name="sticky" style="width:auto;"><option value="1" {"selected" if header_cfg.get("sticky", True) else ""}>Yes</option><option value="0" {"selected" if not header_cfg.get("sticky", True) else ""}>No</option></select></div>
                    <div class="form-group" style="margin-top:1rem;"><label>Custom Subtitle</label><input type="text" name="custom_text" value="{escape_html(header_cfg.get('custom_text', ''))}" placeholder="Optional subtitle"></div>
                    <div class="inline-form">
                        <div class="form-group"><label>Header Background (empty=default)</label><input type="text" name="bg_color" value="{escape_html(header_cfg.get('bg_color', ''))}" placeholder="#141416"></div>
                        <div class="form-group"><label>Header Text Color (empty=default)</label><input type="text" name="text_color" value="{escape_html(header_cfg.get('text_color', ''))}" placeholder="#e8e8e8"></div>
                    </div>
                    <button type="submit" style="margin-top:0.5rem;">Save Header</button>
                </form>
            </div>
            
            <div class="admin-subsection">
                <h4>📝 Footer Settings</h4>
                <form method="POST" action="/admin/appearance/footer">
                    <div class="toggle-row"><label>Show Footer</label><select name="show" style="width:auto;"><option value="1" {"selected" if footer_cfg.get("show", True) else ""}>Yes</option><option value="0" {"selected" if not footer_cfg.get("show", True) else ""}>No</option></select></div>
                    <div class="toggle-row"><label>Show Python Version</label><select name="show_python_version" style="width:auto;"><option value="1" {"selected" if footer_cfg.get("show_python_version", True) else ""}>Yes</option><option value="0" {"selected" if not footer_cfg.get("show_python_version", True) else ""}>No</option></select></div>
                    <div class="form-group" style="margin-top:1rem;"><label>Footer Text</label><input type="text" name="text" value="{escape_html(footer_cfg.get('text', 'Multi-Frames v1.1.10 by LTS, Inc.'))}" placeholder="Footer text"></div>
                    <button type="submit">Save Footer</button>
                </form>
                
                <div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);">
                    <h5 style="font-size:0.85rem;margin-bottom:0.75rem;color:var(--text-secondary);">🔗 Footer Links</h5>
                    {render_footer_links_editor(footer_cfg.get('links', []))}
                </div>
            </div>
            
            <div class="admin-subsection">
                <h4>✨ Custom CSS</h4>
                <form method="POST" action="/admin/appearance/css">
                    <div class="form-group"><label>Additional CSS (Advanced)</label><textarea name="custom_css" rows="5" placeholder="/* Custom CSS */">{escape_html(appearance.get('custom_css', ''))}</textarea></div>
                    <button type="submit">Save CSS</button>
                </form>
            </div>
        </div>
    </div>
    </div>
    
    <!-- Branding Panel -->
    <div class="tab-panel" id="panel-branding">
    <div class="admin-section">
        <h3>✨ Branding</h3>
        <div class="admin-content">
            <div class="admin-subsection"><h4>Logo</h4>{logo_preview}
                <form method="POST" action="/admin/branding/logo" enctype="multipart/form-data" class="inline-form">
                    <div class="form-group" style="flex:2;"><label>Upload Logo (max 500KB)</label><input type="file" name="logo" accept="image/*" required style="padding:0.5rem;"></div>
                    <button type="submit">Upload</button>
                </form>
            </div>
            <div class="admin-subsection"><h4>Favicon</h4>{favicon_preview}
                <form method="POST" action="/admin/branding/favicon" enctype="multipart/form-data" class="inline-form">
                    <div class="form-group" style="flex:2;"><label>Upload Favicon (max 500KB)</label><input type="file" name="favicon" accept="image/*" required style="padding:0.5rem;"></div>
                    <button type="submit">Upload</button>
                </form>
            </div>
            <div class="admin-subsection"><h4>📱 iOS Home Screen Icon</h4>{apple_touch_icon_preview}
                <form method="POST" action="/admin/branding/apple-touch-icon" enctype="multipart/form-data" class="inline-form">
                    <div class="form-group" style="flex:2;"><label>Upload Icon (PNG, 180x180px recommended, max 500KB)</label><input type="file" name="apple_touch_icon" accept="image/png" required style="padding:0.5rem;"></div>
                    <button type="submit">Upload</button>
                </form>
                <small style="color:var(--text-secondary);display:block;margin-top:0.8rem;">This icon appears when users tap "Add to Home Screen" on iPhone/iPad. Use a square PNG image (180x180px for best quality). iOS will automatically add rounded corners.</small>
            </div>
        </div>
    </div>
    </div>
    
    <!-- Users Panel -->
    <div class="tab-panel" id="panel-users">
    <div class="admin-section">
        <h3>👥 Users</h3>
        <div class="admin-content">
            <ul class="item-list">{users_list}</ul>
            <hr style="border:none;border-top:1px solid var(--border);margin:1.5rem 0;">
            <form method="POST" action="/admin/user/add" class="inline-form">
                <div class="form-group"><label>Username</label><input type="text" name="username" required pattern="[a-zA-Z0-9_]+"></div>
                <div class="form-group"><label>Password</label><input type="password" name="password" required minlength="6"></div>
                <div class="form-group" style="flex:0.5;"><label>Role</label><select name="is_admin"><option value="0">User</option><option value="1">Admin</option></select></div>
                <button type="submit">Add User</button>
            </form>
        </div>
    </div>
    
    {render_password_reset_requests(config)}
    </div>
    
    <!-- Network Panel -->
    <div class="tab-panel" id="panel-network">
    <div class="admin-section">
        <h3>🌐 Network</h3>
        <div class="admin-content">
            {render_network_section(config, SERVER_PORT)}
        </div>
    </div>
    </div>
    
    <!-- Settings Panel -->
    <div class="tab-panel" id="panel-settings">
    <div class="admin-section">
        <h3>⚙️ Settings</h3>
        <div class="admin-content">
            <form method="POST" action="/admin/settings">
                <div class="edit-section">
                    <h5>Page & Browser Title</h5>
                    <div class="inline-form" style="margin-bottom:0.5rem;">
                        <div class="form-group"><label>Page Title (shown in header)</label><input type="text" name="page_title" value="{escape_html(config['settings'].get('page_title', 'Dashboard'))}" required></div>
                    </div>
                    <div class="inline-form">
                        <div class="form-group"><label>Browser Tab Title (empty = use Page Title)</label><input type="text" name="tab_title" value="{escape_html(config['settings'].get('tab_title', ''))}" placeholder="Custom tab title"></div>
                        <div class="form-group"><label>Tab Title Suffix (empty = no suffix)</label><input type="text" name="tab_suffix" value="{escape_html(config['settings'].get('tab_suffix', 'Multi-Frames'))}" placeholder="Multi-Frames"></div>
                    </div>
                    <small style="color:var(--text-secondary);display:block;margin-top:0.5rem;">Browser tab will show: "Tab Title | Suffix" or just "Tab Title" if suffix is empty</small>
                </div>
                
                <div class="edit-section">
                    <h5>Display Settings</h5>
                    <div class="inline-form">
                        <div class="form-group" style="flex:0.5;"><label>Grid Columns</label><input type="number" name="grid_columns" value="{config['settings'].get('grid_columns', 2)}" min="1" max="6"></div>
                        <div class="form-group" style="flex:0.5;"><label>Auto-refresh (sec, 0=off)</label><input type="number" name="refresh_interval" value="{config['settings'].get('refresh_interval', 0)}" min="0" max="3600"></div>
                    </div>
                </div>
                
                <div class="toggle-row" style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:1rem;">
                    <div>
                        <label style="margin-bottom:0;">Auto Fullscreen</label>
                        <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Show fullscreen button and prompt on dashboard</small>
                    </div>
                    <select name="auto_fullscreen" style="width:auto;">
                        <option value="0" {"selected" if not config['settings'].get('auto_fullscreen', False) else ""}>Off</option>
                        <option value="1" {"selected" if config['settings'].get('auto_fullscreen', False) else ""}>On</option>
                    </select>
                </div>
                <button type="submit">Save Settings</button>
            </form>
        </div>
    </div>
    
    <div class="admin-section">
        <h3>🖼️ Fallback Image</h3>
        <div class="admin-content">
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">Display a custom image when an iFrame fails to load its content.</p>
            <form method="POST" action="/admin/settings/fallback" enctype="multipart/form-data">
                <div class="toggle-row" style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:1rem;">
                    <div>
                        <label style="margin-bottom:0;">Enable Fallback Image</label>
                        <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Show custom image when iFrame can't load</small>
                    </div>
                    <select name="fallback_enabled" style="width:auto;">
                        <option value="0" {"selected" if not config.get('fallback_image', {}).get('enabled', False) else ""}>Off</option>
                        <option value="1" {"selected" if config.get('fallback_image', {}).get('enabled', False) else ""}>On</option>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom:1rem;">
                    <label>Fallback Text</label>
                    <input type="text" name="fallback_text" value="{escape_html(config.get('fallback_image', {}).get('text', 'Content Unavailable'))}" placeholder="Content Unavailable">
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">Text shown over the fallback image</small>
                </div>
                <div class="form-group" style="margin-bottom:1rem;">
                    <label>Fallback Image (max 500KB)</label>
                    <input type="file" name="fallback_img" accept="image/*" style="padding:0.5rem;">
                    {f'<div class="preview-box" style="margin-top:0.5rem;"><img src="data:{config.get("fallback_image", {}).get("image_mime", "image/png")};base64,{config.get("fallback_image", {}).get("image", "")}" style="max-height:100px;max-width:200px;border-radius:var(--radius);"></div>' if config.get('fallback_image', {}).get('image') else ''}
                </div>
                <div style="display:flex;gap:0.5rem;">
                    <button type="submit">Save Fallback Settings</button>
                    {'<button type="submit" name="delete_fallback" value="1" class="btn btn-danger" onclick="return confirm(&#39;Remove fallback image?&#39;)">Remove Image</button>' if config.get('fallback_image', {}).get('image') else ''}
                </div>
            </form>
        </div>
    </div>

    <div class="admin-section">
        <h3>☁️ Cloud Sync</h3>
        <div class="admin-content">
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">Connect to Multi-Frames Cloud for remote management, config sync, and monitoring.</p>
            <form method="POST" action="/admin/settings/cloud">
                <div class="toggle-row" style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:1rem;">
                    <div>
                        <label style="margin-bottom:0;">Enable Cloud Sync</label>
                        <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Connect this device to your cloud dashboard</small>
                    </div>
                    <select name="cloud_enabled" style="width:auto;">
                        <option value="0" {"selected" if not config.get('cloud', {}).get('enabled', False) else ""}>Off</option>
                        <option value="1" {"selected" if config.get('cloud', {}).get('enabled', False) else ""}>On</option>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom:1rem;">
                    <label>Cloud URL</label>
                    <input type="url" name="cloud_url" value="{escape_html(config.get('cloud', {}).get('url', ''))}" placeholder="https://your-worker.workers.dev">
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">Your Cloudflare Worker URL</small>
                </div>
                <div class="form-group" style="margin-bottom:1rem;">
                    <label>Device Key</label>
                    <input type="text" name="cloud_device_key" value="{escape_html(config.get('cloud', {}).get('device_key', ''))}" placeholder="mf_xxxxxxxxxxxx" style="font-family:monospace;">
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">Get this from your cloud dashboard after registering this device</small>
                </div>
                <button type="submit">Save Cloud Settings</button>
            </form>
        </div>
    </div>
    </div>

    <!-- Watchdog Panel -->
    <div class="tab-panel" id="panel-watchdog">
        {render_watchdog_section(config)}
    </div>

    <!-- System Panel -->
    <div class="tab-panel" id="panel-system">
        {render_modern_logs(config)}
        {render_system_section(config)}
    </div>
    """
    return render_page("Admin Panel", content, user, config)


def render_widgets_section(config):
    """Render the widgets management section."""
    widgets = config.get("widgets", [])
    
    # Build widgets list
    widgets_list = ""
    total_widgets = len(widgets)
    
    widget_types = {
        'clock': {'icon': '🕐', 'name': 'Clock'},
        'date': {'icon': '📅', 'name': 'Date'},
        'text': {'icon': '📝', 'name': 'Text/HTML'},
        'image': {'icon': '🖼️', 'name': 'Image'},
        'weather': {'icon': '🌤️', 'name': 'Weather'},
        'countdown': {'icon': '⏳', 'name': 'Countdown'},
        'notes': {'icon': '📋', 'name': 'Notes'},
        'buttons': {'icon': '🔘', 'name': 'Command Buttons'}
    }
    
    for i, widget in enumerate(widgets):
        wtype = widget.get('type', 'text')
        wname = escape_html(widget.get('name', f'Widget {i+1}'))
        winfo = widget_types.get(wtype, {'icon': '📦', 'name': 'Unknown'})
        wsize = widget.get('size', 'medium')
        enabled = widget.get('enabled', True)
        wcontent = widget.get('content', '')
        
        # Move buttons
        move_up_disabled = 'disabled style="opacity:0.3;cursor:not-allowed;"' if i == 0 else ''
        move_down_disabled = 'disabled style="opacity:0.3;cursor:not-allowed;"' if i == total_widgets - 1 else ''
        
        # For buttons type, parse existing buttons for the editor
        buttons_editor_html = ""
        if wtype == 'buttons':
            try:
                import json as json_mod
                existing_buttons = json_mod.loads(wcontent) if wcontent else []
            except:
                existing_buttons = []
            
            for bi, btn in enumerate(existing_buttons):
                buttons_editor_html += f'''
                <div class="button-entry" data-index="{bi}">
                    <div class="inline-form" style="margin-bottom:0.5rem;align-items:flex-end;">
                        <div class="form-group" style="flex:1;"><label>Label</label><input type="text" class="btn-label" value="{escape_html(btn.get('label', ''))}" placeholder="Button text"></div>
                        <div class="form-group" style="flex:1;"><label>Protocol</label>
                            <select class="btn-protocol">
                                <option value="tcp" {'selected' if btn.get('protocol') == 'tcp' else ''}>TCP</option>
                                <option value="udp" {'selected' if btn.get('protocol') == 'udp' else ''}>UDP</option>
                                <option value="telnet" {'selected' if btn.get('protocol') == 'telnet' else ''}>Telnet</option>
                                <option value="dummy" {'selected' if btn.get('protocol') == 'dummy' else ''}>Dummy (test OK)</option>
                                <option value="dummy_fail" {'selected' if btn.get('protocol') == 'dummy_fail' else ''}>Dummy (test fail)</option>
                                <option value="dummy_random" {'selected' if btn.get('protocol') == 'dummy_random' else ''}>Dummy (random)</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex:1;"><label>Host/IP</label><input type="text" class="btn-host" value="{escape_html(btn.get('host', ''))}" placeholder="192.168.1.100"></div>
                        <div class="form-group" style="flex:0.5;"><label>Port</label><input type="number" class="btn-port" value="{btn.get('port', 23)}" min="0" max="65535"></div>
                    </div>
                    <div class="inline-form" style="align-items:flex-end;">
                        <div class="form-group" style="flex:2;"><label>Command</label><input type="text" class="btn-command" value="{escape_html(btn.get('command', ''))}" placeholder="POWER ON"></div>
                        <div class="form-group" style="flex:0.3;"><label>Color</label><input type="color" class="btn-color" value="{btn.get('color', '#3b82f6')}"></div>
                        <button type="button" class="btn btn-danger btn-sm" onclick="removeButton(this)" style="margin-bottom:0.5rem;">✕</button>
                    </div>
                    <hr style="border:none;border-top:1px dashed var(--border);margin:0.75rem 0;">
                </div>
                '''
        
        widgets_list += f"""
        <li class="item-row">
            <div class="item-info">
                <strong style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="opacity:{1 if enabled else 0.5};">{winfo['icon']} {wname}</span>
                    {'' if enabled else '<span style="font-size:0.75rem;color:var(--text-secondary);">(disabled)</span>'}
                </strong>
                <small style="display:block;margin-top:0.25rem;color:var(--text-secondary);">
                    Type: {winfo['name']} | Size: {wsize}
                </small>
            </div>
            <div class="item-actions">
                <form method="POST" action="/admin/widget/move" style="display:inline;">
                    <input type="hidden" name="index" value="{i}">
                    <button type="submit" name="direction" value="up" class="btn btn-sm btn-secondary" {move_up_disabled}>↑</button>
                    <button type="submit" name="direction" value="down" class="btn btn-sm btn-secondary" {move_down_disabled}>↓</button>
                </form>
                <button class="btn btn-sm btn-secondary" onclick="toggleWidgetEdit({i})">Edit</button>
                <form method="POST" action="/admin/widget/delete" style="display:inline;">
                    <input type="hidden" name="index" value="{i}">
                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this widget?')">Delete</button>
                </form>
            </div>
        </li>
        <li id="widget-edit-{i}" class="edit-form" style="display:none;">
            <form method="POST" action="/admin/widget/edit" onsubmit="return prepareWidgetForm(this, {i})">
                <input type="hidden" name="index" value="{i}">
                <input type="hidden" name="content" id="edit-content-{i}" value="{escape_html(wcontent)}">
                <div class="inline-form" style="margin-bottom:1rem;">
                    <div class="form-group"><label>Name</label><input type="text" name="name" value="{wname}" required></div>
                    <div class="form-group"><label>Type</label>
                        <select name="type" onchange="toggleEditContentType(this, {i})">
                            <option value="clock" {'selected' if wtype == 'clock' else ''}>🕐 Clock</option>
                            <option value="date" {'selected' if wtype == 'date' else ''}>📅 Date</option>
                            <option value="text" {'selected' if wtype == 'text' else ''}>📝 Text/HTML</option>
                            <option value="image" {'selected' if wtype == 'image' else ''}>🖼️ Image</option>
                            <option value="weather" {'selected' if wtype == 'weather' else ''}>🌤️ Weather</option>
                            <option value="countdown" {'selected' if wtype == 'countdown' else ''}>⏳ Countdown</option>
                            <option value="notes" {'selected' if wtype == 'notes' else ''}>📋 Notes</option>
                            <option value="buttons" {'selected' if wtype == 'buttons' else ''}>🔘 Command Buttons</option>
                        </select>
                    </div>
                    <div class="form-group"><label>Size</label>
                        <select name="size">
                            <option value="small" {'selected' if wsize == 'small' else ''}>Small (1 col)</option>
                            <option value="medium" {'selected' if wsize == 'medium' else ''}>Medium (2 col)</option>
                            <option value="large" {'selected' if wsize == 'large' else ''}>Large (full width)</option>
                        </select>
                    </div>
                    <div class="form-group"><label>Enabled</label>
                        <select name="enabled">
                            <option value="1" {'selected' if enabled else ''}>Yes</option>
                            <option value="0" {'selected' if not enabled else ''}>No</option>
                        </select>
                    </div>
                </div>
                
                <!-- Regular content field (for non-buttons types) -->
                <div id="edit-regular-{i}" class="form-group" style="margin-bottom:1rem;{'display:none;' if wtype == 'buttons' else ''}">
                    <label>Content / Settings</label>
                    <textarea id="edit-textarea-{i}" rows="3" placeholder="Widget content">{escape_html(wcontent) if wtype != 'buttons' else ''}</textarea>
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">
                        Clock: 12h/24h | Text: HTML | Image: URL | Weather: city,C or city,F | Countdown: YYYY-MM-DD HH:MM
                    </small>
                </div>
                
                <!-- Button builder (for buttons type) -->
                <div id="edit-buttons-{i}" class="button-builder" style="{'display:block;' if wtype == 'buttons' else 'display:none;'}margin-bottom:1rem;">
                    <label style="display:block;margin-bottom:0.5rem;">Command Buttons</label>
                    <div class="buttons-list" id="edit-buttons-list-{i}">
                        {buttons_editor_html}
                    </div>
                    <button type="button" class="btn btn-secondary btn-sm" onclick="addButton('edit-buttons-list-{i}')" style="margin-top:0.5rem;">+ Add Button</button>
                </div>
                
                <div class="inline-form" style="margin-bottom:1rem;">
                    <div class="form-group"><label>Background</label><input type="color" name="bg_color" value="{widget.get('bg_color', '#141416')}"></div>
                    <div class="form-group"><label>Text</label><input type="color" name="text_color" value="{widget.get('text_color', '#e8e8e8')}"></div>
                    <div class="form-group"><label>Radius</label><input type="number" name="border_radius" value="{widget.get('border_radius', 8)}" min="0" max="50"> px</div>
                </div>
                <button type="submit">Save Widget</button>
            </form>
        </li>
        """
    
    if not widgets_list:
        widgets_list = '<li style="padding:1rem;color:var(--text-secondary);text-align:center;">No widgets configured. Add one below!</li>'
    
    return f'''
    <style>
    .button-builder {{
        background: var(--bg-primary);
        padding: 1rem;
        border-radius: var(--radius);
        border: 1px solid var(--border);
    }}
    .button-entry {{
        background: var(--bg-secondary);
        padding: 0.75rem;
        border-radius: var(--radius);
        margin-bottom: 0.5rem;
    }}
    .button-entry:last-child hr {{
        display: none;
    }}
    .buttons-list:empty::before {{
        content: "No buttons added yet. Click '+ Add Button' below.";
        color: var(--text-secondary);
        font-style: italic;
        display: block;
        padding: 1rem;
        text-align: center;
    }}
    </style>
    
    <div class="admin-section">
        <h3>🧩 Widgets</h3>
        <div class="admin-content">
            <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">
                Add responsive widgets to your dashboard. Widgets appear above iFrames.
            </p>
            
            <ul class="item-list">{widgets_list}</ul>
            
            <hr style="border:none;border-top:1px solid var(--border);margin:1.5rem 0;">
            <h4 style="font-size:0.85rem;margin-bottom:1rem;color:var(--text-secondary);">Add New Widget</h4>
            
            <form method="POST" action="/admin/widget/add" id="add-widget-form" onsubmit="return prepareAddWidgetForm(this)">
                <input type="hidden" name="content" id="add-content-hidden" value="">
                <div class="inline-form" style="margin-bottom:1rem;">
                    <div class="form-group"><label>Name</label><input type="text" name="name" placeholder="My Widget" required></div>
                    <div class="form-group"><label>Type</label>
                        <select name="type" id="add-type-select" onchange="toggleAddContentType(this.value)">
                            <option value="clock">🕐 Clock</option>
                            <option value="date">📅 Date</option>
                            <option value="text">📝 Text/HTML</option>
                            <option value="image">🖼️ Image</option>
                            <option value="weather">🌤️ Weather</option>
                            <option value="countdown">⏳ Countdown</option>
                            <option value="notes">📋 Notes</option>
                            <option value="buttons">🔘 Command Buttons</option>
                        </select>
                    </div>
                    <div class="form-group"><label>Size</label>
                        <select name="size">
                            <option value="small">Small (1 col)</option>
                            <option value="medium" selected>Medium (2 col)</option>
                            <option value="large">Large (full width)</option>
                        </select>
                    </div>
                </div>
                
                <!-- Regular content field -->
                <div id="add-regular-content" class="form-group" style="margin-bottom:1rem;">
                    <label>Content / Settings</label>
                    <textarea id="add-content-textarea" rows="2" placeholder="Widget content or settings"></textarea>
                    <small id="widget-help" style="color:var(--text-secondary);display:block;margin-top:0.25rem;">
                        Clock: Use "12h" or "24h" for time format
                    </small>
                </div>
                
                <!-- Button builder for buttons type -->
                <div id="add-buttons-builder" class="button-builder" style="display:none;margin-bottom:1rem;">
                    <label style="display:block;margin-bottom:0.5rem;">Command Buttons</label>
                    <div class="buttons-list" id="add-buttons-list"></div>
                    <button type="button" class="btn btn-secondary btn-sm" onclick="addButton('add-buttons-list')" style="margin-top:0.5rem;">+ Add Button</button>
                </div>
                
                <details style="margin-bottom:1rem;">
                    <summary style="cursor:pointer;color:var(--accent);font-size:0.85rem;">+ Style Options</summary>
                    <div style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-top:0.5rem;">
                        <div class="inline-form">
                            <div class="form-group"><label>Background Color</label><input type="color" name="bg_color" value="#141416"></div>
                            <div class="form-group"><label>Text Color</label><input type="color" name="text_color" value="#e8e8e8"></div>
                            <div class="form-group"><label>Border Radius</label><input type="number" name="border_radius" value="8" min="0" max="50"> px</div>
                        </div>
                    </div>
                </details>
                
                <button type="submit">Add Widget</button>
            </form>
            
            <script>
            function toggleWidgetEdit(index) {{
                var form = document.getElementById('widget-edit-' + index);
                form.style.display = form.style.display === 'none' ? 'block' : 'none';
            }}
            
            function toggleAddContentType(type) {{
                var regularContent = document.getElementById('add-regular-content');
                var buttonsBuilder = document.getElementById('add-buttons-builder');
                var helpText = document.getElementById('widget-help');
                
                if (type === 'buttons') {{
                    regularContent.style.display = 'none';
                    buttonsBuilder.style.display = 'block';
                }} else {{
                    regularContent.style.display = 'block';
                    buttonsBuilder.style.display = 'none';
                    
                    var hints = {{
                        'clock': 'Use "12h" or "24h" for time format',
                        'date': 'Use "full" for full date display',
                        'text': 'Enter HTML content',
                        'image': 'Enter image URL',
                        'weather': 'City name or lat,lon. Add ",C" for Celsius or ",F" for Fahrenheit. Examples: "London,C" or "40.7,-74.0,F"',
                        'countdown': 'Enter target: YYYY-MM-DD HH:MM',
                        'notes': 'Enter note text'
                    }};
                    helpText.textContent = hints[type] || 'Enter content';
                }}
            }}
            
            function toggleEditContentType(select, index) {{
                var type = select.value;
                var regularContent = document.getElementById('edit-regular-' + index);
                var buttonsBuilder = document.getElementById('edit-buttons-' + index);
                
                if (type === 'buttons') {{
                    regularContent.style.display = 'none';
                    buttonsBuilder.style.display = 'block';
                }} else {{
                    regularContent.style.display = 'block';
                    buttonsBuilder.style.display = 'none';
                }}
            }}
            
            function addButton(listId) {{
                var list = document.getElementById(listId);
                var entry = document.createElement('div');
                entry.className = 'button-entry';
                entry.innerHTML = `
                    <div class="inline-form" style="margin-bottom:0.5rem;align-items:flex-end;">
                        <div class="form-group" style="flex:1;"><label>Label</label><input type="text" class="btn-label" placeholder="Button text"></div>
                        <div class="form-group" style="flex:1;"><label>Protocol</label>
                            <select class="btn-protocol">
                                <option value="dummy" selected>Dummy (test OK)</option>
                                <option value="dummy_fail">Dummy (test fail)</option>
                                <option value="dummy_random">Dummy (random)</option>
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="telnet">Telnet</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex:1;"><label>Host/IP</label><input type="text" class="btn-host" placeholder="192.168.1.100"></div>
                        <div class="form-group" style="flex:0.5;"><label>Port</label><input type="number" class="btn-port" value="23" min="0" max="65535"></div>
                    </div>
                    <div class="inline-form" style="align-items:flex-end;">
                        <div class="form-group" style="flex:2;"><label>Command</label><input type="text" class="btn-command" placeholder="POWER ON"></div>
                        <div class="form-group" style="flex:0.3;"><label>Color</label><input type="color" class="btn-color" value="#3b82f6"></div>
                        <button type="button" class="btn btn-danger btn-sm" onclick="removeButton(this)" style="margin-bottom:0.5rem;">✕</button>
                    </div>
                    <hr style="border:none;border-top:1px dashed var(--border);margin:0.75rem 0;">
                `;
                list.appendChild(entry);
            }}
            
            function removeButton(btn) {{
                btn.closest('.button-entry').remove();
            }}
            
            function collectButtons(listId) {{
                var list = document.getElementById(listId);
                var entries = list.querySelectorAll('.button-entry');
                var buttons = [];
                entries.forEach(function(entry) {{
                    var label = entry.querySelector('.btn-label').value.trim();
                    if (label) {{
                        buttons.push({{
                            label: label,
                            protocol: entry.querySelector('.btn-protocol').value,
                            host: entry.querySelector('.btn-host').value.trim(),
                            port: parseInt(entry.querySelector('.btn-port').value) || 0,
                            command: entry.querySelector('.btn-command').value,
                            color: entry.querySelector('.btn-color').value
                        }});
                    }}
                }});
                return JSON.stringify(buttons);
            }}
            
            function prepareAddWidgetForm(form) {{
                var type = document.getElementById('add-type-select').value;
                var hiddenContent = document.getElementById('add-content-hidden');
                
                if (type === 'buttons') {{
                    hiddenContent.value = collectButtons('add-buttons-list');
                }} else {{
                    hiddenContent.value = document.getElementById('add-content-textarea').value;
                }}
                return true;
            }}
            
            function prepareWidgetForm(form, index) {{
                var typeSelect = form.querySelector('select[name="type"]');
                var type = typeSelect.value;
                var hiddenContent = document.getElementById('edit-content-' + index);
                
                if (type === 'buttons') {{
                    hiddenContent.value = collectButtons('edit-buttons-list-' + index);
                }} else {{
                    var textarea = document.getElementById('edit-textarea-' + index);
                    hiddenContent.value = textarea.value;
                }}
                return true;
            }}
            </script>
        </div>
    </div>
    '''


def render_password_reset_requests(config):
    """Render the password reset requests section for admin."""
    requests = config.get("password_reset_requests", [])
    
    if not requests:
        return '''
        <div class="admin-section">
            <h3>🔑 Password Reset Requests</h3>
            <div class="admin-content">
                <p style="color:var(--text-secondary);font-style:italic;">No pending password reset requests.</p>
            </div>
        </div>
        '''
    
    requests_html = ""
    for i, req in enumerate(requests):
        username = escape_html(req.get('username', 'Unknown'))
        timestamp = escape_html(req.get('timestamp', 'Unknown'))
        req_id = escape_html(req.get('id', ''))
        
        # Check if user exists
        user_exists = username in config.get("users", {})
        user_status = "" if user_exists else ' <span style="color:var(--danger);font-size:0.75rem;">(user not found)</span>'
        
        requests_html += f'''
        <div class="reset-request" style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);margin-bottom:0.75rem;border-left:3px solid var(--accent);">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:0.5rem;">
                <div>
                    <strong>{username}</strong>{user_status}
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">
                        Requested: {timestamp}
                    </div>
                </div>
                <div style="display:flex;gap:0.5rem;align-items:center;">
                    {f"""
                    <form method="POST" action="/admin/password-reset/set" style="display:flex;gap:0.25rem;align-items:center;">
                        <input type="hidden" name="request_id" value="{req_id}">
                        <input type="password" name="new_password" placeholder="New password" required minlength="6" style="width:140px;padding:0.4rem;">
                        <button type="submit" class="btn btn-sm">Set Password</button>
                    </form>
                    """ if user_exists else ""}
                    <form method="POST" action="/admin/password-reset/dismiss" style="display:inline;">
                        <input type="hidden" name="request_id" value="{req_id}">
                        <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Dismiss this request?')">Dismiss</button>
                    </form>
                </div>
            </div>
        </div>
        '''
    
    return f'''
    <div class="admin-section">
        <h3>🔑 Password Reset Requests <span style="background:var(--danger);color:white;font-size:0.75rem;padding:0.2rem 0.5rem;border-radius:10px;margin-left:0.5rem;">{len(requests)}</span></h3>
        <div class="admin-content">
            {requests_html}
            <form method="POST" action="/admin/password-reset/dismiss-all" style="margin-top:1rem;">
                <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Dismiss all requests?')">Dismiss All Requests</button>
            </form>
        </div>
    </div>
    '''


def render_admin_alerts(config):
    """Render alert banners for important admin notifications."""
    alerts = []

    # Check for connectivity reports
    reports = config.get("connectivity_reports", [])
    if reports:
        count = len(reports)
        latest = reports[-1] if reports else {}
        latest_user = escape_html(latest.get('username', 'Unknown'))
        latest_time = escape_html(latest.get('timestamp', ''))
        alerts.append({
            'type': 'warning',
            'icon': '📡',
            'title': f'{count} Connectivity Report{"s" if count > 1 else ""} Pending',
            'message': f'Latest from {latest_user} at {latest_time}',
            'action_text': 'View Reports',
            'action_js': "switchTab('system'); document.querySelector('.connectivity-report')?.scrollIntoView({behavior:'smooth'})"
        })

    # Check for password reset requests
    reset_requests = config.get("password_reset_requests", [])
    if reset_requests:
        count = len(reset_requests)
        alerts.append({
            'type': 'info',
            'icon': '🔑',
            'title': f'{count} Password Reset Request{"s" if count > 1 else ""}',
            'message': 'Users are waiting for password reset approval',
            'action_text': 'View Requests',
            'action_js': "switchTab('users'); document.querySelector('.password-reset-requests')?.scrollIntoView({behavior:'smooth'})"
        })

    if not alerts:
        return ''

    # Build alerts HTML
    alerts_html = ''
    for alert in alerts:
        alert_type = alert['type']
        if alert_type == 'warning':
            bg_color = 'rgba(245, 158, 11, 0.15)'
            border_color = '#f59e0b'
            icon_bg = '#f59e0b'
        elif alert_type == 'error':
            bg_color = 'rgba(239, 68, 68, 0.15)'
            border_color = '#ef4444'
            icon_bg = '#ef4444'
        else:  # info
            bg_color = 'rgba(59, 130, 246, 0.15)'
            border_color = '#3b82f6'
            icon_bg = '#3b82f6'

        alerts_html += f'''
        <div class="admin-alert" style="
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: var(--radius);
            padding: 0.75rem 1rem;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        ">
            <div style="
                width: 36px;
                height: 36px;
                border-radius: 50%;
                background: {icon_bg};
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.1rem;
                flex-shrink: 0;
            ">{alert['icon']}</div>
            <div style="flex: 1; min-width: 200px;">
                <div style="font-weight: 600; font-size: 0.95rem;">{alert['title']}</div>
                <div style="font-size: 0.8rem; color: var(--text-secondary);">{alert['message']}</div>
            </div>
            <button class="btn btn-sm" onclick="{alert['action_js']}" style="
                background: {border_color};
                border-color: {border_color};
                white-space: nowrap;
            ">{alert['action_text']}</button>
        </div>
        '''

    return f'''
    <div class="admin-alerts" style="margin-bottom: 1rem;">
        {alerts_html}
    </div>
    '''


def render_connectivity_reports(config):
    """Render the user-submitted connectivity reports section for admin."""
    reports = config.get("connectivity_reports", [])
    
    if not reports:
        return '''
        <div class="admin-subsection" style="margin-top:1.5rem;">
            <h4>📋 User Connectivity Reports</h4>
            <p style="color:var(--text-secondary);font-style:italic;font-size:0.85rem;">
                No user reports submitted. Users can submit reports from the Help page when connectivity tests fail.
            </p>
        </div>
        '''
    
    reports_html = ""
    # Show most recent first
    for report in reversed(reports[-10:]):  # Show last 10
        report_id = escape_html(report.get('id', ''))
        username = escape_html(report.get('username', 'Unknown'))
        timestamp = escape_html(report.get('timestamp', 'Unknown'))
        failure_count = report.get('failure_count', 0)
        total_count = report.get('total_count', 0)
        user_agent = escape_html(report.get('user_agent', '')[:60])
        connection_type = escape_html(report.get('connection_type', ''))
        
        # Build failed items list
        results = report.get('results', [])
        failed_items = [r for r in results if not r.get('success', True)]
        
        failed_list = ""
        for item in failed_items[:5]:  # Show max 5 failures
            name = escape_html(item.get('name', 'Unknown'))
            load_time = item.get('time', 0)
            failed_list += f'<div style="padding:0.25rem 0;"><span style="color:#ef4444;">✗</span> {name} <span style="color:var(--text-secondary);font-size:0.8rem;">({load_time}ms)</span></div>'
        
        if len(failed_items) > 5:
            failed_list += f'<div style="color:var(--text-secondary);font-size:0.8rem;">... and {len(failed_items) - 5} more</div>'
        
        reports_html += f'''
        <div class="connectivity-report" style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);margin-bottom:0.75rem;border-left:3px solid #ef4444;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.75rem;">
                <div>
                    <strong>{username}</strong>
                    <span style="margin-left:0.5rem;padding:0.15rem 0.4rem;background:#ef444420;color:#ef4444;border-radius:3px;font-size:0.75rem;">
                        {failure_count} of {total_count} failed
                    </span>
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">
                        {timestamp}{f' · {connection_type}' if connection_type else ''}
                    </div>
                </div>
                <form method="POST" action="/admin/connectivity-report/dismiss" style="margin:0;">
                    <input type="hidden" name="report_id" value="{report_id}">
                    <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Dismiss this report?')">Dismiss</button>
                </form>
            </div>
            <div style="font-size:0.85rem;">
                {failed_list if failed_list else '<span style="color:var(--text-secondary);">No details available</span>'}
            </div>
            {f'<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.5rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{user_agent}">{user_agent}</div>' if user_agent else ''}
        </div>
        '''
    
    total_reports = len(reports)
    
    return f'''
    <div class="admin-subsection" style="margin-top:1.5rem;">
        <h4>📋 User Connectivity Reports <span style="background:var(--danger);color:white;font-size:0.75rem;padding:0.2rem 0.5rem;border-radius:10px;margin-left:0.5rem;">{total_reports}</span></h4>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:1rem;">
            Reports submitted by users when connectivity tests fail.
        </p>
        <div style="max-height:400px;overflow-y:auto;">
            {reports_html}
        </div>
        <form method="POST" action="/admin/connectivity-report/dismiss-all" style="margin-top:1rem;">
            <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Dismiss all reports?')">Dismiss All Reports</button>
        </form>
    </div>
    '''


def get_firmware_backup_dir():
    """Get the firmware backup directory path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backup_dir = os.path.join(script_dir, 'firmware_backups')
    return backup_dir


def get_firmware_backups():
    """Get list of firmware backups sorted by date (newest first)."""
    backup_dir = get_firmware_backup_dir()
    if not os.path.exists(backup_dir):
        return []
    
    backups = []
    try:
        for filename in os.listdir(backup_dir):
            if filename.endswith('.py'):
                filepath = os.path.join(backup_dir, filename)
                stat = os.stat(filepath)
                backups.append({
                    'filename': filename,
                    'filepath': filepath,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime)
                })
        backups.sort(key=lambda x: x['modified'], reverse=True)
    except Exception as e:
        server_logger.error(f"Error listing backups: {e}")
    
    return backups


def render_firmware_backups():
    """Render the firmware backup list HTML."""
    backups = get_firmware_backups()
    
    if not backups:
        return '<div style="color:var(--text-secondary);font-style:italic;">No backups found</div>'
    
    html = '<table style="width:100%;">'
    html += '<tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:0.3rem 0;">Filename</th><th style="text-align:right;padding:0.3rem 0;">Size</th><th style="text-align:right;padding:0.3rem 0;">Date</th><th style="width:80px;"></th></tr>'
    
    for backup in backups[:10]:  # Show max 10
        filename = escape_html(backup['filename'])
        size_kb = backup['size'] / 1024
        date_str = backup['modified'].strftime('%Y-%m-%d %H:%M')
        
        html += f'''
        <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:0.4rem 0;font-family:monospace;font-size:0.75rem;">{filename}</td>
            <td style="padding:0.4rem 0;text-align:right;">{size_kb:.1f} KB</td>
            <td style="padding:0.4rem 0;text-align:right;color:var(--text-secondary);">{date_str}</td>
            <td style="padding:0.4rem 0;text-align:right;">
                <a href="/admin/system/firmware-download/{filename}" class="btn btn-sm btn-secondary" style="margin-right:0.25rem;" title="Download">⬇</a>
                <form method="POST" action="/admin/system/firmware-restore" style="display:inline;margin:0;">
                    <input type="hidden" name="filename" value="{filename}">
                    <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Restore this backup?\\n\\n{filename}\\n\\nThe server will restart.')">Restore</button>
                </form>
            </td>
        </tr>
        '''
    
    html += '</table>'
    
    if len(backups) > 10:
        html += f'<div style="margin-top:0.5rem;color:var(--text-secondary);font-size:0.75rem;">Showing 10 of {len(backups)} backups</div>'
    
    return html


def create_firmware_backup():
    """Create a backup of the current firmware file."""
    backup_dir = get_firmware_backup_dir()
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    current_script = os.path.abspath(__file__)
    backup_filename = f'multi_frames_v{VERSION}_{timestamp}.py'
    backup_path = os.path.join(backup_dir, backup_filename)
    
    # Copy current script to backup
    import shutil
    shutil.copy2(current_script, backup_path)
    
    # Clean up old backups (keep only FIRMWARE_MAX_BACKUPS)
    backups = get_firmware_backups()
    if len(backups) > FIRMWARE_MAX_BACKUPS:
        for old_backup in backups[FIRMWARE_MAX_BACKUPS:]:
            try:
                os.remove(old_backup['filepath'])
                server_logger.info(f"Removed old backup: {old_backup['filename']}")
            except Exception as e:
                server_logger.warning(f"Failed to remove old backup: {e}")
    
    return backup_path


def validate_firmware_file(content):
    """Validate that the uploaded firmware file is valid Python."""
    try:
        # Try to compile the code to check for syntax errors
        compile(content, '<firmware>', 'exec')
        
        # Check for required components
        required_patterns = [
            r'class IFrameHandler',
            r'def main\(',
            r'VERSION\s*=',
        ]
        
        missing = []
        for pattern in required_patterns:
            if not re.search(pattern, content):
                missing.append(pattern)
        
        if missing:
            return False, f"Missing required components: {', '.join(missing)}"
        
        # Extract version info from new firmware
        version_match = re.search(r'VERSION\s*=\s*["\']([^"\']+)["\']', content)
        version = version_match.group(1) if version_match else 'Unknown'
        
        return True, version
        
    except SyntaxError as e:
        return False, f"Syntax error at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def render_footer_links_editor(links):
    """Render the footer links editor."""
    links_html = ""
    for i, link in enumerate(links):
        label = escape_html(link.get('label', ''))
        url = escape_html(link.get('url', ''))
        links_html += f'''
        <div class="footer-link-entry" style="display:flex;gap:0.5rem;margin-bottom:0.5rem;align-items:flex-end;">
            <div class="form-group" style="flex:1;margin-bottom:0;">
                <label style="font-size:0.75rem;">Label</label>
                <input type="text" value="{label}" readonly style="background:var(--bg-primary);">
            </div>
            <div class="form-group" style="flex:2;margin-bottom:0;">
                <label style="font-size:0.75rem;">URL</label>
                <input type="text" value="{url}" readonly style="background:var(--bg-primary);">
            </div>
            <form method="POST" action="/admin/footer-link/delete" style="margin-bottom:0;">
                <input type="hidden" name="index" value="{i}">
                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this link?')">✕</button>
            </form>
        </div>
        '''
    
    if not links_html:
        links_html = '<p style="color:var(--text-secondary);font-style:italic;font-size:0.85rem;">No footer links configured.</p>'
    
    return f'''
    <div class="footer-links-list" style="margin-bottom:1rem;">
        {links_html}
    </div>
    <form method="POST" action="/admin/footer-link/add" style="background:var(--bg-primary);padding:0.75rem;border-radius:var(--radius);">
        <div style="display:flex;gap:0.5rem;align-items:flex-end;">
            <div class="form-group" style="flex:1;margin-bottom:0;">
                <label style="font-size:0.75rem;">Label</label>
                <input type="text" name="label" placeholder="GitHub" required>
            </div>
            <div class="form-group" style="flex:2;margin-bottom:0;">
                <label style="font-size:0.75rem;">URL</label>
                <input type="url" name="url" placeholder="https://github.com/..." required>
            </div>
            <button type="submit" class="btn btn-sm" style="margin-bottom:0;">+ Add</button>
        </div>
    </form>
    '''


def render_network_section(config, server_port=8080):
    """Render the network configuration section."""
    global mdns_service
    
    net_info = get_current_network_info()
    net_config = config.get("network", DEFAULT_CONFIG["network"])
    mdns_config = net_config.get("mdns", DEFAULT_CONFIG["network"]["mdns"])
    
    interfaces = net_info.get('interfaces', ['eth0'])
    current_interface = net_config.get('interface', interfaces[0] if interfaces else 'eth0')
    
    # Build interface options
    iface_options = ""
    for iface in interfaces:
        selected = "selected" if iface == current_interface else ""
        iface_options += f'<option value="{escape_html(iface)}" {selected}>{escape_html(iface)}</option>'
    
    # Current status display
    current_ip = net_info.get('current_ip', 'Unknown')
    current_gw = net_info.get('current_gateway', 'Unknown')
    current_dns = ', '.join(net_info.get('current_dns', [])) or 'Unknown'
    config_method = net_info.get('config_method', 'unknown')
    current_platform = net_info.get('platform', 'unknown')
    
    # Platform display name
    platform_names = {
        'windows': 'Windows',
        'darwin': 'macOS',
        'linux': 'Linux'
    }
    platform_display = platform_names.get(current_platform, current_platform.title())
    
    # Check if running with admin privileges
    is_admin = check_admin_privileges()
    
    if not is_admin:
        if current_platform == 'windows':
            admin_warning = '''
            <div class="message error" style="margin-bottom:1rem;">
                <strong>⚠️ Administrator Required:</strong> Network changes require running the server as Administrator.
                Right-click Command Prompt → "Run as Administrator"
            </div>
            '''
        else:
            admin_warning = '''
            <div class="message error" style="margin-bottom:1rem;">
                <strong>⚠️ Root Required:</strong> Network changes require running the server with sudo/root privileges.
            </div>
            '''
    else:
        admin_warning = ""
    
    mode = net_config.get('mode', 'dhcp')
    
    # Platform-specific recovery instructions
    if current_platform == 'windows':
        recovery_instructions = '''
            <p>If you lose access after applying network changes:</p>
            <ol style="margin:0.5rem 0 0 1.5rem;">
                <li>Open Control Panel → Network and Internet → Network Connections</li>
                <li>Right-click your adapter → Properties → Internet Protocol Version 4</li>
                <li>Select "Obtain an IP address automatically" to restore DHCP</li>
                <li>Or use Command Prompt (Admin): <code>netsh interface ip set address "Ethernet" dhcp</code></li>
            </ol>
        '''
    elif current_platform == 'darwin':
        recovery_instructions = '''
            <p>If you lose access after applying network changes:</p>
            <ol style="margin:0.5rem 0 0 1.5rem;">
                <li>Open System Preferences → Network</li>
                <li>Select your interface and click "Advanced"</li>
                <li>Under TCP/IP, change "Configure IPv4" to "Using DHCP"</li>
                <li>Or use Terminal: <code>sudo networksetup -setdhcp "Ethernet"</code></li>
            </ol>
        '''
    else:
        recovery_instructions = '''
            <p>If you lose access after applying network changes:</p>
            <ol style="margin:0.5rem 0 0 1.5rem;">
                <li>Connect a monitor and keyboard directly to the server</li>
                <li>For netplan: Edit <code>/etc/netplan/*.yaml</code> and run <code>sudo netplan apply</code></li>
                <li>For interfaces: Edit <code>/etc/network/interfaces</code> and run <code>sudo systemctl restart networking</code></li>
                <li>Or restore from backup: <code>/etc/network/interfaces.backup</code></li>
            </ol>
        '''
    
    return f'''
    {admin_warning}
    
    <div class="admin-subsection">
        <h4>📡 Current Network Status</h4>
        <div class="preview-box">
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:1rem;">
                <div><small style="color:var(--text-secondary);display:block;">Platform</small><strong>{escape_html(platform_display)}</strong></div>
                <div><small style="color:var(--text-secondary);display:block;">IP Address</small><strong>{escape_html(current_ip)}</strong></div>
                <div><small style="color:var(--text-secondary);display:block;">Gateway</small><strong>{escape_html(current_gw)}</strong></div>
                <div><small style="color:var(--text-secondary);display:block;">DNS Servers</small><strong>{escape_html(current_dns)}</strong></div>
                <div><small style="color:var(--text-secondary);display:block;">Config Method</small><strong>{escape_html(config_method)}</strong></div>
            </div>
        </div>
    </div>
    
    <div class="admin-subsection">
        <h4>⚙️ Network Configuration</h4>
        <form method="POST" action="/admin/network">
            <div class="inline-form" style="margin-bottom:1rem;">
                <div class="form-group">
                    <label>Network Interface</label>
                    <select name="interface">{iface_options}</select>
                </div>
                <div class="form-group">
                    <label>Configuration Mode</label>
                    <select name="mode" id="net-mode-select" onchange="toggleNetworkOptions()">
                        <option value="dhcp" {"selected" if mode == "dhcp" else ""}>DHCP (Automatic)</option>
                        <option value="static" {"selected" if mode == "static" else ""}>Static IP</option>
                    </select>
                </div>
            </div>
            
            <div id="static-options" style="display:{"block" if mode == "static" else "none"};">
                <div class="inline-form" style="margin-bottom:1rem;">
                    <div class="form-group" style="flex:2;">
                        <label>IP Address</label>
                        <input type="text" name="ip_address" value="{escape_html(net_config.get('ip_address', ''))}" placeholder="192.168.1.100">
                    </div>
                    <div class="form-group">
                        <label>Subnet (CIDR)</label>
                        <select name="subnet_mask">
                            <option value="8" {"selected" if net_config.get('subnet_mask') == '8' else ""}>8 (255.0.0.0)</option>
                            <option value="16" {"selected" if net_config.get('subnet_mask') == '16' else ""}>16 (255.255.0.0)</option>
                            <option value="24" {"selected" if net_config.get('subnet_mask') == '24' else ""}>24 (255.255.255.0)</option>
                            <option value="25" {"selected" if net_config.get('subnet_mask') == '25' else ""}>25 (255.255.255.128)</option>
                            <option value="26" {"selected" if net_config.get('subnet_mask') == '26' else ""}>26 (255.255.255.192)</option>
                            <option value="27" {"selected" if net_config.get('subnet_mask') == '27' else ""}>27 (255.255.255.224)</option>
                            <option value="28" {"selected" if net_config.get('subnet_mask') == '28' else ""}>28 (255.255.255.240)</option>
                            <option value="29" {"selected" if net_config.get('subnet_mask') == '29' else ""}>29 (255.255.255.248)</option>
                            <option value="30" {"selected" if net_config.get('subnet_mask') == '30' else ""}>30 (255.255.255.252)</option>
                        </select>
                    </div>
                </div>
                <div class="inline-form" style="margin-bottom:1rem;">
                    <div class="form-group">
                        <label>Gateway</label>
                        <input type="text" name="gateway" value="{escape_html(net_config.get('gateway', ''))}" placeholder="192.168.1.1">
                    </div>
                    <div class="form-group">
                        <label>Primary DNS</label>
                        <input type="text" name="dns_primary" value="{escape_html(net_config.get('dns_primary', '8.8.8.8'))}" placeholder="8.8.8.8">
                    </div>
                    <div class="form-group">
                        <label>Secondary DNS</label>
                        <input type="text" name="dns_secondary" value="{escape_html(net_config.get('dns_secondary', '8.8.4.4'))}" placeholder="8.8.4.4">
                    </div>
                </div>
            </div>
            
            <div style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);margin-bottom:1rem;">
                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;margin-bottom:0;">
                    <input type="checkbox" name="confirm" value="1" required style="width:auto;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">I understand this may disconnect me from the server if misconfigured</span>
                </label>
            </div>
            
            <div style="display:flex;gap:0.5rem;">
                <button type="submit" {"disabled" if not is_admin else ""}>Apply Network Settings</button>
                <button type="submit" name="save_only" value="1" class="btn btn-secondary">Save Without Applying</button>
            </div>
        </form>
        <script>
        function toggleNetworkOptions() {{
            var mode = document.getElementById('net-mode-select').value;
            document.getElementById('static-options').style.display = mode === 'static' ? 'block' : 'none';
        }}
        </script>
    </div>
    
    <div class="admin-subsection">
        <h4>🔗 mDNS / Bonjour (Local Network Discovery)</h4>
        {f'<p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:1rem;">Access your server at <strong>http://{escape_html(mdns_config.get("hostname", "multi-frames"))}.local:{server_port}</strong> instead of remembering the IP address.</p>' if mdns_config.get("enabled") else '<p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:1rem;">Enable mDNS to access your server using a friendly hostname (e.g., http://dashboard.local) instead of an IP address.</p>'}
        
        {f'<div class="message error" style="margin-bottom:1rem;"><strong>⚠️ zeroconf library not installed.</strong> Run: <code>pip install zeroconf</code></div>' if not ZEROCONF_AVAILABLE else ''}
        
        <form method="POST" action="/admin/network/mdns">
            <div class="toggle-row" style="padding:1rem;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:1rem;">
                <div>
                    <label style="margin-bottom:0;">Enable mDNS</label>
                    <small style="display:block;color:var(--text-secondary);margin-top:0.25rem;">Advertise this server on your local network</small>
                </div>
                <select name="mdns_enabled" style="width:auto;">
                    <option value="0" {"selected" if not mdns_config.get("enabled", False) else ""}>Off</option>
                    <option value="1" {"selected" if mdns_config.get("enabled", False) else ""} {"disabled" if not ZEROCONF_AVAILABLE else ""}>On</option>
                </select>
            </div>
            
            <div class="inline-form" style="margin-bottom:1rem;">
                <div class="form-group" style="flex:1;">
                    <label>Hostname</label>
                    <div style="display:flex;align-items:center;gap:0;">
                        <input type="text" name="mdns_hostname" value="{escape_html(mdns_config.get('hostname', 'multi-frames'))}" pattern="[-a-zA-Z0-9]+" placeholder="multi-frames" style="border-radius:var(--radius) 0 0 var(--radius);">
                        <span style="background:var(--bg-tertiary);border:1px solid var(--border);border-left:none;padding:0.5rem 0.75rem;color:var(--text-secondary);font-size:0.9rem;border-radius:0 var(--radius) var(--radius) 0;">.local</span>
                    </div>
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">Letters, numbers, and hyphens only</small>
                </div>
                <div class="form-group" style="flex:1;">
                    <label>Service Name</label>
                    <input type="text" name="mdns_service_name" value="{escape_html(mdns_config.get('service_name', 'iFrame Dashboard'))}" placeholder="iFrame Dashboard">
                    <small style="color:var(--text-secondary);display:block;margin-top:0.25rem;">Friendly name shown in network browsers</small>
                </div>
            </div>
            
            <button type="submit" {"disabled" if not ZEROCONF_AVAILABLE else ""}>Save mDNS Settings</button>
        </form>
        
        {f'<div class="preview-box" style="margin-top:1rem;"><div style="display:flex;align-items:center;gap:0.5rem;"><span class="status-dot connected"></span><strong>mDNS Active</strong></div><small style="color:var(--text-secondary);display:block;margin-top:0.5rem;">Service: {escape_html(mdns_config.get("service_name", "iFrame Dashboard"))}<br>URL: http://{escape_html(mdns_config.get("hostname", "multi-frames"))}.local:{server_port}</small></div>' if mdns_config.get("enabled") and ZEROCONF_AVAILABLE and mdns_service and mdns_service.running else ''}
    </div>
    
    <div class="admin-subsection">
        <h4>📋 Recovery Instructions ({escape_html(platform_display)})</h4>
        <div style="font-size:0.85rem;color:var(--text-secondary);">
            {recovery_instructions}
        </div>
    </div>
    '''


def render_raspberry_pi_section():
    """Render Raspberry Pi specific system information and controls."""
    pi_info = get_raspberry_pi_info()
    
    if not pi_info:
        return ""
    
    # Build status indicators
    temp_status = ""
    temp_color = "#22c55e"  # green
    if pi_info.get('temperature'):
        temp = pi_info['temperature']
        if temp >= 80:
            temp_color = "#ef4444"  # red
            temp_status = "🔥 Critical!"
        elif temp >= 70:
            temp_color = "#f59e0b"  # orange
            temp_status = "⚠️ Hot"
        elif temp >= 60:
            temp_color = "#eab308"  # yellow
            temp_status = "Warm"
        else:
            temp_status = "Normal"
    
    # Throttling status
    throttle_html = ""
    if pi_info.get('throttled'):
        t = pi_info['throttled']
        issues = []
        if t.get('under_voltage'):
            issues.append('<span style="color:#ef4444;">⚡ Under-voltage NOW</span>')
        if t.get('throttled'):
            issues.append('<span style="color:#ef4444;">🌡️ Throttled NOW</span>')
        if t.get('freq_capped'):
            issues.append('<span style="color:#f59e0b;">📉 Frequency capped</span>')
        if t.get('under_voltage_occurred'):
            issues.append('<span style="color:#f59e0b;">⚡ Under-voltage occurred</span>')
        if t.get('throttled_occurred'):
            issues.append('<span style="color:#f59e0b;">🌡️ Throttling occurred</span>')
        
        if issues:
            throttle_html = '<div style="margin-top:0.5rem;padding:0.5rem;background:rgba(239,68,68,0.1);border-radius:0.25rem;font-size:0.8rem;">' + '<br>'.join(issues) + '</div>'
        elif t.get('value') == '0x0':
            throttle_html = '<div style="margin-top:0.5rem;color:#22c55e;font-size:0.85rem;">✓ No throttling issues detected</div>'
    
    # Network config method
    net_config = pi_info.get('network_config', 'unknown')
    net_config_display = {
        'dhcpcd': 'dhcpcd (Raspberry Pi OS default)',
        'netplan': 'netplan (Ubuntu)',
        'interfaces': '/etc/network/interfaces',
        'unknown': 'Unknown'
    }.get(net_config, net_config)
    
    return f'''
    <div class="admin-subsection" style="background:linear-gradient(135deg, rgba(192,51,74,0.1) 0%, rgba(117,29,74,0.1) 100%);border:1px solid rgba(192,51,74,0.3);border-radius:var(--radius);padding:1rem;margin-bottom:1rem;">
        <h4 style="display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;">
            <span style="font-size:1.5rem;">🍓</span> Raspberry Pi Detected
        </h4>
        
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:1rem;margin-bottom:1rem;">
            <div style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.8rem;">Model</div>
                <div style="font-weight:600;font-size:0.95rem;">{escape_html(pi_info.get('model', 'Unknown'))}</div>
            </div>
            <div style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.8rem;">Temperature</div>
                <div style="font-weight:600;font-size:1.1rem;color:{temp_color};">
                    {pi_info.get('temperature', 'N/A')}°C
                    <span style="font-size:0.75rem;font-weight:normal;margin-left:0.5rem;">{temp_status}</span>
                </div>
            </div>
            <div style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.8rem;">Memory</div>
                <div style="font-weight:600;">{pi_info.get('memory_total', 'N/A')} MB</div>
            </div>
            <div style="background:var(--bg-primary);padding:1rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.8rem;">Hostname</div>
                <div style="font-weight:600;font-family:monospace;">{escape_html(pi_info.get('hostname', 'Unknown'))}</div>
            </div>
        </div>
        
        {throttle_html}
        
        <details style="margin-top:1rem;">
            <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.85rem;">📊 Hardware Details</summary>
            <table style="width:100%;font-size:0.85rem;margin-top:0.75rem;">
                <tr><td style="padding:0.3rem 0;color:var(--text-secondary);width:40%;">Serial</td><td style="font-family:monospace;">{escape_html(pi_info.get('serial', 'N/A') or 'N/A')}</td></tr>
                <tr><td style="padding:0.3rem 0;color:var(--text-secondary);">Revision</td><td style="font-family:monospace;">{escape_html(pi_info.get('revision', 'N/A') or 'N/A')}</td></tr>
                <tr><td style="padding:0.3rem 0;color:var(--text-secondary);">Boot Config</td><td style="font-family:monospace;font-size:0.8rem;">{escape_html(pi_info.get('boot_config', 'Not found') or 'Not found')}</td></tr>
                <tr><td style="padding:0.3rem 0;color:var(--text-secondary);">Network Config</td><td>{escape_html(net_config_display)}</td></tr>
                <tr><td style="padding:0.3rem 0;color:var(--text-secondary);">Detection Method</td><td>{escape_html(pi_info.get('detection_method', 'N/A'))}</td></tr>
            </table>
        </details>
        
        <details style="margin-top:1rem;">
            <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.85rem;">⚙️ Raspberry Pi Settings</summary>
            <div style="margin-top:0.75rem;padding:1rem;background:var(--bg-primary);border-radius:var(--radius);">
                <form method="POST" action="/admin/system/pi-hostname">
                    <div class="form-group" style="margin-bottom:0.75rem;">
                        <label>Change Hostname</label>
                        <div style="display:flex;gap:0.5rem;">
                            <input type="text" name="hostname" value="{escape_html(pi_info.get('hostname', ''))}" 
                                   pattern="[a-zA-Z0-9]([-a-zA-Z0-9]{{0,61}}[a-zA-Z0-9])?" 
                                   placeholder="my-raspberry-pi" style="flex:1;">
                            <button type="submit" class="btn btn-sm">Set Hostname</button>
                        </div>
                        <small style="color:var(--text-secondary);">Requires reboot. Letters, numbers, and hyphens only.</small>
                    </div>
                </form>
                
                <hr style="border:none;border-top:1px solid var(--border);margin:1rem 0;">
                
                <div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">
                    <strong>Quick Actions</strong>
                </div>
                <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                    <form method="POST" action="/admin/system/pi-reboot" onsubmit="return confirm('Reboot the Raspberry Pi now?')">
                        <button type="submit" class="btn btn-secondary btn-sm">🔄 Reboot Pi</button>
                    </form>
                    <form method="POST" action="/admin/system/pi-shutdown" onsubmit="return confirm('Shutdown the Raspberry Pi? You will need physical access to turn it back on.')">
                        <button type="submit" class="btn btn-danger btn-sm">⏻ Shutdown Pi</button>
                    </form>
                    <button type="button" class="btn btn-secondary btn-sm" onclick="refreshPiTemp()">🌡️ Refresh Temp</button>
                </div>
                
                <script>
                function refreshPiTemp() {{
                    fetch('/api/pi-status')
                        .then(r => r.json())
                        .then(data => {{
                            if (data.temperature) {{
                                alert('Current temperature: ' + data.temperature + '°C');
                            }} else {{
                                alert('Could not read temperature');
                            }}
                        }})
                        .catch(() => alert('Failed to get temperature'));
                }}
                </script>
            </div>
        </details>
    </div>
    '''


def render_update_section(config):
    """Render the firmware update and git pull section."""
    git_info = get_git_info()
    update_settings = get_update_settings(config)
    
    # Check if configured
    repo_owner = update_settings.get('github_owner', '').strip()
    repo_name = update_settings.get('github_repo', '').strip()
    github_url = update_settings.get('github_url', '').strip()
    
    # Try to get from git if not configured
    if not repo_owner and git_info.get('repo_owner'):
        repo_owner = git_info['repo_owner']
    if not repo_name and git_info.get('repo_name'):
        repo_name = git_info['repo_name']
    
    # Build display URL
    if repo_owner and repo_name:
        display_url = github_url if github_url else f"https://github.com/{repo_owner}/{repo_name}"
    else:
        display_url = github_url
    
    is_configured = bool(repo_owner and repo_name)
    
    # Git status display
    git_status_html = ""
    if git_info['is_git_repo']:
        branch_color = "#22c55e" if git_info['current_branch'] in ['main', 'master'] else "#3b82f6"
        changes_badge = '<span style="color:#f59e0b;margin-left:0.5rem;">⚠ uncommitted changes</span>' if git_info['has_changes'] else ''
        
        git_status_html = f'''
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:0.75rem;margin-bottom:1rem;">
            <div style="background:var(--bg-primary);padding:0.75rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.75rem;">Branch</div>
                <div style="font-family:monospace;color:{branch_color};">{escape_html(git_info.get('current_branch', 'N/A'))}</div>
            </div>
            <div style="background:var(--bg-primary);padding:0.75rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.75rem;">Commit</div>
                <div style="font-family:monospace;">{escape_html(git_info.get('commit_short', 'N/A'))}</div>
            </div>
            <div style="background:var(--bg-primary);padding:0.75rem;border-radius:var(--radius);">
                <div style="color:var(--text-secondary);font-size:0.75rem;">Status</div>
                <div>{"⚠️ Changes" if git_info['has_changes'] else "✓ Clean"}</div>
            </div>
        </div>
        '''
    else:
        git_status_html = '''
        <div style="background:rgba(239,183,0,0.1);border:1px solid #f59e0b;padding:1rem;border-radius:var(--radius);margin-bottom:1rem;">
            <div style="color:#f59e0b;font-weight:600;margin-bottom:0.5rem;">📁 Not a Git Repository</div>
            <div style="color:var(--text-secondary);font-size:0.85rem;">
                Git pull updates are not available. Clone Multi-Frames from GitHub to enable automatic updates:<br>
                <code style="background:var(--bg-secondary);padding:0.2rem 0.4rem;border-radius:0.25rem;font-size:0.8rem;margin-top:0.5rem;display:inline-block;">
                    git clone https://github.com/owner/repo.git
                </code>
            </div>
        </div>
        '''
    
    # Update check result display
    last_check = update_settings.get('last_check')
    last_result = update_settings.get('last_result') or {}
    
    update_status_html = ""
    if last_result.get('update_available'):
        update_status_html = f'''
        <div style="background:rgba(34,197,94,0.1);border:1px solid #22c55e;padding:1rem;border-radius:var(--radius);margin-bottom:1rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;color:#22c55e;font-weight:600;margin-bottom:0.5rem;">
                <span style="font-size:1.25rem;">🎉</span> Update Available!
            </div>
            <div style="color:var(--text-primary);margin-bottom:0.5rem;">
                <strong>v{escape_html(last_result.get('latest_version', '?'))}</strong>
                <span style="color:var(--text-secondary);margin-left:0.5rem;">({escape_html(last_result.get('latest_date', ''))})</span>
            </div>
            <div style="color:var(--text-secondary);font-size:0.85rem;">
                Current: v{VERSION}
            </div>
        </div>
        '''
    elif last_result.get('error'):
        update_status_html = f'''
        <div style="background:rgba(239,68,68,0.1);border:1px solid #ef4444;padding:0.75rem;border-radius:var(--radius);margin-bottom:1rem;font-size:0.85rem;color:#ef4444;">
            ⚠️ {escape_html(last_result.get('error', 'Unknown error'))}
        </div>
        '''
    elif last_check:
        update_status_html = f'''
        <div style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:1rem;">
            ✓ Up to date (checked: {escape_html(last_check[:16] if last_check else 'never')})
        </div>
        '''
    
    # Configuration status
    if not is_configured:
        config_status_html = '''
        <div style="background:rgba(59,130,246,0.1);border:1px solid #3b82f6;padding:1rem;border-radius:var(--radius);margin-bottom:1rem;">
            <div style="color:#3b82f6;font-weight:600;margin-bottom:0.5rem;">📋 Configure Repository</div>
            <div style="color:var(--text-secondary);font-size:0.85rem;">
                Enter your GitHub repository URL below to enable update checking.
            </div>
        </div>
        '''
    else:
        config_status_html = f'''
        <div style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:1rem;">
            📦 Repository: <a href="https://github.com/{escape_html(repo_owner)}/{escape_html(repo_name)}" target="_blank" 
                style="color:var(--primary);font-family:monospace;">{escape_html(repo_owner)}/{escape_html(repo_name)}</a>
        </div>
        '''
    
    # Settings form - now always visible when not configured
    form_visible = "open" if not is_configured else ""
    auto_detected_msg = "✓ Auto-detected from git remote" if git_info.get('repo_owner') and not update_settings.get('github_owner') else ""
    
    settings_html = f'''
    <details style="margin-top:1rem;" {form_visible}>
        <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.85rem;">⚙️ Repository Settings {"(click to configure)" if not is_configured else ""}</summary>
        <div style="margin-top:0.75rem;padding:1rem;background:var(--bg-primary);border-radius:var(--radius);">
            <form method="POST" action="/admin/system/update-settings">
                <div class="form-group" style="margin-bottom:1rem;">
                    <label style="font-weight:600;">Git Clone URL</label>
                    <input type="text" name="github_url" value="{escape_html(display_url)}" 
                           placeholder="https://github.com/username/multi-frames.git" 
                           style="font-family:monospace;width:100%;">
                    <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem;">
                        Paste your repository URL (HTTPS or SSH format)
                    </div>
                </div>
                
                <details style="margin-bottom:1rem;">
                    <summary style="cursor:pointer;font-size:0.8rem;color:var(--text-secondary);">Advanced: Manual Owner/Repo</summary>
                    <div style="margin-top:0.5rem;display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;">
                        <div class="form-group">
                            <label>GitHub Owner/Org</label>
                            <input type="text" name="github_owner" value="{escape_html(repo_owner)}" 
                                   placeholder="username" style="font-family:monospace;">
                        </div>
                        <div class="form-group">
                            <label>Repository Name</label>
                            <input type="text" name="github_repo" value="{escape_html(repo_name)}" 
                                   placeholder="multi-frames" style="font-family:monospace;">
                        </div>
                    </div>
                </details>
                
                <div style="display:flex;gap:0.5rem;align-items:center;">
                    <button type="submit" class="btn btn-sm">💾 Save Settings</button>
                    <span style="color:var(--text-secondary);font-size:0.8rem;margin-left:0.5rem;">
                        {auto_detected_msg}
                    </span>
                </div>
            </form>
        </div>
    </details>
    '''
    
    # Action buttons
    pull_disabled = "" if git_info['is_git_repo'] and not git_info['has_changes'] else "disabled"
    check_disabled = "" if is_configured else "disabled"
    pull_tooltip = ""
    if not git_info['is_git_repo']:
        pull_tooltip = "Not a git repository"
    elif git_info['has_changes']:
        pull_tooltip = "Uncommitted changes - commit or stash first"
    
    return f'''
    <div class="admin-subsection">
        <h4>🔄 Firmware Updates</h4>
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
            <div>
                <span style="font-size:1.5rem;font-weight:700;">v{VERSION}</span>
                <span style="color:var(--text-secondary);margin-left:0.5rem;">({VERSION_DATE})</span>
            </div>
        </div>
        
        {config_status_html}
        {update_status_html}
        {git_status_html}
        
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem;">
            <form method="POST" action="/admin/system/check-updates" style="display:inline;">
                <button type="submit" class="btn btn-secondary" id="check-updates-btn" {check_disabled}
                        title="{"Configure repository first" if not is_configured else "Check GitHub for updates"}">
                    🔍 Check for Updates
                </button>
            </form>
            <form method="POST" action="/admin/system/git-pull" style="display:inline;" 
                  onsubmit="return confirm('This will update Multi-Frames to the latest version from GitHub.\\n\\nThe server will restart after updating.\\n\\nContinue?')">
                <button type="submit" class="btn" {pull_disabled} title="{pull_tooltip}">
                    ⬇️ Pull Latest Updates
                </button>
            </form>
        </div>
        
        <div id="update-result" style="display:none;margin-bottom:1rem;"></div>
        
        {settings_html}
    </div>
    '''


def render_status_dashboard(config):
    """Render a modern status dashboard with server health, Pi info, and alerts."""
    global server_logger, SERVER_START_TIME, server_alerts, cloud_agent

    sys_info = get_system_info()
    stats = server_logger.get_stats()
    alert_stats = server_alerts.get_stats()
    net_diag = get_network_diagnostics()
    cloud_status = cloud_agent.get_status()
    
    # Calculate uptime
    uptime_str = sys_info.get('server_uptime', '0h 0m 0s')
    
    # Server health status
    error_rate = 0
    total_req = stats.get('total_requests', 0)
    total_err = stats.get('total_errors', 0)
    if total_req > 0:
        error_rate = (total_err / total_req) * 100
    
    # Determine overall health
    if alert_stats['crash_count'] > 0 or error_rate > 10:
        health_status = 'critical'
        health_icon = '🔴'
        health_text = 'Issues Detected'
        health_color = '#ef4444'
    elif total_err > 0 or error_rate > 5:
        health_status = 'warning'
        health_icon = '🟡'
        health_text = 'Minor Issues'
        health_color = '#f59e0b'
    else:
        health_status = 'healthy'
        health_icon = '🟢'
        health_text = 'All Systems Operational'
        health_color = '#22c55e'
    
    # Raspberry Pi section
    pi_section = ""
    pi_info = get_raspberry_pi_info()
    if pi_info:
        temp = pi_info.get('temperature', 0)
        temp_color = '#22c55e' if temp < 60 else '#f59e0b' if temp < 70 else '#ef4444'
        temp_icon = '🌡️' if temp < 60 else '🔥' if temp < 70 else '🌋'
        
        throttle_status = ""
        throttle_data = pi_info.get('throttled')
        if throttle_data:
            # Check for CURRENT throttling issues (bits 0-3)
            current_issues = []
            if throttle_data.get('under_voltage'):
                current_issues.append('⚡ Under-voltage detected')
            if throttle_data.get('freq_capped'):
                current_issues.append('📉 Frequency capped')
            if throttle_data.get('throttled'):
                current_issues.append('🌡️ CPU throttled')
            if throttle_data.get('soft_temp_limit'):
                current_issues.append('🔥 Soft temperature limit')

            # Check for PAST issues (bits 16-19)
            past_issues = []
            if throttle_data.get('under_voltage_occurred'):
                past_issues.append('Under-voltage occurred')
            if throttle_data.get('freq_capped_occurred'):
                past_issues.append('Frequency was capped')
            if throttle_data.get('throttled_occurred'):
                past_issues.append('Throttling occurred')
            if throttle_data.get('soft_temp_occurred'):
                past_issues.append('Soft temp limit reached')

            if current_issues:
                # Active throttling - show red warning
                throttle_status = f'''
            <div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:0.5rem;padding:0.75rem;margin-top:1rem;">
                <span style="color:#ef4444;font-weight:600;">⚠️ Throttling Active</span>
                <span style="color:var(--text-secondary);font-size:0.85rem;margin-left:0.5rem;">{escape_html(', '.join(current_issues))}</span>
            </div>
            '''
            elif past_issues:
                # Past issues only - show orange warning
                throttle_status = f'''
            <div style="background:rgba(245,158,11,0.15);border:1px solid #f59e0b;border-radius:0.5rem;padding:0.75rem;margin-top:1rem;">
                <span style="color:#f59e0b;font-weight:600;">⚠️ Past Issues Detected</span>
                <span style="color:var(--text-secondary);font-size:0.85rem;margin-left:0.5rem;">{escape_html(', '.join(past_issues))} (since boot)</span>
            </div>
            '''
            # If throttle_data exists but no issues (0x0), show nothing - system is healthy
        
        pi_section = f'''
        <div style="background:linear-gradient(135deg, #c0194820 0%, #c0194810 100%);border:1px solid #c0194840;border-radius:0.75rem;padding:1.25rem;margin-bottom:1.5rem;">
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1rem;">
                <span style="font-size:1.5rem;">🍓</span>
                <div>
                    <div style="font-weight:600;font-size:1.1rem;">Raspberry Pi</div>
                    <div style="color:var(--text-secondary);font-size:0.85rem;">{escape_html(pi_info.get('model', 'Unknown Model'))}</div>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(120px, 1fr));gap:1rem;">
                <div style="background:var(--bg-primary);padding:0.75rem;border-radius:0.5rem;text-align:center;">
                    <div style="font-size:1.5rem;">{temp_icon}</div>
                    <div style="font-size:1.25rem;font-weight:700;color:{temp_color};">{temp}°C</div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);">Temperature</div>
                </div>
                <div style="background:var(--bg-primary);padding:0.75rem;border-radius:0.5rem;text-align:center;">
                    <div style="font-size:1.5rem;">💾</div>
                    <div style="font-size:1.1rem;font-weight:700;">{pi_info.get('memory_used', 0)}<span style="font-size:0.75rem;font-weight:400;">/{pi_info.get('memory_total', 0)} MB</span></div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);">Memory</div>
                </div>
                <div style="background:var(--bg-primary);padding:0.75rem;border-radius:0.5rem;text-align:center;">
                    <div style="font-size:1.5rem;">💽</div>
                    <div style="font-size:1.1rem;font-weight:700;">{pi_info.get('disk_used', 0)}<span style="font-size:0.75rem;font-weight:400;">/{pi_info.get('disk_total', 0)} GB</span></div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);">Disk</div>
                </div>
                <div style="background:var(--bg-primary);padding:0.75rem;border-radius:0.5rem;text-align:center;">
                    <div style="font-size:1.5rem;">⚡</div>
                    <div style="font-size:1.1rem;font-weight:700;color:{"#22c55e" if not pi_info.get('throttled', {}).get('under_voltage') else "#ef4444"}">{pi_info.get('voltage_core', 'N/A')}<span style="font-size:0.75rem;font-weight:400;">V</span></div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);">Core Voltage</div>
                </div>
            </div>
            {throttle_status}
        </div>
        '''
    
    # Health alerts section
    alerts_section = ""
    if alert_stats['crash_count'] > 0 or alert_stats['critical_count'] > 0 or alert_stats['error_count'] > 0:
        recent_alerts = server_alerts.get_alerts(limit=5)
        alerts_list = ""
        for alert in recent_alerts:
            severity_icons = {'critical': '🔴', 'error': '🟠', 'warning': '🟡', 'info': '🔵'}
            icon = severity_icons.get(alert['severity'], '⚪')
            time_str = alert['timestamp'][11:19] if len(alert['timestamp']) > 19 else alert['timestamp']
            count_badge = f'<span style="background:var(--bg-tertiary);padding:0.1rem 0.4rem;border-radius:0.25rem;font-size:0.7rem;margin-left:0.25rem;">×{alert["count"]}</span>' if alert.get('count', 1) > 1 else ''
            alerts_list += f'''
            <div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.5rem 0;border-bottom:1px solid var(--border);">
                <span>{icon}</span>
                <div style="flex:1;min-width:0;">
                    <div style="font-size:0.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{escape_html(alert["message"][:100])}{count_badge}</div>
                    <div style="font-size:0.7rem;color:var(--text-secondary);">{time_str}</div>
                </div>
            </div>
            '''
        
        alerts_section = f'''
        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:0.75rem;padding:1rem;margin-bottom:1.5rem;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
                <div style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="font-size:1.1rem;">🚨</span>
                    <span style="font-weight:600;">Health Alerts</span>
                    {f'<span style="background:#ef4444;color:white;padding:0.15rem 0.5rem;border-radius:1rem;font-size:0.75rem;">{alert_stats["crash_count"]} restart{"s" if alert_stats["crash_count"] != 1 else ""}</span>' if alert_stats["crash_count"] > 0 else ''}
                </div>
                <form method="POST" action="/admin/system/clear-alerts">
                    <button type="submit" class="btn btn-sm btn-secondary" style="font-size:0.75rem;padding:0.25rem 0.5rem;" onclick="return confirm('Clear all alerts?')">Clear</button>
                </form>
            </div>
            <div style="max-height:180px;overflow-y:auto;">
                {alerts_list}
            </div>
        </div>
        '''
    
    return f'''
    <div class="admin-section" style="margin-bottom:0;">
        <!-- Server Health Banner -->
        <div style="background:linear-gradient(135deg, {health_color}15 0%, {health_color}05 100%);border:1px solid {health_color}40;border-radius:0.75rem;padding:1.25rem;margin-bottom:1.5rem;">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
                <div style="display:flex;align-items:center;gap:0.75rem;">
                    <span style="font-size:2rem;">{health_icon}</span>
                    <div>
                        <div style="font-size:1.25rem;font-weight:700;">{health_text}</div>
                        <div style="color:var(--text-secondary);font-size:0.9rem;">Multi-Frames v{VERSION}</div>
                    </div>
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">Uptime:</span>
                    <span style="font-family:monospace;font-weight:600;font-size:1.1rem;">{escape_html(uptime_str)}</span>
                </div>
            </div>
        </div>
        
        {pi_section}
        {alerts_section}
        
        <!-- Stats Cards -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:1rem;margin-bottom:1.5rem;">
            <div style="background:var(--bg-secondary);border-radius:0.75rem;padding:1rem;text-align:center;border:1px solid var(--border);">
                <div style="font-size:1.75rem;">📊</div>
                <div style="font-size:1.5rem;font-weight:700;margin:0.25rem 0;">{stats.get('total_requests', 0):,}</div>
                <div style="font-size:0.8rem;color:var(--text-secondary);">Total Requests</div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.75rem;padding:1rem;text-align:center;border:1px solid var(--border);">
                <div style="font-size:1.75rem;">{"✅" if total_err == 0 else "⚠️"}</div>
                <div style="font-size:1.5rem;font-weight:700;color:{'inherit' if total_err == 0 else '#ef4444'};">{total_err:,}</div>
                <div style="font-size:0.8rem;color:var(--text-secondary);">Errors</div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.75rem;padding:1rem;text-align:center;border:1px solid var(--border);">
                <div style="font-size:1.75rem;">🧠</div>
                <div style="font-size:1.5rem;font-weight:700;">{sys_info.get('memory_mb', 'N/A')}</div>
                <div style="font-size:0.8rem;color:var(--text-secondary);">Memory (MB)</div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.75rem;padding:1rem;text-align:center;border:1px solid var(--border);">
                <div style="font-size:1.75rem;">🌐</div>
                <div style="font-size:1.1rem;font-weight:700;font-family:monospace;">{escape_html(net_diag.get('local_ip', '?'))}</div>
                <div style="font-size:0.8rem;color:var(--text-secondary);">IP Address</div>
            </div>
        </div>
        
        <!-- Quick Info -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:1rem;">
            <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:0.75rem 1rem;border:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">Hostname</span>
                    <span style="font-family:monospace;font-weight:500;">{escape_html(net_diag.get('hostname', 'Unknown'))}</span>
                </div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:0.75rem 1rem;border:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">Port</span>
                    <span style="font-family:monospace;font-weight:500;">{sys_info.get('server_port', '?')}</span>
                </div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:0.75rem 1rem;border:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">Python</span>
                    <span style="font-family:monospace;font-weight:500;">{escape_html(sys_info.get('python_version', '?'))}</span>
                </div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:0.75rem 1rem;border:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">mDNS</span>
                    <span style="font-weight:500;">{"✓ Active" if sys_info.get('mdns_running') else "✗ Off"}</span>
                </div>
            </div>
            <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:0.75rem 1rem;border:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:var(--text-secondary);font-size:0.85rem;">☁️ Cloud</span>
                    <span style="font-weight:500;color:{'#22c55e' if cloud_status.get('connected') else '#f59e0b' if cloud_status.get('enabled') else 'var(--text-secondary)'};">{"✓ Connected" if cloud_status.get('connected') else "⋯ Connecting" if cloud_status.get('enabled') else "✗ Off"}</span>
                </div>
            </div>
        </div>
    </div>
    '''


def render_modern_logs(config):
    """Render modern tabbed logs viewer."""
    global server_logger
    
    # Get log data
    recent_logs = server_logger.get_logs(limit=100)
    recent_requests = server_logger.get_requests(limit=50)
    recent_errors = server_logger.get_errors(limit=30)
    stats = server_logger.get_stats()
    
    # Build logs HTML
    logs_html = ""
    for log in reversed(recent_logs[-50:]):
        level_styles = {
            'DEBUG': ('var(--text-secondary)', 'transparent', '○'),
            'INFO': ('#3b82f6', 'rgba(59,130,246,0.1)', '●'),
            'WARNING': ('#f59e0b', 'rgba(245,158,11,0.1)', '▲'),
            'ERROR': ('#ef4444', 'rgba(239,68,68,0.1)', '✕')
        }
        color, bg, icon = level_styles.get(log['level'], ('#888', 'transparent', '○'))
        time_str = log['timestamp'].split(' ')[1] if ' ' in log['timestamp'] else log['timestamp']
        extra = f' <span style="color:var(--text-secondary);">({log["extra"]})</span>' if log.get('extra') else ''
        
        logs_html += f'''
        <div style="display:flex;align-items:flex-start;gap:0.75rem;padding:0.6rem 0.75rem;border-bottom:1px solid var(--border);background:{bg};">
            <span style="color:{color};font-size:0.9rem;line-height:1.4;">{icon}</span>
            <span style="color:var(--text-secondary);font-family:monospace;font-size:0.75rem;min-width:55px;">{time_str[:8]}</span>
            <span style="flex:1;font-size:0.85rem;line-height:1.4;">{escape_html(log['message'])}{extra}</span>
        </div>
        '''
    if not logs_html:
        logs_html = '<div style="padding:2rem;text-align:center;color:var(--text-secondary);">No logs recorded yet</div>'
    
    # Build requests HTML
    requests_html = ""
    for req in reversed(recent_requests[:30]):
        status = req.get('status', 0)
        if 200 <= status < 300:
            status_color, status_bg = '#22c55e', 'rgba(34,197,94,0.1)'
        elif 300 <= status < 400:
            status_color, status_bg = '#3b82f6', 'rgba(59,130,246,0.1)'
        elif status >= 400:
            status_color, status_bg = '#ef4444', 'rgba(239,68,68,0.1)'
        else:
            status_color, status_bg = 'var(--text-secondary)', 'transparent'
        
        time_str = req['timestamp'].split(' ')[1] if ' ' in req['timestamp'] else req['timestamp']
        method_color = '#22c55e' if req['method'] == 'GET' else '#f59e0b'
        user_badge = f'<span style="background:var(--bg-tertiary);padding:0.1rem 0.4rem;border-radius:0.25rem;font-size:0.7rem;margin-left:0.5rem;">{escape_html(req["user"])}</span>' if req.get('user') else ''
        
        requests_html += f'''
        <div style="display:flex;align-items:center;gap:0.5rem;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);font-size:0.8rem;">
            <span style="color:var(--text-secondary);font-family:monospace;min-width:55px;">{time_str[:8]}</span>
            <span style="color:{method_color};font-weight:600;min-width:40px;">{req['method']}</span>
            <span style="background:{status_bg};color:{status_color};padding:0.1rem 0.4rem;border-radius:0.25rem;font-family:monospace;font-size:0.75rem;">{status}</span>
            <span style="flex:1;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{escape_html(req['path'])}</span>
            <span style="color:var(--text-secondary);font-size:0.75rem;">{req.get('duration_ms', 0)}ms</span>
            <span style="color:var(--text-secondary);font-size:0.75rem;">{escape_html(req.get('client_ip', ''))}</span>
            {user_badge}
        </div>
        '''
    if not requests_html:
        requests_html = '<div style="padding:2rem;text-align:center;color:var(--text-secondary);">No requests logged yet</div>'
    
    # Build errors HTML
    errors_html = ""
    for err in reversed(recent_errors[:20]):
        time_str = err['timestamp'].split(' ')[1] if ' ' in err['timestamp'] else err['timestamp']
        errors_html += f'''
        <div style="padding:0.75rem;border-bottom:1px solid var(--border);background:rgba(239,68,68,0.05);">
            <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem;">
                <span style="color:#ef4444;">✕</span>
                <span style="color:var(--text-secondary);font-family:monospace;font-size:0.75rem;">{time_str[:8]}</span>
            </div>
            <div style="font-size:0.85rem;padding-left:1.25rem;">{escape_html(err['message'])}</div>
        </div>
        '''
    if not errors_html:
        errors_html = '<div style="padding:2rem;text-align:center;color:#22c55e;">✓ No errors recorded</div>'
    
    # Stats badges
    method_stats = stats.get('requests_by_method', {})
    status_stats = stats.get('status_codes', {})
    
    return f'''
    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>📋</span> Server Logs
            <span style="margin-left:auto;display:flex;gap:0.5rem;">
                <form method="POST" action="/admin/system/clear-logs" style="display:inline;">
                    <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Clear all logs?')">Clear</button>
                </form>
            </span>
        </h3>
        
        <!-- Log Stats Bar -->
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:1rem;padding:0.75rem;background:var(--bg-secondary);border-radius:0.5rem;">
            <span style="font-size:0.8rem;padding:0.25rem 0.5rem;background:var(--bg-primary);border-radius:0.25rem;">
                <span style="color:var(--text-secondary);">GET</span> <strong>{method_stats.get('GET', 0)}</strong>
            </span>
            <span style="font-size:0.8rem;padding:0.25rem 0.5rem;background:var(--bg-primary);border-radius:0.25rem;">
                <span style="color:var(--text-secondary);">POST</span> <strong>{method_stats.get('POST', 0)}</strong>
            </span>
            <span style="font-size:0.8rem;padding:0.25rem 0.5rem;background:rgba(34,197,94,0.1);border-radius:0.25rem;color:#22c55e;">
                2xx: <strong>{status_stats.get('200', 0) + status_stats.get('201', 0)}</strong>
            </span>
            <span style="font-size:0.8rem;padding:0.25rem 0.5rem;background:rgba(59,130,246,0.1);border-radius:0.25rem;color:#3b82f6;">
                3xx: <strong>{status_stats.get('302', 0) + status_stats.get('301', 0)}</strong>
            </span>
            <span style="font-size:0.8rem;padding:0.25rem 0.5rem;background:rgba(239,68,68,0.1);border-radius:0.25rem;color:#ef4444;">
                4xx+: <strong>{status_stats.get('401', 0) + status_stats.get('404', 0) + status_stats.get('500', 0)}</strong>
            </span>
            
            <span style="margin-left:auto;display:flex;align-items:center;gap:0.5rem;">
                <form method="POST" action="/admin/system/log-level" style="display:flex;align-items:center;gap:0.25rem;">
                    <label style="font-size:0.75rem;color:var(--text-secondary);">Level:</label>
                    <select name="level" style="padding:0.2rem 0.4rem;font-size:0.8rem;width:auto;">
                        <option value="DEBUG" {"selected" if server_logger.log_level == "DEBUG" else ""}>DEBUG</option>
                        <option value="INFO" {"selected" if server_logger.log_level == "INFO" else ""}>INFO</option>
                        <option value="WARNING" {"selected" if server_logger.log_level == "WARNING" else ""}>WARNING</option>
                        <option value="ERROR" {"selected" if server_logger.log_level == "ERROR" else ""}>ERROR</option>
                    </select>
                    <button type="submit" class="btn btn-sm" style="padding:0.2rem 0.5rem;font-size:0.75rem;">Set</button>
                </form>
            </span>
        </div>
        
        <!-- Tabbed Logs -->
        <div class="logs-tabs">
            <style>
            .logs-tabs .tab-buttons {{ display:flex; gap:0.25rem; margin-bottom:-1px; position:relative; z-index:1; }}
            .logs-tabs .tab-btn {{ padding:0.5rem 1rem; border:1px solid var(--border); border-bottom:none; border-radius:0.5rem 0.5rem 0 0; background:var(--bg-secondary); cursor:pointer; font-size:0.85rem; transition:all 0.2s; }}
            .logs-tabs .tab-btn:hover {{ background:var(--bg-primary); }}
            .logs-tabs .tab-btn.active {{ background:var(--bg-primary); border-bottom:1px solid var(--bg-primary); font-weight:600; }}
            .logs-tabs .tab-content {{ display:none; border:1px solid var(--border); border-radius:0 0.5rem 0.5rem 0.5rem; background:var(--bg-primary); max-height:350px; overflow-y:auto; }}
            .logs-tabs .tab-content.active {{ display:block; }}
            </style>
            
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="showLogTab('requests', this)">
                    🔗 Requests <span style="background:var(--bg-tertiary);padding:0.1rem 0.4rem;border-radius:1rem;font-size:0.7rem;margin-left:0.25rem;">{len(recent_requests)}</span>
                </button>
                <button class="tab-btn" onclick="showLogTab('logs', this)">
                    📜 Logs <span style="background:var(--bg-tertiary);padding:0.1rem 0.4rem;border-radius:1rem;font-size:0.7rem;margin-left:0.25rem;">{len(recent_logs)}</span>
                </button>
                <button class="tab-btn" onclick="showLogTab('errors', this)">
                    ⚠️ Errors <span style="background:{'#ef444420' if recent_errors else 'var(--bg-tertiary)'};color:{'#ef4444' if recent_errors else 'inherit'};padding:0.1rem 0.4rem;border-radius:1rem;font-size:0.7rem;margin-left:0.25rem;">{len(recent_errors)}</span>
                </button>
            </div>
            
            <div id="log-tab-requests" class="tab-content active">
                {requests_html}
            </div>
            <div id="log-tab-logs" class="tab-content">
                {logs_html}
            </div>
            <div id="log-tab-errors" class="tab-content">
                {errors_html}
            </div>
        </div>
        
        <script>
        function showLogTab(name, btn) {{
            document.querySelectorAll('.logs-tabs .tab-content').forEach(function(el) {{ el.classList.remove('active'); }});
            document.querySelectorAll('.logs-tabs .tab-btn').forEach(function(el) {{ el.classList.remove('active'); }});
            document.getElementById('log-tab-' + name).classList.add('active');
            btn.classList.add('active');
        }}
        </script>
    </div>
    '''


def render_watchdog_section(config):
    """Render the watchdog monitoring section with uptime tracking and history."""
    global uptime_tracker, server_alerts, SERVER_START_TIME

    # Get uptime statistics
    stats = uptime_tracker.get_stats(config)
    alert_stats = server_alerts.get_stats()

    # Determine uptime status color and icon
    uptime_pct = stats['uptime_30d']
    if uptime_pct >= 99.9:
        status_color = '#22c55e'
        status_icon = '🟢'
        status_text = 'Excellent'
    elif uptime_pct >= 99.0:
        status_color = '#84cc16'
        status_icon = '🟢'
        status_text = 'Good'
    elif uptime_pct >= 95.0:
        status_color = '#f59e0b'
        status_icon = '🟡'
        status_text = 'Fair'
    else:
        status_color = '#ef4444'
        status_icon = '🔴'
        status_text = 'Poor'

    # Build 30-day uptime chart (bar chart visualization)
    daily_uptime = stats.get('daily_uptime', {})
    chart_bars = ""
    for i in range(29, -1, -1):  # Last 30 days, oldest first
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        day_data = daily_uptime.get(date, {'uptime_seconds': 0, 'downtime_seconds': 0, 'crashes': 0})
        day_up = day_data.get('uptime_seconds', 0)
        day_down = day_data.get('downtime_seconds', 0)
        day_total = day_up + day_down

        if day_total > 0:
            day_pct = (day_up / day_total) * 100
        else:
            # No data for this day yet
            day_pct = -1

        # Determine bar color based on uptime percentage
        if day_pct < 0:
            bar_color = 'var(--border)'  # No data - gray
            height = 4
            tooltip = f'{date}: No data'
        elif day_pct >= 99.9:
            bar_color = '#22c55e'
            height = 100
            tooltip = f'{date}: {day_pct:.1f}% uptime'
        elif day_pct >= 99.0:
            bar_color = '#84cc16'
            height = int(day_pct)
            tooltip = f'{date}: {day_pct:.1f}% uptime'
        elif day_pct >= 95.0:
            bar_color = '#f59e0b'
            height = int(day_pct)
            tooltip = f'{date}: {day_pct:.1f}% uptime'
        else:
            bar_color = '#ef4444'
            height = max(4, int(day_pct))
            tooltip = f'{date}: {day_pct:.1f}% uptime'

        # Add crash indicator
        crashes = day_data.get('crashes', 0)
        crash_indicator = f' ({crashes} crash{"es" if crashes != 1 else ""})' if crashes > 0 else ''
        tooltip += crash_indicator

        chart_bars += f'''
        <div class="uptime-bar" title="{tooltip}" style="height:{height}%;background:{bar_color};min-height:4px;"></div>
        '''

    # Build events list
    events_html = ""
    for event in stats.get('recent_events', [])[:15]:
        event_type = event.get('type', 'unknown')
        event_icons = {
            'start': '🚀',
            'stop': '🛑',
            'crash': '💥',
            'downtime': '⏱️'
        }
        icon = event_icons.get(event_type, '📌')

        severity = event.get('severity', 'info')
        severity_colors = {
            'critical': '#ef4444',
            'error': '#f59e0b',
            'warning': '#eab308',
            'info': 'var(--text-secondary)'
        }
        color = severity_colors.get(severity, 'var(--text-secondary)')

        timestamp = event.get('timestamp', '')
        time_str = timestamp[11:19] if len(timestamp) > 19 else timestamp
        date_str = timestamp[:10] if len(timestamp) > 10 else ''

        events_html += f'''
        <div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.5rem 0;border-bottom:1px solid var(--border);">
            <span style="font-size:1.1rem;">{icon}</span>
            <div style="flex:1;min-width:0;">
                <div style="color:{color};font-size:0.9rem;">{escape_html(event.get('message', '')[:80])}</div>
                <div style="font-size:0.75rem;color:var(--text-secondary);">{date_str} {time_str}</div>
            </div>
        </div>
        '''

    if not events_html:
        events_html = '<div style="padding:1rem;text-align:center;color:var(--text-secondary);">No events recorded yet</div>'

    return f'''
    <style>
    .uptime-chart {{
        display:flex;
        align-items:flex-end;
        gap:2px;
        height:60px;
        padding:0.5rem;
        background:var(--bg-primary);
        border-radius:0.5rem;
    }}
    .uptime-bar {{
        flex:1;
        border-radius:2px 2px 0 0;
        transition:opacity 0.2s;
        cursor:pointer;
    }}
    .uptime-bar:hover {{
        opacity:0.8;
    }}
    .uptime-stat-card {{
        background:var(--bg-secondary);
        border-radius:0.75rem;
        padding:1.25rem;
        text-align:center;
        border:1px solid var(--border);
    }}
    .uptime-stat-value {{
        font-size:2rem;
        font-weight:700;
        font-family:monospace;
    }}
    .uptime-stat-label {{
        font-size:0.8rem;
        color:var(--text-secondary);
        margin-top:0.25rem;
    }}
    </style>

    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>🐕</span> Server Watchdog
        </h3>
        <div class="admin-content">
            <!-- Status Overview -->
            <div style="background:linear-gradient(135deg, {status_color}15 0%, {status_color}05 100%);border:1px solid {status_color}40;border-radius:0.75rem;padding:1.5rem;margin-bottom:1.5rem;">
                <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
                    <div style="display:flex;align-items:center;gap:1rem;">
                        <span style="font-size:3rem;">{status_icon}</span>
                        <div>
                            <div style="font-size:1.5rem;font-weight:700;">{uptime_pct:.3f}% Uptime</div>
                            <div style="color:var(--text-secondary);">30-Day Average: {status_text}</div>
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:0.85rem;color:var(--text-secondary);">Current Session</div>
                        <div style="font-size:1.5rem;font-weight:700;font-family:monospace;">{escape_html(stats['current_session_formatted'])}</div>
                    </div>
                </div>
            </div>

            <!-- Uptime Stats Cards -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:1rem;margin-bottom:1.5rem;">
                <div class="uptime-stat-card">
                    <div class="uptime-stat-value" style="color:{('#22c55e' if stats['uptime_24h'] >= 99 else '#f59e0b' if stats['uptime_24h'] >= 95 else '#ef4444')};">{stats['uptime_24h']:.1f}%</div>
                    <div class="uptime-stat-label">24 Hour Uptime</div>
                </div>
                <div class="uptime-stat-card">
                    <div class="uptime-stat-value" style="color:{('#22c55e' if stats['uptime_7d'] >= 99 else '#f59e0b' if stats['uptime_7d'] >= 95 else '#ef4444')};">{stats['uptime_7d']:.1f}%</div>
                    <div class="uptime-stat-label">7 Day Uptime</div>
                </div>
                <div class="uptime-stat-card">
                    <div class="uptime-stat-value" style="color:{('#22c55e' if stats['uptime_30d'] >= 99 else '#f59e0b' if stats['uptime_30d'] >= 95 else '#ef4444')};">{stats['uptime_30d']:.1f}%</div>
                    <div class="uptime-stat-label">30 Day Uptime</div>
                </div>
                <div class="uptime-stat-card">
                    <div class="uptime-stat-value">{stats['total_crashes']}</div>
                    <div class="uptime-stat-label">Total Crashes</div>
                </div>
            </div>

            <!-- 30-Day Uptime Chart -->
            <div style="margin-bottom:1.5rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                    <h4 style="margin:0;font-size:0.95rem;">30-Day Uptime History</h4>
                    <span style="font-size:0.75rem;color:var(--text-secondary);">Hover for details</span>
                </div>
                <div class="uptime-chart">
                    {chart_bars}
                </div>
                <div style="display:flex;justify-content:space-between;font-size:0.7rem;color:var(--text-secondary);padding:0.25rem 0.5rem;">
                    <span>30 days ago</span>
                    <span>Today</span>
                </div>
            </div>

            <!-- Detailed Stats -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:1rem;margin-bottom:1.5rem;">
                <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:1rem;border:1px solid var(--border);">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Total Uptime (30d)</span>
                        <span style="font-weight:600;font-family:monospace;">{escape_html(stats['total_uptime_formatted'])}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Total Downtime (30d)</span>
                        <span style="font-weight:600;font-family:monospace;color:{'#ef4444' if stats['total_downtime_seconds'] > 0 else 'inherit'};">{escape_html(stats['total_downtime_formatted'])}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Days Tracked</span>
                        <span style="font-weight:600;">{stats['days_tracked']} days</span>
                    </div>
                </div>
                <div style="background:var(--bg-secondary);border-radius:0.5rem;padding:1rem;border:1px solid var(--border);">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Server Restarts</span>
                        <span style="font-weight:600;">{stats['total_restarts']}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Crash Events</span>
                        <span style="font-weight:600;color:{'#ef4444' if stats['total_crashes'] > 0 else 'inherit'};">{stats['total_crashes']}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="color:var(--text-secondary);font-size:0.85rem;">Alert Count</span>
                        <span style="font-weight:600;">{alert_stats['total_alerts']}</span>
                    </div>
                </div>
            </div>

            <!-- Recent Events -->
            <div style="margin-bottom:1rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                    <h4 style="margin:0;font-size:0.95rem;">Recent Events</h4>
                    <form method="POST" action="/admin/watchdog/clear-events">
                        <button type="submit" class="btn btn-sm btn-secondary" style="font-size:0.75rem;padding:0.25rem 0.5rem;" onclick="return confirm('Clear all watchdog events?')">Clear</button>
                    </form>
                </div>
                <div style="background:var(--bg-primary);border-radius:0.5rem;max-height:250px;overflow-y:auto;">
                    {events_html}
                </div>
            </div>

            <!-- Watchdog Actions -->
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;padding-top:0.5rem;border-top:1px solid var(--border);">
                <button class="btn btn-secondary btn-sm" onclick="location.reload()">🔄 Refresh Stats</button>
                <form method="POST" action="/admin/watchdog/test-event" style="display:inline;">
                    <button type="submit" class="btn btn-secondary btn-sm">🧪 Test Event</button>
                </form>
                <form method="POST" action="/admin/watchdog/reset-stats" style="display:inline;">
                    <button type="submit" class="btn btn-secondary btn-sm" onclick="return confirm('Reset all uptime statistics? This cannot be undone.')">🗑️ Reset All Stats</button>
                </form>
            </div>
        </div>
    </div>
    '''


def render_system_section(config):
    """Render the system section with diagnostics, connectivity tests, and tools."""
    global server_logger, SERVER_START_TIME
    
    sys_info = get_system_info()
    net_diag = get_network_diagnostics()
    stats = server_logger.get_stats()
    
    # Check if config file is writable
    config_writable = check_config_writable()
    config_warning = ""
    if not config_writable:
        config_warning = f'''
        <div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:0.5rem;padding:1rem;margin-bottom:1.5rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;color:#ef4444;font-weight:600;margin-bottom:0.5rem;">
                <span style="font-size:1.25rem;">⚠️</span> Configuration File Not Writable
            </div>
            <div style="color:var(--text-secondary);font-size:0.9rem;">
                The config file <code style="background:var(--bg-secondary);padding:0.15rem 0.4rem;border-radius:0.25rem;">{CONFIG_FILE}</code> cannot be written. 
                Changes will not be saved.
            </div>
            <div style="margin-top:0.75rem;padding:0.75rem;background:var(--bg-secondary);border-radius:0.25rem;font-family:monospace;font-size:0.85rem;">
                <span style="color:var(--text-secondary);"># Fix:</span> chmod 666 {CONFIG_FILE}
            </div>
        </div>
        '''
    
    # iFrame connectivity test HTML
    iframes = config.get('iframes', [])
    iframe_test_html = ""
    for i, iframe in enumerate(iframes):
        name = escape_html(iframe.get('name', f'Frame {i+1}'))
        url = iframe.get('url', '')
        url_escaped = escape_html(url).replace("'", "&#39;")
        enabled = iframe.get('enabled', True)
        enabled_badge = '' if enabled else ' <span style="font-size:0.7rem;color:var(--text-secondary);">(disabled)</span>'
        
        if iframe.get('use_embed_code'):
            iframe_test_html += f'''
            <div style="padding:0.6rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:0.75rem;">
                <span style="color:#22c55e;">✓</span>
                <span style="flex:1;font-weight:500;">{name}{enabled_badge}</span>
                <span style="color:var(--text-secondary);font-size:0.8rem;">📋 Embed Code</span>
            </div>'''
        else:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.netloc or url[:30]
                is_https = parsed.scheme == 'https'
            except:
                host = url[:30]
                is_https = False
            
            iframe_test_html += f'''
            <div style="padding:0.6rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                <span class="status-dot" id="test-{i}" style="color:var(--text-secondary);">●</span>
                <span style="flex:1;font-weight:500;min-width:100px;">{name}{enabled_badge}</span>
                <span style="font-size:0.7rem;padding:0.15rem 0.35rem;background:{'rgba(34,197,94,0.1)' if is_https else 'rgba(245,158,11,0.1)'};color:{'#22c55e' if is_https else '#f59e0b'};border-radius:3px;">{'🔒' if is_https else '⚠️'}</span>
                <span style="color:var(--text-secondary);font-size:0.75rem;font-family:monospace;">{escape_html(host[:25])}</span>
                <button class="btn btn-sm btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.75rem;" onclick="testUrl({i},'{url_escaped}','{name}')">Test</button>
            </div>'''
    
    if not iframe_test_html:
        iframe_test_html = '<div style="padding:1rem;text-align:center;color:var(--text-secondary);">No iFrames configured</div>'
    
    # Config export (sanitized)
    safe_config = json.loads(json.dumps(config))
    for u in safe_config.get('users', {}): safe_config['users'][u]['password_hash'] = '***'
    if 'sessions' in safe_config: safe_config['sessions'] = {}
    config_json = json.dumps(safe_config, indent=2)
    
    return f'''
    {config_warning}
    
    <!-- Connectivity Testing -->
    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>🧪</span> Connectivity Testing
        </h3>
        <div class="admin-content">
            <div style="background:var(--bg-primary);border-radius:0.5rem;max-height:300px;overflow-y:auto;">
                {iframe_test_html}
            </div>
            
            <script>
            var apiBase = window.location.origin;  // Get correct protocol, host, and port

            function testUrl(idx, url, name) {{
                var dot = document.getElementById('test-' + idx);
                if (!dot) return;
                dot.style.color = '#f59e0b';
                dot.textContent = '◐';
                dot.title = 'Testing...';

                var start = performance.now();

                // Use server-side proxy test for accurate HTTP status checking
                // This avoids false positives from iframe.onload firing on error pages
                fetch(apiBase + '/admin/system/connectivity-test-single', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ url: url, index: idx }})
                }})
                .then(function(response) {{ return response.json(); }})
                .then(function(data) {{
                    var ms = Math.round(performance.now() - start);
                    var result = data.result || {{}};

                    // Determine success based on actual HTTP response
                    var isSuccess = result.status === 'success';
                    var isBlocked = false;
                    var reason = '';

                    // Check for X-Frame-Options that would block embedding
                    if (result.x_frame_options) {{
                        var xfo = result.x_frame_options.toUpperCase();
                        if (xfo === 'DENY' || xfo === 'SAMEORIGIN') {{
                            isSuccess = false;
                            isBlocked = true;
                            reason = 'X-Frame-Options: ' + result.x_frame_options;
                        }}
                    }}

                    // Check for CSP frame-ancestors that would block embedding
                    if (result.csp_frame_ancestors) {{
                        var csp = result.csp_frame_ancestors.toLowerCase();
                        if (csp.includes("'none'") || (csp.includes("'self'") && !csp.includes('*'))) {{
                            isSuccess = false;
                            isBlocked = true;
                            reason = 'CSP blocks framing';
                        }}
                    }}

                    // Handle error cases - 'success' includes HTTP 4xx/5xx (server reachable)
                    if (result.status === 'error') {{
                        isSuccess = false;
                        reason = result.error || 'Not reachable';
                    }} else if (result.status === 'warning') {{
                        // SSL issues - server reachable but with certificate problems
                        isBlocked = true;
                        reason = result.error || 'SSL certificate issue';
                    }}

                    // Update UI
                    dot.style.color = isSuccess ? '#22c55e' : (isBlocked ? '#f59e0b' : '#ef4444');
                    dot.textContent = isSuccess ? '✓' : (isBlocked ? '⚠' : '✗');

                    var title = isSuccess ? 'Reachable' : (isBlocked ? 'Warning' : 'Failed');
                    title += ' (' + (result.response_time || ms + ' ms') + ')';
                    if (result.note) title += '\\n' + result.note;
                    if (reason) title += '\\n' + reason;
                    dot.title = title;
                }})
                .catch(function(err) {{
                    // Fallback: if server test fails, try iframe-based test with enhanced validation
                    testUrlFallback(idx, url, name, start);
                }});
            }}

            function testUrlFallback(idx, url, name, start) {{
                var dot = document.getElementById('test-' + idx);
                if (!dot) return;

                var f = document.createElement('iframe');
                f.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0;';
                var done = false;

                function finish(ok, reason) {{
                    if (done) return;
                    done = true;
                    var ms = Math.round(performance.now() - start);
                    dot.style.color = ok ? '#22c55e' : '#ef4444';
                    dot.textContent = ok ? '✓' : '✗';
                    var title = (ok ? 'OK' : 'Failed') + ' (' + ms + 'ms)';
                    if (reason) title += '\\n' + reason;
                    dot.title = title;
                    try {{ document.body.removeChild(f); }} catch(e) {{}}
                }}

                f.onload = function() {{
                    // onload fires even for error pages and blocked frames
                    // Try to detect if content actually loaded by checking accessibility
                    try {{
                        // This will throw for cross-origin iframes (which is expected)
                        // But if we can access it and it's blank/error, that's a failure
                        var doc = f.contentDocument || f.contentWindow.document;
                        var body = doc.body;
                        // If we get here, same-origin - check if it has content
                        if (body && body.innerHTML && body.innerHTML.length > 50) {{
                            finish(true);
                        }} else {{
                            finish(false, 'Empty or error page');
                        }}
                    }} catch(e) {{
                        // Cross-origin - we can't tell if it loaded properly
                        // Check iframe dimensions as a heuristic
                        setTimeout(function() {{
                            // For cross-origin, we have to assume success if onload fired
                            // but warn that we can't fully verify
                            finish(true, 'Cross-origin (unverified)');
                        }}, 100);
                    }}
                }};
                f.onerror = function() {{ finish(false, 'Network error'); }};
                setTimeout(function() {{ finish(false, 'Timeout'); }}, 8000);

                document.body.appendChild(f);
                f.src = url;
            }}

            function testAllFrames() {{
                document.querySelectorAll('[id^="test-"]').forEach(function(dot, i) {{
                    var btn = dot.parentElement.querySelector('button');
                    if (btn) setTimeout(function() {{ btn.click(); }}, i * 300);
                }});
            }}
            </script>

            <div style="margin-top:0.75rem;">
                <button class="btn btn-secondary btn-sm" onclick="testAllFrames()">🧪 Test All</button>
            </div>

            {render_connectivity_reports(config)}
        </div>
    </div>

    <!-- Updates & Firmware -->
    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>🔄</span> Updates & Firmware
        </h3>
        <div class="admin-content">
            {render_update_section(config)}
            
            <div class="admin-subsection" style="margin-top:1.5rem;">
                <h4>⬆️ Manual Firmware Upload</h4>
                <form method="POST" action="/admin/system/firmware-upload" enctype="multipart/form-data">
                    <div style="display:flex;gap:0.75rem;align-items:flex-end;flex-wrap:wrap;">
                        <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0;">
                            <label>Firmware File (.py)</label>
                            <input type="file" name="firmware" accept=".py" required style="padding:0.4rem;">
                        </div>
                        <button type="submit" class="btn" onclick="return confirm('Upload and install firmware?')">⬆️ Upload</button>
                    </div>
                </form>
                <details style="margin-top:0.75rem;">
                    <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.8rem;">📁 Backups</summary>
                    <div style="margin-top:0.5rem;background:var(--bg-primary);padding:0.5rem;border-radius:0.25rem;font-size:0.8rem;">
                        {render_firmware_backups()}
                    </div>
                </details>
            </div>
        </div>
    </div>
    
    <!-- Configuration -->
    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>📄</span> Configuration
        </h3>
        <div class="admin-content">
            <div class="admin-subsection">
                <h4>📤 Export</h4>
                <textarea readonly style="width:100%;height:120px;font-family:monospace;font-size:0.7rem;background:var(--bg-primary);border:1px solid var(--border);border-radius:0.25rem;padding:0.5rem;resize:vertical;">{escape_html(config_json)}</textarea>
                <div style="margin-top:0.5rem;display:flex;gap:0.5rem;">
                    <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText(document.querySelector('textarea[readonly]').value).then(()=>alert('Copied!'))">Copy</button>
                    <form method="POST" action="/admin/system/export-config"><button type="submit" class="btn btn-secondary btn-sm">Download</button></form>
                </div>
            </div>
            
            <div class="admin-subsection" style="margin-top:1rem;">
                <h4>📥 Import</h4>
                <form method="POST" action="/admin/system/config-upload" enctype="multipart/form-data">
                    <div style="display:flex;gap:0.75rem;align-items:flex-end;flex-wrap:wrap;">
                        <div class="form-group" style="flex:1;min-width:200px;margin-bottom:0;">
                            <input type="file" name="config_file" accept=".json" required style="padding:0.4rem;">
                        </div>
                        <button type="submit" class="btn" onclick="return confirm('Import this config? Current settings will be overwritten.')">📥 Import</button>
                    </div>
                    <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-size:0.8rem;margin-top:0.5rem;">
                        <input type="checkbox" name="preserve_users" value="1" checked>
                        <span>Preserve users</span>
                    </label>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Debug Tools -->
    <div class="admin-section">
        <h3 style="display:flex;align-items:center;gap:0.5rem;">
            <span>🔧</span> Debug Tools
        </h3>
        <div class="admin-content">
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                <form method="POST" action="/admin/system/test-log"><button type="submit" class="btn btn-secondary btn-sm">Test Log</button></form>
                <form method="POST" action="/admin/system/test-error"><button type="submit" class="btn btn-secondary btn-sm">Test Error</button></form>
                <form method="POST" action="/admin/system/clear-stats"><button type="submit" class="btn btn-secondary btn-sm" onclick="return confirm('Reset stats?')">Reset Stats</button></form>
                <form method="POST" action="/admin/system/restart" onsubmit="return confirm('Restart server?')"><button type="submit" class="btn btn-sm" style="background:#f59e0b;">🔄 Restart</button></form>
                <button class="btn btn-secondary btn-sm" onclick="location.reload()">Refresh Page</button>
            </div>
        </div>
    </div>
    '''


# =============================================================================
# Request Handler
# =============================================================================

class IFrameHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the iFrame server."""
    
    def log_message(self, format, *args):
        """Custom log format - also logs to server_logger."""
        msg = args[0] if args else ""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        
        # Parse the log message to extract request info
        # Format is typically "METHOD /path HTTP/1.1" status_code -
        try:
            parts = msg.split()
            if len(parts) >= 3:
                method = parts[0].strip('"')
                path = parts[1]
                status = int(parts[-2]) if parts[-2].isdigit() else 200
                client_ip = self.client_address[0] if self.client_address else 'unknown'
                user = getattr(self, '_current_user', None)
                server_logger.log_request(method, path, status, 0, client_ip, user)
        except:
            pass
    
    def get_session_user(self):
        """Get the current user from session cookie."""
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        if 'session' in cookie:
            session = get_session(cookie['session'].value)
            if session:
                return session['username']
        return None
    
    def send_html(self, html, status=200):
        """Send an HTML response."""
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_json(self, data, status=200):
        """Send a JSON response."""
        import json as json_mod
        body = json_mod.dumps(data)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))
    
    def _handle_request_error(self, error, method):
        """Handle and log request errors gracefully."""
        error_msg = str(error)
        path = getattr(self, 'path', 'unknown')
        client = self.client_address[0] if self.client_address else 'unknown'
        
        # Log the error
        server_logger.error(f"{method} {path} error from {client}: {error_msg}")
        
        # Track the error for alerts
        track_server_alert('request_error', f"{method} {path}: {error_msg}")
        
        # Try to send an error response to the client
        try:
            error_html = f'''
            <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                <h2 style="color:#ef4444;">⚠️ Server Error</h2>
                <p style="margin:1rem 0;color:var(--text-secondary);">
                    An unexpected error occurred while processing your request.
                </p>
                <p style="font-size:0.85rem;color:var(--text-secondary);">
                    Error has been logged. Please try again or contact the administrator.
                </p>
                <div style="margin-top:1.5rem;">
                    <a href="/" class="btn">Return Home</a>
                </div>
            </div>
            '''
            self.send_html(render_page("Error", error_html, None, load_config()), 500)
        except:
            # If we can't even send an error page, just pass
            pass
    
    def redirect(self, location, set_cookie=None, clear_cookie=None):
        """Send a redirect response."""
        self.send_response(302)
        self.send_header('Location', location)
        if set_cookie:
            self.send_header('Set-Cookie', f'session={set_cookie}; Path=/; HttpOnly; SameSite=Strict')
        if clear_cookie:
            self.send_header('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0')
        self.end_headers()
    
    def read_post_data(self):
        """Read and parse POST data."""
        content_length = int(self.headers.get('Content-Length', 0))
        content_type = self.headers.get('Content-Type', '')
        post_body = self.rfile.read(content_length)
        
        if 'multipart/form-data' in content_type:
            return parse_multipart(content_type, post_body)
        elif 'application/json' in content_type:
            # Return raw JSON body for API endpoints
            return {'_json_body': post_body.decode('utf-8'), '_is_json': True}
        else:
            return {k: v[0] for k, v in parse_qs(post_body.decode('utf-8')).items()}
    
    def do_GET(self):
        """Handle GET requests with comprehensive error handling."""
        try:
            self._handle_get()
        except BrokenPipeError:
            # Client disconnected - this is normal, don't log as error
            pass
        except ConnectionResetError:
            # Client reset connection - normal
            pass
        except Exception as e:
            self._handle_request_error(e, 'GET')
    
    def _handle_get(self):
        """Internal GET handler."""
        user = self.get_session_user()
        config = load_config()
        path = self.path.split('?')[0]

        # Periodic uptime tracking update (updates config every minute)
        uptime_tracker.periodic_update(config)

        if path == '/':
            if user:
                self.send_html(render_main_page(user, config))
            else:
                self.redirect('/login')
        
        elif path == '/login':
            if user:
                self.redirect('/')
            else:
                self.send_html(render_login_page())
        
        elif path == '/forgot-password':
            if user:
                self.redirect('/')
            else:
                self.send_html(render_forgot_password_page())
        
        elif path == '/logout':
            self.redirect('/login', clear_cookie=True)
        
        elif path == '/help':
            if not user:
                self.redirect('/login')
            else:
                self.send_html(render_help_page(user, config))
        
        elif path == '/admin':
            if not user:
                self.redirect('/login')
            elif not config["users"].get(user, {}).get("is_admin"):
                self.send_html(render_page("Access Denied", '<div class="card"><h2>Access Denied</h2><p>Admin privileges required.</p></div>', user, config), 403)
            else:
                self.send_html(render_admin_page(user, config))
        
        elif path.startswith('/admin/system/firmware-download/'):
            # Download firmware backup
            if not user:
                self.redirect('/login')
                return
            if not config["users"].get(user, {}).get("is_admin"):
                self.send_html(render_page("Access Denied", '<div class="card"><h2>Access Denied</h2><p>Admin privileges required.</p></div>', user, config), 403)
                return
            
            # Extract filename from path
            filename = path.replace('/admin/system/firmware-download/', '')
            filename = os.path.basename(filename)  # Security: prevent path traversal
            
            backup_dir = get_firmware_backup_dir()
            filepath = os.path.join(backup_dir, filename)
            
            if not os.path.exists(filepath) or not filename.endswith('.py'):
                self.send_html(render_page("Not Found", '<div class="card"><h2>404</h2><p>Backup file not found.</p></div>', user, config), 404)
                return
            
            # Send the file
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/x-python')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', len(content))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_html(render_page("Error", f'<div class="card"><h2>Error</h2><p>{escape_html(str(e))}</p></div>', user, config), 500)
        
        elif path == '/api/client-info':
            # Return client connection information
            client_ip = self.client_address[0]
            
            # Check for forwarded IP (if behind proxy)
            forwarded_for = self.headers.get('X-Forwarded-For')
            if forwarded_for:
                client_ip = forwarded_for.split(',')[0].strip()
            
            real_ip = self.headers.get('X-Real-IP')
            if real_ip:
                client_ip = real_ip.strip()
            
            self.send_json({
                'ip': client_ip,
                'server_port': SERVER_PORT
            })
        
        elif path == '/api/pi-status':
            # Return Raspberry Pi status information
            pi_info = get_raspberry_pi_info()
            if pi_info:
                self.send_json({
                    'is_raspberry_pi': True,
                    'model': pi_info.get('model'),
                    'temperature': pi_info.get('temperature'),
                    'memory_total': pi_info.get('memory_total'),
                    'hostname': pi_info.get('hostname'),
                    'throttled': pi_info.get('throttled'),
                    'network_config': pi_info.get('network_config')
                })
            else:
                self.send_json({
                    'is_raspberry_pi': False,
                    'message': 'Not running on Raspberry Pi'
                })
        
        elif path == '/api/ping':
            # Simple ping endpoint for connectivity check
            self.send_json({'status': 'ok', 'timestamp': datetime.now().isoformat()})

        elif path == '/api/watchdog':
            # Watchdog status API endpoint
            if not user:
                self.send_json({'error': 'Authentication required'}, 401)
                return

            # Update uptime stats before returning
            uptime_tracker.periodic_update(config)

            stats = uptime_tracker.get_stats(config)
            alert_stats = server_alerts.get_stats()

            self.send_json({
                'status': 'ok',
                'uptime': {
                    'current_session': stats['current_session_formatted'],
                    'current_session_seconds': stats['current_session_duration'],
                    'uptime_24h': stats['uptime_24h'],
                    'uptime_7d': stats['uptime_7d'],
                    'uptime_30d': stats['uptime_30d'],
                    'total_uptime': stats['total_uptime_formatted'],
                    'total_downtime': stats['total_downtime_formatted'],
                    'days_tracked': stats['days_tracked']
                },
                'health': {
                    'crashes': stats['total_crashes'],
                    'restarts': stats['total_restarts'],
                    'alerts': alert_stats['total_alerts']
                },
                'recent_events': stats['recent_events'][:10],
                'daily_uptime': stats['daily_uptime']
            })

        else:
            self.send_html(render_page("Not Found", '<div class="card"><h2>404</h2><p>Page not found.</p></div>', user, config), 404)
    
    def do_POST(self):
        """Handle POST requests with comprehensive error handling."""
        try:
            self._handle_post()
        except BrokenPipeError:
            # Client disconnected - this is normal
            pass
        except ConnectionResetError:
            # Client reset connection - normal
            pass
        except Exception as e:
            self._handle_request_error(e, 'POST')
    
    def _handle_post(self):
        """Internal POST handler."""
        user = self.get_session_user()
        config = load_config()
        path = self.path.split('?')[0]
        raw_data = self.read_post_data()
        
        # Handle multipart vs regular form data
        if isinstance(raw_data, dict) and 'fields' in raw_data:
            data = raw_data['fields']
            files = raw_data['files']
        else:
            data = raw_data
            files = {}
        
        if path == '/login':
            client_ip = self.client_address[0]
            
            # Check rate limiting
            allowed, lockout_msg = check_login_allowed(client_ip)
            if not allowed:
                self.send_html(render_login_page(error=lockout_msg))
                return
            
            username = data.get('username', '')
            password = data.get('password', '')
            user_data = config["users"].get(username)
            
            # Use constant-time comparison to prevent timing attacks
            password_hash = hash_password(password)
            stored_hash = user_data["password_hash"] if user_data else hash_password("dummy_password_to_prevent_timing")
            
            if user_data and secrets.compare_digest(password_hash, stored_hash):
                clear_failed_logins(client_ip)
                session_id = create_session(username)
                server_logger.info(f"Successful login for user: {username}")
                self.redirect('/', set_cookie=session_id)
            else:
                record_failed_login(client_ip)
                server_logger.warning(f"Failed login attempt for user: {username} from {client_ip}")
                self.send_html(render_login_page(error="Invalid username or password"))
        
        elif path == '/forgot-password':
            username = data.get('username', '').strip()
            if not username:
                self.send_html(render_forgot_password_page(error="Username is required"))
            elif username not in config.get("users", {}):
                # Don't reveal if user exists or not for security
                self.send_html(render_forgot_password_page(success=True))
            else:
                # Check for duplicate request
                existing_requests = config.get("password_reset_requests", [])
                already_requested = any(req.get('username') == username for req in existing_requests)
                
                if already_requested:
                    self.send_html(render_forgot_password_page(success=True))
                else:
                    # Create new request
                    import uuid
                    new_request = {
                        "id": str(uuid.uuid4())[:8],
                        "username": username,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    config.setdefault("password_reset_requests", []).append(new_request)
                    save_config(config)
                    server_logger.info(f"Password reset requested for user: {username}")
                    self.send_html(render_forgot_password_page(success=True))
        
        elif path == '/api/send-command':
            # API endpoint for sending network commands (requires login)
            if not user:
                self.send_json({'success': False, 'error': 'Authentication required'}, 401)
                return
            
            # Parse JSON body
            try:
                import json as json_mod
                
                # Get JSON body from parsed data
                if not data.get('_is_json'):
                    self.send_json({'success': False, 'error': 'JSON body required'})
                    return
                
                cmd_data = json_mod.loads(data.get('_json_body', '{}'))
                
                protocol = cmd_data.get('protocol', 'tcp').lower()
                host = cmd_data.get('host', '')
                port = int(cmd_data.get('port', 23))
                command_b64 = cmd_data.get('command', '')
                
                # Decode command from base64
                command = base64.b64decode(command_b64).decode('utf-8')
                
                # Validate
                if not host:
                    self.send_json({'success': False, 'error': 'Host is required'})
                    return
                if not command:
                    self.send_json({'success': False, 'error': 'Command is required'})
                    return
                if protocol not in ('tcp', 'udp', 'telnet', 'dummy', 'dummy_fail', 'dummy_random'):
                    self.send_json({'success': False, 'error': 'Invalid protocol'})
                    return
                
                # Send the command
                result = send_network_command(protocol, host, port, command)
                
                if result['success']:
                    server_logger.info(f"Command sent via {protocol} to {host}:{port}", extra=user)
                    self.send_json({'success': True, 'response': result.get('response', '')})
                else:
                    server_logger.warning(f"Command failed to {host}:{port}: {result.get('error', 'Unknown')}", extra=user)
                    self.send_json({'success': False, 'error': result.get('error', 'Unknown error')})
                    
            except json_mod.JSONDecodeError:
                self.send_json({'success': False, 'error': 'Invalid JSON'})
            except Exception as e:
                server_logger.error(f"Command API error: {str(e)}")
                self.send_json({'success': False, 'error': str(e)})
        
        elif path == '/api/submit-connectivity-report':
            # API endpoint for users to submit connectivity reports
            if not user:
                self.send_json({'success': False, 'error': 'Authentication required'}, 401)
                return
            
            try:
                import json as json_mod
                
                # Get JSON body from parsed data
                if not data.get('_is_json'):
                    self.send_json({'success': False, 'error': 'JSON body required'})
                    return
                
                report_data = json_mod.loads(data.get('_json_body', '{}'))
                
                # Build the report
                import uuid
                report = {
                    "id": str(uuid.uuid4())[:8],
                    "username": user,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "results": report_data.get('results', []),
                    "user_agent": report_data.get('userAgent', '')[:200],
                    "online": report_data.get('online', True),
                    "connection_type": report_data.get('connectionType', '')
                }
                
                # Count failures
                failures = [r for r in report['results'] if not r.get('success', True)]
                report['failure_count'] = len(failures)
                report['total_count'] = len(report['results'])
                
                # Save to config
                config.setdefault("connectivity_reports", []).append(report)
                # Keep only last 50 reports
                config["connectivity_reports"] = config["connectivity_reports"][-50:]
                save_config(config)
                
                server_logger.info(f"Connectivity report submitted by {user}: {len(failures)} failures")
                self.send_json({'success': True, 'message': 'Report submitted'})
                
            except json_mod.JSONDecodeError:
                self.send_json({'success': False, 'error': 'Invalid JSON'})
            except Exception as e:
                server_logger.error(f"Connectivity report error: {str(e)}")
                self.send_json({'success': False, 'error': str(e)})

        elif path == '/api/connectivity-test-url':
            # Public API endpoint for testing a single URL's connectivity
            # Tests if the server is reachable (not if it returns 200 OK)
            # An iframe can display content even with 4xx/5xx responses
            if not user:
                self.send_json({'success': False, 'error': 'Authentication required'}, 401)
                return

            import urllib.request
            import urllib.error
            import ssl
            import socket

            url = data.get('url', '')
            idx = data.get('index', 0)

            if not url:
                self.send_json({'success': False, 'error': 'No URL provided'})
                return

            # Create SSL context that doesn't verify certificates (for local/self-signed)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            result = {
                'index': idx,
                'url': url[:100],
                'status': 'testing'
            }

            # Use browser-like headers for better compatibility
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close',
            }

            def try_request(method='GET'):
                """Try to connect with specified method."""
                req = urllib.request.Request(url, method=method, headers=headers)
                start = time_module.time()
                with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                    elapsed = round((time_module.time() - start) * 1000)
                    return {
                        'status': 'success',
                        'response_time': f'{elapsed} ms',
                        'http_status': response.status
                    }

            try:
                # Try GET request (most compatible)
                start_time = time_module.time()
                res = try_request('GET')
                result.update(res)

            except urllib.error.HTTPError as e:
                # HTTP errors (4xx, 5xx) still mean the server is REACHABLE
                # The iframe will display the error page, login page, etc.
                elapsed = round((time_module.time() - start_time) * 1000)
                result['status'] = 'success'  # Server responded
                result['response_time'] = f'{elapsed} ms'
                result['http_status'] = e.code
                result['note'] = f'HTTP {e.code} (server reachable)'

            except urllib.error.URLError as e:
                # Network-level errors - server truly not reachable
                reason = str(e.reason) if hasattr(e, 'reason') else str(e)
                reason_lower = reason.lower()
                if 'timed out' in reason_lower or isinstance(getattr(e, 'reason', None), socket.timeout):
                    result['status'] = 'error'
                    result['error'] = 'Connection timeout'
                elif 'refused' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'Connection refused'
                elif 'name or service not known' in reason_lower or 'getaddrinfo' in reason_lower or 'nodename nor servname' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'DNS lookup failed'
                elif 'no route to host' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'No route to host'
                elif 'network is unreachable' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'Network unreachable'
                elif 'ssl' in reason_lower or 'certificate' in reason_lower:
                    result['status'] = 'warning'
                    result['error'] = 'SSL/Certificate issue'
                else:
                    result['status'] = 'error'
                    result['error'] = f'Connection failed'

            except socket.timeout:
                result['status'] = 'error'
                result['error'] = 'Connection timeout'

            except ssl.SSLError as e:
                # SSL errors - browser might still show warning page
                result['status'] = 'warning'
                result['error'] = 'SSL certificate issue'

            except Exception as e:
                error_str = str(e).lower()
                if 'timeout' in error_str:
                    result['status'] = 'error'
                    result['error'] = 'Connection timeout'
                elif 'refused' in error_str:
                    result['status'] = 'error'
                    result['error'] = 'Connection refused'
                else:
                    result['status'] = 'error'
                    result['error'] = 'Connection failed'

            self.send_json({
                'success': True,
                'result': result
            })

        elif not user:
            self.redirect('/login')
        
        elif not config["users"].get(user, {}).get("is_admin"):
            self.redirect('/')
        
        elif path == '/admin/iframe/add':
            name = data.get('name', '').strip()
            url = data.get('url', '').strip()
            height = int(data.get('height', 400))
            width = int(data.get('width', 100)) if data.get('width') else 100
            zoom = int(data.get('zoom', 100)) if data.get('zoom') else 100
            show_url = data.get('show_url', '1') == '1'
            show_header = data.get('show_header', '1') == '1'
            show_status = data.get('show_status', '1') == '1'
            header_text = data.get('header_text', '').strip()
            border_style = data.get('border_style', 'default')
            border_color = data.get('border_color', '').strip()
            allow_external = data.get('allow_external', '0') == '1'
            use_embed_code = data.get('use_embed_code', '0') == '1'
            embed_code = data.get('embed_code', '').strip()
            
            # Validate border_style
            if border_style not in ('default', 'none', 'thin', 'thick', 'rounded'):
                border_style = 'default'
            
            # Validate based on mode
            if use_embed_code:
                # Using embed code - URL is not required
                if not name:
                    self.send_html(render_admin_page(user, config, error="Name is required"))
                elif not embed_code:
                    self.send_html(render_admin_page(user, config, error="Embed code is required when 'Use Embed Code' is enabled"))
                else:
                    new_iframe = {
                        "name": name,
                        "url": "",
                        "height": max(100, min(2000, height)),
                        "width": max(20, min(100, width)),
                        "zoom": max(25, min(200, zoom)),
                        "show_url": show_url,
                        "show_header": show_header,
                        "show_status": show_status,
                        "header_text": header_text[:100],
                        "border_style": border_style,
                        "border_color": border_color[:20],
                        "allow_external": True,
                        "use_embed_code": True,
                        "embed_code": embed_code[:10000]  # Limit embed code length
                    }
                    config.setdefault("iframes", []).append(new_iframe)
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"iFrame '{name}' added with embed code"))
            else:
                # Using URL mode
                if not allow_external and not validate_local_ip(url):
                    self.send_html(render_admin_page(user, config, error="Only local/private IP addresses are allowed. Enable 'Allow External URLs' in Advanced Options for public websites."))
                elif name and url:
                    new_iframe = {
                        "name": name,
                        "url": url,
                        "height": max(100, min(2000, height)),
                        "width": max(20, min(100, width)),
                        "zoom": max(25, min(200, zoom)),
                        "show_url": show_url,
                        "show_header": show_header,
                        "show_status": show_status,
                        "header_text": header_text[:100],
                        "border_style": border_style,
                        "border_color": border_color[:20],
                        "allow_external": allow_external,
                        "use_embed_code": False,
                        "embed_code": ""
                    }
                    config.setdefault("iframes", []).append(new_iframe)
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"iFrame '{name}' added successfully"))
                else:
                    self.send_html(render_admin_page(user, config, error="Name and URL are required"))
        
        elif path == '/admin/iframe/delete':
            try:
                index = int(data.get('index', -1))
                if 0 <= index < len(config.get("iframes", [])):
                    removed = config["iframes"].pop(index)
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"iFrame '{removed['name']}' deleted"))
                else:
                    self.send_html(render_admin_page(user, config, error="Invalid iFrame index"))
            except (ValueError, IndexError):
                self.send_html(render_admin_page(user, config, error="Invalid request"))
        
        elif path == '/admin/iframe/edit':
            try:
                index = int(data.get('index', -1))
                name = data.get('name', '').strip()
                url = data.get('url', '').strip()
                height = int(data.get('height', 400))
                width = int(data.get('width', 100))
                zoom = int(data.get('zoom', 100))
                show_url = data.get('show_url') == '1'
                show_header = data.get('show_header') == '1'
                show_status = data.get('show_status') == '1'
                header_text = data.get('header_text', '').strip()
                border_style = data.get('border_style', 'default')
                border_color = data.get('border_color', '').strip()
                allow_external = data.get('allow_external') == '1'
                use_embed_code = data.get('use_embed_code') == '1'
                embed_code = data.get('embed_code', '').strip()
                
                # Validate border_style
                if border_style not in ('default', 'none', 'thin', 'thick', 'rounded'):
                    border_style = 'default'
                
                # Validate border_color (basic check)
                if border_color and not border_color.startswith('#') and not border_color.startswith('rgb'):
                    border_color = ''
                
                if not (0 <= index < len(config.get("iframes", []))):
                    self.send_html(render_admin_page(user, config, error="Invalid iFrame index"))
                elif not name:
                    self.send_html(render_admin_page(user, config, error="Name is required"))
                elif use_embed_code and not embed_code:
                    self.send_html(render_admin_page(user, config, error="Embed code is required when 'Use Embed Code' is enabled"))
                elif not use_embed_code and not url:
                    self.send_html(render_admin_page(user, config, error="URL is required"))
                elif not use_embed_code and not allow_external and not validate_local_ip(url):
                    self.send_html(render_admin_page(user, config, error="Only local/private IP addresses are allowed. Enable 'Allow External URLs' for public websites."))
                else:
                    config["iframes"][index] = {
                        "name": name,
                        "url": url if not use_embed_code else "",
                        "height": max(100, min(2000, height)),
                        "width": max(20, min(100, width)),
                        "zoom": max(25, min(200, zoom)),
                        "show_url": show_url,
                        "show_header": show_header,
                        "show_status": show_status,
                        "header_text": header_text[:100],
                        "border_style": border_style,
                        "border_color": border_color[:20],
                        "allow_external": allow_external or use_embed_code,
                        "use_embed_code": use_embed_code,
                        "embed_code": embed_code[:10000] if use_embed_code else ""
                    }
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"iFrame '{name}' updated"))
            except (ValueError, IndexError) as e:
                self.send_html(render_admin_page(user, config, error=f"Invalid request: {str(e)}"))
        
        elif path == '/admin/iframe/move':
            try:
                index = int(data.get('index', -1))
                direction = data.get('direction', '')
                iframes = config.get("iframes", [])
                
                if not (0 <= index < len(iframes)):
                    self.send_html(render_admin_page(user, config, error="Invalid iFrame index"))
                elif direction == 'up' and index > 0:
                    iframes[index], iframes[index - 1] = iframes[index - 1], iframes[index]
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message="iFrame moved up"))
                elif direction == 'down' and index < len(iframes) - 1:
                    iframes[index], iframes[index + 1] = iframes[index + 1], iframes[index]
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message="iFrame moved down"))
                else:
                    self.send_html(render_admin_page(user, config, error="Cannot move iFrame in that direction"))
            except (ValueError, IndexError):
                self.send_html(render_admin_page(user, config, error="Invalid request"))
        
        elif path == '/admin/branding/logo':
            if 'logo' not in files:
                self.send_html(render_admin_page(user, config, error="No logo file uploaded"))
            else:
                file_info = files['logo']
                file_data = file_info['data']
                mime_type = file_info['content_type']
                
                if mime_type not in ALLOWED_IMAGE_TYPES:
                    self.send_html(render_admin_page(user, config, error=f"Invalid file type. Allowed: PNG, JPG, GIF, SVG, WebP"))
                elif len(file_data) > MAX_LOGO_SIZE:
                    self.send_html(render_admin_page(user, config, error=f"File too large. Maximum size: {MAX_LOGO_SIZE // 1024}KB"))
                else:
                    config.setdefault("branding", {})["logo"] = base64.b64encode(file_data).decode('ascii')
                    config["branding"]["logo_mime"] = mime_type
                    success, err = save_config(config)
                    if success:
                        self.send_html(render_admin_page(user, config, message="Logo uploaded successfully"))
                    else:
                        self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/branding/logo/delete':
            config.setdefault("branding", {})["logo"] = None
            config["branding"]["logo_mime"] = None
            success, err = save_config(config)
            if success:
                self.send_html(render_admin_page(user, config, message="Logo removed"))
            else:
                self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/branding/favicon':
            if 'favicon' not in files:
                self.send_html(render_admin_page(user, config, error="No favicon file uploaded"))
            else:
                file_info = files['favicon']
                file_data = file_info['data']
                mime_type = file_info['content_type']
                
                if mime_type not in ALLOWED_IMAGE_TYPES:
                    self.send_html(render_admin_page(user, config, error=f"Invalid file type. Allowed: PNG, ICO, SVG"))
                elif len(file_data) > MAX_LOGO_SIZE:
                    self.send_html(render_admin_page(user, config, error=f"File too large. Maximum size: {MAX_LOGO_SIZE // 1024}KB"))
                else:
                    config.setdefault("branding", {})["favicon"] = base64.b64encode(file_data).decode('ascii')
                    config["branding"]["favicon_mime"] = mime_type
                    success, err = save_config(config)
                    if success:
                        self.send_html(render_admin_page(user, config, message="Favicon uploaded successfully"))
                    else:
                        self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/branding/favicon/delete':
            config.setdefault("branding", {})["favicon"] = None
            config["branding"]["favicon_mime"] = None
            success, err = save_config(config)
            if success:
                self.send_html(render_admin_page(user, config, message="Favicon removed"))
            else:
                self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/branding/apple-touch-icon':
            if 'apple_touch_icon' not in files:
                self.send_html(render_admin_page(user, config, error="No icon file uploaded"))
            else:
                file_info = files['apple_touch_icon']
                file_data = file_info['data']
                mime_type = file_info['content_type']
                
                # Only allow PNG for apple touch icon
                if mime_type != 'image/png':
                    self.send_html(render_admin_page(user, config, error="Apple Touch Icon must be a PNG file"))
                elif len(file_data) > MAX_LOGO_SIZE:
                    self.send_html(render_admin_page(user, config, error=f"File too large. Maximum size: {MAX_LOGO_SIZE // 1024}KB"))
                else:
                    config.setdefault("branding", {})["apple_touch_icon"] = base64.b64encode(file_data).decode('ascii')
                    config["branding"]["apple_touch_icon_mime"] = mime_type
                    success, err = save_config(config)
                    if success:
                        self.send_html(render_admin_page(user, config, message="iOS Home Screen icon uploaded successfully"))
                    else:
                        self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/branding/apple-touch-icon/delete':
            config.setdefault("branding", {})["apple_touch_icon"] = None
            config["branding"]["apple_touch_icon_mime"] = None
            success, err = save_config(config)
            if success:
                self.send_html(render_admin_page(user, config, message="iOS Home Screen icon removed"))
            else:
                self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/user/add':
            username = data.get('username', '').strip()
            password = data.get('password', '')
            is_admin = data.get('is_admin') == '1'
            
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                self.send_html(render_admin_page(user, config, error="Username must be alphanumeric"))
            elif username in config["users"]:
                self.send_html(render_admin_page(user, config, error="Username already exists"))
            elif len(password) < 6:
                self.send_html(render_admin_page(user, config, error="Password must be at least 6 characters"))
            else:
                config["users"][username] = {"password_hash": hash_password(password), "is_admin": is_admin}
                save_config(config)
                self.send_html(render_admin_page(user, config, message=f"User '{username}' created"))
        
        elif path == '/admin/user/delete':
            username = data.get('username', '')
            if username == user:
                self.send_html(render_admin_page(user, config, error="Cannot delete your own account"))
            elif username in config["users"]:
                del config["users"][username]
                save_config(config)
                self.send_html(render_admin_page(user, config, message=f"User '{username}' deleted"))
            else:
                self.send_html(render_admin_page(user, config, error="User not found"))
        
        elif path == '/admin/user/change-password':
            target_username = data.get('username', '')
            new_password = data.get('new_password', '')
            confirm_password = data.get('confirm_password', '')
            
            if not target_username or target_username not in config.get("users", {}):
                self.send_html(render_admin_page(user, config, error="User not found"))
            elif not new_password or len(new_password) < 6:
                self.send_html(render_admin_page(user, config, error="Password must be at least 6 characters"))
            elif new_password != confirm_password:
                self.send_html(render_admin_page(user, config, error="Passwords do not match"))
            else:
                config["users"][target_username]["password_hash"] = hash_password(new_password)
                success, err = save_config(config)
                if success:
                    server_logger.info(f"Password changed for user: {target_username} by admin: {user}")
                    self.send_html(render_admin_page(user, config, message=f"Password updated for '{target_username}'"))
                else:
                    self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/password-reset/set':
            request_id = data.get('request_id', '')
            new_password = data.get('new_password', '')
            
            if not new_password or len(new_password) < 6:
                self.send_html(render_admin_page(user, config, error="Password must be at least 6 characters"))
            else:
                # Find and process the request
                requests = config.get("password_reset_requests", [])
                request_found = None
                for i, req in enumerate(requests):
                    if req.get('id') == request_id:
                        request_found = req
                        break
                
                if request_found:
                    target_user = request_found.get('username', '')
                    if target_user in config.get("users", {}):
                        # Set new password
                        config["users"][target_user]["password_hash"] = hash_password(new_password)
                        # Remove the request
                        config["password_reset_requests"] = [r for r in requests if r.get('id') != request_id]
                        save_config(config)
                        server_logger.info(f"Password reset completed for user: {target_user} by admin: {user}")
                        self.send_html(render_admin_page(user, config, message=f"Password updated for '{target_user}'"))
                    else:
                        self.send_html(render_admin_page(user, config, error="User not found"))
                else:
                    self.send_html(render_admin_page(user, config, error="Request not found"))
        
        elif path == '/admin/password-reset/dismiss':
            request_id = data.get('request_id', '')
            requests = config.get("password_reset_requests", [])
            original_count = len(requests)
            config["password_reset_requests"] = [r for r in requests if r.get('id') != request_id]
            if len(config["password_reset_requests"]) < original_count:
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Request dismissed"))
            else:
                self.send_html(render_admin_page(user, config, error="Request not found"))
        
        elif path == '/admin/password-reset/dismiss-all':
            count = len(config.get("password_reset_requests", []))
            config["password_reset_requests"] = []
            save_config(config)
            self.send_html(render_admin_page(user, config, message=f"Dismissed {count} request(s)"))
        
        elif path == '/admin/connectivity-report/dismiss':
            report_id = data.get('report_id', '')
            reports = config.get("connectivity_reports", [])
            original_count = len(reports)
            config["connectivity_reports"] = [r for r in reports if r.get('id') != report_id]
            if len(config["connectivity_reports"]) < original_count:
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Report dismissed"))
            else:
                self.send_html(render_admin_page(user, config, error="Report not found"))
        
        elif path == '/admin/connectivity-report/dismiss-all':
            count = len(config.get("connectivity_reports", []))
            config["connectivity_reports"] = []
            save_config(config)
            self.send_html(render_admin_page(user, config, message=f"Dismissed {count} report(s)"))
        
        elif path == '/admin/settings':
            config["settings"]["page_title"] = data.get('page_title', 'Dashboard').strip()[:50]
            config["settings"]["tab_title"] = data.get('tab_title', '').strip()[:100]
            config["settings"]["tab_suffix"] = data.get('tab_suffix', 'Multi-Frames').strip()[:50]
            config["settings"]["grid_columns"] = max(1, min(6, int(data.get('grid_columns', 2))))
            config["settings"]["refresh_interval"] = max(0, min(3600, int(data.get('refresh_interval', 0))))
            config["settings"]["auto_fullscreen"] = data.get('auto_fullscreen') == '1'
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Settings saved"))
        
        elif path == '/admin/settings/fallback':
            config.setdefault("fallback_image", {})
            
            if data.get('delete_fallback') == '1':
                config["fallback_image"]["image"] = None
                config["fallback_image"]["image_mime"] = None
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Fallback image removed"))
            else:
                config["fallback_image"]["enabled"] = data.get('fallback_enabled') == '1'
                config["fallback_image"]["text"] = data.get('fallback_text', 'Content Unavailable').strip()[:100]
                
                # Handle image upload
                if 'fallback_img' in files and files['fallback_img']['data']:
                    file_info = files['fallback_img']
                    if len(file_info['data']) > MAX_FALLBACK_SIZE:
                        self.send_html(render_admin_page(user, config, error="Image too large. Max: 500KB"))
                        return
                    if file_info['content_type'] not in ALLOWED_IMAGE_TYPES:
                        self.send_html(render_admin_page(user, config, error="Invalid image type"))
                        return
                    config["fallback_image"]["image"] = base64.b64encode(file_info['data']).decode('ascii')
                    config["fallback_image"]["image_mime"] = file_info['content_type']
                
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Fallback settings saved"))

        elif path == '/admin/settings/cloud':
            global cloud_agent
            config.setdefault("cloud", {})

            cloud_enabled = data.get('cloud_enabled') == '1'
            cloud_url = data.get('cloud_url', '').strip().rstrip('/')
            device_key = data.get('cloud_device_key', '').strip()

            # Update config
            config["cloud"]["enabled"] = cloud_enabled
            config["cloud"]["url"] = cloud_url
            config["cloud"]["device_key"] = device_key

            save_config(config)

            # Update cloud agent
            if cloud_enabled and cloud_url and device_key:
                cloud_agent.enabled = True
                cloud_agent.cloud_url = cloud_url
                cloud_agent.device_key = device_key
                cloud_agent.start()
                self.send_html(render_admin_page(user, config, message="Cloud sync enabled and started"))
            else:
                cloud_agent.stop()
                cloud_agent.enabled = False
                self.send_html(render_admin_page(user, config, message="Cloud settings saved"))

        elif path == '/admin/widget/add':
            name = data.get('name', '').strip()
            wtype = data.get('type', 'text')
            size = data.get('size', 'medium')
            content = data.get('content', '').strip()
            bg_color = data.get('bg_color', '#141416')
            text_color = data.get('text_color', '#e8e8e8')
            border_radius = int(data.get('border_radius', 8))
            
            if not name:
                self.send_html(render_admin_page(user, config, error="Widget name is required"))
            else:
                new_widget = {
                    "name": name[:50],
                    "type": wtype,
                    "size": size,
                    "content": content[:2000],
                    "bg_color": bg_color[:20],
                    "text_color": text_color[:20],
                    "border_radius": max(0, min(50, border_radius)),
                    "enabled": True
                }
                config.setdefault("widgets", []).append(new_widget)
                save_config(config)
                self.send_html(render_admin_page(user, config, message=f"Widget '{name}' added"))
        
        elif path == '/admin/widget/edit':
            try:
                index = int(data.get('index', -1))
                name = data.get('name', '').strip()
                wtype = data.get('type', 'text')
                size = data.get('size', 'medium')
                content = data.get('content', '').strip()
                bg_color = data.get('bg_color', '#141416')
                text_color = data.get('text_color', '#e8e8e8')
                border_radius = int(data.get('border_radius', 8))
                enabled = data.get('enabled') == '1'
                
                if not (0 <= index < len(config.get("widgets", []))):
                    self.send_html(render_admin_page(user, config, error="Invalid widget index"))
                elif not name:
                    self.send_html(render_admin_page(user, config, error="Widget name is required"))
                else:
                    config["widgets"][index] = {
                        "name": name[:50],
                        "type": wtype,
                        "size": size,
                        "content": content[:2000],
                        "bg_color": bg_color[:20],
                        "text_color": text_color[:20],
                        "border_radius": max(0, min(50, border_radius)),
                        "enabled": enabled
                    }
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"Widget '{name}' updated"))
            except (ValueError, IndexError) as e:
                self.send_html(render_admin_page(user, config, error=f"Invalid request: {str(e)}"))
        
        elif path == '/admin/widget/delete':
            try:
                index = int(data.get('index', -1))
                if 0 <= index < len(config.get("widgets", [])):
                    removed = config["widgets"].pop(index)
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"Widget '{removed['name']}' deleted"))
                else:
                    self.send_html(render_admin_page(user, config, error="Invalid widget index"))
            except (ValueError, IndexError):
                self.send_html(render_admin_page(user, config, error="Invalid request"))
        
        elif path == '/admin/widget/move':
            try:
                index = int(data.get('index', -1))
                direction = data.get('direction', '')
                widgets = config.get("widgets", [])
                
                if not (0 <= index < len(widgets)):
                    self.send_html(render_admin_page(user, config, error="Invalid widget index"))
                elif direction == 'up' and index > 0:
                    widgets[index], widgets[index-1] = widgets[index-1], widgets[index]
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message="Widget moved up"))
                elif direction == 'down' and index < len(widgets) - 1:
                    widgets[index], widgets[index+1] = widgets[index+1], widgets[index]
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message="Widget moved down"))
                else:
                    self.send_html(render_admin_page(user, config))
            except (ValueError, IndexError):
                self.send_html(render_admin_page(user, config, error="Invalid request"))
        
        elif path == '/admin/appearance/colors':
            if data.get('reset') == '1':
                config.setdefault("appearance", {})["colors"] = DEFAULT_CONFIG["appearance"]["colors"].copy()
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Colors reset to defaults"))
            else:
                config.setdefault("appearance", {}).setdefault("colors", {})
                for key in ['bg_primary', 'bg_secondary', 'bg_tertiary', 'border', 
                           'text_primary', 'text_secondary', 'accent', 'accent_hover', 
                           'success', 'danger']:
                    if key in data:
                        config["appearance"]["colors"][key] = data[key]
                save_config(config)
                self.send_html(render_admin_page(user, config, message="Colors saved"))
        
        elif path == '/admin/appearance/background':
            config.setdefault("appearance", {}).setdefault("background", {})
            bg_type = data.get('bg_type', 'solid')
            config["appearance"]["background"]["type"] = bg_type
            
            if bg_type == 'gradient':
                config["appearance"]["background"]["gradient_start"] = data.get('gradient_start', '#0a0a0b')
                config["appearance"]["background"]["gradient_end"] = data.get('gradient_end', '#1a1a2e')
                config["appearance"]["background"]["gradient_direction"] = data.get('gradient_direction', 'to bottom')
            elif bg_type == 'image':
                config["appearance"]["background"]["image_size"] = data.get('image_size', 'cover')
                config["appearance"]["background"]["image_opacity"] = max(10, min(100, int(data.get('image_opacity', 100))))
                # Handle image upload
                if 'bg_image' in files and files['bg_image']['data']:
                    file_info = files['bg_image']
                    if len(file_info['data']) > MAX_BG_SIZE:
                        self.send_html(render_admin_page(user, config, error=f"Image too large. Max: {MAX_BG_SIZE // (1024*1024)}MB"))
                        return
                    if file_info['content_type'] not in ALLOWED_IMAGE_TYPES:
                        self.send_html(render_admin_page(user, config, error="Invalid image type"))
                        return
                    config["appearance"]["background"]["image"] = base64.b64encode(file_info['data']).decode('ascii')
                    config["appearance"]["background"]["image_mime"] = file_info['content_type']
            
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Background saved"))
        
        elif path == '/admin/appearance/bg/delete':
            config.setdefault("appearance", {}).setdefault("background", {})
            config["appearance"]["background"]["image"] = None
            config["appearance"]["background"]["image_mime"] = None
            config["appearance"]["background"]["type"] = "solid"
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Background image removed"))
        
        elif path == '/admin/appearance/header':
            config.setdefault("appearance", {}).setdefault("header", {})
            config["appearance"]["header"]["show"] = data.get('show') == '1'
            config["appearance"]["header"]["sticky"] = data.get('sticky') == '1'
            config["appearance"]["header"]["custom_text"] = data.get('custom_text', '').strip()[:100]
            config["appearance"]["header"]["bg_color"] = data.get('bg_color', '').strip()[:20]
            config["appearance"]["header"]["text_color"] = data.get('text_color', '').strip()[:20]
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Header settings saved"))
        
        elif path == '/admin/appearance/footer':
            config.setdefault("appearance", {}).setdefault("footer", {})
            config["appearance"]["footer"]["show"] = data.get('show') == '1'
            config["appearance"]["footer"]["show_python_version"] = data.get('show_python_version') == '1'
            config["appearance"]["footer"]["text"] = data.get('text', 'Multi-Frames v1.1.10 by LTS, Inc.').strip()[:100]
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Footer settings saved"))
        
        elif path == '/admin/footer-link/add':
            label = data.get('label', '').strip()[:50]
            url = data.get('url', '').strip()[:500]
            if label and url:
                config.setdefault("appearance", {}).setdefault("footer", {}).setdefault("links", [])
                config["appearance"]["footer"]["links"].append({"label": label, "url": url})
                save_config(config)
                self.send_html(render_admin_page(user, config, message=f"Footer link '{label}' added"))
            else:
                self.send_html(render_admin_page(user, config, error="Label and URL are required"))
        
        elif path == '/admin/footer-link/delete':
            try:
                index = int(data.get('index', -1))
                links = config.get("appearance", {}).get("footer", {}).get("links", [])
                if 0 <= index < len(links):
                    removed = links.pop(index)
                    save_config(config)
                    self.send_html(render_admin_page(user, config, message=f"Footer link '{removed.get('label', '')}' removed"))
                else:
                    self.send_html(render_admin_page(user, config, error="Invalid link index"))
            except (ValueError, IndexError):
                self.send_html(render_admin_page(user, config, error="Invalid request"))
        
        elif path == '/admin/appearance/css':
            config.setdefault("appearance", {})["custom_css"] = data.get('custom_css', '')[:5000]
            save_config(config)
            self.send_html(render_admin_page(user, config, message="Custom CSS saved"))
        
        elif path == '/admin/network':
            # Get form data
            interface = data.get('interface', 'eth0').strip()
            mode = data.get('mode', 'dhcp')
            ip_address = data.get('ip_address', '').strip()
            subnet_mask = data.get('subnet_mask', '24')
            gateway = data.get('gateway', '').strip()
            dns_primary = data.get('dns_primary', '8.8.8.8').strip()
            dns_secondary = data.get('dns_secondary', '').strip()
            save_only = data.get('save_only') == '1'
            confirmed = data.get('confirm') == '1'
            
            # Validate static IP settings
            if mode == 'static':
                errors = []
                if not ip_address:
                    errors.append("IP address is required for static configuration")
                elif not validate_ip_address(ip_address):
                    errors.append("Invalid IP address format")
                
                if not gateway:
                    errors.append("Gateway is required for static configuration")
                elif not validate_ip_address(gateway):
                    errors.append("Invalid gateway format")
                
                if dns_primary and not validate_ip_address(dns_primary):
                    errors.append("Invalid primary DNS format")
                
                if dns_secondary and not validate_ip_address(dns_secondary):
                    errors.append("Invalid secondary DNS format")
                
                if errors:
                    self.send_html(render_admin_page(user, config, error="; ".join(errors)))
                    return
            
            # Save to config
            config.setdefault("network", {})
            config["network"]["interface"] = interface
            config["network"]["mode"] = mode
            config["network"]["ip_address"] = ip_address
            config["network"]["subnet_mask"] = subnet_mask
            config["network"]["gateway"] = gateway
            config["network"]["dns_primary"] = dns_primary
            config["network"]["dns_secondary"] = dns_secondary
            save_config(config)
            
            if save_only:
                self.send_html(render_admin_page(user, config, message="Network settings saved (not applied)"))
            elif not confirmed:
                self.send_html(render_admin_page(user, config, error="Please confirm you understand the risks"))
            else:
                # Apply network configuration
                success, message = apply_network_config(config, config["network"])
                if success:
                    self.send_html(render_admin_page(user, config, message=message))
                else:
                    self.send_html(render_admin_page(user, config, error=message))
        
        elif path == '/admin/network/mdns':
            # Get mDNS form data
            mdns_enabled = data.get('mdns_enabled') == '1'
            mdns_hostname = data.get('mdns_hostname', 'multi-frames').strip()
            mdns_service_name = data.get('mdns_service_name', 'iFrame Dashboard').strip()
            
            # Sanitize hostname (only alphanumeric and hyphens)
            mdns_hostname = re.sub(r'[^a-zA-Z0-9-]', '-', mdns_hostname).strip('-').lower()
            if not mdns_hostname:
                mdns_hostname = 'multi-frames'
            
            # Limit lengths
            mdns_hostname = mdns_hostname[:63]  # DNS label max length
            mdns_service_name = mdns_service_name[:100]
            
            # Save to config
            config.setdefault("network", {}).setdefault("mdns", {})
            config["network"]["mdns"]["enabled"] = mdns_enabled
            config["network"]["mdns"]["hostname"] = mdns_hostname
            config["network"]["mdns"]["service_name"] = mdns_service_name
            save_config(config)
            
            # Start or stop mDNS service
            global mdns_service
            if mdns_enabled:
                if not ZEROCONF_AVAILABLE:
                    self.send_html(render_admin_page(user, config, error="mDNS not available - install zeroconf: pip install zeroconf"))
                    return
                
                if not mdns_service:
                    mdns_service = MDNSService()
                
                if mdns_service.running:
                    mdns_service.restart(mdns_hostname, mdns_service_name, SERVER_PORT)
                else:
                    mdns_service.start(mdns_hostname, mdns_service_name, SERVER_PORT)
                
                if mdns_service.running:
                    self.send_html(render_admin_page(user, config, message=f"mDNS enabled: http://{mdns_hostname}.local:{SERVER_PORT}"))
                else:
                    self.send_html(render_admin_page(user, config, error="Failed to start mDNS service"))
            else:
                if mdns_service:
                    mdns_service.stop()
                self.send_html(render_admin_page(user, config, message="mDNS disabled"))
        
        # System/Debug endpoints
        elif path == '/admin/system/log-level':
            level = data.get('level', 'INFO').upper()
            if server_logger.set_level(level):
                server_logger.info(f"Log level changed to {level}", extra=user)
                self.send_html(render_admin_page(user, config, message=f"Log level set to {level}"))
            else:
                self.send_html(render_admin_page(user, config, error="Invalid log level"))
        
        elif path == '/admin/system/clear-logs':
            server_logger.clear_logs()
            server_logger.info("Logs cleared", extra=user)
            self.send_html(render_admin_page(user, config, message="All logs cleared"))
        
        elif path == '/admin/system/clear-stats':
            server_logger.clear_stats()
            server_logger.info("Statistics reset", extra=user)
            self.send_html(render_admin_page(user, config, message="Statistics reset"))
        
        elif path == '/admin/system/clear-alerts':
            server_alerts.clear()
            server_logger.info("Server alerts cleared", extra=user)
            self.send_html(render_admin_page(user, config, message="Server alerts cleared"))

        # Watchdog endpoints
        elif path == '/admin/watchdog/clear-events':
            # Clear all watchdog events
            if 'watchdog' in config:
                config['watchdog']['events'] = []
            save_config(config)
            server_logger.info("Watchdog events cleared", extra=user)
            self.send_html(render_admin_page(user, config, message="Watchdog events cleared"))

        elif path == '/admin/watchdog/test-event':
            # Generate a test event for the watchdog
            uptime_tracker._record_event(config, 'test', 'Test event generated by admin', severity='info')
            save_config(config)
            server_logger.info("Watchdog test event generated", extra=user)
            self.send_html(render_admin_page(user, config, message="Test event generated"))

        elif path == '/admin/watchdog/reset-stats':
            # Reset all watchdog statistics
            config['watchdog'] = {
                'daily_uptime': {},
                'events': [],
                'last_shutdown': None,
                'current_session_start': uptime_tracker.current_session_start.isoformat() if uptime_tracker.current_session_start else None,
                'current_session_duration': 0
            }
            # Re-record server start
            uptime_tracker._record_event(config, 'start', 'Statistics reset - new tracking period started')
            save_config(config)
            server_logger.info("Watchdog statistics reset", extra=user)
            self.send_html(render_admin_page(user, config, message="Watchdog statistics reset"))

        elif path == '/admin/system/test-log':
            server_logger.debug("Test DEBUG message", extra=user)
            server_logger.info("Test INFO message", extra=user)
            server_logger.warning("Test WARNING message", extra=user)
            self.send_html(render_admin_page(user, config, message="Test log entries generated"))
        
        elif path == '/admin/system/test-error':
            server_logger.error("Test error - this is a simulated error", extra=user)
            self.send_html(render_admin_page(user, config, message="Test error generated"))
        
        elif path == '/admin/system/connectivity-test':
            # Server-side connectivity test for all iFrames
            import urllib.request
            import urllib.error
            import ssl
            
            results = []
            iframes = config.get('iframes', [])
            
            # Create SSL context that doesn't verify certificates (for testing)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            for i, iframe in enumerate(iframes):
                if iframe.get('use_embed_code'):
                    results.append({
                        'index': i,
                        'name': iframe.get('name', f'Frame {i+1}'),
                        'status': 'skip',
                        'message': 'Embed code'
                    })
                    continue
                
                url = iframe.get('url', '')
                if not url:
                    results.append({
                        'index': i,
                        'name': iframe.get('name', f'Frame {i+1}'),
                        'status': 'error',
                        'error': 'No URL'
                    })
                    continue
                
                result = {
                    'index': i,
                    'name': iframe.get('name', f'Frame {i+1}'),
                    'url': url[:50],
                    'status': 'testing'
                }
                
                try:
                    start_time = time_module.time()
                    req = urllib.request.Request(url, method='HEAD', headers={
                        'User-Agent': 'Multi-Frames-Connectivity-Test/1.0'
                    })
                    
                    with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                        elapsed = round((time_module.time() - start_time) * 1000)
                        result['status'] = 'success'
                        result['response_time'] = f'{elapsed} ms'
                        result['http_status'] = response.status
                        result['content_type'] = response.headers.get('Content-Type', 'Unknown')[:50]
                        
                        # Check for common headers
                        result['server'] = response.headers.get('Server', '')[:30]
                        result['x_frame_options'] = response.headers.get('X-Frame-Options', 'Not set')
                        
                except urllib.error.HTTPError as e:
                    elapsed = round((time_module.time() - start_time) * 1000)
                    result['status'] = 'warning' if e.code < 500 else 'error'
                    result['response_time'] = f'{elapsed} ms'
                    result['http_status'] = e.code
                    result['error'] = f'HTTP {e.code}: {e.reason}'
                    
                except urllib.error.URLError as e:
                    result['status'] = 'error'
                    result['error'] = str(e.reason)[:50]
                    
                except ssl.SSLError as e:
                    result['status'] = 'error'
                    result['error'] = f'SSL Error: {str(e)[:40]}'
                    
                except Exception as e:
                    result['status'] = 'error'
                    result['error'] = str(e)[:50]
                
                results.append(result)
            
            # Return JSON response
            self.send_json({
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'total': len(results),
                'results': results
            })

        elif path == '/admin/system/connectivity-test-single':
            # Server-side connectivity test for a single URL
            # Tests if the server is reachable - HTTP errors still mean "reachable"
            import urllib.request
            import urllib.error
            import ssl
            import socket

            url = data.get('url', '')
            idx = data.get('index', 0)

            if not url:
                self.send_json({'success': False, 'error': 'No URL provided'})
                return

            # Create SSL context that doesn't verify certificates (for local/self-signed)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            result = {
                'index': idx,
                'url': url[:100],
                'status': 'testing'
            }

            # Use browser-like headers for better compatibility
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close',
            }

            try:
                start_time = time_module.time()
                req = urllib.request.Request(url, method='GET', headers=headers)

                with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                    elapsed = round((time_module.time() - start_time) * 1000)
                    result['status'] = 'success'
                    result['response_time'] = f'{elapsed} ms'
                    result['http_status'] = response.status

                    # Check for iframe-blocking headers
                    result['x_frame_options'] = response.headers.get('X-Frame-Options', '')

                    # Check Content-Security-Policy for frame-ancestors
                    csp = response.headers.get('Content-Security-Policy', '')
                    if 'frame-ancestors' in csp.lower():
                        match = re.search(r'frame-ancestors\s+([^;]+)', csp, re.IGNORECASE)
                        if match:
                            result['csp_frame_ancestors'] = match.group(1).strip()

            except urllib.error.HTTPError as e:
                # HTTP errors (4xx, 5xx) still mean the server is REACHABLE
                elapsed = round((time_module.time() - start_time) * 1000)
                result['status'] = 'success'  # Server responded
                result['response_time'] = f'{elapsed} ms'
                result['http_status'] = e.code
                result['note'] = f'HTTP {e.code} (server reachable)'
                try:
                    result['x_frame_options'] = e.headers.get('X-Frame-Options', '')
                except:
                    pass

            except urllib.error.URLError as e:
                # Network-level errors - server truly not reachable
                reason = str(e.reason) if hasattr(e, 'reason') else str(e)
                reason_lower = reason.lower()
                if 'timed out' in reason_lower or isinstance(getattr(e, 'reason', None), socket.timeout):
                    result['status'] = 'error'
                    result['error'] = 'Connection timeout'
                elif 'refused' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'Connection refused'
                elif 'name or service not known' in reason_lower or 'getaddrinfo' in reason_lower or 'nodename nor servname' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'DNS lookup failed'
                elif 'no route to host' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'No route to host'
                elif 'network is unreachable' in reason_lower:
                    result['status'] = 'error'
                    result['error'] = 'Network unreachable'
                elif 'ssl' in reason_lower or 'certificate' in reason_lower:
                    result['status'] = 'warning'
                    result['error'] = 'SSL/Certificate issue'
                else:
                    result['status'] = 'error'
                    result['error'] = 'Connection failed'

            except socket.timeout:
                result['status'] = 'error'
                result['error'] = 'Connection timeout'

            except ssl.SSLError as e:
                # SSL errors - browser might still show warning page
                result['status'] = 'warning'
                result['error'] = 'SSL certificate issue'

            except Exception as e:
                error_str = str(e).lower()
                if 'timeout' in error_str:
                    result['status'] = 'error'
                    result['error'] = 'Connection timeout'
                elif 'refused' in error_str:
                    result['status'] = 'error'
                    result['error'] = 'Connection refused'
                else:
                    result['status'] = 'error'
                    result['error'] = 'Connection failed'

            self.send_json({
                'success': True,
                'result': result
            })

        elif path == '/admin/system/export-config':
            # Export full config for backup/restore (includes password hashes)
            export_config = json.loads(json.dumps(config))
            # Remove active sessions for security
            if 'sessions' in export_config:
                export_config['sessions'] = {}
            config_json = json.dumps(export_config, indent=2)
            filename = f"multi_frames_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', len(config_json))
            self.end_headers()
            self.wfile.write(config_json.encode('utf-8'))
            server_logger.info(f"Configuration exported by {user}", extra=user)
        
        elif path == '/admin/system/config-upload':
            # Handle config file upload
            try:
                config_content = None
                config_filename = None
                preserve_users = data.get('preserve_users') == '1'
                
                if 'config_file' in files:
                    file_data = files['config_file']
                    config_content = file_data.get('data', b'')
                    config_filename = file_data.get('filename', 'unknown.json')
                else:
                    self.send_html(render_admin_page(user, config, error="No config file uploaded"))
                    return
                
                if not config_content:
                    self.send_html(render_admin_page(user, config, error="Empty config file"))
                    return
                
                # Decode and parse JSON
                try:
                    config_text = config_content.decode('utf-8')
                    new_config = json.loads(config_text)
                except UnicodeDecodeError:
                    self.send_html(render_admin_page(user, config, error="Invalid file encoding (must be UTF-8)"))
                    return
                except json.JSONDecodeError as e:
                    self.send_html(render_admin_page(user, config, error=f"Invalid JSON: {str(e)}"))
                    return
                
                # Validate basic structure
                if not isinstance(new_config, dict):
                    self.send_html(render_admin_page(user, config, error="Config must be a JSON object"))
                    return
                
                # Preserve current users if requested
                if preserve_users:
                    new_config['users'] = config.get('users', {})
                else:
                    # If not preserving, check if users have redacted passwords
                    imported_users = new_config.get('users', {})
                    for username, user_data in imported_users.items():
                        if user_data.get('password_hash') == '***REDACTED***':
                            # Keep existing password if available, otherwise set default
                            if username in config.get('users', {}):
                                user_data['password_hash'] = config['users'][username]['password_hash']
                            else:
                                # Set default password for new users with redacted passwords
                                user_data['password_hash'] = hashlib.sha256("changeme".encode()).hexdigest()
                
                # Always preserve active sessions
                new_config['sessions'] = config.get('sessions', {})
                
                # Merge with defaults to ensure all required fields exist
                merged_config = json.loads(json.dumps(DEFAULT_CONFIG))
                
                # Deep merge function
                def deep_merge(base, override):
                    for key, value in override.items():
                        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                            deep_merge(base[key], value)
                        else:
                            base[key] = value
                    return base
                
                merged_config = deep_merge(merged_config, new_config)
                
                # Save the new config
                save_config(merged_config)
                server_logger.info(f"Configuration imported from {config_filename} by {user}", extra=user)
                
                self.send_html(render_admin_page(user, merged_config, message=f"Configuration imported successfully from {config_filename}"))
                
            except Exception as e:
                server_logger.error(f"Config upload error: {str(e)}")
                self.send_html(render_admin_page(user, config, error=f"Config import failed: {str(e)}"))
        
        elif path == '/admin/system/firmware-upload':
            # Handle firmware file upload
            try:
                # Get the uploaded file from multipart data
                firmware_content = None
                firmware_filename = None
                
                if 'firmware' in files:
                    file_data = files['firmware']
                    firmware_content = file_data.get('data', b'')
                    firmware_filename = file_data.get('filename', 'unknown.py')
                else:
                    self.send_html(render_admin_page(user, config, error="No firmware file uploaded"))
                    return
                
                if not firmware_content:
                    self.send_html(render_admin_page(user, config, error="Empty firmware file"))
                    return
                
                # Decode content
                try:
                    firmware_text = firmware_content.decode('utf-8')
                except UnicodeDecodeError:
                    self.send_html(render_admin_page(user, config, error="Invalid file encoding (must be UTF-8)"))
                    return
                
                # Validate the firmware
                is_valid, validation_result = validate_firmware_file(firmware_text)
                if not is_valid:
                    self.send_html(render_admin_page(user, config, error=f"Firmware validation failed: {validation_result}"))
                    return
                
                new_version = validation_result
                
                # Create backup of current firmware
                backup_path = create_firmware_backup()
                server_logger.info(f"Created firmware backup: {backup_path}", extra=user)
                
                # Write new firmware to current script location
                current_script = os.path.abspath(__file__)
                with open(current_script, 'w', encoding='utf-8') as f:
                    f.write(firmware_text)
                
                server_logger.info(f"Firmware updated from v{VERSION} to v{new_version} by {user}", extra=user)
                
                # Send response with restart notice
                restart_html = f'''
                <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                    <h2>✅ Firmware Updated</h2>
                    <p style="margin:1rem 0;">
                        <strong>Old Version:</strong> {VERSION}<br>
                        <strong>New Version:</strong> {new_version}
                    </p>
                    <p style="color:var(--text-secondary);">
                        Backup created: {os.path.basename(backup_path)}
                    </p>
                    <p style="margin:1.5rem 0;">
                        The server will restart in <span id="countdown">3</span> seconds...
                    </p>
                    <div class="status-dot loading" style="margin:1rem auto;"></div>
                    <script>
                    var seconds = 3;
                    var countdown = document.getElementById('countdown');
                    var interval = setInterval(function() {{
                        seconds--;
                        if (countdown) countdown.textContent = seconds;
                        if (seconds <= 0) {{
                            clearInterval(interval);
                            // Try to reconnect
                            setTimeout(function() {{
                                window.location.href = '/admin';
                            }}, 2000);
                        }}
                    }}, 1000);
                    </script>
                    <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem;">
                        <a href="/admin">Click here</a> if not redirected automatically.
                    </p>
                </div>
                '''
                self.send_html(render_page("Firmware Updated", restart_html, user, config))
                
                # Schedule restart
                import threading
                def restart_server():
                    time_module.sleep(2)
                    server_logger.info("Restarting server after firmware update...")
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                
                threading.Thread(target=restart_server, daemon=True).start()
                
            except Exception as e:
                server_logger.error(f"Firmware upload error: {str(e)}")
                self.send_html(render_admin_page(user, config, error=f"Firmware upload failed: {str(e)}"))
        
        elif path == '/admin/system/firmware-restore':
            # Restore firmware from backup
            try:
                filename = data.get('filename', '')
                if not filename:
                    self.send_html(render_admin_page(user, config, error="No backup file specified"))
                    return
                
                # Security check - only allow files from backup directory
                backup_dir = get_firmware_backup_dir()
                backup_path = os.path.join(backup_dir, os.path.basename(filename))
                
                if not os.path.exists(backup_path):
                    self.send_html(render_admin_page(user, config, error="Backup file not found"))
                    return
                
                # Read backup content
                with open(backup_path, 'r', encoding='utf-8') as f:
                    backup_content = f.read()
                
                # Validate the backup
                is_valid, validation_result = validate_firmware_file(backup_content)
                if not is_valid:
                    self.send_html(render_admin_page(user, config, error=f"Backup validation failed: {validation_result}"))
                    return
                
                restore_version = validation_result
                
                # Create backup of current firmware before restoring
                create_firmware_backup()
                
                # Write backup content to current script
                current_script = os.path.abspath(__file__)
                with open(current_script, 'w', encoding='utf-8') as f:
                    f.write(backup_content)
                
                server_logger.info(f"Firmware restored to v{restore_version} from {filename} by {user}", extra=user)
                
                # Send response with restart notice
                restart_html = f'''
                <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                    <h2>✅ Firmware Restored</h2>
                    <p style="margin:1rem 0;">
                        <strong>Restored Version:</strong> {restore_version}<br>
                        <strong>From Backup:</strong> {escape_html(filename)}
                    </p>
                    <p style="margin:1.5rem 0;">
                        The server will restart in <span id="countdown">3</span> seconds...
                    </p>
                    <div class="status-dot loading" style="margin:1rem auto;"></div>
                    <script>
                    var seconds = 3;
                    var countdown = document.getElementById('countdown');
                    var interval = setInterval(function() {{
                        seconds--;
                        if (countdown) countdown.textContent = seconds;
                        if (seconds <= 0) {{
                            clearInterval(interval);
                            setTimeout(function() {{
                                window.location.href = '/admin';
                            }}, 2000);
                        }}
                    }}, 1000);
                    </script>
                    <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem;">
                        <a href="/admin">Click here</a> if not redirected automatically.
                    </p>
                </div>
                '''
                self.send_html(render_page("Firmware Restored", restart_html, user, config))
                
                # Schedule restart
                import threading
                def restart_server():
                    time_module.sleep(2)
                    server_logger.info("Restarting server after firmware restore...")
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                
                threading.Thread(target=restart_server, daemon=True).start()
                
            except Exception as e:
                server_logger.error(f"Firmware restore error: {str(e)}")
                self.send_html(render_admin_page(user, config, error=f"Firmware restore failed: {str(e)}"))
        
        elif path == '/admin/system/check-updates':
            # Check for updates from GitHub
            server_logger.info(f"Update check initiated by {user}")
            
            result = check_for_updates(config)
            
            # Save result to config
            update_settings = get_update_settings(config)
            update_settings['last_check'] = result['checked_at']
            update_settings['last_result'] = result
            config['update_settings'] = update_settings
            save_config(config)
            
            if result.get('error'):
                self.send_html(render_admin_page(user, config, error=f"Update check failed: {result['error']}"))
            elif result.get('update_available'):
                self.send_html(render_admin_page(user, config, message=f"Update available! v{result['latest_version']} ({result.get('latest_date', 'unknown date')})"))
            else:
                self.send_html(render_admin_page(user, config, message=f"You're running the latest version (v{VERSION})"))
        
        elif path == '/admin/system/update-settings':
            # Save update settings
            github_url = data.get('github_url', '').strip()
            github_owner = data.get('github_owner', '').strip()
            github_repo = data.get('github_repo', '').strip()
            
            # Parse URL if provided
            if github_url:
                parsed_owner, parsed_repo = parse_git_url(github_url)
                if parsed_owner and parsed_repo:
                    github_owner = parsed_owner
                    github_repo = parsed_repo
            
            update_settings = get_update_settings(config)
            update_settings['github_url'] = github_url
            update_settings['github_owner'] = github_owner
            update_settings['github_repo'] = github_repo
            config['update_settings'] = update_settings
            
            success, err = save_config(config)
            if success:
                if github_owner and github_repo:
                    server_logger.info(f"Update settings changed by {user}: {github_owner}/{github_repo}")
                    self.send_html(render_admin_page(user, config, message=f"Repository configured: {github_owner}/{github_repo}"))
                else:
                    self.send_html(render_admin_page(user, config, error="Could not parse repository URL. Try owner/repo format."))
            else:
                self.send_html(render_admin_page(user, config, error=err))
        
        elif path == '/admin/system/git-pull':
            # Perform git pull to update firmware
            server_logger.info(f"Git pull initiated by {user}")
            
            success, message, details = perform_git_pull()
            
            if not success:
                self.send_html(render_admin_page(user, config, error=f"Update failed: {message}"))
                return
            
            if 'Already up to date' in message:
                self.send_html(render_admin_page(user, config, message="Already running the latest version"))
                return
            
            # Update succeeded - show restart page
            files_list = ""
            if details.get('files_changed'):
                files_list = '<div style="margin-top:1rem;text-align:left;max-height:150px;overflow-y:auto;background:var(--bg-secondary);padding:0.75rem;border-radius:var(--radius);font-size:0.8rem;font-family:monospace;">'
                for f in details['files_changed'][:20]:
                    files_list += f'<div>{escape_html(f)}</div>'
                if len(details['files_changed']) > 20:
                    files_list += f'<div style="color:var(--text-secondary);">... and {len(details["files_changed"]) - 20} more files</div>'
                files_list += '</div>'
            
            restart_html = f'''
            <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                <h2>✅ Firmware Updated</h2>
                <p style="margin:1rem 0;">
                    {escape_html(message)}
                </p>
                {files_list}
                <p style="margin:1.5rem 0;">
                    The server will restart in <span id="countdown">3</span> seconds...
                </p>
                <div class="status-dot loading" style="margin:1rem auto;"></div>
                <script>
                var seconds = 3;
                var countdown = document.getElementById('countdown');
                var interval = setInterval(function() {{
                    seconds--;
                    if (countdown) countdown.textContent = seconds;
                    if (seconds <= 0) {{
                        clearInterval(interval);
                        setTimeout(function() {{
                            window.location.href = '/admin';
                        }}, 3000);
                    }}
                }}, 1000);
                </script>
                <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem;">
                    <a href="/admin">Click here</a> if not redirected automatically.
                </p>
            </div>
            '''
            
            self.send_html(render_page("Firmware Updated", restart_html, user, config))
            server_logger.info(f"Git pull successful: {message}")
            
            # Schedule restart
            import threading
            def restart_server():
                time_module.sleep(3)
                server_logger.info("Restarting server after git pull update...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
            
            threading.Thread(target=restart_server, daemon=True).start()
        
        elif path == '/admin/system/restart':
            # Manual server restart
            server_logger.info(f"Manual server restart initiated by {user}", extra=user)
            
            restart_html = '''
            <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                <h2>🔄 Server Restarting</h2>
                <p style="margin:1.5rem 0;">
                    The server will restart in <span id="countdown">3</span> seconds...
                </p>
                <div class="status-dot loading" style="margin:1rem auto;"></div>
                <script>
                var seconds = 3;
                var countdown = document.getElementById('countdown');
                var interval = setInterval(function() {
                    seconds--;
                    if (countdown) countdown.textContent = seconds;
                    if (seconds <= 0) {
                        clearInterval(interval);
                        setTimeout(function() {
                            window.location.href = '/admin';
                        }, 2000);
                    }
                }, 1000);
                </script>
                <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem;">
                    <a href="/admin">Click here</a> if not redirected automatically.
                </p>
            </div>
            '''
            self.send_html(render_page("Server Restarting", restart_html, user, config))
            
            # Schedule restart
            import threading
            def restart_server():
                time_module.sleep(2)
                server_logger.info("Server restarting...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
            
            threading.Thread(target=restart_server, daemon=True).start()
        
        elif path == '/admin/system/pi-hostname':
            # Raspberry Pi hostname change
            pi_info = get_raspberry_pi_info()
            if not pi_info:
                self.send_html(render_admin_page(user, config, error="Not running on Raspberry Pi"))
                return
            
            new_hostname = data.get('hostname', '').strip().lower()
            success, message = set_pi_hostname(new_hostname)
            
            if success:
                server_logger.info(f"Raspberry Pi hostname changed to '{new_hostname}' by {user}")
                self.send_html(render_admin_page(user, config, message=message))
            else:
                self.send_html(render_admin_page(user, config, error=message))
        
        elif path == '/admin/system/pi-reboot':
            # Raspberry Pi reboot
            pi_info = get_raspberry_pi_info()
            if not pi_info:
                self.send_html(render_admin_page(user, config, error="Not running on Raspberry Pi"))
                return
            
            server_logger.info(f"Raspberry Pi reboot initiated by {user}")
            
            reboot_html = '''
            <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                <h2>🔄 Raspberry Pi Rebooting</h2>
                <p style="margin:1.5rem 0;">
                    The Raspberry Pi will reboot now. Please wait about 30-60 seconds.
                </p>
                <div class="status-dot loading" style="margin:1rem auto;"></div>
                <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:1rem;">
                    The page will attempt to reconnect automatically.
                </p>
                <script>
                setTimeout(function() {
                    var attempts = 0;
                    var maxAttempts = 30;
                    var checkInterval = setInterval(function() {
                        attempts++;
                        fetch('/api/ping', {method: 'GET', cache: 'no-cache'})
                            .then(function(r) {
                                if (r.ok) {
                                    clearInterval(checkInterval);
                                    window.location.href = '/admin';
                                }
                            })
                            .catch(function() {});
                        if (attempts >= maxAttempts) {
                            clearInterval(checkInterval);
                            document.body.innerHTML = '<div style="text-align:center;padding:2rem;"><h2>Connection Lost</h2><p>Could not reconnect. <a href="/admin">Try manually</a></p></div>';
                        }
                    }, 3000);
                }, 5000);
                </script>
            </div>
            '''
            self.send_html(render_page("Rebooting", reboot_html, user, config))
            
            # Schedule reboot
            import threading
            def reboot_pi():
                time_module.sleep(2)
                try:
                    subprocess.run(['sudo', 'reboot'], capture_output=True, timeout=10)
                except:
                    pass
            
            threading.Thread(target=reboot_pi, daemon=True).start()
        
        elif path == '/admin/system/pi-shutdown':
            # Raspberry Pi shutdown
            pi_info = get_raspberry_pi_info()
            if not pi_info:
                self.send_html(render_admin_page(user, config, error="Not running on Raspberry Pi"))
                return
            
            server_logger.info(f"Raspberry Pi shutdown initiated by {user}")
            
            shutdown_html = '''
            <div class="card" style="max-width:500px;margin:2rem auto;text-align:center;">
                <h2>⏻ Raspberry Pi Shutting Down</h2>
                <p style="margin:1.5rem 0;">
                    The Raspberry Pi is shutting down. You will need physical access to power it back on.
                </p>
                <div style="font-size:3rem;margin:1rem 0;">🔌</div>
                <p style="font-size:0.85rem;color:var(--text-secondary);">
                    Wait for the green activity light to stop blinking before disconnecting power.
                </p>
            </div>
            '''
            self.send_html(render_page("Shutting Down", shutdown_html, user, config))
            
            # Schedule shutdown
            import threading
            def shutdown_pi():
                time_module.sleep(2)
                try:
                    subprocess.run(['sudo', 'shutdown', '-h', 'now'], capture_output=True, timeout=10)
                except:
                    pass
            
            threading.Thread(target=shutdown_pi, daemon=True).start()
        
        else:
            self.redirect('/admin')

# =============================================================================
# Main Entry Point
# =============================================================================

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server for handling concurrent requests."""
    allow_reuse_address = True
    daemon_threads = True


# =============================================================================
# Terminal UI Helpers
# =============================================================================

class TermColors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Backgrounds
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_CYAN = '\033[46m'

def supports_color():
    """Check if terminal supports ANSI colors."""
    import sys
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get('NO_COLOR'):
        return False
    return True

def print_banner(args, config, use_color=True):
    """Print the startup banner."""
    c = TermColors if use_color else type('NoColor', (), {k: '' for k in dir(TermColors) if not k.startswith('_')})()
    
    # Get network info
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        pass
    
    # mDNS info
    mdns_enabled = config.get("network", {}).get("mdns", {}).get("enabled", False)
    mdns_hostname = config.get("network", {}).get("mdns", {}).get("hostname", "multi-frames")
    
    # Check if default password
    default_pw = config.get("users", {}).get("admin", {}).get("password_hash") == hashlib.sha256("admin123".encode()).hexdigest()
    
    # Count configured items
    iframe_count = len(config.get("iframes", []))
    user_count = len(config.get("users", {}))
    widget_count = len(config.get("widgets", []))
    
    print()
    print(f"  {c.CYAN}{c.BOLD}MULTI-FRAMES{c.RESET} {c.DIM}v{VERSION}{c.RESET}")
    print(f"  {c.DIM}Dashboard & iFrame Display Server{c.RESET}")
    print(f"  {c.DIM}Designed by {VERSION_AUTHOR}, {VERSION_COMPANY}{c.RESET}")
    print()
    print(f"  {c.DIM}{'─' * 44}{c.RESET}")
    print()
    print(f"  {c.GREEN}●{c.RESET} Server running")
    print()
    print(f"    {c.DIM}Local:{c.RESET}      http://{args.host}:{args.port}")
    print(f"    {c.DIM}Network:{c.RESET}    http://{local_ip}:{args.port}")
    if mdns_enabled and ZEROCONF_AVAILABLE:
        print(f"    {c.DIM}Bonjour:{c.RESET}    http://{mdns_hostname}.local:{args.port}")
    print()
    print(f"  {c.BLUE}◆{c.RESET} Configuration")
    print()
    print(f"    {c.DIM}Config:{c.RESET}     {CONFIG_FILE}")
    print(f"    {c.DIM}iFrames:{c.RESET}    {iframe_count} configured")
    print(f"    {c.DIM}Widgets:{c.RESET}    {widget_count} configured")
    print(f"    {c.DIM}Users:{c.RESET}      {user_count} registered")
    if mdns_enabled:
        if ZEROCONF_AVAILABLE:
            print(f"    {c.DIM}mDNS:{c.RESET}       {c.GREEN}●{c.RESET} Active ({mdns_hostname}.local)")
        else:
            print(f"    {c.DIM}mDNS:{c.RESET}       {c.YELLOW}○{c.RESET} zeroconf not installed")
    else:
        print(f"    {c.DIM}mDNS:{c.RESET}       {c.GRAY}○{c.RESET} Disabled")
    
    # Security status
    if default_pw:
        print(f"    {c.DIM}Security:{c.RESET}   {c.YELLOW}○{c.RESET} Default password")
    else:
        print(f"    {c.DIM}Security:{c.RESET}   {c.GREEN}●{c.RESET} Password changed")
    print()
    
    if default_pw:
        print(f"  {c.YELLOW}⚠{c.RESET}  {c.YELLOW}Security Warning{c.RESET}")
        print(f"    Default password in use: {c.BOLD}admin{c.RESET} / {c.BOLD}admin123{c.RESET}")
        print(f"    {c.DIM}Change in Admin → Users{c.RESET}")
        print()
    
    print(f"  {c.DIM}{'─' * 44}{c.RESET}")
    print(f"  {c.DIM}Press Ctrl+C to stop{c.RESET}")
    print()


def print_shutdown(use_color=True):
    """Print shutdown message."""
    c = TermColors if use_color else type('NoColor', (), {k: '' for k in dir(TermColors) if not k.startswith('_')})()
    print()
    print(f"  {c.YELLOW}●{c.RESET} {c.BOLD}Shutting down...{c.RESET}")
    stop_mdns_service()
    print(f"  {c.RED}●{c.RESET} {c.BOLD}Server stopped{c.RESET}")
    print()


def main():
    global SERVER_PORT, SERVER_START_TIME, uptime_tracker

    parser = argparse.ArgumentParser(description='Multi-Frames v1.1.11 - Dashboard & iFrame Display Server by LTS, Inc.')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-auto-restart', action='store_true', help='Disable auto-restart on crash')
    args = parser.parse_args()

    # Check color support
    use_color = supports_color() and not args.no_color

    # Set global port and start time
    SERVER_PORT = args.port
    SERVER_START_TIME = datetime.now()

    # Log startup
    server_logger.info(f"Server starting on {args.host}:{args.port}")

    # Ensure config exists
    config = load_config()

    # Initialize uptime tracker with 30-day history
    uptime_tracker.initialize(config)
    save_config(config)
    server_logger.info("Watchdog uptime tracking initialized")

    # Initialize cloud agent for remote management
    cloud_agent.initialize(config)
    if cloud_agent.enabled:
        server_logger.info("Cloud agent initialized")

    # Start mDNS if enabled
    if config.get("network", {}).get("mdns", {}).get("enabled", False):
        if ZEROCONF_AVAILABLE:
            start_mdns_service(config, args.port)

    # Print banner
    print_banner(args, config, use_color)
    
    # Auto-restart settings
    max_restarts = 10
    restart_count = 0
    restart_window = 300  # Reset restart count after 5 minutes of stability
    last_restart = None
    
    while True:
        try:
            with ThreadedTCPServer((args.host, args.port), IFrameHandler) as httpd:
                # Reset restart count if server has been stable
                if last_restart and (datetime.now() - last_restart).total_seconds() > restart_window:
                    restart_count = 0
                
                httpd.serve_forever()
                
        except KeyboardInterrupt:
            # Record graceful shutdown in uptime tracker
            try:
                config = load_config()
                uptime_tracker.record_shutdown(config)
                save_config(config)
            except:
                pass
            print_shutdown(use_color)
            break

        except OSError as e:
            if 'Address already in use' in str(e):
                print(f"\n{'='*60}")
                print(f"ERROR: Port {args.port} is already in use!")
                print(f"Try: python multi_frames.py --port {args.port + 1}")
                print(f"{'='*60}\n")
                break
            else:
                raise
                
        except Exception as e:
            error_msg = str(e)
            server_logger.error(f"Server crashed: {error_msg}")
            server_alerts.record_crash(error_msg)

            # Record crash in uptime tracker
            try:
                config = load_config()
                uptime_tracker.record_crash(config, error_msg)
                save_config(config)
            except:
                pass

            if args.no_auto_restart:
                print(f"\n{'='*60}")
                print(f"SERVER CRASHED: {error_msg}")
                print(f"Auto-restart disabled. Exiting.")
                print(f"{'='*60}\n")
                break
            
            restart_count += 1
            last_restart = datetime.now()
            
            if restart_count > max_restarts:
                print(f"\n{'='*60}")
                print(f"SERVER CRASHED TOO MANY TIMES ({max_restarts})")
                print(f"Last error: {error_msg}")
                print(f"Please check the logs and fix the issue.")
                print(f"{'='*60}\n")
                break
            
            # Wait before restart (exponential backoff)
            wait_time = min(2 ** restart_count, 30)  # Max 30 seconds
            print(f"\n{'='*60}")
            print(f"SERVER CRASHED: {error_msg}")
            print(f"Restarting in {wait_time} seconds... (attempt {restart_count}/{max_restarts})")
            print(f"{'='*60}\n")
            
            time_module.sleep(wait_time)
            
            # Reload config in case it was corrupted
            try:
                config = load_config()
            except:
                pass
            
            server_logger.info(f"Server restarting after crash (attempt {restart_count})")


if __name__ == '__main__':
    main()
