"""
Configuration management for Multi-Frames.
Handles loading, saving, and default configuration values.
"""

import os
import json
import hashlib

# Configuration file name
CONFIG_FILE = "multi_frames_config.json"

# Default admin password hash (admin123)
DEFAULT_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

# Default configuration
DEFAULT_CONFIG = {
    "users": {
        "admin": {
            "password_hash": DEFAULT_PASSWORD_HASH,
            "is_admin": True
        }
    },
    "iframes": [],
    "widgets": [],
    "settings": {
        "page_title": "Multi-Frames Dashboard",
        "refresh_interval": 0,
        "grid_columns": 2,
        "show_header": True,
        "show_footer": True
    },
    "branding": {
        "logo": "",
        "logo_mime": "",
        "favicon": "",
        "favicon_mime": "",
        "apple_touch_icon": "",
        "apple_touch_icon_mime": ""
    },
    "appearance": {
        "colors": {
            "bg_primary": "#0a0a0b",
            "bg_secondary": "#141416",
            "bg_tertiary": "#1a1a1e",
            "text_primary": "#e8e8e8",
            "text_secondary": "#888888",
            "border": "#2a2a2e",
            "accent": "#3b82f6",
            "accent_hover": "#2563eb",
            "success": "#22c55e",
            "danger": "#ef4444"
        },
        "background": {
            "type": "solid",
            "gradient_start": "#0a0a0b",
            "gradient_end": "#1a1a2e",
            "gradient_direction": "to bottom",
            "image": "",
            "image_mime": "",
            "image_size": "cover",
            "image_opacity": 100
        },
        "header": {
            "show": True,
            "sticky": True,
            "custom_text": "",
            "bg_color": "",
            "text_color": ""
        },
        "footer": {
            "show": True,
            "text": "Multi-Frames v1.1 by LTS, Inc.",
            "show_python_version": False,
            "links": []
        },
        "custom_css": ""
    },
    "network": {
        "mode": "dhcp",
        "interface": "",
        "ip_address": "",
        "subnet_mask": "24",
        "gateway": "",
        "dns_primary": "8.8.8.8",
        "dns_secondary": "8.8.4.4"
    },
    "mdns": {
        "enabled": False,
        "hostname": "multi-frames",
        "service_name": "Multi-Frames Dashboard"
    },
    "fallback": {
        "enabled": False,
        "image": "",
        "image_mime": "",
        "text": "Content unavailable",
        "auto_hide": True
    },
    "active_sessions": {},
    "password_reset_requests": {},
    "connectivity_reports": []
}


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base dict, returning merged result."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict:
    """Load configuration from file, merging with defaults."""
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                loaded = json.load(f)
                config = deep_merge(DEFAULT_CONFIG, loaded)
        except (json.JSONDecodeError, IOError):
            pass
    return config


def save_config(config: dict) -> None:
    """Save configuration to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def hash_password(password: str) -> str:
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def is_default_password(config: dict) -> bool:
    """Check if admin is using the default password."""
    admin_user = config.get("users", {}).get("admin", {})
    return admin_user.get("password_hash") == DEFAULT_PASSWORD_HASH
