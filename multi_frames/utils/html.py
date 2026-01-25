"""
HTML utility functions for Multi-Frames.
"""

import html
from typing import Optional


def escape_html(text: Optional[str]) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return html.escape(str(text))


def make_safe_id(text: str) -> str:
    """Convert text to a safe HTML ID."""
    import re
    # Replace non-alphanumeric with dashes
    safe = re.sub(r'[^a-zA-Z0-9]', '-', text.lower())
    # Remove consecutive dashes
    safe = re.sub(r'-+', '-', safe)
    # Remove leading/trailing dashes
    return safe.strip('-')


def truncate(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate text to max length with suffix."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def nl2br(text: str) -> str:
    """Convert newlines to HTML <br> tags."""
    return escape_html(text).replace('\n', '<br>')
