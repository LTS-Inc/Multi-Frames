"""
Authentication and session management for Multi-Frames.
"""

import secrets
import time
from typing import Optional, Tuple

# Session timeout in seconds (24 hours)
SESSION_TIMEOUT = 86400


def create_session(username: str, config: dict) -> str:
    """Create a new session for a user and return the session ID."""
    session_id = secrets.token_hex(32)
    config["active_sessions"][session_id] = {
        "username": username,
        "created": time.time()
    }
    return session_id


def get_session(session_id: str, config: dict) -> Optional[str]:
    """Get username from session ID, or None if invalid/expired."""
    if not session_id:
        return None
    
    session = config.get("active_sessions", {}).get(session_id)
    if not session:
        return None
    
    # Check if session has expired
    if time.time() - session.get("created", 0) > SESSION_TIMEOUT:
        # Remove expired session
        config["active_sessions"].pop(session_id, None)
        return None
    
    return session.get("username")


def delete_session(session_id: str, config: dict) -> None:
    """Delete a session."""
    config.get("active_sessions", {}).pop(session_id, None)


def validate_credentials(username: str, password: str, config: dict) -> bool:
    """Validate username and password against stored credentials."""
    from .config import hash_password
    
    user = config.get("users", {}).get(username)
    if not user:
        return False
    
    return user.get("password_hash") == hash_password(password)


def is_admin(username: str, config: dict) -> bool:
    """Check if a user has admin privileges."""
    user = config.get("users", {}).get(username)
    return user.get("is_admin", False) if user else False


def cleanup_expired_sessions(config: dict) -> int:
    """Remove all expired sessions. Returns count of removed sessions."""
    current_time = time.time()
    expired = []
    
    for session_id, session in config.get("active_sessions", {}).items():
        if current_time - session.get("created", 0) > SESSION_TIMEOUT:
            expired.append(session_id)
    
    for session_id in expired:
        config["active_sessions"].pop(session_id, None)
    
    return len(expired)
