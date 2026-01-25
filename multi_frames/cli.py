"""
Command-line interface and terminal UI for Multi-Frames.
"""

import sys
import os
import socket
import argparse
from typing import Optional

from . import VERSION, VERSION_NAME, VERSION_AUTHOR, VERSION_COMPANY


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


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    if os.environ.get('NO_COLOR'):
        return False
    if not hasattr(sys.stdout, 'isatty'):
        return False
    return sys.stdout.isatty()


def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_banner(args, config: dict, use_color: bool = True) -> None:
    """Print the startup banner."""
    c = TermColors if use_color else type('NoColor', (), {k: '' for k in dir(TermColors) if not k.startswith('_')})()
    
    local_ip = get_local_ip()
    port = getattr(args, 'port', 8080)
    host = getattr(args, 'host', '0.0.0.0')
    
    # Count configuration items
    iframe_count = len(config.get('iframes', []))
    widget_count = len(config.get('widgets', []))
    user_count = len(config.get('users', {}))
    
    # mDNS status
    mdns_config = config.get('mdns', {})
    mdns_enabled = mdns_config.get('enabled', False)
    mdns_hostname = mdns_config.get('hostname', 'multi-frames')
    
    # Check for zeroconf
    try:
        import zeroconf
        zeroconf_available = True
    except ImportError:
        zeroconf_available = False
    
    # Check for default password
    from .config import is_default_password
    show_password_warning = is_default_password(config)
    
    print()
    print(f"  {c.BOLD}{c.CYAN}{VERSION_NAME.upper()} v{VERSION}{c.RESET}")
    print(f"  {c.DIM}Dashboard & iFrame Display Server{c.RESET}")
    print(f"  {c.DIM}Designed by {VERSION_AUTHOR}, {VERSION_COMPANY}{c.RESET}")
    print()
    print(f"  {c.DIM}{'─' * 44}{c.RESET}")
    print()
    print(f"  {c.GREEN}●{c.RESET} {c.BOLD}Server running{c.RESET}")
    print()
    print(f"    {c.DIM}Local:{c.RESET}      http://{host}:{port}")
    print(f"    {c.DIM}Network:{c.RESET}    http://{local_ip}:{port}")
    
    if mdns_enabled and zeroconf_available:
        print(f"    {c.DIM}Bonjour:{c.RESET}    http://{mdns_hostname}.local:{port}")
    
    print()
    print(f"  {c.BLUE}◆{c.RESET} {c.BOLD}Configuration{c.RESET}")
    print()
    print(f"    {c.DIM}Config:{c.RESET}     multi_frames_config.json")
    print(f"    {c.DIM}iFrames:{c.RESET}    {iframe_count} configured")
    print(f"    {c.DIM}Widgets:{c.RESET}    {widget_count} configured")
    print(f"    {c.DIM}Users:{c.RESET}      {user_count} registered")
    
    # mDNS status line
    if mdns_enabled:
        if zeroconf_available:
            print(f"    {c.DIM}mDNS:{c.RESET}       {c.GREEN}●{c.RESET} Active ({mdns_hostname}.local)")
        else:
            print(f"    {c.DIM}mDNS:{c.RESET}       {c.YELLOW}○{c.RESET} zeroconf not installed")
    else:
        print(f"    {c.DIM}mDNS:{c.RESET}       {c.GRAY}○{c.RESET} Disabled")
    
    # Password warning
    if show_password_warning:
        print()
        print(f"  {c.YELLOW}⚠{c.RESET}  {c.YELLOW}Security Warning{c.RESET}")
        print(f"    {c.DIM}Default password in use: admin / admin123{c.RESET}")
        print(f"    {c.DIM}Change in Admin → Users{c.RESET}")
    
    print()
    print(f"  {c.DIM}{'─' * 44}{c.RESET}")
    print(f"  {c.DIM}Press Ctrl+C to stop{c.RESET}")
    print()


def print_shutdown(use_color: bool = True) -> None:
    """Print shutdown message."""
    c = TermColors if use_color else type('NoColor', (), {k: '' for k in dir(TermColors) if not k.startswith('_')})()
    
    print()
    print(f"  {c.YELLOW}●{c.RESET} Shutting down...")
    print(f"  {c.RED}●{c.RESET} Server stopped")
    print()


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=f'{VERSION_NAME} v{VERSION} - Dashboard & iFrame Display Server by {VERSION_COMPANY}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host address to bind to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored terminal output'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'{VERSION_NAME} v{VERSION}'
    )
    
    return parser
