"""
Validation utilities for Multi-Frames.
"""

import re
import socket
from urllib.parse import urlparse
from typing import Tuple


def validate_local_ip(url: str) -> Tuple[bool, str]:
    """
    Validate that a URL points to a local/private IP address.
    Returns (is_valid, error_message).
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        
        if not host:
            return False, "Invalid URL: no hostname found"
        
        # Allow localhost
        if host in ("localhost", "127.0.0.1", "::1"):
            return True, ""
        
        # Allow .local and .lan domains
        if host.endswith(".local") or host.endswith(".lan"):
            return True, ""
        
        # Try to resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {host}"
        
        # Check if IP is private
        parts = ip.split(".")
        if len(parts) != 4:
            return False, "Invalid IP address format"
        
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False, "Invalid IP address format"
        
        # Check private ranges
        # 10.0.0.0 - 10.255.255.255
        if octets[0] == 10:
            return True, ""
        
        # 172.16.0.0 - 172.31.255.255
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True, ""
        
        # 192.168.0.0 - 192.168.255.255
        if octets[0] == 192 and octets[1] == 168:
            return True, ""
        
        # 127.0.0.0 - 127.255.255.255 (loopback)
        if octets[0] == 127:
            return True, ""
        
        return False, f"External IP not allowed: {ip}"
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def validate_ip_address(ip: str) -> bool:
    """Validate an IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def validate_subnet_mask(mask: str) -> bool:
    """Validate a subnet mask (CIDR notation: 0-32)."""
    try:
        cidr = int(mask)
        return 0 <= cidr <= 32
    except ValueError:
        return False


def cidr_to_netmask(cidr: int) -> str:
    """Convert CIDR notation to dotted decimal netmask."""
    if not 0 <= cidr <= 32:
        return "255.255.255.0"
    
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return ".".join(str((mask >> (8 * i)) & 0xff) for i in range(3, -1, -1))


def validate_hostname(hostname: str) -> bool:
    """Validate a hostname."""
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True


def validate_port(port: int) -> bool:
    """Validate a port number."""
    return 1 <= port <= 65535


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename for safe storage."""
    # Remove path separators and null bytes
    filename = filename.replace('/', '').replace('\\', '').replace('\0', '')
    # Remove other problematic characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name = 255 - len(ext) - 1 if ext else 255
        filename = name[:max_name] + ('.' + ext if ext else '')
    return filename or 'unnamed'
