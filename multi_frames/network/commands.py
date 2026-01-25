"""
Network command sending for Multi-Frames.
Supports TCP, UDP, and Telnet protocols for device control.
"""

import socket
import time
from typing import Tuple, Optional


def send_network_command(
    protocol: str,
    host: str,
    port: int,
    command: str,
    timeout: float = 5.0,
    expect_response: bool = True
) -> Tuple[bool, str, Optional[str]]:
    """
    Send a network command to a device.
    
    Args:
        protocol: 'tcp', 'udp', or 'telnet'
        host: Target hostname or IP
        port: Target port
        command: Command string to send
        timeout: Socket timeout in seconds
        expect_response: Whether to wait for a response
    
    Returns:
        Tuple of (success, message, response_data)
    """
    protocol = protocol.lower()
    
    # Handle dummy protocols for testing
    if protocol == "dummy":
        time.sleep(0.1)
        return True, "Dummy command executed", "OK"
    elif protocol == "dummy_fail":
        time.sleep(0.1)
        return False, "Dummy command failed (intentional)", None
    elif protocol == "dummy_random":
        import random
        time.sleep(0.1)
        if random.random() > 0.5:
            return True, "Random success", "OK"
        return False, "Random failure", None
    
    # Validate inputs
    if not host:
        return False, "No host specified", None
    
    if not 1 <= port <= 65535:
        return False, f"Invalid port: {port}", None
    
    if not command:
        return False, "No command specified", None
    
    # Dispatch to appropriate handler
    if protocol == "tcp":
        return _send_tcp(host, port, command, timeout, expect_response)
    elif protocol == "udp":
        return _send_udp(host, port, command, timeout, expect_response)
    elif protocol == "telnet":
        return _send_telnet(host, port, command, timeout, expect_response)
    else:
        return False, f"Unknown protocol: {protocol}", None


def _send_tcp(
    host: str,
    port: int,
    command: str,
    timeout: float,
    expect_response: bool
) -> Tuple[bool, str, Optional[str]]:
    """Send command via TCP."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send command
        if not command.endswith('\n'):
            command += '\n'
        sock.sendall(command.encode('utf-8'))
        
        # Get response if expected
        response = None
        if expect_response:
            try:
                data = sock.recv(4096)
                response = data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                response = "(no response - timeout)"
        
        return True, "Command sent via TCP", response
        
    except socket.timeout:
        return False, f"Connection timeout to {host}:{port}", None
    except ConnectionRefusedError:
        return False, f"Connection refused by {host}:{port}", None
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}", None
    except Exception as e:
        return False, f"TCP error: {str(e)}", None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _send_udp(
    host: str,
    port: int,
    command: str,
    timeout: float,
    expect_response: bool
) -> Tuple[bool, str, Optional[str]]:
    """Send command via UDP."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Send command
        if not command.endswith('\n'):
            command += '\n'
        sock.sendto(command.encode('utf-8'), (host, port))
        
        # Get response if expected
        response = None
        if expect_response:
            try:
                data, _ = sock.recvfrom(4096)
                response = data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                response = "(no response - UDP is connectionless)"
        
        return True, "Command sent via UDP", response
        
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}", None
    except Exception as e:
        return False, f"UDP error: {str(e)}", None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _send_telnet(
    host: str,
    port: int,
    command: str,
    timeout: float,
    expect_response: bool
) -> Tuple[bool, str, Optional[str]]:
    """Send command via Telnet."""
    import telnetlib
    
    tn = None
    try:
        tn = telnetlib.Telnet(host, port, timeout=timeout)
        
        # Wait briefly for any login prompts
        time.sleep(0.2)
        
        # Read and discard initial output
        try:
            tn.read_very_eager()
        except Exception:
            pass
        
        # Send command
        if not command.endswith('\n'):
            command += '\n'
        tn.write(command.encode('utf-8'))
        
        # Get response if expected
        response = None
        if expect_response:
            try:
                time.sleep(0.3)
                data = tn.read_very_eager()
                response = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                response = "(no response)"
        
        return True, "Command sent via Telnet", response
        
    except socket.timeout:
        return False, f"Telnet timeout to {host}:{port}", None
    except ConnectionRefusedError:
        return False, f"Telnet connection refused by {host}:{port}", None
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}", None
    except Exception as e:
        return False, f"Telnet error: {str(e)}", None
    finally:
        if tn:
            try:
                tn.close()
            except Exception:
                pass


def test_connection(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, str]:
    """
    Test if a TCP connection can be established.
    Returns (success, message).
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return True, f"Connection successful to {host}:{port}"
    except socket.timeout:
        return False, f"Connection timeout to {host}:{port}"
    except ConnectionRefusedError:
        return False, f"Connection refused by {host}:{port}"
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}"
    except Exception as e:
        return False, f"Connection error: {str(e)}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
