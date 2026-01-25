"""
Network interface detection and information for Multi-Frames.
"""

import os
import sys
import socket
import subprocess
import re
from typing import List, Dict, Any, Optional


def get_network_interfaces() -> List[Dict[str, Any]]:
    """Get list of network interfaces with their details."""
    interfaces = []
    system = sys.platform
    
    try:
        if system == "win32":
            interfaces = _get_interfaces_windows()
        elif system == "darwin":
            interfaces = _get_interfaces_macos()
        else:
            interfaces = _get_interfaces_linux()
    except Exception as e:
        # Return a basic interface if detection fails
        interfaces = [{"name": "eth0", "description": "Default interface"}]
    
    return interfaces


def _get_interfaces_windows() -> List[Dict[str, Any]]:
    """Get network interfaces on Windows."""
    interfaces = []
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=10
        )
        
        for line in result.stdout.split('\n')[3:]:
            parts = line.split()
            if len(parts) >= 4:
                name = ' '.join(parts[3:])
                state = parts[1]
                interfaces.append({
                    "name": name,
                    "description": name,
                    "state": state,
                    "is_up": state.lower() == "connected"
                })
    except Exception:
        pass
    
    return interfaces or [{"name": "Ethernet", "description": "Default"}]


def _get_interfaces_macos() -> List[Dict[str, Any]]:
    """Get network interfaces on macOS."""
    interfaces = []
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10
        )
        
        current_name = None
        for line in result.stdout.split('\n'):
            if line.startswith("Hardware Port:"):
                current_name = line.replace("Hardware Port:", "").strip()
            elif line.startswith("Device:") and current_name:
                device = line.replace("Device:", "").strip()
                interfaces.append({
                    "name": device,
                    "description": current_name,
                    "device": device
                })
                current_name = None
    except Exception:
        pass
    
    return interfaces or [{"name": "en0", "description": "Default"}]


def _get_interfaces_linux() -> List[Dict[str, Any]]:
    """Get network interfaces on Linux."""
    interfaces = []
    
    # Try /sys/class/net first
    try:
        net_path = "/sys/class/net"
        if os.path.exists(net_path):
            for iface in os.listdir(net_path):
                if iface == "lo":
                    continue
                
                iface_path = os.path.join(net_path, iface)
                is_up = False
                
                # Check operstate
                operstate_path = os.path.join(iface_path, "operstate")
                if os.path.exists(operstate_path):
                    with open(operstate_path) as f:
                        is_up = f.read().strip() == "up"
                
                interfaces.append({
                    "name": iface,
                    "description": iface,
                    "is_up": is_up
                })
    except Exception:
        pass
    
    # Fallback to ip command
    if not interfaces:
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                match = re.match(r'\d+:\s+(\w+):', line)
                if match:
                    name = match.group(1)
                    if name != "lo":
                        interfaces.append({
                            "name": name,
                            "description": name,
                            "is_up": "UP" in line
                        })
        except Exception:
            pass
    
    return interfaces or [{"name": "eth0", "description": "Default"}]


def get_current_network_info() -> Dict[str, Any]:
    """Get current network configuration information."""
    info = {
        "ip_address": "",
        "netmask": "",
        "gateway": "",
        "dns_servers": [],
        "interfaces": []
    }
    
    system = sys.platform
    
    try:
        if system == "win32":
            info = _get_network_info_windows()
        elif system == "darwin":
            info = _get_network_info_macos()
        else:
            info = _get_network_info_linux()
    except Exception:
        pass
    
    return info


def _get_network_info_windows() -> Dict[str, Any]:
    """Get network info on Windows."""
    info = {"ip_address": "", "netmask": "", "gateway": "", "dns_servers": [], "interfaces": []}
    
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=10
        )
        
        # Parse output
        current_adapter = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if "adapter" in line.lower() and ":" in line:
                current_adapter = line.replace(":", "").strip()
            elif current_adapter:
                if "IPv4 Address" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info["ip_address"] = match.group(1)
                elif "Subnet Mask" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info["netmask"] = match.group(1)
                elif "Default Gateway" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info["gateway"] = match.group(1)
                elif "DNS Servers" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info["dns_servers"].append(match.group(1))
    except Exception:
        pass
    
    return info


def _get_network_info_macos() -> Dict[str, Any]:
    """Get network info on macOS."""
    info = {"ip_address": "", "netmask": "", "gateway": "", "dns_servers": [], "interfaces": []}
    
    try:
        # Get IP and netmask
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=10
        )
        
        for line in result.stdout.split('\n'):
            if "inet " in line and "127.0.0.1" not in line:
                parts = line.strip().split()
                for i, part in enumerate(parts):
                    if part == "inet" and i + 1 < len(parts):
                        info["ip_address"] = parts[i + 1]
                    elif part == "netmask" and i + 1 < len(parts):
                        # Convert hex netmask to dotted decimal
                        try:
                            hex_mask = parts[i + 1]
                            if hex_mask.startswith("0x"):
                                mask_int = int(hex_mask, 16)
                                info["netmask"] = ".".join(str((mask_int >> (8 * i)) & 0xff) for i in range(3, -1, -1))
                        except Exception:
                            pass
                break
        
        # Get gateway
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\n'):
            if "gateway:" in line:
                info["gateway"] = line.split(":")[1].strip()
                break
        
        # Get DNS
        result = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\n'):
            if "nameserver" in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match and match.group(1) not in info["dns_servers"]:
                    info["dns_servers"].append(match.group(1))
    except Exception:
        pass
    
    return info


def _get_network_info_linux() -> Dict[str, Any]:
    """Get network info on Linux."""
    info = {"ip_address": "", "netmask": "", "gateway": "", "dns_servers": [], "interfaces": []}
    
    try:
        # Get IP using ip command
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True, timeout=10
        )
        
        for line in result.stdout.split('\n'):
            if "inet " in line and "127.0.0.1" not in line:
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    info["ip_address"] = match.group(1)
                    # Convert CIDR to netmask
                    cidr = int(match.group(2))
                    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
                    info["netmask"] = ".".join(str((mask >> (8 * i)) & 0xff) for i in range(3, -1, -1))
                break
        
        # Get gateway
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10
        )
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            info["gateway"] = match.group(1)
        
        # Get DNS from /etc/resolv.conf
        if os.path.exists("/etc/resolv.conf"):
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1:
                            info["dns_servers"].append(parts[1])
    except Exception:
        pass
    
    return info


def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
