"""
mDNS/Bonjour service for Multi-Frames.
Allows accessing the server via hostname.local addresses.
"""

import socket
from typing import Optional

# Global mDNS service instance
_mdns_service: Optional['MDNSService'] = None


class MDNSService:
    """mDNS service wrapper using zeroconf library."""
    
    def __init__(self):
        self.zeroconf = None
        self.service_info = None
        self.running = False
        self.hostname = ""
        self.port = 8080
    
    def start(self, hostname: str, service_name: str, port: int) -> bool:
        """Start the mDNS service."""
        try:
            from zeroconf import Zeroconf, ServiceInfo
        except ImportError:
            return False
        
        try:
            self.hostname = hostname
            self.port = port
            
            # Get local IP
            local_ip = self._get_local_ip()
            
            # Create service info
            self.service_info = ServiceInfo(
                "_http._tcp.local.",
                f"{service_name}._http._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=port,
                properties={
                    'path': '/',
                    'version': '1.1.0'
                },
                server=f"{hostname}.local."
            )
            
            # Start zeroconf
            self.zeroconf = Zeroconf()
            self.zeroconf.register_service(self.service_info)
            self.running = True
            
            return True
            
        except Exception as e:
            self.running = False
            return False
    
    def stop(self) -> None:
        """Stop the mDNS service."""
        if self.zeroconf and self.service_info:
            try:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()
            except Exception:
                pass
        
        self.zeroconf = None
        self.service_info = None
        self.running = False
    
    def restart(self, hostname: str, service_name: str, port: int) -> bool:
        """Restart the mDNS service with new settings."""
        self.stop()
        return self.start(hostname, service_name, port)
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    @property
    def is_running(self) -> bool:
        """Check if service is running."""
        return self.running
    
    @property
    def url(self) -> str:
        """Get the .local URL."""
        if self.hostname and self.running:
            return f"http://{self.hostname}.local:{self.port}"
        return ""


def is_zeroconf_available() -> bool:
    """Check if zeroconf library is available."""
    try:
        import zeroconf
        return True
    except ImportError:
        return False


def start_mdns_service(config: dict, port: int) -> Optional[MDNSService]:
    """Start the mDNS service based on config."""
    global _mdns_service
    
    mdns_config = config.get("mdns", {})
    if not mdns_config.get("enabled", False):
        return None
    
    if not is_zeroconf_available():
        return None
    
    hostname = mdns_config.get("hostname", "multi-frames")
    service_name = mdns_config.get("service_name", "Multi-Frames Dashboard")
    
    _mdns_service = MDNSService()
    if _mdns_service.start(hostname, service_name, port):
        return _mdns_service
    
    return None


def stop_mdns_service() -> None:
    """Stop the global mDNS service."""
    global _mdns_service
    
    if _mdns_service:
        _mdns_service.stop()
        _mdns_service = None


def get_mdns_service() -> Optional[MDNSService]:
    """Get the current mDNS service instance."""
    return _mdns_service
