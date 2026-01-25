"""
Server logging for Multi-Frames.
Provides in-memory logging with configurable retention.
"""

import time
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional


class ServerLogger:
    """In-memory server logger with log level support."""
    
    LEVELS = {
        "DEBUG": 10,
        "INFO": 20,
        "WARNING": 30,
        "ERROR": 40,
        "CRITICAL": 50
    }
    
    def __init__(self, max_entries: int = 500, min_level: str = "INFO"):
        self.logs: deque = deque(maxlen=max_entries)
        self.min_level = self.LEVELS.get(min_level.upper(), 20)
        self.request_count = 0
        self.error_count = 0
        self.start_time = time.time()
    
    def _log(self, level: str, message: str, **kwargs) -> None:
        """Internal logging method."""
        level_num = self.LEVELS.get(level.upper(), 20)
        if level_num < self.min_level:
            return
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level.upper(),
            "message": message,
            **kwargs
        }
        self.logs.append(entry)
        
        if level.upper() in ("ERROR", "CRITICAL"):
            self.error_count += 1
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self._log("DEBUG", message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self._log("INFO", message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self._log("WARNING", message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self._log("ERROR", message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self._log("CRITICAL", message, **kwargs)
    
    def log_request(self, method: str, path: str, status: int, 
                    client_ip: str = "", duration_ms: float = 0) -> None:
        """Log an HTTP request."""
        self.request_count += 1
        self.info(
            f"{method} {path} - {status}",
            method=method,
            path=path,
            status=status,
            client_ip=client_ip,
            duration_ms=round(duration_ms, 2)
        )
    
    def get_logs(self, level: Optional[str] = None, 
                 limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent logs, optionally filtered by level."""
        logs = list(self.logs)
        
        if level:
            level_num = self.LEVELS.get(level.upper(), 0)
            logs = [l for l in logs if self.LEVELS.get(l["level"], 0) >= level_num]
        
        return logs[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        uptime = time.time() - self.start_time
        return {
            "total_requests": self.request_count,
            "total_errors": self.error_count,
            "uptime_seconds": int(uptime),
            "uptime_formatted": self._format_uptime(uptime),
            "log_count": len(self.logs),
            "requests_per_minute": round(self.request_count / (uptime / 60), 2) if uptime > 0 else 0
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime as human-readable string."""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0 or days > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        
        return " ".join(parts)
    
    def clear(self) -> None:
        """Clear all logs."""
        self.logs.clear()


# Global server logger instance
server_logger = ServerLogger()
