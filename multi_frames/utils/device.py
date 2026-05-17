"""
Device profile detection for Multi-Frames adaptive UI layer.

Mirrors the helper embedded in the single-file distribution
(multi_frames.py). When the build pipeline matures, this module will be
the canonical source and build.py will inline it.
"""

import threading
from typing import Optional, Tuple

VALID_DEVICE_PROFILES = ("phone", "tablet", "kiosk", "desktop")

_request_ctx = threading.local()


def set_request_context(headers, path: str) -> None:
    """Stash per-request headers/path on a thread-local so renderers can
    detect the device profile without threading the request handler through
    every render call site."""
    _request_ctx.headers = headers
    _request_ctx.path = path


def get_request_context() -> Tuple[Optional[object], str]:
    return (
        getattr(_request_ctx, "headers", None),
        getattr(_request_ctx, "path", ""),
    )


def detect_device_profile(headers, path: str = "", config=None) -> str:
    """Classify the requesting device into one of: phone, tablet, kiosk, desktop.

    Priority order:
      1. ?kiosk=1 query string → kiosk
      2. mf_device cookie override (set by client capability probe)
      3. Optional kiosk_hosts list in config (hostname pinning)
      4. Sec-CH-UA-Mobile client hint → phone
      5. User-Agent string parsing
      6. Default: desktop
    """
    if "kiosk=1" in (path or ""):
        return "kiosk"

    cookie_header = ""
    try:
        cookie_header = headers.get("Cookie", "") if headers else ""
    except Exception:
        cookie_header = ""
    if cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("mf_device="):
                val = part.split("=", 1)[1].strip()
                if val in VALID_DEVICE_PROFILES:
                    return val

    if config is not None:
        try:
            host = (headers.get("Host", "") or "").split(":")[0].lower() if headers else ""
            kiosk_hosts = [h.lower() for h in config.get("settings", {}).get("kiosk_hosts", [])]
            if host and host in kiosk_hosts:
                return "kiosk"
        except Exception:
            pass

    try:
        ch_mobile = headers.get("Sec-CH-UA-Mobile", "") if headers else ""
        if ch_mobile.strip() == "?1":
            return "phone"
    except Exception:
        pass

    ua = ""
    try:
        ua = headers.get("User-Agent", "") if headers else ""
    except Exception:
        ua = ""
    if not ua:
        return "desktop"

    ua_lower = ua.lower()
    if "ipad" in ua_lower or "tablet" in ua_lower:
        return "tablet"
    if "android" in ua_lower and "mobile" not in ua_lower:
        return "tablet"
    if "iphone" in ua_lower or "ipod" in ua_lower:
        return "phone"
    if "android" in ua_lower and "mobile" in ua_lower:
        return "phone"
    if "mobile" in ua_lower and ("webkit" in ua_lower or "firefox" in ua_lower):
        return "phone"
    if "raspbian" in ua_lower or "raspberry" in ua_lower:
        return "kiosk"
    return "desktop"
