"""
Multipart form data parsing for Multi-Frames.
"""

import re
from typing import Dict, Any, Tuple
from urllib.parse import parse_qs, unquote_plus


def parse_multipart(content_type: str, body: bytes) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    Parse multipart/form-data request body.
    Returns (fields, files) where:
        - fields: dict of form field name -> value
        - files: dict of file field name -> {filename, content_type, data}
    """
    fields = {}
    files = {}
    
    # Handle URL-encoded forms
    if "application/x-www-form-urlencoded" in content_type:
        try:
            decoded = body.decode("utf-8")
            parsed = parse_qs(decoded, keep_blank_values=True)
            for key, values in parsed.items():
                fields[key] = values[0] if values else ""
        except Exception:
            pass
        return fields, files
    
    # Handle multipart forms
    if "multipart/form-data" not in content_type:
        return fields, files
    
    # Extract boundary
    boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
    if not boundary_match:
        return fields, files
    
    boundary = boundary_match.group(1).strip('"')
    
    # Split by boundary
    try:
        parts = body.split(f"--{boundary}".encode())
    except Exception:
        return fields, files
    
    for part in parts:
        if not part or part == b"--" or part == b"--\r\n":
            continue
        
        # Split headers from content
        try:
            if b"\r\n\r\n" in part:
                headers_raw, content = part.split(b"\r\n\r\n", 1)
            elif b"\n\n" in part:
                headers_raw, content = part.split(b"\n\n", 1)
            else:
                continue
            
            headers_str = headers_raw.decode("utf-8", errors="ignore")
            
            # Remove trailing boundary markers
            if content.endswith(b"\r\n"):
                content = content[:-2]
            elif content.endswith(b"\n"):
                content = content[:-1]
            
        except Exception:
            continue
        
        # Parse Content-Disposition header
        name_match = re.search(r'name="([^"]*)"', headers_str)
        if not name_match:
            name_match = re.search(r"name='([^']*)'", headers_str)
        if not name_match:
            continue
        
        field_name = name_match.group(1)
        
        # Check if this is a file upload
        filename_match = re.search(r'filename="([^"]*)"', headers_str)
        if not filename_match:
            filename_match = re.search(r"filename='([^']*)'", headers_str)
        
        if filename_match:
            filename = filename_match.group(1)
            
            # Get content type
            ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', headers_str, re.IGNORECASE)
            file_content_type = ct_match.group(1).strip() if ct_match else "application/octet-stream"
            
            files[field_name] = {
                "filename": filename,
                "content_type": file_content_type,
                "data": content
            }
        else:
            # Regular form field
            try:
                fields[field_name] = content.decode("utf-8")
            except Exception:
                fields[field_name] = content.decode("latin-1", errors="ignore")
    
    return fields, files


def parse_json_body(body: bytes) -> Dict[str, Any]:
    """Parse JSON request body."""
    import json
    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
