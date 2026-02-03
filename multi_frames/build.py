#!/usr/bin/env python3
"""
Build script for Multi-Frames.
Combines modular source files into a single distributable Python file.

Usage:
    python build.py              # Build to dist/multi_frames.py
    python build.py --output my_server.py
"""

import os
import sys
import argparse
import re
from datetime import datetime

# Modules to combine in order
MODULES = [
    # Core modules
    ('multi_frames/__init__.py', 'VERSION INFO'),
    ('multi_frames/config.py', 'CONFIGURATION'),
    ('multi_frames/auth.py', 'AUTHENTICATION'),
    ('multi_frames/logger.py', 'LOGGING'),
    
    # Utils
    ('multi_frames/utils/html.py', 'HTML UTILITIES'),
    ('multi_frames/utils/validation.py', 'VALIDATION'),
    ('multi_frames/utils/multipart.py', 'MULTIPART PARSING'),
    
    # Network
    ('multi_frames/network/interfaces.py', 'NETWORK INTERFACES'),
    ('multi_frames/network/mdns.py', 'MDNS SERVICE'),
    ('multi_frames/network/commands.py', 'NETWORK COMMANDS'),
    
    # CLI
    ('multi_frames/cli.py', 'CLI'),
]

HEADER = '''#!/usr/bin/env python3
"""
Multi-Frames v{version} - Dashboard & iFrame Display Server
Designed and Developed by Marco Longoria, LTS, Inc.

A lightweight, zero-dependency Python web server for displaying
configurable iFrames and dashboard widgets.

Built: {build_date}

For documentation, visit: https://github.com/lts-inc/multi-frames
"""

'''

def read_module(filepath):
    """Read a module file and extract its content."""
    if not os.path.exists(filepath):
        print(f"Warning: Module not found: {filepath}")
        return ""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Remove module docstring (first triple-quoted string)
    content = re.sub(r'^"""[\s\S]*?"""\n*', '', content, count=1)
    
    # Remove relative imports (will be handled differently in combined file)
    content = re.sub(r'from \.[a-z_]+ import .*\n', '', content)
    content = re.sub(r'from \.\. import .*\n', '', content)
    
    return content.strip()


def build(output_path='dist/multi_frames.py', version='1.1.0'):
    """Build the combined single-file distribution."""
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    
    # Start with header
    output = HEADER.format(
        version=version,
        build_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    # Add standard library imports
    output += '''
# ==============================================================================
# IMPORTS
# ==============================================================================

import os
import sys
import json
import time
import socket
import secrets
import hashlib
import html
import re
import subprocess
import http.server
import socketserver
import argparse
from collections import deque
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote_plus
from typing import Dict, List, Any, Optional, Tuple

'''
    
    # Process each module
    for filepath, section_name in MODULES:
        content = read_module(filepath)
        if content:
            output += f'''
# ==============================================================================
# {section_name}
# ==============================================================================

{content}

'''
    
    # Write output
    with open(output_path, 'w') as f:
        f.write(output)
    
    print(f"Built: {output_path}")
    print(f"Size: {os.path.getsize(output_path):,} bytes")


def main():
    parser = argparse.ArgumentParser(description='Build Multi-Frames distribution')
    parser.add_argument('--output', '-o', default='dist/multi_frames.py',
                        help='Output file path')
    parser.add_argument('--version', '-v', default='1.1.15',
                        help='Version string')
    
    args = parser.parse_args()
    build(args.output, args.version)


if __name__ == '__main__':
    main()
