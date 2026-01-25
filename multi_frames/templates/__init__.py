"""
HTML templates for Multi-Frames.
"""

from .base import render_page, generate_dynamic_styles
from .login import render_login_page, render_forgot_password_page
from .dashboard import render_main_page
from .help import render_help_page
from .widgets import render_widget

__all__ = [
    'render_page',
    'generate_dynamic_styles',
    'render_login_page',
    'render_forgot_password_page',
    'render_main_page',
    'render_help_page',
    'render_widget'
]
