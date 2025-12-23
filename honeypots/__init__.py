"""
Honeypot modules for security monitoring
"""

from .web_honeypot import WebHoneypot
from .ssh_honeypot import SSHHoneypot

__all__ = ['WebHoneypot', 'SSHHoneypot']
