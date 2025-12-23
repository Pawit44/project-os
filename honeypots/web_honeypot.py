"""
Web Honeypot - Fake Login Page
Simulates a router/admin login page to capture credentials
"""

import os
import sys
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for
from threading import Thread
from typing import Callable, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class WebHoneypot:
    """Flask-based web honeypot with fake login page"""

    def __init__(self,
                 host: str = '0.0.0.0',
                 port: int = 8080,
                 on_attack: Callable = None):
        """
        Initialize Web Honeypot

        Args:
            host: Host to bind to
            port: Port to listen on
            on_attack: Callback function when attack is detected
        """
        self.host = host
        self.port = port
        self.on_attack = on_attack

        # Create Flask app
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.app = Flask(__name__, template_folder=template_dir)
        self.app.secret_key = os.urandom(24)

        # Setup routes
        self._setup_routes()

        # Thread for running server
        self._thread: Optional[Thread] = None
        self._running = False

    def _setup_routes(self) -> None:
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            return redirect(url_for('login'))

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            error = None
            if request.method == 'POST':
                # Capture credentials
                username = request.form.get('username', '')
                password = request.form.get('password', '')

                # Get client info
                ip_address = self._get_client_ip()
                user_agent = request.headers.get('User-Agent', '')

                # Log the attack
                self._handle_login_attempt(
                    ip_address=ip_address,
                    username=username,
                    password=password,
                    user_agent=user_agent,
                    path=request.path,
                    method=request.method
                )

                # Always show error (it's a honeypot)
                error = 'Invalid username or password. Please try again.'

            return render_template('login.html', error=error)

        @self.app.route('/admin')
        @self.app.route('/administrator')
        @self.app.route('/wp-admin')
        @self.app.route('/wp-login.php')
        @self.app.route('/phpmyadmin')
        def common_paths():
            """Trap common admin paths"""
            ip_address = self._get_client_ip()
            user_agent = request.headers.get('User-Agent', '')

            self._handle_login_attempt(
                ip_address=ip_address,
                username=None,
                password=None,
                user_agent=user_agent,
                path=request.path,
                method=request.method
            )

            return redirect(url_for('login'))

        @self.app.errorhandler(404)
        def not_found(e):
            """Log 404 attempts - might be scanning"""
            ip_address = self._get_client_ip()
            user_agent = request.headers.get('User-Agent', '')

            # Log as scan attempt
            if self.on_attack:
                self.on_attack(
                    source='WEB',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    extra_data={
                        'path': request.path,
                        'method': request.method,
                        'type': 'scan'
                    }
                )

            return redirect(url_for('login'))

    def _get_client_ip(self) -> str:
        """Get real client IP, handling proxies"""
        # Check for forwarded IP
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr

    def _handle_login_attempt(self,
                              ip_address: str,
                              username: str,
                              password: str,
                              user_agent: str,
                              path: str,
                              method: str) -> None:
        """Handle captured login attempt"""
        print(f"[WEB] Login attempt from {ip_address}: {username}:{password}")

        if self.on_attack:
            self.on_attack(
                source='WEB',
                ip_address=ip_address,
                username=username,
                password=password,
                user_agent=user_agent,
                extra_data={
                    'path': path,
                    'method': method,
                    'type': 'login'
                }
            )

    def start(self, threaded: bool = True) -> None:
        """Start the web honeypot server"""
        self._running = True

        if threaded:
            self._thread = Thread(target=self._run_server, daemon=True)
            self._thread.start()
            print(f"[WEB] Honeypot started on http://{self.host}:{self.port}")
        else:
            self._run_server()

    def _run_server(self) -> None:
        """Run Flask server"""
        # Disable Flask debug output
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        self.app.run(
            host=self.host,
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True
        )

    def stop(self) -> None:
        """Stop the web honeypot server"""
        self._running = False
        print("[WEB] Honeypot stopped")


if __name__ == '__main__':
    # Test run
    def test_callback(**kwargs):
        print(f"Attack detected: {kwargs}")

    honeypot = WebHoneypot(port=8080, on_attack=test_callback)
    honeypot.start(threaded=False)
