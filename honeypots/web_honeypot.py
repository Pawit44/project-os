"""
Web Honeypot - Fake Login Page with SQL Injection Trap
Simulates a router/admin login page to capture credentials and SQL injection attempts
Enhanced with fake dashboard to keep attackers engaged
"""

import os
import sys
import re
import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, request, render_template, render_template_string, redirect, url_for, session, make_response
from threading import Thread
from typing import Callable, Optional, Dict, List, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# SQL Injection patterns to detect
SQL_INJECTION_PATTERNS = [
    r"['\"]\s*OR\s*['\"]*\d+['\"]*\s*=\s*['\"]*\d+",  # ' OR '1'='1
    r"['\"]\s*OR\s*['\"]*\w+['\"]*\s*=\s*['\"]*\w+",  # ' OR 'a'='a
    r"UNION\s+(ALL\s+)?SELECT",  # UNION SELECT
    r"--\s*$",  # SQL comment
    r";\s*DROP\s+",  # DROP TABLE
    r";\s*DELETE\s+",  # DELETE FROM
    r";\s*UPDATE\s+",  # UPDATE SET
    r";\s*INSERT\s+",  # INSERT INTO
    r"'\s*;\s*",  # '; injection
    r"1\s*=\s*1",  # 1=1
    r"'\s*OR\s+1\s*=\s*1",  # ' OR 1=1
    r"admin'\s*--",  # admin'--
    r"'\s*OR\s*''='",  # ' OR ''='
    r"SLEEP\s*\(",  # Time-based blind SQLi
    r"BENCHMARK\s*\(",  # MySQL benchmark
    r"WAITFOR\s+DELAY",  # MSSQL delay
]


def detect_sql_injection(input_string: str) -> Tuple[bool, str]:
    """
    Detect SQL injection attempts in input
    Returns (is_sqli, matched_pattern)
    """
    if not input_string:
        return False, ""

    input_upper = input_string.upper()

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_upper, re.IGNORECASE):
            return True, pattern

    # Additional checks for common SQLi strings
    sqli_strings = ["'--", "' --", "1'='1", "1=1", "or 1=1", "' or '", "admin'--"]
    for sqli in sqli_strings:
        if sqli.lower() in input_string.lower():
            return True, sqli

    return False, ""


class WebHoneypot:
    """Flask-based web honeypot with fake login page and SQL injection trap"""

    # Fake data to lure attackers
    FAKE_USERS = [
        {'id': 1, 'username': 'admin', 'email': 'admin@router.local', 'role': 'Administrator', 'password_hash': '$2b$12$LQv3c1yqBw...', 'last_login': None},
        {'id': 2, 'username': 'operator', 'email': 'operator@company.com', 'role': 'Operator', 'password_hash': '$2b$12$Kj8dF9mL2...', 'last_login': None},
        {'id': 3, 'username': 'guest', 'email': 'guest@company.com', 'role': 'Guest', 'password_hash': '$2b$12$Nm7sD3kL9...', 'last_login': None},
        {'id': 4, 'username': 'backup_admin', 'email': 'backup@company.com', 'role': 'Backup Admin', 'password_hash': '$2b$12$Pq4rT7yU1...', 'last_login': None},
        {'id': 5, 'username': 'monitor', 'email': 'monitor@company.com', 'role': 'Monitor', 'password_hash': '$2b$12$Wx9zV5bN8...', 'last_login': None},
    ]

    FAKE_NETWORK_DEVICES = [
        {'ip': '192.168.1.1', 'mac': '00:1A:2B:3C:4D:5E', 'hostname': 'Gateway', 'type': 'Router', 'status': 'Online'},
        {'ip': '192.168.1.10', 'mac': '00:1A:2B:3C:4D:5F', 'hostname': 'FileServer', 'type': 'Server', 'status': 'Online'},
        {'ip': '192.168.1.20', 'mac': '00:1A:2B:3C:4D:60', 'hostname': 'WebServer', 'type': 'Server', 'status': 'Online'},
        {'ip': '192.168.1.30', 'mac': '00:1A:2B:3C:4D:61', 'hostname': 'Database', 'type': 'Server', 'status': 'Online'},
        {'ip': '192.168.1.100', 'mac': '00:1A:2B:3C:4D:62', 'hostname': 'Workstation-1', 'type': 'PC', 'status': 'Online'},
        {'ip': '192.168.1.101', 'mac': '00:1A:2B:3C:4D:63', 'hostname': 'Workstation-2', 'type': 'PC', 'status': 'Offline'},
        {'ip': '192.168.1.150', 'mac': '00:1A:2B:3C:4D:64', 'hostname': 'IP-Camera-1', 'type': 'IoT', 'status': 'Online'},
        {'ip': '192.168.1.151', 'mac': '00:1A:2B:3C:4D:65', 'hostname': 'IP-Camera-2', 'type': 'IoT', 'status': 'Online'},
    ]

    FAKE_CREDENTIALS = [
        {'service': 'MySQL Database', 'username': 'root', 'password': 'Mysql_R00t_2024!', 'host': '192.168.1.30'},
        {'service': 'FTP Server', 'username': 'ftpadmin', 'password': 'Ftp@dmin123', 'host': '192.168.1.10'},
        {'service': 'SSH Gateway', 'username': 'admin', 'password': 'G@teway_SSH_2024', 'host': '192.168.1.1'},
        {'service': 'Web Admin', 'username': 'webmaster', 'password': 'W3bM@ster!', 'host': '192.168.1.20'},
        {'service': 'Backup Server', 'username': 'backup', 'password': 'B@ckup_Secure_99', 'host': '192.168.1.10'},
    ]

    FAKE_LOGS = []

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

        # Generate fake logs
        self._generate_fake_logs()

        # Create Flask app
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.app = Flask(__name__, template_folder=template_dir)
        self.app.secret_key = os.urandom(24)

        # Setup routes
        self._setup_routes()

        # Thread for running server
        self._thread: Optional[Thread] = None
        self._running = False

    def _generate_fake_logs(self):
        """Generate fake system logs"""
        now = datetime.now()
        log_messages = [
            ('INFO', 'System started successfully'),
            ('INFO', 'Network interface eth0 up'),
            ('INFO', 'DHCP server started'),
            ('WARNING', 'High CPU usage detected (85%)'),
            ('INFO', 'User admin logged in from 192.168.1.100'),
            ('INFO', 'Firmware update available: v3.2.2'),
            ('WARNING', 'Failed login attempt from 10.0.0.55'),
            ('INFO', 'Backup completed successfully'),
            ('ERROR', 'Connection to NTP server failed'),
            ('INFO', 'User operator logged in from 192.168.1.101'),
            ('WARNING', 'Disk usage at 78%'),
            ('INFO', 'Scheduled reboot cancelled'),
            ('INFO', 'SSL certificate renewed'),
            ('WARNING', 'Port scan detected from 203.0.113.50'),
            ('INFO', 'Firewall rules updated'),
        ]

        for i, (level, message) in enumerate(log_messages):
            log_time = now - timedelta(hours=i*2, minutes=random.randint(0, 59))
            self.FAKE_LOGS.append({
                'timestamp': log_time.strftime('%Y-%m-%d %H:%M:%S'),
                'level': level,
                'message': message
            })

    def _setup_routes(self) -> None:
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            if session.get('logged_in'):
                return redirect(url_for('dashboard'))
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

                # Check for SQL injection
                sqli_in_user, pattern1 = detect_sql_injection(username)
                sqli_in_pass, pattern2 = detect_sql_injection(password)

                is_sqli = sqli_in_user or sqli_in_pass
                sqli_pattern = pattern1 or pattern2

                # Log the attack
                self._handle_login_attempt(
                    ip_address=ip_address,
                    username=username,
                    password=password,
                    user_agent=user_agent,
                    path=request.path,
                    method=request.method,
                    is_sqli=is_sqli,
                    sqli_pattern=sqli_pattern
                )

                # If SQL injection detected, "let them in" (trap!)
                if is_sqli:
                    session['logged_in'] = True
                    session['username'] = 'admin'  # They think they're admin
                    session['sqli_victim'] = True
                    session['login_time'] = datetime.now().isoformat()
                    print(f"[WEB] SQL Injection detected from {ip_address}: {sqli_pattern}")
                    return redirect(url_for('dashboard'))

                # Normal login always fails
                error = 'Invalid username or password. Please try again.'

            return render_template('login.html', error=error)

        @self.app.route('/logout')
        def logout():
            ip_address = self._get_client_ip()
            if self.on_attack:
                self.on_attack(
                    source='WEB',
                    ip_address=ip_address,
                    extra_data={'type': 'logout', 'path': '/logout'}
                )
            session.clear()
            return redirect(url_for('login'))

        @self.app.route('/dashboard')
        def dashboard():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/dashboard')

            return render_template('dashboard.html',
                                 username=session.get('username', 'admin'),
                                 devices=self.FAKE_NETWORK_DEVICES,
                                 logs=self.FAKE_LOGS[:5])

        @self.app.route('/users')
        def users():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/users')

            return render_template('users.html',
                                 username=session.get('username', 'admin'),
                                 users=self.FAKE_USERS)

        @self.app.route('/network')
        def network():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/network')

            return render_template('network.html',
                                 username=session.get('username', 'admin'),
                                 devices=self.FAKE_NETWORK_DEVICES)

        @self.app.route('/settings')
        def settings():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/settings')

            return render_template('settings.html',
                                 username=session.get('username', 'admin'),
                                 credentials=self.FAKE_CREDENTIALS)

        @self.app.route('/logs')
        def logs():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/logs')

            return render_template('logs.html',
                                 username=session.get('username', 'admin'),
                                 logs=self.FAKE_LOGS)

        @self.app.route('/backup')
        def backup():
            if not session.get('logged_in'):
                return redirect(url_for('login'))

            ip_address = self._get_client_ip()
            self._log_page_access(ip_address, '/backup')

            return render_template('backup.html',
                                 username=session.get('username', 'admin'))

        @self.app.route('/api/export', methods=['POST'])
        def api_export():
            """Fake export API - logs what attacker tries to export"""
            if not session.get('logged_in'):
                return {'error': 'Unauthorized'}, 401

            ip_address = self._get_client_ip()
            export_type = request.form.get('type', 'unknown')

            if self.on_attack:
                self.on_attack(
                    source='WEB',
                    ip_address=ip_address,
                    extra_data={
                        'type': 'data_export_attempt',
                        'export_type': export_type,
                        'path': '/api/export'
                    }
                )

            # Return fake "success" but with delay
            import time
            time.sleep(2)  # Make them wait
            return {'status': 'success', 'message': 'Export queued. Download link will be sent to admin email.'}

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

    def _log_page_access(self, ip_address: str, path: str) -> None:
        """Log when attacker accesses a page"""
        if self.on_attack:
            self.on_attack(
                source='WEB',
                ip_address=ip_address,
                extra_data={
                    'type': 'page_access',
                    'path': path,
                    'session_user': session.get('username'),
                    'is_sqli_session': session.get('sqli_victim', False)
                }
            )

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
                              method: str,
                              is_sqli: bool = False,
                              sqli_pattern: str = None) -> None:
        """Handle captured login attempt"""
        if is_sqli:
            print(f"[WEB] SQL INJECTION from {ip_address}: username='{username}' password='{password}' pattern='{sqli_pattern}'")
        else:
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
                    'type': 'sql_injection' if is_sqli else 'login',
                    'sqli_detected': is_sqli,
                    'sqli_pattern': sqli_pattern
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
