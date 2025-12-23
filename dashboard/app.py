"""
Flask Dashboard for Honeypot Security System
Real-time attack monitoring and visualization
"""

import os
import sys
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Dashboard:
    """Flask-based dashboard for honeypot monitoring"""

    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.host = host
        self.port = port

        # Create Flask app
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        static_dir = os.path.join(os.path.dirname(__file__), 'static')

        self.app = Flask(__name__,
                         template_folder=template_dir,
                         static_folder=static_dir)

        self.app.secret_key = os.urandom(24)

        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('index.html')

        @self.app.route('/attacks')
        def attacks():
            """Attack details page"""
            return render_template('attacks.html')

        @self.app.route('/api/stats')
        def api_stats():
            """API endpoint for dashboard statistics"""
            from core.database import Database
            db = Database()

            stats = db.get_dashboard_stats()

            # Format for JSON
            return jsonify({
                'total_attacks': stats['total_attacks'],
                'unique_ips': stats['unique_ips'],
                'blocked_ips': stats['blocked_ips'],
                'high_threats': stats['high_threats'],
                'today_attacks': stats['today_attacks'],
                'top_passwords': [{'password': p[0], 'count': p[1]} for p in stats['top_passwords']],
                'top_usernames': [{'username': u[0], 'count': u[1]} for u in stats['top_usernames']],
                'top_countries': [{'country': c[0], 'count': c[1]} for c in stats['top_countries']],
                'attacks_by_source': stats['attacks_by_source'],
                'threat_distribution': stats['threat_distribution'],
                'hourly_stats': stats['hourly_stats'],
            })

        @self.app.route('/api/attacks')
        def api_attacks():
            """API endpoint for recent attacks"""
            from core.database import Database
            db = Database()

            limit = request.args.get('limit', 50, type=int)
            attacks = db.get_recent_attacks(limit=limit)

            return jsonify({
                'attacks': attacks,
                'count': len(attacks)
            })

        @self.app.route('/api/attacks/<ip_address>')
        def api_attacks_by_ip(ip_address):
            """API endpoint for attacks from specific IP"""
            from core.database import Database
            db = Database()

            attacks = db.get_attacks_by_ip(ip_address)
            ip_stats = db.get_ip_stats(ip_address)

            return jsonify({
                'ip_address': ip_address,
                'stats': ip_stats,
                'attacks': attacks
            })

        @self.app.route('/api/blocked')
        def api_blocked():
            """API endpoint for blocked IPs"""
            from core.database import Database
            db = Database()

            blocked = db.get_blocked_ips()

            return jsonify({
                'blocked_ips': blocked,
                'count': len(blocked)
            })

        @self.app.route('/api/block/<ip_address>', methods=['POST'])
        def api_block_ip(ip_address):
            """API endpoint to manually block an IP"""
            from response.auto_blocker import AutoBlocker
            blocker = AutoBlocker()

            success, message = blocker.block_ip(
                ip_address=ip_address,
                reason="Manual block via dashboard",
                threat_level="HIGH"
            )

            return jsonify({
                'success': success,
                'message': message
            })

        @self.app.route('/api/unblock/<ip_address>', methods=['POST'])
        def api_unblock_ip(ip_address):
            """API endpoint to unblock an IP"""
            from response.auto_blocker import AutoBlocker
            blocker = AutoBlocker()

            success, message = blocker.unblock_ip(ip_address)

            return jsonify({
                'success': success,
                'message': message
            })

    def start(self, threaded: bool = True):
        """Start the dashboard server"""
        from threading import Thread

        if threaded:
            thread = Thread(target=self._run_server, daemon=True)
            thread.start()
            print(f"[Dashboard] Started on http://{self.host}:{self.port}")
        else:
            self._run_server()

    def _run_server(self):
        """Run Flask server"""
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


if __name__ == '__main__':
    dashboard = Dashboard()
    dashboard.start(threaded=False)
