"""
Flask Dashboard for Honeypot Security System
Real-time attack monitoring and visualization
"""

import os
import sys
import csv
import io
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response

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

        @self.app.route('/commands')
        def commands():
            """SSH commands page"""
            return render_template('commands.html')

        @self.app.route('/credentials')
        def credentials():
            """Credentials analysis page"""
            return render_template('credentials.html')

        @self.app.route('/ips')
        def ips():
            """IP analysis page"""
            return render_template('ips.html')

        @self.app.route('/sessions')
        def sessions():
            """Web sessions page - track attacker behavior"""
            return render_template('sessions.html')

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
            """API endpoint for recent attacks with pagination"""
            from core.database import Database
            db = Database()

            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)
            attacks = db.get_recent_attacks(limit=limit, offset=offset)
            total = db.get_total_attacks_count()

            return jsonify({
                'attacks': attacks,
                'count': len(attacks),
                'total': total,
                'offset': offset,
                'has_more': offset + len(attacks) < total
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

        @self.app.route('/api/commands')
        def api_commands():
            """API endpoint for SSH commands"""
            from core.database import Database
            db = Database()

            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)

            with db.cursor() as cur:
                # Get commands with filters
                cur.execute('''
                    SELECT id, timestamp, ip_address, country, command, threat_score, threat_level
                    FROM attacks
                    WHERE source = 'SSH' AND command IS NOT NULL AND command != ''
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                commands = [dict(row) for row in cur.fetchall()]

                # Get total count
                cur.execute('''
                    SELECT COUNT(*) FROM attacks
                    WHERE source = 'SSH' AND command IS NOT NULL AND command != ''
                ''')
                total = cur.fetchone()[0]

                # Get top commands
                cur.execute('''
                    SELECT command, COUNT(*) as count
                    FROM attacks
                    WHERE source = 'SSH' AND command IS NOT NULL AND command != ''
                    GROUP BY command
                    ORDER BY count DESC
                    LIMIT 20
                ''')
                top_commands = [{'command': row['command'], 'count': row['count']} for row in cur.fetchall()]

            return jsonify({
                'commands': commands,
                'total': total,
                'top_commands': top_commands
            })

        @self.app.route('/api/credentials')
        def api_credentials():
            """API endpoint for credential analysis"""
            from core.database import Database
            db = Database()

            limit = request.args.get('limit', 100, type=int)

            with db.cursor() as cur:
                # Get username/password combinations
                cur.execute('''
                    SELECT username, password, COUNT(*) as count,
                           MAX(timestamp) as last_seen,
                           GROUP_CONCAT(DISTINCT source) as sources
                    FROM attacks
                    WHERE username IS NOT NULL AND username != ''
                    GROUP BY username, password
                    ORDER BY count DESC
                    LIMIT ?
                ''', (limit,))
                combinations = [dict(row) for row in cur.fetchall()]

                # Get passwords that look like SQL injection
                cur.execute('''
                    SELECT username, password, ip_address, timestamp
                    FROM attacks
                    WHERE source = 'WEB' AND (
                        password LIKE '%OR%=%' OR
                        password LIKE '%''%' OR
                        password LIKE '%--%' OR
                        password LIKE '%UNION%' OR
                        password LIKE '%SELECT%' OR
                        username LIKE '%OR%=%' OR
                        username LIKE '%''%' OR
                        username LIKE '%--%' OR
                        username LIKE '%UNION%'
                    )
                    ORDER BY timestamp DESC
                    LIMIT 50
                ''')
                sql_injections = [dict(row) for row in cur.fetchall()]

            return jsonify({
                'combinations': combinations,
                'sql_injections': sql_injections,
                'top_passwords': [{'password': p[0], 'count': p[1]} for p in db.get_top_passwords(20)],
                'top_usernames': [{'username': u[0], 'count': u[1]} for u in db.get_top_usernames(20)]
            })

        @self.app.route('/api/ips')
        def api_ips():
            """API endpoint for IP analysis"""
            from core.database import Database
            db = Database()

            limit = request.args.get('limit', 50, type=int)

            with db.cursor() as cur:
                # Get top attackers
                cur.execute('''
                    SELECT ip_address, country,
                           COUNT(*) as attack_count,
                           SUM(threat_score) as total_score,
                           MAX(threat_level) as max_threat,
                           MIN(timestamp) as first_seen,
                           MAX(timestamp) as last_seen,
                           COUNT(DISTINCT username) as unique_usernames,
                           COUNT(DISTINCT command) as unique_commands
                    FROM attacks
                    GROUP BY ip_address
                    ORDER BY attack_count DESC
                    LIMIT ?
                ''', (limit,))
                top_attackers = [dict(row) for row in cur.fetchall()]

                # Get IPs with most commands
                cur.execute('''
                    SELECT ip_address, COUNT(DISTINCT command) as cmd_count
                    FROM attacks
                    WHERE command IS NOT NULL AND command != ''
                    GROUP BY ip_address
                    ORDER BY cmd_count DESC
                    LIMIT 10
                ''')
                ips_with_commands = [dict(row) for row in cur.fetchall()]

            return jsonify({
                'top_attackers': top_attackers,
                'ips_with_commands': ips_with_commands,
                'blocked_ips': db.get_blocked_ips()
            })

        @self.app.route('/api/export/<data_type>')
        def api_export(data_type):
            """Export data as CSV"""
            from core.database import Database
            db = Database()

            output = io.StringIO()
            writer = csv.writer(output)

            if data_type == 'attacks':
                attacks = db.get_recent_attacks(limit=1000)
                writer.writerow(['Timestamp', 'Source', 'IP', 'Country', 'Username', 'Password', 'Command', 'Threat Level', 'Score'])
                for a in attacks:
                    writer.writerow([a['timestamp'], a['source'], a['ip_address'], a['country'],
                                   a['username'], a['password'], a['command'], a['threat_level'], a['threat_score']])

            elif data_type == 'credentials':
                with db.cursor() as cur:
                    cur.execute('''
                        SELECT username, password, COUNT(*) as count FROM attacks
                        WHERE username IS NOT NULL
                        GROUP BY username, password ORDER BY count DESC
                    ''')
                    writer.writerow(['Username', 'Password', 'Count'])
                    for row in cur.fetchall():
                        writer.writerow([row['username'], row['password'], row['count']])

            elif data_type == 'commands':
                with db.cursor() as cur:
                    cur.execute('''
                        SELECT command, COUNT(*) as count FROM attacks
                        WHERE command IS NOT NULL AND command != ''
                        GROUP BY command ORDER BY count DESC
                    ''')
                    writer.writerow(['Command', 'Count'])
                    for row in cur.fetchall():
                        writer.writerow([row['command'], row['count']])

            elif data_type == 'ips':
                with db.cursor() as cur:
                    cur.execute('''
                        SELECT ip_address, country, COUNT(*) as count, SUM(threat_score) as score
                        FROM attacks GROUP BY ip_address ORDER BY count DESC
                    ''')
                    writer.writerow(['IP Address', 'Country', 'Attack Count', 'Total Score'])
                    for row in cur.fetchall():
                        writer.writerow([row['ip_address'], row['country'], row['count'], row['score']])

            else:
                return jsonify({'error': 'Invalid data type'}), 400

            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={data_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )

        @self.app.route('/api/search')
        def api_search():
            """Search across all data"""
            from core.database import Database
            db = Database()

            query = request.args.get('q', '')
            if len(query) < 2:
                return jsonify({'error': 'Query too short'}), 400

            with db.cursor() as cur:
                cur.execute('''
                    SELECT * FROM attacks
                    WHERE ip_address LIKE ? OR username LIKE ? OR password LIKE ? OR command LIKE ? OR country LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 100
                ''', (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
                results = [dict(row) for row in cur.fetchall()]

            return jsonify({
                'query': query,
                'results': results,
                'count': len(results)
            })

        @self.app.route('/api/sessions')
        def api_sessions():
            """API endpoint for web honeypot sessions"""
            from core.database import Database
            import json
            db = Database()

            with db.cursor() as cur:
                # Get all web attacks grouped by IP to show sessions
                cur.execute('''
                    SELECT ip_address, country,
                           MIN(timestamp) as first_seen,
                           MAX(timestamp) as last_seen,
                           COUNT(*) as total_actions,
                           GROUP_CONCAT(raw_data) as all_raw_data
                    FROM attacks
                    WHERE source = 'WEB'
                    GROUP BY ip_address
                    ORDER BY last_seen DESC
                    LIMIT 50
                ''')
                sessions_raw = cur.fetchall()

                sessions = []
                for row in sessions_raw:
                    session = dict(row)

                    # Parse actions from raw_data
                    actions = []
                    paths_visited = set()
                    sqli_attempts = 0
                    login_attempts = 0

                    if session.get('all_raw_data'):
                        for raw in session['all_raw_data'].split(','):
                            try:
                                data = json.loads(raw)
                                action_type = data.get('type', 'unknown')
                                path = data.get('path', '')

                                if path:
                                    paths_visited.add(path)
                                if action_type == 'sql_injection' or data.get('sqli_detected'):
                                    sqli_attempts += 1
                                if action_type == 'login':
                                    login_attempts += 1
                            except:
                                pass

                    session['paths_visited'] = list(paths_visited)
                    session['sqli_attempts'] = sqli_attempts
                    session['login_attempts'] = login_attempts
                    del session['all_raw_data']  # Don't send raw data
                    sessions.append(session)

                # Get detailed timeline for each IP
                cur.execute('''
                    SELECT ip_address, timestamp, username, password, raw_data
                    FROM attacks
                    WHERE source = 'WEB'
                    ORDER BY timestamp DESC
                    LIMIT 200
                ''')
                timeline = []
                for row in cur.fetchall():
                    entry = dict(row)
                    if entry.get('raw_data'):
                        try:
                            entry['extra'] = json.loads(entry['raw_data'])
                        except:
                            entry['extra'] = {}
                    del entry['raw_data']
                    timeline.append(entry)

                # Get path statistics
                cur.execute('''
                    SELECT raw_data FROM attacks
                    WHERE source = 'WEB' AND raw_data IS NOT NULL
                ''')
                path_counts = {}
                for row in cur.fetchall():
                    try:
                        data = json.loads(row['raw_data'])
                        path = data.get('path', '')
                        if path:
                            path_counts[path] = path_counts.get(path, 0) + 1
                    except:
                        pass

                top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            return jsonify({
                'sessions': sessions,
                'timeline': timeline,
                'top_paths': [{'path': p[0], 'count': p[1]} for p in top_paths]
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
