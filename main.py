#!/usr/bin/env python3
"""
Honeypot Security System - Main Entry Point
A comprehensive honeypot system for detecting and analyzing attacker behavior

Author: Security Research Project
License: MIT
"""

import os
import sys
import signal
import argparse
from pathlib import Path

# Ensure the project directory is in Python path
PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(PROJECT_DIR))


def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     🍯 HONEYPOT SECURITY SYSTEM                              ║
    ║                                                               ║
    ║     Detect • Analyze • Respond                                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


class HoneypotSystem:
    """Main honeypot system orchestrator"""

    def __init__(self):
        self.running = False
        self.web_honeypot = None
        self.ssh_honeypot = None
        self.dashboard = None
        self.auto_blocker = None

        # Load configuration
        from core.config import Config
        self.config = Config()

        # Initialize database
        from core.database import Database
        self.db = Database()

        # Initialize components
        from core.log_collector import LogCollector
        self.log_collector = LogCollector()

        from analysis.geoip import GeoIPLookup
        self.geoip = GeoIPLookup()

        from analysis.threat_scorer import ThreatScorer
        self.scorer = ThreatScorer()

        from alerting.discord_webhook import DiscordAlert
        self.discord = DiscordAlert()

        from response.auto_blocker import AutoBlocker
        self.auto_blocker = AutoBlocker()

    def handle_attack(self,
                      source: str,
                      ip_address: str,
                      username: str = None,
                      password: str = None,
                      command: str = None,
                      user_agent: str = None,
                      session_id: str = None,
                      extra_data: dict = None):
        """
        Central attack handler - processes all attacks from honeypots

        This is the callback function passed to honeypots
        """
        # Get GeoIP information
        geo_info = self.geoip.lookup(ip_address)
        country = geo_info.get('country')
        city = geo_info.get('city')

        # Calculate threat score
        score, threat_level, details = self.scorer.calculate_score(
            source=source,
            ip_address=ip_address,
            username=username,
            password=password,
            command=command,
            user_agent=user_agent
        )

        # Log the attack
        attack_id = self.log_collector.log_attack(
            source=source,
            ip_address=ip_address,
            username=username,
            password=password,
            command=command,
            user_agent=user_agent,
            country=country,
            city=city,
            session_id=session_id,
            threat_score=score,
            threat_level=threat_level,
            extra_data=extra_data
        )

        # Check if should send alert
        if self.scorer.should_alert(threat_level):
            self.discord.send_async(
                source=source,
                ip_address=ip_address,
                threat_level=threat_level,
                threat_score=score,
                username=username,
                password=password,
                command=command,
                country=country,
                details=details
            )

        # Check if should block
        self.auto_blocker.check_and_block(ip_address, score, threat_level)

        return attack_id

    def start(self,
              web: bool = True,
              ssh: bool = True,
              dashboard: bool = True):
        """Start the honeypot system"""
        print_banner()
        self.running = True

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Start auto-blocker cleanup thread
        self.auto_blocker.start_cleanup_thread()

        # Start Web Honeypot
        if web and self.config.get('honeypots', 'web', 'enabled', default=True):
            self._start_web_honeypot()

        # Start SSH Honeypot
        if ssh and self.config.get('honeypots', 'ssh', 'enabled', default=True):
            self._start_ssh_honeypot()

        # Start Dashboard
        if dashboard and self.config.get('dashboard', 'enabled', default=True):
            self._start_dashboard()

        print("\n[System] Honeypot system is running. Press Ctrl+C to stop.\n")

        # Keep main thread alive
        try:
            while self.running:
                signal.pause() if hasattr(signal, 'pause') else __import__('time').sleep(1)
        except KeyboardInterrupt:
            pass

        self.stop()

    def _start_web_honeypot(self):
        """Start the web honeypot"""
        from honeypots.web_honeypot import WebHoneypot

        web_config = self.config.get_honeypot_config('web')
        host = web_config.get('host', '0.0.0.0')
        port = web_config.get('port', 8080)

        self.web_honeypot = WebHoneypot(
            host=host,
            port=port,
            on_attack=self.handle_attack
        )
        self.web_honeypot.start(threaded=True)

    def _start_ssh_honeypot(self):
        """Start the SSH honeypot"""
        from honeypots.ssh_honeypot import SSHHoneypot

        ssh_config = self.config.get_honeypot_config('ssh')
        host = ssh_config.get('host', '0.0.0.0')
        port = ssh_config.get('port', 2222)
        host_key = ssh_config.get('host_key')

        self.ssh_honeypot = SSHHoneypot(
            host=host,
            port=port,
            host_key_path=host_key,
            on_attack=self.handle_attack
        )
        self.ssh_honeypot.start(threaded=True)

    def _start_dashboard(self):
        """Start the dashboard"""
        from dashboard.app import Dashboard

        dash_config = self.config.get_dashboard_config()
        host = dash_config.get('host', '0.0.0.0')
        port = dash_config.get('port', 5000)

        self.dashboard = Dashboard(host=host, port=port)
        self.dashboard.start(threaded=True)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n[System] Shutdown signal received...")
        self.running = False

    def stop(self):
        """Stop all honeypot components"""
        print("[System] Stopping honeypot system...")

        if self.web_honeypot:
            self.web_honeypot.stop()

        if self.ssh_honeypot:
            self.ssh_honeypot.stop()

        if self.auto_blocker:
            self.auto_blocker.stop()

        if self.geoip:
            self.geoip.close()

        print("[System] Honeypot system stopped.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Honeypot Security System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start all components
  python main.py --no-dashboard     # Start without dashboard
  python main.py --web-only         # Start only web honeypot
  python main.py --ssh-only         # Start only SSH honeypot
        """
    )

    parser.add_argument(
        '--no-web',
        action='store_true',
        help='Disable web honeypot'
    )

    parser.add_argument(
        '--no-ssh',
        action='store_true',
        help='Disable SSH honeypot'
    )

    parser.add_argument(
        '--no-dashboard',
        action='store_true',
        help='Disable dashboard'
    )

    parser.add_argument(
        '--web-only',
        action='store_true',
        help='Run only web honeypot'
    )

    parser.add_argument(
        '--ssh-only',
        action='store_true',
        help='Run only SSH honeypot'
    )

    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='Path to configuration file'
    )

    args = parser.parse_args()

    # Determine which components to start
    web = not args.no_web
    ssh = not args.no_ssh
    dashboard = not args.no_dashboard

    if args.web_only:
        ssh = False
        dashboard = False

    if args.ssh_only:
        web = False
        dashboard = False

    # Load custom config if specified
    if args.config:
        from core.config import Config
        config = Config()
        config.load(args.config)

    # Start the system
    try:
        system = HoneypotSystem()
        system.start(web=web, ssh=ssh, dashboard=dashboard)
    except FileNotFoundError as e:
        print(f"[Error] Configuration error: {e}")
        print("[Error] Please copy config.example.yaml to config.yaml and configure it.")
        sys.exit(1)
    except PermissionError as e:
        print(f"[Error] Permission denied: {e}")
        print("[Error] Some ports may require root/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] Failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
