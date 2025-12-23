"""
Discord Webhook Alert System
Sends real-time alerts to Discord channel via webhook
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
from threading import Lock, Thread
from collections import defaultdict
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DiscordAlert:
    """Discord webhook notification system"""

    # Embed colors
    COLOR_LOW = 0x2ECC71      # Green
    COLOR_MEDIUM = 0xF39C12   # Orange
    COLOR_HIGH = 0xE74C3C     # Red
    COLOR_INFO = 0x3498DB     # Blue

    def __init__(self, webhook_url: str = None):
        """
        Initialize Discord Alert system

        Args:
            webhook_url: Discord webhook URL (optional, loads from config)
        """
        from core.config import Config
        self.config = Config()

        # Get configuration
        alerting_config = self.config.get_alerting_config()
        discord_config = alerting_config.get('discord', {})

        self.webhook_url = webhook_url or discord_config.get('webhook_url', '')
        self.enabled = discord_config.get('enabled', False) and self.webhook_url
        self.alert_threshold = discord_config.get('alert_threshold', 'MEDIUM')
        self.rate_limit = discord_config.get('rate_limit', 60)  # seconds

        # Rate limiting
        self._last_alert: Dict[str, float] = defaultdict(float)
        self._lock = Lock()

        # Validate webhook URL
        if self.enabled and 'YOUR_' in self.webhook_url:
            print("[Discord] Warning: Webhook URL not configured")
            self.enabled = False

        if self.enabled:
            print(f"[Discord] Alert system enabled (threshold: {self.alert_threshold})")

    def _is_rate_limited(self, ip_address: str) -> bool:
        """Check if IP is rate limited"""
        with self._lock:
            last_time = self._last_alert.get(ip_address, 0)
            current_time = time.time()

            if current_time - last_time < self.rate_limit:
                return True

            self._last_alert[ip_address] = current_time
            return False

    def _get_color(self, threat_level: str) -> int:
        """Get embed color based on threat level"""
        colors = {
            'LOW': self.COLOR_LOW,
            'MEDIUM': self.COLOR_MEDIUM,
            'HIGH': self.COLOR_HIGH,
        }
        return colors.get(threat_level.upper(), self.COLOR_INFO)

    def _get_emoji(self, threat_level: str) -> str:
        """Get emoji based on threat level"""
        emojis = {
            'LOW': ':green_circle:',
            'MEDIUM': ':orange_circle:',
            'HIGH': ':red_circle:',
        }
        return emojis.get(threat_level.upper(), ':white_circle:')

    def send_alert(self,
                   source: str,
                   ip_address: str,
                   threat_level: str,
                   threat_score: int,
                   username: str = None,
                   password: str = None,
                   command: str = None,
                   country: str = None,
                   details: Dict = None) -> bool:
        """
        Send attack alert to Discord

        Args:
            source: Attack source (WEB, SSH)
            ip_address: Attacker IP
            threat_level: LOW, MEDIUM, HIGH
            threat_score: Numeric threat score
            username: Attempted username
            password: Attempted password (masked)
            command: Command executed
            country: Country from GeoIP
            details: Additional details

        Returns:
            Boolean indicating success
        """
        if not self.enabled:
            return False

        # Check rate limit
        if self._is_rate_limited(ip_address):
            return False

        # Build embed
        embed = {
            "title": f"{self._get_emoji(threat_level)} Honeypot Alert - {threat_level}",
            "color": self._get_color(threat_level),
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [],
            "footer": {
                "text": "Honeypot Security System"
            }
        }

        # Add fields
        embed["fields"].append({
            "name": ":globe_with_meridians: Source",
            "value": f"`{source}`",
            "inline": True
        })

        embed["fields"].append({
            "name": ":dart: IP Address",
            "value": f"`{ip_address}`",
            "inline": True
        })

        if country:
            embed["fields"].append({
                "name": ":earth_americas: Country",
                "value": country,
                "inline": True
            })

        embed["fields"].append({
            "name": ":bar_chart: Threat Score",
            "value": f"`{threat_score}`",
            "inline": True
        })

        if username:
            embed["fields"].append({
                "name": ":bust_in_silhouette: Username",
                "value": f"`{username}`",
                "inline": True
            })

        if password:
            # Mask password for security
            masked = password[:2] + '*' * (len(password) - 2) if len(password) > 2 else '***'
            embed["fields"].append({
                "name": ":key: Password",
                "value": f"`{masked}`",
                "inline": True
            })

        if command:
            # Truncate long commands
            cmd_display = command[:100] + '...' if len(command) > 100 else command
            embed["fields"].append({
                "name": ":computer: Command",
                "value": f"```{cmd_display}```",
                "inline": False
            })

        if details:
            # Add breakdown if available
            breakdown = details.get('breakdown', [])
            if breakdown:
                breakdown_text = '\n'.join(breakdown[:5])  # Limit to 5 items
                embed["fields"].append({
                    "name": ":mag: Analysis",
                    "value": f"```{breakdown_text}```",
                    "inline": False
                })

        # Send webhook
        return self._send_webhook({"embeds": [embed]})

    def send_block_notification(self,
                                ip_address: str,
                                reason: str,
                                threat_level: str,
                                duration: int = 3600) -> bool:
        """
        Send IP block notification

        Args:
            ip_address: Blocked IP
            reason: Block reason
            threat_level: Threat level
            duration: Block duration in seconds

        Returns:
            Boolean indicating success
        """
        if not self.enabled:
            return False

        embed = {
            "title": ":no_entry: IP Blocked",
            "color": self.COLOR_HIGH,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {
                    "name": ":dart: IP Address",
                    "value": f"`{ip_address}`",
                    "inline": True
                },
                {
                    "name": ":warning: Threat Level",
                    "value": threat_level,
                    "inline": True
                },
                {
                    "name": ":clock1: Duration",
                    "value": f"{duration // 60} minutes",
                    "inline": True
                },
                {
                    "name": ":memo: Reason",
                    "value": reason,
                    "inline": False
                }
            ],
            "footer": {
                "text": "Honeypot Security System - Auto Response"
            }
        }

        return self._send_webhook({"embeds": [embed]})

    def send_daily_summary(self, stats: Dict) -> bool:
        """
        Send daily summary report

        Args:
            stats: Dashboard statistics

        Returns:
            Boolean indicating success
        """
        if not self.enabled:
            return False

        embed = {
            "title": ":bar_chart: Daily Security Summary",
            "color": self.COLOR_INFO,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {
                    "name": ":crossed_swords: Total Attacks",
                    "value": str(stats.get('total_attacks', 0)),
                    "inline": True
                },
                {
                    "name": ":busts_in_silhouette: Unique IPs",
                    "value": str(stats.get('unique_ips', 0)),
                    "inline": True
                },
                {
                    "name": ":no_entry_sign: Blocked IPs",
                    "value": str(stats.get('blocked_ips', 0)),
                    "inline": True
                },
                {
                    "name": ":rotating_light: High Threats",
                    "value": str(stats.get('high_threats', 0)),
                    "inline": True
                },
                {
                    "name": ":calendar: Today",
                    "value": str(stats.get('today_attacks', 0)),
                    "inline": True
                }
            ],
            "footer": {
                "text": "Honeypot Security System"
            }
        }

        # Add top countries if available
        top_countries = stats.get('top_countries', [])
        if top_countries:
            countries_text = '\n'.join([f"{c[0]}: {c[1]}" for c in top_countries[:5]])
            embed["fields"].append({
                "name": ":earth_americas: Top Countries",
                "value": f"```{countries_text}```",
                "inline": False
            })

        # Add top passwords if available
        top_passwords = stats.get('top_passwords', [])
        if top_passwords:
            passwords_text = '\n'.join([f"{p[0]}: {p[1]}" for p in top_passwords[:5]])
            embed["fields"].append({
                "name": ":key: Top Passwords",
                "value": f"```{passwords_text}```",
                "inline": False
            })

        return self._send_webhook({"embeds": [embed]})

    def _send_webhook(self, payload: Dict) -> bool:
        """Send payload to Discord webhook"""
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 204:
                return True
            elif response.status_code == 429:
                print("[Discord] Rate limited by Discord")
                return False
            else:
                print(f"[Discord] Error: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"[Discord] Request error: {e}")
            return False

    def send_async(self, *args, **kwargs) -> None:
        """Send alert asynchronously"""
        thread = Thread(target=self.send_alert, args=args, kwargs=kwargs, daemon=True)
        thread.start()


# Global Discord alert instance
discord_alert = DiscordAlert()
