"""
Auto Blocker - Automated IP blocking using iptables
SOAR (Security Orchestration, Automation and Response) component
"""

import os
import sys
import subprocess
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from threading import Thread, Lock
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AutoBlocker:
    """Automated IP blocking system"""

    def __init__(self):
        from core.config import Config
        from core.database import Database

        self.config = Config()
        self.db = Database()

        # Get configuration
        response_config = self.config.get_response_config()

        self.enabled = response_config.get('auto_block', False)
        self.block_threshold = response_config.get('block_threshold', 'HIGH')
        self.block_duration = response_config.get('block_duration', 3600)
        self.use_iptables = response_config.get('use_iptables', True)

        self._lock = Lock()
        self._cleanup_thread: Optional[Thread] = None
        self._running = False

        # Check if we can use iptables
        self.is_linux = platform.system() == 'Linux'
        self.is_root = os.geteuid() == 0 if self.is_linux else False

        if self.enabled:
            if not self.is_linux:
                print("[AutoBlocker] Warning: iptables only available on Linux")
                print("[AutoBlocker] IP blocking will be logged but not enforced")
            elif not self.is_root:
                print("[AutoBlocker] Warning: Root privileges required for iptables")
                print("[AutoBlocker] IP blocking will be logged but not enforced")
            else:
                print(f"[AutoBlocker] Enabled (threshold: {self.block_threshold})")

    def start_cleanup_thread(self) -> None:
        """Start background thread to cleanup expired blocks"""
        if self._running:
            return

        self._running = True
        self._cleanup_thread = Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        print("[AutoBlocker] Cleanup thread started")

    def stop(self) -> None:
        """Stop the auto blocker"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)

    def _cleanup_loop(self) -> None:
        """Background loop to cleanup expired blocks"""
        while self._running:
            try:
                self._cleanup_expired()
            except Exception as e:
                print(f"[AutoBlocker] Cleanup error: {e}")

            # Sleep for 60 seconds between checks
            for _ in range(60):
                if not self._running:
                    break
                time.sleep(1)

    def _cleanup_expired(self) -> None:
        """Remove expired IP blocks"""
        # Get expired blocks from database
        with self._lock:
            # This is handled by database cleanup
            count = self.db.cleanup_expired_blocks()
            if count > 0:
                print(f"[AutoBlocker] Cleaned up {count} expired blocks")

    def block_ip(self, ip_address: str, reason: str, threat_level: str) -> Tuple[bool, str]:
        """
        Block an IP address

        Args:
            ip_address: IP to block
            reason: Reason for blocking
            threat_level: Threat level (LOW, MEDIUM, HIGH)

        Returns:
            Tuple of (success, message)
        """
        if not self.enabled:
            return False, "Auto-block is disabled"

        # Check if already blocked
        if self.db.is_blocked(ip_address):
            return False, f"{ip_address} is already blocked"

        with self._lock:
            # Add to database
            self.db.block_ip(
                ip_address=ip_address,
                reason=reason,
                threat_level=threat_level,
                duration_seconds=self.block_duration
            )

            # Block with iptables if possible
            iptables_result = self._iptables_block(ip_address)

            # Send notification
            self._send_block_notification(ip_address, reason, threat_level)

            if iptables_result:
                message = f"Blocked {ip_address} for {self.block_duration // 60} minutes"
            else:
                message = f"Logged block for {ip_address} (iptables not available)"

            print(f"[AutoBlocker] {message}")
            return True, message

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Unblock an IP address

        Args:
            ip_address: IP to unblock

        Returns:
            Tuple of (success, message)
        """
        with self._lock:
            # Remove from database
            if not self.db.unblock_ip(ip_address):
                return False, f"{ip_address} is not blocked"

            # Unblock with iptables
            self._iptables_unblock(ip_address)

            message = f"Unblocked {ip_address}"
            print(f"[AutoBlocker] {message}")
            return True, message

    def _iptables_block(self, ip_address: str) -> bool:
        """Block IP using iptables"""
        if not self.is_linux or not self.is_root or not self.use_iptables:
            return False

        try:
            # Check if rule already exists
            check_cmd = ['iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(check_cmd, capture_output=True)

            if result.returncode == 0:
                # Rule already exists
                return True

            # Add rule
            add_cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(add_cmd, capture_output=True)

            return result.returncode == 0

        except Exception as e:
            print(f"[AutoBlocker] iptables error: {e}")
            return False

    def _iptables_unblock(self, ip_address: str) -> bool:
        """Unblock IP using iptables"""
        if not self.is_linux or not self.is_root or not self.use_iptables:
            return False

        try:
            # Remove rule
            cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True)

            return result.returncode == 0

        except Exception as e:
            print(f"[AutoBlocker] iptables error: {e}")
            return False

    def _send_block_notification(self, ip_address: str, reason: str, threat_level: str) -> None:
        """Send notification about blocked IP"""
        try:
            from alerting.discord_webhook import DiscordAlert
            discord = DiscordAlert()
            discord.send_block_notification(
                ip_address=ip_address,
                reason=reason,
                threat_level=threat_level,
                duration=self.block_duration
            )
        except Exception as e:
            print(f"[AutoBlocker] Failed to send notification: {e}")

    def check_and_block(self, ip_address: str, threat_score: int, threat_level: str) -> bool:
        """
        Check if IP should be blocked and block if necessary

        Args:
            ip_address: IP to check
            threat_score: Current threat score
            threat_level: Current threat level

        Returns:
            Boolean indicating if IP was blocked
        """
        if not self.enabled:
            return False

        # Check if already blocked
        if self.db.is_blocked(ip_address):
            return False

        # Check against threshold
        from analysis.threat_scorer import ThreatScorer
        scorer = ThreatScorer()

        should_block, reason = scorer.should_block(ip_address, threat_score)

        if should_block:
            success, _ = self.block_ip(ip_address, reason, threat_level)
            return success

        return False

    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        return self.db.get_blocked_ips()

    def get_block_stats(self) -> Dict:
        """Get blocking statistics"""
        blocked = self.db.get_blocked_ips()

        return {
            'total_blocked': len(blocked),
            'blocked_ips': [b['ip_address'] for b in blocked],
            'by_threat_level': self._group_by_threat_level(blocked),
        }

    def _group_by_threat_level(self, blocked: List[Dict]) -> Dict[str, int]:
        """Group blocked IPs by threat level"""
        result = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        for b in blocked:
            level = b.get('threat_level', 'UNKNOWN')
            if level in result:
                result[level] += 1
        return result


# Global auto blocker instance
auto_blocker = AutoBlocker()
