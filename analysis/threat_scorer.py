"""
Threat Scoring System
Calculates threat scores and levels based on attack behavior
"""

import os
import sys
from typing import Dict, Optional, Tuple
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ThreatScorer:
    """Calculate threat scores and levels for attacks"""

    # Threat levels
    LEVEL_LOW = 'LOW'
    LEVEL_MEDIUM = 'MEDIUM'
    LEVEL_HIGH = 'HIGH'

    def __init__(self):
        from core.config import Config
        self.config = Config()

        # Load scoring configuration
        scoring_config = self.config.get_scoring_config()

        # Thresholds
        thresholds = scoring_config.get('thresholds', {})
        self.threshold_low = thresholds.get('low', 5)
        self.threshold_medium = thresholds.get('medium', 15)

        # Behavior scores
        behaviors = scoring_config.get('behaviors', {})
        self.score_login_attempt = behaviors.get('login_attempt', 1)
        self.score_failed_login = behaviors.get('failed_login', 2)
        self.score_bruteforce = behaviors.get('bruteforce_bonus', 5)
        self.score_dangerous_command = behaviors.get('dangerous_command', 10)
        self.score_malware_download = behaviors.get('malware_download', 15)
        self.score_known_bad_password = behaviors.get('known_bad_password', 3)

        self.bruteforce_threshold = behaviors.get('bruteforce_threshold', 5)

        # Dangerous commands list
        self.dangerous_commands = scoring_config.get('dangerous_commands', [
            'wget', 'curl', 'nc', 'netcat', 'chmod', 'rm -rf',
            '/etc/passwd', '/etc/shadow', 'base64', 'python -c',
            'perl -e', 'bash -i'
        ])

    def calculate_score(self,
                        source: str,
                        ip_address: str,
                        username: str = None,
                        password: str = None,
                        command: str = None,
                        user_agent: str = None) -> Tuple[int, str, Dict]:
        """
        Calculate threat score for an attack

        Args:
            source: Attack source (WEB, SSH)
            ip_address: Attacker IP
            username: Attempted username
            password: Attempted password
            command: Command executed (SSH)
            user_agent: HTTP User-Agent (Web)

        Returns:
            Tuple of (score, threat_level, details)
        """
        score = 0
        details = {
            'breakdown': [],
            'ip_address': ip_address,
            'source': source,
        }

        # Import here to avoid circular imports
        from analysis.threat_intel import ThreatIntelligence
        threat_intel = ThreatIntelligence()
        from core.database import Database
        db = Database()

        # Base score for any login attempt
        score += self.score_login_attempt
        details['breakdown'].append(f"+{self.score_login_attempt}: Login attempt")

        # Password analysis
        if password:
            pwd_analysis = threat_intel.analyze_password(password)
            if pwd_analysis['common']:
                score += self.score_known_bad_password
                details['breakdown'].append(f"+{self.score_known_bad_password}: Common password")
            if pwd_analysis['weak']:
                score += 1
                details['breakdown'].append("+1: Weak password")

        # Username analysis
        if username:
            user_analysis = threat_intel.analyze_username(username)
            if user_analysis['is_root']:
                score += 2
                details['breakdown'].append("+2: Root login attempt")
            elif user_analysis['common']:
                score += 1
                details['breakdown'].append("+1: Common attack username")

        # Command analysis (SSH)
        if command:
            cmd_analysis = threat_intel.analyze_command(command)
            if cmd_analysis['dangerous']:
                score += self.score_dangerous_command * len(cmd_analysis['matches'])
                for match in cmd_analysis['matches']:
                    details['breakdown'].append(f"+{self.score_dangerous_command}: {match}")

            # Check for specific dangerous patterns
            cmd_lower = command.lower()
            for dangerous in self.dangerous_commands:
                if dangerous.lower() in cmd_lower:
                    # Already counted in analyze_command, but track it
                    pass

        # Bruteforce detection
        attempt_count = db.get_ip_attempt_count(ip_address, minutes=5)
        if attempt_count >= self.bruteforce_threshold:
            score += self.score_bruteforce
            details['breakdown'].append(f"+{self.score_bruteforce}: Bruteforce ({attempt_count} attempts)")
            details['bruteforce'] = True

        # Get cumulative score for this IP
        ip_stats = db.get_ip_stats(ip_address)
        if ip_stats:
            details['cumulative_score'] = ip_stats['total_score'] + score
            details['total_attempts'] = ip_stats['total_attempts'] + 1
            details['first_seen'] = ip_stats['first_seen']

        # Calculate threat level
        threat_level = self.get_threat_level(score)

        details['score'] = score
        details['threat_level'] = threat_level

        return score, threat_level, details

    def get_threat_level(self, score: int) -> str:
        """
        Convert score to threat level

        Args:
            score: Numeric threat score

        Returns:
            Threat level string (LOW, MEDIUM, HIGH)
        """
        if score >= self.threshold_medium:
            return self.LEVEL_HIGH
        elif score >= self.threshold_low:
            return self.LEVEL_MEDIUM
        else:
            return self.LEVEL_LOW

    def get_cumulative_threat_level(self, ip_address: str) -> Tuple[int, str]:
        """
        Get cumulative threat level for an IP

        Args:
            ip_address: IP to check

        Returns:
            Tuple of (cumulative_score, threat_level)
        """
        from core.database import Database
        db = Database()

        total_score = db.get_ip_total_score(ip_address)
        threat_level = self.get_threat_level(total_score)

        return total_score, threat_level

    def should_block(self, ip_address: str, current_score: int = 0) -> Tuple[bool, str]:
        """
        Determine if an IP should be blocked

        Args:
            ip_address: IP to check
            current_score: Score from current attack

        Returns:
            Tuple of (should_block, reason)
        """
        response_config = self.config.get_response_config()

        if not response_config.get('auto_block', False):
            return False, "Auto-block disabled"

        block_threshold = response_config.get('block_threshold', 'HIGH')

        # Get cumulative score
        cumulative_score, threat_level = self.get_cumulative_threat_level(ip_address)
        total_score = cumulative_score + current_score

        # Check against threshold
        threshold_levels = {
            'LOW': self.threshold_low,
            'MEDIUM': self.threshold_medium,
            'HIGH': self.threshold_medium,  # HIGH is >= medium threshold
        }

        block_score = threshold_levels.get(block_threshold, self.threshold_medium)

        if total_score >= block_score:
            final_level = self.get_threat_level(total_score)
            if self._level_meets_threshold(final_level, block_threshold):
                return True, f"Threat level {final_level} (score: {total_score})"

        return False, f"Score {total_score} below {block_threshold} threshold"

    def _level_meets_threshold(self, level: str, threshold: str) -> bool:
        """Check if threat level meets or exceeds threshold"""
        level_order = {self.LEVEL_LOW: 1, self.LEVEL_MEDIUM: 2, self.LEVEL_HIGH: 3}
        return level_order.get(level, 0) >= level_order.get(threshold, 0)

    def should_alert(self, threat_level: str) -> bool:
        """
        Determine if an alert should be sent

        Args:
            threat_level: Current threat level

        Returns:
            Boolean indicating if alert should be sent
        """
        alerting_config = self.config.get_alerting_config()
        discord_config = alerting_config.get('discord', {})

        if not discord_config.get('enabled', False):
            return False

        alert_threshold = discord_config.get('alert_threshold', 'MEDIUM')

        return self._level_meets_threshold(threat_level, alert_threshold)


# Global threat scorer instance
threat_scorer = ThreatScorer()
