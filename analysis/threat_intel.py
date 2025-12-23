"""
Threat Intelligence Analyzer
Analyzes attack patterns, common passwords, and suspicious behavior
"""

import os
import sys
import re
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ThreatIntelligence:
    """Threat intelligence and pattern analysis"""

    # Common weak passwords used in attacks
    COMMON_PASSWORDS = {
        '123456', 'password', '12345678', 'qwerty', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon',
        '123123', 'baseball', 'iloveyou', 'trustno1', '1234567890',
        'sunshine', 'master', 'welcome', 'shadow', 'ashley',
        'football', 'jesus', 'michael', 'ninja', 'mustang',
        'admin', 'root', 'toor', 'pass', 'test',
        'guest', 'master', 'changeme', 'default', 'administrator',
        'letmein', 'login', 'passw0rd', 'p@ssw0rd', 'abc123',
        '1q2w3e4r', 'qwerty123', 'password1', 'password123',
    }

    # Common attack usernames
    COMMON_USERNAMES = {
        'root', 'admin', 'administrator', 'user', 'test',
        'guest', 'info', 'mysql', 'postgres', 'oracle',
        'ftp', 'ftpuser', 'www', 'www-data', 'apache',
        'nginx', 'tomcat', 'webmaster', 'support', 'backup',
        'pi', 'ubuntu', 'ec2-user', 'centos', 'debian',
    }

    # Dangerous command patterns
    DANGEROUS_PATTERNS = [
        # Download tools
        (r'wget\s+', 'Wget download attempt'),
        (r'curl\s+', 'Curl download attempt'),
        (r'fetch\s+', 'Fetch download attempt'),

        # Reverse shells
        (r'bash\s+-i', 'Bash reverse shell'),
        (r'/dev/tcp/', 'TCP reverse shell'),
        (r'nc\s+-e', 'Netcat reverse shell'),
        (r'netcat\s+-e', 'Netcat reverse shell'),
        (r'python\s+-c.*socket', 'Python reverse shell'),
        (r'perl\s+-e.*socket', 'Perl reverse shell'),
        (r'php\s+-r.*fsockopen', 'PHP reverse shell'),

        # Privilege escalation
        (r'sudo\s+', 'Sudo privilege escalation'),
        (r'chmod\s+[0-7]*777', 'Chmod 777 attempt'),
        (r'chmod\s+\+s', 'SUID bit setting'),

        # Sensitive file access
        (r'/etc/passwd', 'Password file access'),
        (r'/etc/shadow', 'Shadow file access'),
        (r'/etc/ssh/', 'SSH config access'),
        (r'\.ssh/', 'SSH directory access'),
        (r'id_rsa', 'SSH key access'),

        # System modification
        (r'rm\s+-rf', 'Recursive delete'),
        (r'mkfs', 'Filesystem format attempt'),
        (r'dd\s+if=', 'DD disk operation'),

        # Cryptocurrency mining
        (r'xmrig', 'XMRig miner'),
        (r'minerd', 'Mining daemon'),
        (r'stratum', 'Mining pool connection'),

        # Malware indicators
        (r'base64\s+-d', 'Base64 decode'),
        (r'eval\s*\(', 'Code evaluation'),
        (r'exec\s*\(', 'Command execution'),

        # Persistence
        (r'crontab', 'Cron job manipulation'),
        (r'/etc/rc\.local', 'Startup script modification'),
        (r'systemctl\s+enable', 'Service enabling'),

        # Network scanning
        (r'nmap', 'Nmap scanning'),
        (r'masscan', 'Masscan scanning'),
        (r'zmap', 'Zmap scanning'),
    ]

    def __init__(self):
        self.attack_history: List[Dict] = []
        self.ip_patterns: Dict[str, Counter] = {}

        # Compile regex patterns
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), description)
            for pattern, description in self.DANGEROUS_PATTERNS
        ]

    def analyze_password(self, password: str) -> Dict[str, any]:
        """
        Analyze a password for threat indicators

        Returns:
            Dictionary with analysis results
        """
        if not password:
            return {'weak': False, 'common': False, 'score': 0}

        result = {
            'weak': False,
            'common': False,
            'length': len(password),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'score': 0,
        }

        # Check if common password
        if password.lower() in self.COMMON_PASSWORDS:
            result['common'] = True
            result['score'] += 3

        # Check password strength
        if len(password) < 6:
            result['weak'] = True
            result['score'] += 2

        # Simple patterns
        if password.isdigit():
            result['weak'] = True
            result['score'] += 1

        if password.isalpha() and password.islower():
            result['weak'] = True
            result['score'] += 1

        return result

    def analyze_username(self, username: str) -> Dict[str, any]:
        """
        Analyze a username for threat indicators

        Returns:
            Dictionary with analysis results
        """
        if not username:
            return {'common': False, 'suspicious': False, 'score': 0}

        result = {
            'common': False,
            'suspicious': False,
            'is_root': username.lower() == 'root',
            'is_admin': 'admin' in username.lower(),
            'score': 0,
        }

        # Check if common attack username
        if username.lower() in self.COMMON_USERNAMES:
            result['common'] = True
            result['score'] += 2

        if result['is_root']:
            result['score'] += 1

        return result

    def analyze_command(self, command: str) -> Dict[str, any]:
        """
        Analyze a command for malicious patterns

        Returns:
            Dictionary with analysis results and matched patterns
        """
        if not command:
            return {'dangerous': False, 'matches': [], 'score': 0}

        result = {
            'dangerous': False,
            'matches': [],
            'score': 0,
        }

        for pattern, description in self.compiled_patterns:
            if pattern.search(command):
                result['dangerous'] = True
                result['matches'].append(description)
                result['score'] += 10

        return result

    def detect_bruteforce(self, ip_address: str, window_minutes: int = 5,
                          threshold: int = 5) -> Dict[str, any]:
        """
        Detect brute force attacks from an IP

        Args:
            ip_address: IP to check
            window_minutes: Time window in minutes
            threshold: Number of attempts to trigger detection

        Returns:
            Dictionary with bruteforce detection results
        """
        from core.database import Database
        db = Database()

        attempts = db.get_ip_attempt_count(ip_address, minutes=window_minutes)

        return {
            'is_bruteforce': attempts >= threshold,
            'attempt_count': attempts,
            'threshold': threshold,
            'window_minutes': window_minutes,
            'score': 5 if attempts >= threshold else 0,
        }

    def analyze_attack(self,
                       ip_address: str,
                       username: str = None,
                       password: str = None,
                       command: str = None,
                       user_agent: str = None) -> Dict[str, any]:
        """
        Comprehensive attack analysis

        Returns:
            Dictionary with full analysis results
        """
        result = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'indicators': [],
            'total_score': 0,
        }

        # Analyze password
        if password:
            pwd_analysis = self.analyze_password(password)
            result['password_analysis'] = pwd_analysis
            result['total_score'] += pwd_analysis['score']
            if pwd_analysis['common']:
                result['indicators'].append('Common password used')
            if pwd_analysis['weak']:
                result['indicators'].append('Weak password attempted')

        # Analyze username
        if username:
            user_analysis = self.analyze_username(username)
            result['username_analysis'] = user_analysis
            result['total_score'] += user_analysis['score']
            if user_analysis['common']:
                result['indicators'].append('Common attack username')
            if user_analysis['is_root']:
                result['indicators'].append('Root login attempt')

        # Analyze command
        if command:
            cmd_analysis = self.analyze_command(command)
            result['command_analysis'] = cmd_analysis
            result['total_score'] += cmd_analysis['score']
            for match in cmd_analysis['matches']:
                result['indicators'].append(match)

        # Check for bruteforce
        bruteforce = self.detect_bruteforce(ip_address)
        result['bruteforce_analysis'] = bruteforce
        result['total_score'] += bruteforce['score']
        if bruteforce['is_bruteforce']:
            result['indicators'].append(f"Bruteforce detected ({bruteforce['attempt_count']} attempts)")

        # Analyze user agent (for web attacks)
        if user_agent:
            ua_analysis = self._analyze_user_agent(user_agent)
            result['user_agent_analysis'] = ua_analysis
            result['total_score'] += ua_analysis.get('score', 0)
            if ua_analysis.get('suspicious'):
                result['indicators'].append('Suspicious User-Agent')

        return result

    def _analyze_user_agent(self, user_agent: str) -> Dict[str, any]:
        """Analyze HTTP User-Agent for suspicious patterns"""
        result = {
            'suspicious': False,
            'is_bot': False,
            'is_scanner': False,
            'score': 0,
        }

        if not user_agent:
            result['suspicious'] = True
            result['score'] = 2
            return result

        ua_lower = user_agent.lower()

        # Known scanner/attack tool signatures
        scanner_patterns = [
            'sqlmap', 'nikto', 'nessus', 'openvas', 'nmap',
            'masscan', 'dirbuster', 'gobuster', 'wfuzz',
            'hydra', 'medusa', 'burp', 'zaproxy', 'acunetix',
        ]

        for pattern in scanner_patterns:
            if pattern in ua_lower:
                result['is_scanner'] = True
                result['suspicious'] = True
                result['score'] = 5
                return result

        # Bot patterns
        if 'bot' in ua_lower or 'crawler' in ua_lower or 'spider' in ua_lower:
            result['is_bot'] = True

        # Suspicious patterns
        if len(user_agent) < 10:
            result['suspicious'] = True
            result['score'] = 1

        return result

    def get_attack_summary(self) -> Dict[str, any]:
        """Get summary of threat intelligence data"""
        from core.database import Database
        db = Database()

        stats = db.get_dashboard_stats()

        return {
            'total_attacks': stats['total_attacks'],
            'unique_attackers': stats['unique_ips'],
            'blocked_ips': stats['blocked_ips'],
            'top_passwords': stats['top_passwords'][:10],
            'top_usernames': stats['top_usernames'][:10],
            'top_countries': stats['top_countries'][:10],
            'threat_distribution': stats['threat_distribution'],
        }


# Global threat intelligence instance
threat_intel = ThreatIntelligence()
