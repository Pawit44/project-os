"""
Central Log Collector for Honeypot Security System
Collects logs from all honeypots and stores in unified JSON format
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from threading import Lock

from .database import Database
from .config import Config


class LogCollector:
    """Centralized log collection and processing"""

    _instance: Optional['LogCollector'] = None
    _lock = Lock()

    # Source type constants
    SOURCE_WEB = 'WEB'
    SOURCE_SSH = 'SSH'
    SOURCE_DIONAEA = 'DIONAEA'

    def __new__(cls) -> 'LogCollector':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.config = Config()
        self.db = Database()

        # Setup logging
        self._setup_logging()

        # Get attack log path
        self.attack_log_path = self.config.get('logging', 'attack_log',
                                                default='logs/attacks.json')

        # Ensure log directory exists
        Path(self.attack_log_path).parent.mkdir(parents=True, exist_ok=True)

        self._initialized = True

    def _setup_logging(self) -> None:
        """Setup application logging"""
        log_path = self.config.get('logging', 'main_log', default='logs/honeypot.log')
        log_level = self.config.log_level

        # Ensure log directory exists
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger('HoneypotSystem')

    def log_attack(self,
                   source: str,
                   ip_address: str,
                   username: str = None,
                   password: str = None,
                   command: str = None,
                   user_agent: str = None,
                   country: str = None,
                   city: str = None,
                   session_id: str = None,
                   threat_score: int = 0,
                   threat_level: str = 'LOW',
                   extra_data: Dict[str, Any] = None) -> int:
        """
        Log an attack event from any honeypot

        Args:
            source: Attack source (WEB, SSH, DIONAEA)
            ip_address: Attacker's IP address
            username: Attempted username
            password: Attempted password
            command: Command executed (SSH)
            user_agent: HTTP User-Agent (Web)
            country: Country from GeoIP
            city: City from GeoIP
            session_id: Unique session identifier
            threat_score: Calculated threat score
            threat_level: LOW, MEDIUM, or HIGH
            extra_data: Additional data as dictionary

        Returns:
            Attack ID from database
        """
        timestamp = datetime.now()

        # Create unified log entry
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'source': source,
            'ip_address': ip_address,
            'username': username,
            'password': password,
            'command': command,
            'user_agent': user_agent,
            'country': country,
            'city': city,
            'session_id': session_id,
            'threat_score': threat_score,
            'threat_level': threat_level,
        }

        if extra_data:
            log_entry['extra'] = extra_data

        # Log to console/file
        self.logger.info(
            f"[{source}] Attack from {ip_address} ({country or 'Unknown'}) - "
            f"Score: {threat_score} ({threat_level})"
        )

        # Write to JSON log file
        self._write_json_log(log_entry)

        # Store in database
        raw_data = json.dumps(extra_data) if extra_data else None
        attack_id = self.db.log_attack(
            source=source,
            ip_address=ip_address,
            username=username,
            password=password,
            command=command,
            user_agent=user_agent,
            country=country,
            city=city,
            session_id=session_id,
            threat_score=threat_score,
            threat_level=threat_level,
            raw_data=raw_data
        )

        return attack_id

    def _write_json_log(self, log_entry: Dict[str, Any]) -> None:
        """Append log entry to JSON log file"""
        with self._lock:
            try:
                with open(self.attack_log_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            except Exception as e:
                self.logger.error(f"Failed to write to attack log: {e}")

    def log_web_attack(self,
                       ip_address: str,
                       username: str,
                       password: str,
                       user_agent: str = None,
                       path: str = None,
                       method: str = None,
                       **kwargs) -> int:
        """Log a web honeypot attack"""
        extra_data = {}
        if path:
            extra_data['path'] = path
        if method:
            extra_data['method'] = method

        return self.log_attack(
            source=self.SOURCE_WEB,
            ip_address=ip_address,
            username=username,
            password=password,
            user_agent=user_agent,
            extra_data=extra_data if extra_data else None,
            **kwargs
        )

    def log_ssh_attack(self,
                       ip_address: str,
                       username: str = None,
                       password: str = None,
                       command: str = None,
                       session_id: str = None,
                       **kwargs) -> int:
        """Log an SSH honeypot attack"""
        return self.log_attack(
            source=self.SOURCE_SSH,
            ip_address=ip_address,
            username=username,
            password=password,
            command=command,
            session_id=session_id,
            **kwargs
        )

    def log_command(self,
                    ip_address: str,
                    command: str,
                    session_id: str = None,
                    **kwargs) -> int:
        """Log a command execution in SSH honeypot"""
        return self.log_attack(
            source=self.SOURCE_SSH,
            ip_address=ip_address,
            command=command,
            session_id=session_id,
            **kwargs
        )

    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)

    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)


# Global log collector instance
log_collector = LogCollector()
