"""
SQLite Database handler for Honeypot Security System
Stores attack logs, blocked IPs, and statistics
"""

import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from contextlib import contextmanager


class Database:
    """Thread-safe SQLite database handler"""

    _instance: Optional['Database'] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = None) -> 'Database':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: str = None):
        if self._initialized:
            return

        if db_path is None:
            from .config import config
            db_path = config.database_path

        self.db_path = db_path
        self._local = threading.local()

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database schema
        self._init_schema()
        self._initialized = True

    @property
    def connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    @contextmanager
    def cursor(self):
        """Context manager for database cursor with auto-commit"""
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e
        finally:
            cursor.close()

    def _init_schema(self) -> None:
        """Initialize database tables"""
        with self.cursor() as cur:
            # Attacks table - main log of all attack events
            cur.execute('''
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    country TEXT,
                    city TEXT,
                    username TEXT,
                    password TEXT,
                    command TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    threat_score INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'LOW',
                    raw_data TEXT
                )
            ''')

            # Blocked IPs table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    reason TEXT,
                    threat_level TEXT,
                    total_score INTEGER DEFAULT 0
                )
            ''')

            # IP statistics table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS ip_stats (
                    ip_address TEXT PRIMARY KEY,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    total_attempts INTEGER DEFAULT 0,
                    total_score INTEGER DEFAULT 0,
                    country TEXT,
                    is_blocked INTEGER DEFAULT 0
                )
            ''')

            # Create indexes for better query performance
            cur.execute('CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip_address)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_attacks_source ON attacks(source)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_blocked_expires ON blocked_ips(expires_at)')

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
                   raw_data: str = None) -> int:
        """Log an attack event and return the attack ID"""
        with self._lock:
            with self.cursor() as cur:
                cur.execute('''
                    INSERT INTO attacks
                    (source, ip_address, username, password, command, user_agent,
                     country, city, session_id, threat_score, threat_level, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (source, ip_address, username, password, command, user_agent,
                      country, city, session_id, threat_score, threat_level, raw_data))

                attack_id = cur.lastrowid

                # Update IP statistics
                cur.execute('''
                    INSERT INTO ip_stats (ip_address, total_attempts, total_score, country, last_seen)
                    VALUES (?, 1, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        total_attempts = total_attempts + 1,
                        total_score = total_score + ?,
                        last_seen = CURRENT_TIMESTAMP
                ''', (ip_address, threat_score, country, threat_score))

                return attack_id

    def get_ip_stats(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific IP"""
        with self.cursor() as cur:
            cur.execute('SELECT * FROM ip_stats WHERE ip_address = ?', (ip_address,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_ip_total_score(self, ip_address: str) -> int:
        """Get total threat score for an IP"""
        stats = self.get_ip_stats(ip_address)
        return stats['total_score'] if stats else 0

    def get_ip_attempt_count(self, ip_address: str, minutes: int = 60) -> int:
        """Get number of attempts from IP in last N minutes"""
        since = datetime.now() - timedelta(minutes=minutes)
        with self.cursor() as cur:
            cur.execute('''
                SELECT COUNT(*) FROM attacks
                WHERE ip_address = ? AND timestamp > ?
            ''', (ip_address, since))
            return cur.fetchone()[0]

    def block_ip(self, ip_address: str, reason: str, threat_level: str,
                 duration_seconds: int = 3600) -> bool:
        """Block an IP address"""
        expires_at = datetime.now() + timedelta(seconds=duration_seconds)

        with self._lock:
            with self.cursor() as cur:
                try:
                    cur.execute('''
                        INSERT INTO blocked_ips (ip_address, reason, threat_level, expires_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(ip_address) DO UPDATE SET
                            blocked_at = CURRENT_TIMESTAMP,
                            expires_at = ?,
                            reason = ?,
                            threat_level = ?
                    ''', (ip_address, reason, threat_level, expires_at,
                          expires_at, reason, threat_level))

                    # Update IP stats
                    cur.execute('''
                        UPDATE ip_stats SET is_blocked = 1 WHERE ip_address = ?
                    ''', (ip_address,))

                    return True
                except Exception:
                    return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        with self._lock:
            with self.cursor() as cur:
                cur.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
                cur.execute('UPDATE ip_stats SET is_blocked = 0 WHERE ip_address = ?', (ip_address,))
                return cur.rowcount > 0

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT 1 FROM blocked_ips
                WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ''', (ip_address,))
            return cur.fetchone() is not None

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get all currently blocked IPs"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT * FROM blocked_ips
                WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
                ORDER BY blocked_at DESC
            ''')
            return [dict(row) for row in cur.fetchall()]

    def cleanup_expired_blocks(self) -> int:
        """Remove expired IP blocks"""
        with self._lock:
            with self.cursor() as cur:
                cur.execute('''
                    UPDATE ip_stats SET is_blocked = 0
                    WHERE ip_address IN (
                        SELECT ip_address FROM blocked_ips
                        WHERE expires_at < CURRENT_TIMESTAMP
                    )
                ''')
                cur.execute('DELETE FROM blocked_ips WHERE expires_at < CURRENT_TIMESTAMP')
                return cur.rowcount

    def get_recent_attacks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent attack events"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cur.fetchall()]

    def get_attacks_by_ip(self, ip_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get attacks from a specific IP"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT * FROM attacks WHERE ip_address = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (ip_address, limit))
            return [dict(row) for row in cur.fetchall()]

    def get_top_passwords(self, limit: int = 20) -> List[Tuple[str, int]]:
        """Get most commonly attempted passwords"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT password, COUNT(*) as count FROM attacks
                WHERE password IS NOT NULL AND password != ''
                GROUP BY password ORDER BY count DESC LIMIT ?
            ''', (limit,))
            return [(row['password'], row['count']) for row in cur.fetchall()]

    def get_top_usernames(self, limit: int = 20) -> List[Tuple[str, int]]:
        """Get most commonly attempted usernames"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT username, COUNT(*) as count FROM attacks
                WHERE username IS NOT NULL AND username != ''
                GROUP BY username ORDER BY count DESC LIMIT ?
            ''', (limit,))
            return [(row['username'], row['count']) for row in cur.fetchall()]

    def get_top_countries(self, limit: int = 20) -> List[Tuple[str, int]]:
        """Get countries with most attacks"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT country, COUNT(*) as count FROM attacks
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country ORDER BY count DESC LIMIT ?
            ''', (limit,))
            return [(row['country'], row['count']) for row in cur.fetchall()]

    def get_attacks_by_source(self) -> Dict[str, int]:
        """Get attack counts by source type"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT source, COUNT(*) as count FROM attacks
                GROUP BY source ORDER BY count DESC
            ''')
            return {row['source']: row['count'] for row in cur.fetchall()}

    def get_threat_level_distribution(self) -> Dict[str, int]:
        """Get distribution of threat levels"""
        with self.cursor() as cur:
            cur.execute('''
                SELECT threat_level, COUNT(*) as count FROM attacks
                GROUP BY threat_level
            ''')
            return {row['threat_level']: row['count'] for row in cur.fetchall()}

    def get_hourly_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack statistics per hour"""
        since = datetime.now() - timedelta(hours=hours)
        with self.cursor() as cur:
            cur.execute('''
                SELECT
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as count,
                    COUNT(DISTINCT ip_address) as unique_ips
                FROM attacks
                WHERE timestamp > ?
                GROUP BY hour
                ORDER BY hour
            ''', (since,))
            return [dict(row) for row in cur.fetchall()]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics for dashboard"""
        with self.cursor() as cur:
            # Total attacks
            cur.execute('SELECT COUNT(*) FROM attacks')
            total_attacks = cur.fetchone()[0]

            # Unique IPs
            cur.execute('SELECT COUNT(DISTINCT ip_address) FROM attacks')
            unique_ips = cur.fetchone()[0]

            # Blocked IPs
            cur.execute('SELECT COUNT(*) FROM blocked_ips WHERE expires_at > CURRENT_TIMESTAMP OR expires_at IS NULL')
            blocked_ips = cur.fetchone()[0]

            # High threat count
            cur.execute("SELECT COUNT(*) FROM attacks WHERE threat_level = 'HIGH'")
            high_threats = cur.fetchone()[0]

            # Today's attacks
            today = datetime.now().strftime('%Y-%m-%d')
            cur.execute('SELECT COUNT(*) FROM attacks WHERE date(timestamp) = ?', (today,))
            today_attacks = cur.fetchone()[0]

            return {
                'total_attacks': total_attacks,
                'unique_ips': unique_ips,
                'blocked_ips': blocked_ips,
                'high_threats': high_threats,
                'today_attacks': today_attacks,
                'top_passwords': self.get_top_passwords(10),
                'top_usernames': self.get_top_usernames(10),
                'top_countries': self.get_top_countries(10),
                'attacks_by_source': self.get_attacks_by_source(),
                'threat_distribution': self.get_threat_level_distribution(),
                'hourly_stats': self.get_hourly_stats(24),
            }


# Global database instance
db = Database()
