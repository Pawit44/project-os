"""
GeoIP Lookup - Convert IP addresses to geographic locations
Uses MaxMind GeoLite2 database
"""

import os
import sys
from typing import Dict, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class GeoIPLookup:
    """GeoIP lookup using MaxMind database"""

    _instance: Optional['GeoIPLookup'] = None

    def __new__(cls) -> 'GeoIPLookup':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.reader = None
        self.enabled = False
        self._initialized = True

        # Try to load GeoIP database
        self._load_database()

    def _load_database(self) -> None:
        """Load MaxMind GeoIP database"""
        try:
            import geoip2.database as geoip_db

            from core.config import Config
            config = Config()

            db_path = config.get('geoip', 'database_path')
            if db_path and os.path.exists(db_path):
                self.reader = geoip_db.Reader(db_path)
                self.enabled = True
                print(f"[GeoIP] Database loaded: {db_path}")
            else:
                print("[GeoIP] Database not found. GeoIP lookup disabled.")
                print("[GeoIP] Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")

        except ImportError:
            print("[GeoIP] geoip2 module not installed. Run: pip install geoip2")
        except Exception as e:
            print(f"[GeoIP] Error loading database: {e}")

    def lookup(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Lookup geographic information for an IP address

        Args:
            ip_address: IP address to lookup

        Returns:
            Dictionary with country, city, country_code, etc.
        """
        result = {
            'country': None,
            'country_code': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
        }

        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            result['country'] = 'Private Network'
            result['country_code'] = 'XX'
            return result

        if not self.enabled or not self.reader:
            return result

        try:
            response = self.reader.city(ip_address)

            result['country'] = response.country.name
            result['country_code'] = response.country.iso_code
            result['city'] = response.city.name
            result['latitude'] = response.location.latitude
            result['longitude'] = response.location.longitude
            result['timezone'] = response.location.time_zone

        except Exception as e:
            # IP not found in database
            pass

        return result

    def get_country(self, ip_address: str) -> Optional[str]:
        """Get just the country name for an IP"""
        return self.lookup(ip_address).get('country')

    def get_country_code(self, ip_address: str) -> Optional[str]:
        """Get just the country code for an IP"""
        return self.lookup(ip_address).get('country_code')

    def get_location(self, ip_address: str) -> Tuple[Optional[float], Optional[float]]:
        """Get latitude and longitude for an IP"""
        info = self.lookup(ip_address)
        return info.get('latitude'), info.get('longitude')

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/local"""
        private_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.',
            '0.',
            '169.254.',  # Link-local
        ]

        for prefix in private_ranges:
            if ip_address.startswith(prefix):
                return True

        return ip_address in ['localhost', '::1']

    def close(self) -> None:
        """Close the database reader"""
        if self.reader:
            self.reader.close()
            self.reader = None
            self.enabled = False


# Global GeoIP instance
geoip = GeoIPLookup()
