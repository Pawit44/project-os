"""
Configuration management for Honeypot Security System
Loads and validates configuration from YAML file
"""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


class Config:
    """Configuration manager singleton"""

    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls) -> 'Config':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._config:
            self.load()

    def load(self, config_path: str = None) -> None:
        """Load configuration from YAML file"""
        if config_path is None:
            # Look for config in standard locations
            base_dir = Path(__file__).parent.parent
            possible_paths = [
                base_dir / 'config' / 'config.yaml',
                base_dir / 'config.yaml',
                Path('config/config.yaml'),
                Path('config.yaml'),
            ]

            for path in possible_paths:
                if path.exists():
                    config_path = str(path)
                    break
            else:
                # Use example config if no config found
                example_path = base_dir / 'config' / 'config.example.yaml'
                if example_path.exists():
                    config_path = str(example_path)
                    print(f"[WARNING] Using example config. Copy config.example.yaml to config.yaml")
                else:
                    raise FileNotFoundError("No configuration file found")

        with open(config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)

        # Resolve relative paths
        self._resolve_paths()

    def _resolve_paths(self) -> None:
        """Convert relative paths to absolute paths"""
        base_dir = Path(__file__).parent.parent

        path_keys = [
            ('honeypots', 'ssh', 'host_key'),
            ('geoip', 'database_path'),
            ('logging', 'main_log'),
            ('logging', 'attack_log'),
            ('database', 'path'),
        ]

        for keys in path_keys:
            try:
                value = self.get(*keys)
                if value and not os.path.isabs(value):
                    abs_path = str(base_dir / value)
                    self._set_nested(keys, abs_path)
            except (KeyError, TypeError):
                pass

    def _set_nested(self, keys: tuple, value: Any) -> None:
        """Set a nested dictionary value"""
        d = self._config
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value

    def get(self, *keys, default: Any = None) -> Any:
        """Get a configuration value by nested keys"""
        value = self._config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def get_honeypot_config(self, honeypot_type: str) -> Dict[str, Any]:
        """Get configuration for a specific honeypot"""
        return self.get('honeypots', honeypot_type, default={})

    def get_scoring_config(self) -> Dict[str, Any]:
        """Get threat scoring configuration"""
        return self.get('scoring', default={})

    def get_alerting_config(self) -> Dict[str, Any]:
        """Get alerting configuration"""
        return self.get('alerting', default={})

    def get_response_config(self) -> Dict[str, Any]:
        """Get auto-response configuration"""
        return self.get('response', default={})

    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get dashboard configuration"""
        return self.get('dashboard', default={})

    @property
    def database_path(self) -> str:
        """Get database file path"""
        return self.get('database', 'path', default='data/honeypot.db')

    @property
    def log_level(self) -> str:
        """Get logging level"""
        return self.get('logging', 'level', default='INFO')


# Global config instance
config = Config()
