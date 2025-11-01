#!/usr/bin/env python3
"""
Configuration management for VulnHunter Professional
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Config:
    """VulnHunter Professional configuration"""

    # Core settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    max_file_size_mb: int = 50
    timeout_seconds: int = 300

    # Plugin settings
    plugin_dirs: List[str] = field(default_factory=list)
    enabled_plugins: List[str] = field(default_factory=list)
    disabled_plugins: List[str] = field(default_factory=list)

    # Analysis settings
    confidence_threshold: float = 0.5
    enable_mathematical_proofs: bool = True
    enable_exploit_generation: bool = False
    max_concurrent_analyses: int = 4

    # Output settings
    output_format: str = "json"  # json, sarif, html, xml
    output_file: Optional[str] = None
    include_source_code: bool = False
    redact_sensitive_data: bool = True

    # Performance settings
    memory_limit_mb: int = 2048
    enable_caching: bool = True
    cache_directory: str = "~/.vulnhunter/cache"

    # Security settings
    sandbox_analysis: bool = True
    network_access: bool = False
    allow_code_execution: bool = False

    # Integration settings
    github_token: Optional[str] = None
    jira_url: Optional[str] = None
    slack_webhook: Optional[str] = None

    # Advanced settings
    experimental_features: bool = False
    debug_mode: bool = False
    telemetry_enabled: bool = True

    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """Load configuration from file"""
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(path, 'r') as f:
            if path.suffix.lower() in ['.yaml', '.yml']:
                config_data = yaml.safe_load(f)
            elif path.suffix.lower() == '.json':
                config_data = json.load(f)
            else:
                raise ValueError(f"Unsupported configuration file format: {path.suffix}")

        return cls(**config_data)

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables"""
        config_data = {}

        # Map environment variables to config fields
        env_mapping = {
            'VULNHUNTER_LOG_LEVEL': 'log_level',
            'VULNHUNTER_LOG_FILE': 'log_file',
            'VULNHUNTER_MAX_FILE_SIZE_MB': 'max_file_size_mb',
            'VULNHUNTER_TIMEOUT_SECONDS': 'timeout_seconds',
            'VULNHUNTER_CONFIDENCE_THRESHOLD': 'confidence_threshold',
            'VULNHUNTER_OUTPUT_FORMAT': 'output_format',
            'VULNHUNTER_OUTPUT_FILE': 'output_file',
            'VULNHUNTER_MEMORY_LIMIT_MB': 'memory_limit_mb',
            'VULNHUNTER_CACHE_DIR': 'cache_directory',
            'VULNHUNTER_GITHUB_TOKEN': 'github_token',
            'VULNHUNTER_JIRA_URL': 'jira_url',
            'VULNHUNTER_SLACK_WEBHOOK': 'slack_webhook',
            'VULNHUNTER_EXPERIMENTAL': 'experimental_features',
            'VULNHUNTER_DEBUG': 'debug_mode',
            'VULNHUNTER_TELEMETRY': 'telemetry_enabled'
        }

        for env_var, config_field in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                if config_field in ['max_file_size_mb', 'timeout_seconds', 'memory_limit_mb']:
                    config_data[config_field] = int(value)
                elif config_field == 'confidence_threshold':
                    config_data[config_field] = float(value)
                elif config_field in ['experimental_features', 'debug_mode', 'telemetry_enabled']:
                    config_data[config_field] = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    config_data[config_field] = value

        # Handle list environment variables
        plugin_dirs = os.getenv('VULNHUNTER_PLUGIN_DIRS')
        if plugin_dirs:
            config_data['plugin_dirs'] = [d.strip() for d in plugin_dirs.split(',')]

        enabled_plugins = os.getenv('VULNHUNTER_ENABLED_PLUGINS')
        if enabled_plugins:
            config_data['enabled_plugins'] = [p.strip() for p in enabled_plugins.split(',')]

        return cls(**config_data)

    @classmethod
    def default(cls) -> 'Config':
        """Get default configuration"""
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)

    def to_file(self, config_path: str) -> None:
        """Save configuration to file"""
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        config_data = self.to_dict()

        with open(path, 'w') as f:
            if path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config_data, f, default_flow_style=False)
            elif path.suffix.lower() == '.json':
                json.dump(config_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported configuration file format: {path.suffix}")

    def update(self, **kwargs) -> None:
        """Update configuration with new values"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown configuration parameter: {key}")

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Validate numeric ranges
        if self.confidence_threshold < 0.0 or self.confidence_threshold > 1.0:
            errors.append("confidence_threshold must be between 0.0 and 1.0")

        if self.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")

        if self.timeout_seconds <= 0:
            errors.append("timeout_seconds must be positive")

        if self.memory_limit_mb <= 0:
            errors.append("memory_limit_mb must be positive")

        if self.max_concurrent_analyses <= 0:
            errors.append("max_concurrent_analyses must be positive")

        # Validate output format
        valid_formats = ['json', 'sarif', 'html', 'xml']
        if self.output_format not in valid_formats:
            errors.append(f"output_format must be one of: {', '.join(valid_formats)}")

        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level.upper() not in valid_log_levels:
            errors.append(f"log_level must be one of: {', '.join(valid_log_levels)}")

        # Validate paths
        if self.log_file:
            log_path = Path(self.log_file).parent
            if not log_path.exists():
                try:
                    log_path.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    errors.append(f"Cannot create log directory: {e}")

        return errors

    def get_cache_directory(self) -> Path:
        """Get expanded cache directory path"""
        return Path(self.cache_directory).expanduser()

    def setup_directories(self) -> None:
        """Create necessary directories"""
        # Create cache directory
        cache_dir = self.get_cache_directory()
        cache_dir.mkdir(parents=True, exist_ok=True)

        # Create log directory if log_file is specified
        if self.log_file:
            log_path = Path(self.log_file).parent
            log_path.mkdir(parents=True, exist_ok=True)