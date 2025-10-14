"""
VulnHunter Configuration
=======================

Configuration management for VulnHunter platform.
"""

import os
from typing import Dict, Any, Optional
from pathlib import Path
import yaml
import json
from dataclasses import dataclass, asdict

@dataclass
class ModelConfig:
    """Configuration for individual models."""
    path: str
    confidence_threshold: float = 0.5
    max_features: Optional[int] = None
    preprocessing: Dict[str, Any] = None

    def __post_init__(self):
        if self.preprocessing is None:
            self.preprocessing = {}

@dataclass
class CloudConfig:
    """Cloud service configuration."""
    project_id: str = "quantumsentinel-20250927"
    region: str = "us-central1"
    bucket_name: str = "quantumsentinel-20250927-vulnhunter-enhanced"
    use_vertex_ai: bool = False
    credentials_path: Optional[str] = None

@dataclass
class APIConfig:
    """API configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    workers: int = 4
    max_request_size: int = 100 * 1024 * 1024  # 100MB
    rate_limit: int = 1000  # requests per minute

@dataclass
class AnalysisConfig:
    """Analysis configuration."""
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    timeout: int = 300  # 5 minutes
    max_concurrent: int = 10
    cache_results: bool = True
    cache_ttl: int = 3600  # 1 hour

class VulnHunterConfig:
    """
    Main configuration class for VulnHunter.

    Handles loading from files, environment variables, and provides defaults.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration."""
        self.config_path = config_path or Path("config/vulnhunter.yaml")

        # Initialize with defaults
        self.models = {
            'open_source_code': ModelConfig("enhanced_models/open_source_code_enhanced_model.joblib"),
            'http_requests': ModelConfig("enhanced_models/http_requests_enhanced_model.joblib"),
            'mobile_apps': ModelConfig("enhanced_models/mobile_apps_enhanced_model.joblib"),
            'executables': ModelConfig("enhanced_models/executables_enhanced_model.joblib"),
            'smart_contracts': ModelConfig("enhanced_models/smart_contracts_enhanced_model.joblib")
        }

        self.cloud = CloudConfig()
        self.api = APIConfig()
        self.analysis = AnalysisConfig()

        # Load configuration if file exists
        if self.config_path.exists():
            self.load_from_file()

        # Override with environment variables
        self._load_from_env()

    def load_from_file(self) -> None:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                if self.config_path.suffix.lower() == '.yaml':
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)

            self._update_from_dict(config_data)

        except Exception as e:
            print(f"Warning: Could not load config from {self.config_path}: {e}")

    def save_to_file(self) -> None:
        """Save current configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        config_data = self.to_dict()

        with open(self.config_path, 'w') as f:
            if self.config_path.suffix.lower() == '.yaml':
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            else:
                json.dump(config_data, f, indent=2)

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Cloud config
        if os.getenv('VULNHUNTER_PROJECT_ID'):
            self.cloud.project_id = os.getenv('VULNHUNTER_PROJECT_ID')
        if os.getenv('VULNHUNTER_REGION'):
            self.cloud.region = os.getenv('VULNHUNTER_REGION')
        if os.getenv('VULNHUNTER_BUCKET'):
            self.cloud.bucket_name = os.getenv('VULNHUNTER_BUCKET')
        if os.getenv('GOOGLE_APPLICATION_CREDENTIALS'):
            self.cloud.credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

        # API config
        if os.getenv('VULNHUNTER_HOST'):
            self.api.host = os.getenv('VULNHUNTER_HOST')
        if os.getenv('VULNHUNTER_PORT'):
            self.api.port = int(os.getenv('VULNHUNTER_PORT'))
        if os.getenv('VULNHUNTER_DEBUG'):
            self.api.debug = os.getenv('VULNHUNTER_DEBUG').lower() == 'true'

        # Analysis config
        if os.getenv('VULNHUNTER_MAX_FILE_SIZE'):
            self.analysis.max_file_size = int(os.getenv('VULNHUNTER_MAX_FILE_SIZE'))
        if os.getenv('VULNHUNTER_TIMEOUT'):
            self.analysis.timeout = int(os.getenv('VULNHUNTER_TIMEOUT'))

    def _update_from_dict(self, config_data: Dict[str, Any]) -> None:
        """Update configuration from dictionary."""
        if 'models' in config_data:
            for model_name, model_config in config_data['models'].items():
                if model_name in self.models:
                    if isinstance(model_config, str):
                        self.models[model_name].path = model_config
                    elif isinstance(model_config, dict):
                        for key, value in model_config.items():
                            setattr(self.models[model_name], key, value)

        if 'cloud' in config_data:
            for key, value in config_data['cloud'].items():
                if hasattr(self.cloud, key):
                    setattr(self.cloud, key, value)

        if 'api' in config_data:
            for key, value in config_data['api'].items():
                if hasattr(self.api, key):
                    setattr(self.api, key, value)

        if 'analysis' in config_data:
            for key, value in config_data['analysis'].items():
                if hasattr(self.analysis, key):
                    setattr(self.analysis, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'models': {name: asdict(config) for name, config in self.models.items()},
            'cloud': asdict(self.cloud),
            'api': asdict(self.api),
            'analysis': asdict(self.analysis)
        }

    def get_model_path(self, model_name: str) -> Path:
        """Get the path for a specific model."""
        if model_name not in self.models:
            raise ValueError(f"Unknown model: {model_name}")

        path = Path(self.models[model_name].path)

        # If relative path, make it relative to project root
        if not path.is_absolute():
            path = Path(__file__).parent.parent.parent / path

        return path

    def validate(self) -> bool:
        """Validate configuration."""
        try:
            # Check model files exist locally
            for model_name, model_config in self.models.items():
                model_path = self.get_model_path(model_name)
                if not model_path.exists() and not self.cloud.use_vertex_ai:
                    print(f"Warning: Model file not found: {model_path}")

            # Validate numeric values
            assert self.api.port > 0, "API port must be positive"
            assert self.analysis.max_file_size > 0, "Max file size must be positive"
            assert self.analysis.timeout > 0, "Timeout must be positive"

            return True

        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False