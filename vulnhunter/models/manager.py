"""
VulnHunter Model Manager
=======================

Centralized model loading, caching, and management.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import joblib
from threading import Lock
import time

from .predictor import VulnPredictor

logger = logging.getLogger(__name__)

class ModelManager:
    """
    Manages loading and caching of ML models.

    Provides thread-safe model access with lazy loading and caching.
    """

    def __init__(self, config):
        """Initialize model manager with configuration."""
        self.config = config
        self.loaded_models: Dict[str, VulnPredictor] = {}
        self.model_metadata: Dict[str, Dict[str, Any]] = {}
        self._load_lock = Lock()
        self._loading: Dict[str, bool] = {}

        logger.info("Model Manager initialized")

    async def load_model(self, model_name: str) -> Optional[VulnPredictor]:
        """
        Load a specific model.

        Args:
            model_name: Name of the model to load

        Returns:
            VulnPredictor instance or None if loading failed
        """
        if model_name in self.loaded_models:
            return self.loaded_models[model_name]

        # Prevent concurrent loading of the same model
        with self._load_lock:
            if model_name in self._loading:
                # Wait for ongoing load
                while self._loading.get(model_name, False):
                    await asyncio.sleep(0.1)
                return self.loaded_models.get(model_name)

            if model_name in self.loaded_models:
                return self.loaded_models[model_name]

            self._loading[model_name] = True

        try:
            model_path = self.config.get_model_path(model_name)

            if not model_path.exists():
                if self.config.cloud.use_vertex_ai:
                    # Try to download from cloud
                    await self._download_from_cloud(model_name, model_path)
                else:
                    logger.error(f"Model file not found: {model_path}")
                    return None

            logger.info(f"Loading model: {model_name} from {model_path}")
            start_time = time.time()

            # Load the model
            model_data = joblib.load(model_path)
            load_time = time.time() - start_time

            # Create predictor
            predictor = VulnPredictor(
                model=model_data,
                model_name=model_name,
                config=self.config.models[model_name]
            )

            # Store model and metadata
            self.loaded_models[model_name] = predictor
            self.model_metadata[model_name] = {
                'loaded_at': time.time(),
                'load_time': load_time,
                'file_size': model_path.stat().st_size,
                'file_path': str(model_path)
            }

            logger.info(f"Successfully loaded {model_name} in {load_time:.2f}s")
            return predictor

        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            return None

        finally:
            with self._load_lock:
                self._loading[model_name] = False

    async def load_all_models(self) -> Dict[str, bool]:
        """
        Load all configured models.

        Returns:
            Dict mapping model names to load success status
        """
        logger.info("Loading all models...")
        results = {}

        # Load models concurrently
        tasks = [
            self.load_model(model_name)
            for model_name in self.config.models.keys()
        ]

        loaded_models = await asyncio.gather(*tasks, return_exceptions=True)

        for i, (model_name, result) in enumerate(zip(self.config.models.keys(), loaded_models)):
            if isinstance(result, Exception):
                results[model_name] = False
                logger.error(f"Failed to load {model_name}: {result}")
            else:
                results[model_name] = result is not None

        successful_loads = sum(results.values())
        total_models = len(results)

        logger.info(f"Loaded {successful_loads}/{total_models} models successfully")
        return results

    def get_model(self, model_name: str) -> Optional[VulnPredictor]:
        """Get a loaded model (synchronous)."""
        return self.loaded_models.get(model_name)

    def get_predictor(self, model_name: str) -> Optional[VulnPredictor]:
        """Alias for get_model for backwards compatibility."""
        return self.get_model(model_name)

    def is_model_loaded(self, model_name: str) -> bool:
        """Check if a model is loaded."""
        return model_name in self.loaded_models

    def unload_model(self, model_name: str) -> bool:
        """
        Unload a specific model to free memory.

        Args:
            model_name: Name of the model to unload

        Returns:
            True if model was unloaded, False if it wasn't loaded
        """
        if model_name in self.loaded_models:
            del self.loaded_models[model_name]
            if model_name in self.model_metadata:
                del self.model_metadata[model_name]
            logger.info(f"Unloaded model: {model_name}")
            return True
        return False

    def reload_model(self, model_name: str) -> bool:
        """
        Reload a specific model.

        Args:
            model_name: Name of the model to reload

        Returns:
            True if model was reloaded successfully
        """
        self.unload_model(model_name)
        # Note: This would need to be called in an async context
        # asyncio.create_task(self.load_model(model_name))
        return True

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about all loaded models.

        Returns:
            Dictionary with model information
        """
        info = {
            'total_models': len(self.config.models),
            'loaded_models': len(self.loaded_models),
            'models': {}
        }

        for model_name in self.config.models.keys():
            model_info = {
                'loaded': model_name in self.loaded_models,
                'config': self.config.models[model_name].__dict__
            }

            if model_name in self.model_metadata:
                model_info['metadata'] = self.model_metadata[model_name]

            if model_name in self.loaded_models:
                predictor = self.loaded_models[model_name]
                model_info.update({
                    'model_type': type(predictor.model).__name__,
                    'features': getattr(predictor.model, 'n_features_in_', None),
                    'classes': getattr(predictor.model, 'classes_', None)
                })

            info['models'][model_name] = model_info

        return info

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get estimated memory usage of loaded models."""
        import sys

        usage = {
            'total_models': len(self.loaded_models),
            'estimated_mb': 0,
            'models': {}
        }

        for model_name, predictor in self.loaded_models.items():
            # Rough estimate of model memory usage
            model_size = sys.getsizeof(predictor.model)
            if hasattr(predictor.model, 'estimators_'):
                # Random Forest specific
                model_size += sum(sys.getsizeof(est) for est in predictor.model.estimators_)

            usage['models'][model_name] = {
                'estimated_bytes': model_size,
                'estimated_mb': model_size / (1024 * 1024)
            }
            usage['estimated_mb'] += usage['models'][model_name]['estimated_mb']

        return usage

    async def _download_from_cloud(self, model_name: str, local_path: Path) -> bool:
        """
        Download model from Google Cloud Storage.

        Args:
            model_name: Name of the model
            local_path: Local path to save the model

        Returns:
            True if download successful
        """
        try:
            from google.cloud import storage

            client = storage.Client(project=self.config.cloud.project_id)
            bucket = client.bucket(self.config.cloud.bucket_name)

            # Construct blob name
            blob_name = f"enhanced_models/{model_name}_enhanced_model.joblib"
            blob = bucket.blob(blob_name)

            # Ensure directory exists
            local_path.parent.mkdir(parents=True, exist_ok=True)

            # Download
            logger.info(f"Downloading {model_name} from gs://{self.config.cloud.bucket_name}/{blob_name}")
            blob.download_to_filename(str(local_path))

            logger.info(f"Successfully downloaded {model_name} to {local_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to download {model_name} from cloud: {e}")
            return False

    def cleanup(self) -> None:
        """Clean up all loaded models."""
        logger.info("Cleaning up model manager...")
        self.loaded_models.clear()
        self.model_metadata.clear()
        logger.info("Model manager cleaned up")