"""
Base Analyzer
============

Abstract base class for all VulnHunter analyzers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Union, Optional
import logging
import time
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.

    Provides common functionality for feature extraction, caching, and analysis.
    """

    def __init__(self, model_manager, analyzer_name: str):
        """Initialize base analyzer."""
        self.model_manager = model_manager
        self.analyzer_name = analyzer_name
        self.analysis_count = 0
        self.total_analysis_time = 0.0
        self.cache = {}  # Simple in-memory cache

        logger.info(f"Initialized {analyzer_name} analyzer")

    @abstractmethod
    async def analyze(self, target: Any, confidence_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze a target for vulnerabilities.

        Args:
            target: The target to analyze
            confidence_threshold: Minimum confidence threshold

        Returns:
            Analysis results dictionary
        """
        pass

    @abstractmethod
    def extract_features(self, target: Any) -> Dict[str, Any]:
        """
        Extract features from the target.

        Args:
            target: The target to extract features from

        Returns:
            Dictionary of extracted features
        """
        pass

    def _get_cache_key(self, target: Any) -> str:
        """Generate cache key for target."""
        if isinstance(target, str):
            content = target
        elif isinstance(target, bytes):
            content = target.hex()
        elif isinstance(target, Path):
            content = str(target) + str(target.stat().st_mtime if target.exists() else "")
        else:
            content = str(target)

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    async def _analyze_with_model(self,
                                  features: Dict[str, Any],
                                  model_name: str,
                                  confidence_threshold: float) -> Dict[str, Any]:
        """
        Analyze features using specified model.

        Args:
            features: Extracted features
            model_name: Name of model to use
            confidence_threshold: Confidence threshold

        Returns:
            Analysis results
        """
        start_time = time.time()

        try:
            # Get predictor
            predictor = self.model_manager.get_predictor(model_name)
            if not predictor:
                # Try to load the model
                predictor = await self.model_manager.load_model(model_name)
                if not predictor:
                    return {
                        'status': 'error',
                        'error': f'Model {model_name} not available',
                        'model': model_name
                    }

            # Convert features to array
            feature_array = self._features_to_array(features)

            # Make prediction
            prediction_result = predictor.predict(feature_array, return_confidence=True)

            # Update statistics
            analysis_time = time.time() - start_time
            self.analysis_count += 1
            self.total_analysis_time += analysis_time

            # Format results
            result = {
                'status': 'success',
                'analyzer': self.analyzer_name,
                'model': model_name,
                'analysis_time': analysis_time,
                'features_extracted': len(features),
                'prediction': prediction_result
            }

            # Add vulnerability assessment
            if 'confidence' in prediction_result:
                confidence = max(prediction_result['confidence'])
                is_vulnerable = bool(prediction_result['prediction'][0])
                meets_threshold = confidence >= confidence_threshold

                result.update({
                    'vulnerability_detected': is_vulnerable and meets_threshold,
                    'confidence_score': confidence,
                    'meets_threshold': meets_threshold,
                    'risk_assessment': self._assess_risk(confidence, is_vulnerable)
                })

            return result

        except Exception as e:
            logger.error(f"Analysis failed in {self.analyzer_name}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'analyzer': self.analyzer_name,
                'model': model_name,
                'analysis_time': time.time() - start_time
            }

    def _features_to_array(self, features: Dict[str, Any]) -> list:
        """
        Convert feature dictionary to array suitable for ML model.

        Args:
            features: Feature dictionary

        Returns:
            Feature array
        """
        # This should be overridden by specific analyzers to match their model's expected features
        return list(features.values())

    def _assess_risk(self, confidence: float, is_vulnerable: bool) -> Dict[str, Any]:
        """
        Assess risk level based on confidence and vulnerability status.

        Args:
            confidence: Confidence score
            is_vulnerable: Whether vulnerability was detected

        Returns:
            Risk assessment dictionary
        """
        if not is_vulnerable:
            level = "LOW"
            description = "No vulnerability detected"
        elif confidence >= 0.9:
            level = "CRITICAL"
            description = "High confidence vulnerability detected"
        elif confidence >= 0.7:
            level = "HIGH"
            description = "Likely vulnerability detected"
        elif confidence >= 0.5:
            level = "MEDIUM"
            description = "Possible vulnerability detected"
        else:
            level = "LOW"
            description = "Low confidence vulnerability indication"

        return {
            'level': level,
            'score': confidence,
            'description': description,
            'vulnerable': is_vulnerable
        }

    def get_analyzer_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        avg_analysis_time = (
            self.total_analysis_time / self.analysis_count
            if self.analysis_count > 0 else 0
        )

        return {
            'analyzer_name': self.analyzer_name,
            'analysis_count': self.analysis_count,
            'total_analysis_time': self.total_analysis_time,
            'average_analysis_time': avg_analysis_time,
            'cache_entries': len(self.cache)
        }

    def clear_cache(self) -> None:
        """Clear analysis cache."""
        self.cache.clear()
        logger.info(f"Cleared cache for {self.analyzer_name}")

    def reset_stats(self) -> None:
        """Reset analyzer statistics."""
        self.analysis_count = 0
        self.total_analysis_time = 0.0
        logger.info(f"Reset statistics for {self.analyzer_name}")

    async def validate_target(self, target: Any) -> bool:
        """
        Validate if target is suitable for this analyzer.

        Args:
            target: Target to validate

        Returns:
            True if target is valid for this analyzer
        """
        return True  # Default implementation accepts all targets