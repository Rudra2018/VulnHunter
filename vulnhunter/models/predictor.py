"""
VulnHunter Predictor
===================

Individual model prediction interface with confidence scoring.
"""

import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
import time

logger = logging.getLogger(__name__)

class VulnPredictor:
    """
    Wrapper for individual ML models with enhanced prediction capabilities.

    Provides prediction, confidence scoring, and feature importance analysis.
    """

    def __init__(self, model: Any, model_name: str, config: Any):
        """Initialize predictor with model and configuration."""
        self.model = model
        self.model_name = model_name
        self.config = config
        self.prediction_count = 0
        self.total_prediction_time = 0.0

        # Extract model capabilities
        self.has_predict_proba = hasattr(model, 'predict_proba')
        self.has_feature_importance = hasattr(model, 'feature_importances_')
        self.classes = getattr(model, 'classes_', None)

        logger.info(f"Predictor initialized for {model_name}")

    def predict(self, features: np.ndarray, return_confidence: bool = True) -> Dict[str, Any]:
        """
        Make prediction with optional confidence scoring.

        Args:
            features: Feature array for prediction
            return_confidence: Whether to include confidence scores

        Returns:
            Dictionary containing prediction results
        """
        start_time = time.time()

        try:
            # Validate input
            if not isinstance(features, np.ndarray):
                features = np.array(features)

            if features.ndim == 1:
                features = features.reshape(1, -1)

            # Make prediction
            prediction = self.model.predict(features)
            prediction_time = time.time() - start_time

            # Update statistics
            self.prediction_count += 1
            self.total_prediction_time += prediction_time

            result = {
                'model_name': self.model_name,
                'prediction': prediction.tolist(),
                'prediction_time': prediction_time,
                'timestamp': time.time()
            }

            # Add confidence scores if available
            if return_confidence and self.has_predict_proba:
                probabilities = self.model.predict_proba(features)
                confidence_scores = np.max(probabilities, axis=1)

                result.update({
                    'probabilities': probabilities.tolist(),
                    'confidence': confidence_scores.tolist(),
                    'meets_threshold': (confidence_scores >= self.config.confidence_threshold).tolist()
                })

                # Add risk assessment
                risk_level = self._assess_risk_level(confidence_scores[0], prediction[0])
                result['risk_level'] = risk_level

            # Add feature importance if available and requested
            if self.has_feature_importance:
                result['feature_importance'] = self.model.feature_importances_.tolist()

            return result

        except Exception as e:
            logger.error(f"Prediction failed for {self.model_name}: {e}")
            return {
                'model_name': self.model_name,
                'error': str(e),
                'timestamp': time.time()
            }

    def predict_batch(self, features_list: List[np.ndarray]) -> List[Dict[str, Any]]:
        """
        Make predictions for a batch of feature arrays.

        Args:
            features_list: List of feature arrays

        Returns:
            List of prediction results
        """
        results = []
        for features in features_list:
            result = self.predict(features)
            results.append(result)
        return results

    def get_feature_importance(self, top_k: Optional[int] = None) -> Optional[List[Tuple[int, float]]]:
        """
        Get feature importance scores.

        Args:
            top_k: Number of top features to return (None for all)

        Returns:
            List of (feature_index, importance) tuples sorted by importance
        """
        if not self.has_feature_importance:
            return None

        importances = self.model.feature_importances_
        indexed_importance = list(enumerate(importances))
        indexed_importance.sort(key=lambda x: x[1], reverse=True)

        if top_k is not None:
            indexed_importance = indexed_importance[:top_k]

        return indexed_importance

    def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about model usage and performance."""
        avg_prediction_time = (
            self.total_prediction_time / self.prediction_count
            if self.prediction_count > 0 else 0
        )

        return {
            'model_name': self.model_name,
            'prediction_count': self.prediction_count,
            'total_prediction_time': self.total_prediction_time,
            'average_prediction_time': avg_prediction_time,
            'has_predict_proba': self.has_predict_proba,
            'has_feature_importance': self.has_feature_importance,
            'classes': self.classes.tolist() if self.classes is not None else None,
            'n_features': getattr(self.model, 'n_features_in_', None)
        }

    def validate_features(self, features: np.ndarray) -> bool:
        """
        Validate feature array against model expectations.

        Args:
            features: Feature array to validate

        Returns:
            True if features are valid for this model
        """
        try:
            if not isinstance(features, np.ndarray):
                features = np.array(features)

            if features.ndim == 1:
                features = features.reshape(1, -1)

            expected_features = getattr(self.model, 'n_features_in_', None)
            if expected_features is not None and features.shape[1] != expected_features:
                logger.warning(
                    f"Feature count mismatch for {self.model_name}: "
                    f"expected {expected_features}, got {features.shape[1]}"
                )
                return False

            return True

        except Exception as e:
            logger.error(f"Feature validation failed for {self.model_name}: {e}")
            return False

    def _assess_risk_level(self, confidence: float, prediction: Any) -> str:
        """
        Assess risk level based on prediction and confidence.

        Args:
            confidence: Confidence score
            prediction: Model prediction

        Returns:
            Risk level string
        """
        # Convert prediction to vulnerability indicator
        is_vulnerable = bool(prediction) if isinstance(prediction, (int, bool)) else prediction > 0.5

        if not is_vulnerable:
            return "LOW"

        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def reset_stats(self) -> None:
        """Reset prediction statistics."""
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        logger.info(f"Reset statistics for {self.model_name}")

    def __repr__(self) -> str:
        """String representation of predictor."""
        return f"VulnPredictor(model={self.model_name}, predictions={self.prediction_count})"