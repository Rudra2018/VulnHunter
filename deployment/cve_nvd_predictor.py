
import os
import json
import logging
import joblib
import pandas as pd
import numpy as np
from google.cloud import storage
from typing import Dict, List, Any

class VulnHunterCveNvdPredictor:
    """Custom predictor for cve_nvd vulnerability detection"""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_columns = []
        self.model_loaded = False
        self.logger = logging.getLogger(__name__)

    def load(self, artifacts_uri: str):
        """Load model artifacts from GCS"""
        try:
            # Download model from GCS
            client = storage.Client()
            bucket_name = artifacts_uri.split("/")[2]
            model_path = "/".join(artifacts_uri.split("/")[3:])

            bucket = client.bucket(bucket_name)
            blob = bucket.blob(model_path + "/model.joblib")
            blob.download_to_filename("model.joblib")

            # Load model artifacts
            model_data = joblib.load("model.joblib")
            self.model = model_data["model"]
            self.scaler = model_data.get("scaler")
            self.label_encoders = model_data.get("label_encoders", {})
            self.feature_columns = model_data["feature_columns"]

            self.model_loaded = True
            self.logger.info("Model loaded successfully")

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise

    def predict(self, instances: List[Dict[str, Any]]) -> Dict[str, List]:
        """Make predictions on input instances"""
        if not self.model_loaded:
            raise ValueError("Model not loaded")

        try:
            # Convert instances to DataFrame
            df = pd.DataFrame(instances)

            # Encode categorical variables
            for col, encoder in self.label_encoders.items():
                if col in df.columns:
                    df[col] = encoder.transform(df[col].astype(str))

            # Prepare features
            X = df[self.feature_columns].fillna(0)

            # Scale features if scaler is available
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X

            # Make predictions
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)

            # Format results
            results = {
                "predictions": predictions.tolist(),
                "probabilities": probabilities.tolist(),
                "model_name": "cve_nvd",
                "feature_count": len(self.feature_columns),
                "prediction_timestamp": pd.Timestamp.now().isoformat()
            }

            return results

        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            raise

# Global predictor instance
_predictor = None

def load_predictor(artifacts_uri: str):
    """Load predictor instance"""
    global _predictor
    _predictor = VulnHunterCveNvdPredictor()
    _predictor.load(artifacts_uri)

def predict(instances: List[Dict[str, Any]]) -> Dict[str, List]:
    """Prediction endpoint"""
    if _predictor is None:
        raise ValueError("Predictor not loaded")
    return _predictor.predict(instances)
