#!/usr/bin/env python3
"""
Production VulnHunter V4 Trainer for Vertex AI
Enhanced training script optimized for real Vertex AI deployment
"""

import os
import json
import logging
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib

from google.cloud import storage
from google.cloud import aiplatform

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductionVulnHunterV4Trainer:
    """
    Production-ready VulnHunter V4 trainer for Vertex AI deployment.
    """

    def __init__(self, project_id: str, location: str, bucket_name: str):
        """Initialize the production trainer."""
        self.project_id = project_id
        self.location = location
        self.bucket_name = bucket_name

        # Initialize Vertex AI and GCS
        aiplatform.init(project=project_id, location=location)
        self.storage_client = storage.Client(project=project_id)

        # Model configuration
        self.config = {
            "model_version": "VulnHunter_V4_Production",
            "training_timestamp": datetime.now().isoformat(),
            "false_positive_penalty_weight": 15.0,  # Increased for production
            "framework_awareness_weight": 0.9,
            "source_validation_weight": 1.0,
            "market_reality_weight": 0.8,
            "target_false_positive_rate": 0.05,  # 5% max FP rate
            "confidence_threshold": 0.7
        }

        # Training hyperparameters
        self.hyperparameters = {
            "learning_rate": 0.0001,
            "batch_size": 64,
            "epochs": 150,
            "early_stopping_patience": 15,
            "dropout_rate": 0.3,
            "l2_regularization": 0.001,
            "validation_split": 0.2
        }

        logger.info(f"Initialized production trainer for project: {project_id}")

    def download_training_data(self, data_paths: List[str]) -> pd.DataFrame:
        """Download and consolidate training data from GCS."""
        logger.info("Downloading training data from GCS...")

        all_data = []
        bucket = self.storage_client.bucket(self.bucket_name)

        for gcs_path in data_paths:
            if gcs_path.startswith(f"gs://{self.bucket_name}/"):
                blob_name = gcs_path.replace(f"gs://{self.bucket_name}/", "")
                blob = bucket.blob(blob_name)

                try:
                    # Download and parse JSON data
                    content = blob.download_as_text()
                    data = json.loads(content)

                    # Parse different data formats
                    parsed_data = self._parse_training_file(data, blob_name)
                    all_data.extend(parsed_data)

                    logger.info(f"Loaded {len(parsed_data)} examples from {blob_name}")

                except Exception as e:
                    logger.warning(f"Failed to load {blob_name}: {e}")

        df = pd.DataFrame(all_data)
        logger.info(f"Total training examples: {len(df)}")

        return df

    def _parse_training_file(self, data: Dict, file_name: str) -> List[Dict]:
        """Parse training file into standardized format."""
        examples = []

        try:
            if "examples" in data:
                # Synthetic training data format
                for example in data["examples"]:
                    claim = example.get("claimed_vulnerability", {})
                    validation = example.get("validation_features", {})
                    labels = example.get("training_labels", {})

                    parsed_example = {
                        "source_file": file_name,
                        "learning_type": example.get("pattern_type", "synthetic"),
                        "claimed_severity": claim.get("severity", "Unknown"),
                        "actual_severity": example.get("reality", {}).get("actual_severity", "Unknown"),
                        "confidence_adjustment": labels.get("confidence_adjustment", 0.5),
                        "is_false_positive": labels.get("is_false_positive", False),
                        "pattern_type": claim.get("description", ""),
                        "framework_type": claim.get("framework", "unknown").lower(),
                        "file_exists": 1 if validation.get("file_exists", False) else 0,
                        "function_exists": 1 if validation.get("function_exists", False) else 0,
                        "has_security_controls": 1 if validation.get("has_security_controls", False) else 0,
                        "confidence": claim.get("confidence", 0.5),
                        "severity_encoded": self._encode_severity(claim.get("severity", "Unknown")),
                        "line_number": claim.get("line_number", 0),
                        "file_path": claim.get("file_path", "")
                    }
                    examples.append(parsed_example)

            elif "validation_learnings" in data:
                # Validation learning files
                for learning in data["validation_learnings"]:
                    severity_correction = learning.get("severity_correction", {})
                    pattern_detected = learning.get("pattern_detected", {})

                    example = {
                        "source_file": file_name,
                        "learning_type": learning.get("learning_type", "validation"),
                        "claimed_severity": severity_correction.get("claimed_severity", "Unknown"),
                        "actual_severity": severity_correction.get("actual_severity", "Unknown"),
                        "confidence_adjustment": severity_correction.get("confidence_reduction", 0.0),
                        "is_false_positive": severity_correction.get("actual_severity") == "None",
                        "pattern_type": pattern_detected.get("claim", ""),
                        "framework_type": self._extract_framework_type(learning),
                        "file_exists": 1 if self._check_file_existence_claim(learning) else 0,
                        "function_exists": 1 if self._check_function_existence_claim(learning) else 0,
                        "has_security_controls": 1 if self._check_security_controls(learning) else 0,
                        "confidence": np.random.uniform(0.5, 0.9),  # Mock confidence for historical data
                        "severity_encoded": self._encode_severity(severity_correction.get("claimed_severity", "Unknown")),
                        "line_number": 0,
                        "file_path": pattern_detected.get("location", "")
                    }
                    examples.append(example)

            elif "false_positive_patterns" in data:
                # False positive pattern files
                for pattern in data["false_positive_patterns"]:
                    for claim in pattern.get("false_claims", []):
                        example = {
                            "source_file": file_name,
                            "learning_type": "false_positive_pattern",
                            "claimed_severity": claim.get("severity_claimed", "Unknown"),
                            "actual_severity": claim.get("actual_severity", "None"),
                            "confidence_adjustment": 1.0,
                            "is_false_positive": True,
                            "pattern_type": claim.get("claim", ""),
                            "framework_type": "unknown",
                            "file_exists": 0,
                            "function_exists": 0,
                            "has_security_controls": 0,
                            "confidence": np.random.uniform(0.6, 0.9),
                            "severity_encoded": self._encode_severity(claim.get("severity_claimed", "Unknown")),
                            "line_number": 0,
                            "file_path": claim.get("file_reference", "")
                        }
                        examples.append(example)

        except Exception as e:
            logger.warning(f"Error parsing {file_name}: {e}")

        return examples

    def _encode_severity(self, severity: str) -> int:
        """Encode severity to numerical value."""
        severity_map = {
            "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0, "Unknown": 1
        }
        return severity_map.get(severity, 1)

    def _extract_framework_type(self, learning: Dict) -> str:
        """Extract framework type from learning data."""
        pattern = learning.get("pattern_detected", {})
        code_evidence = pattern.get("code_evidence", "").lower()

        if "express" in code_evidence:
            return "express"
        elif "typescript" in code_evidence:
            return "typescript"
        elif "react" in code_evidence:
            return "react"
        elif "gin" in code_evidence:
            return "gin"
        else:
            return "unknown"

    def _check_file_existence_claim(self, learning: Dict) -> bool:
        """Check if the claimed file exists."""
        pattern = learning.get("pattern_detected", {})
        location = pattern.get("location", "")

        # Known fabricated patterns
        fabricated_patterns = [
            "file-operations.ts", "config-parser.ts", "endpoints.ts", "middleware.ts"
        ]
        return not any(fab in location for fab in fabricated_patterns)

    def _check_function_existence_claim(self, learning: Dict) -> bool:
        """Check if the claimed function exists."""
        pattern = learning.get("pattern_detected", {})
        claim = pattern.get("claim", "").lower()

        fictional_functions = [
            "executecommand", "readuserfile", "mergeuserconfig", "handleapirequest"
        ]
        return not any(func in claim for func in fictional_functions)

    def _check_security_controls(self, learning: Dict) -> bool:
        """Check if security controls are present."""
        pattern = learning.get("pattern_detected", {})
        controls = (
            pattern.get("security_controls", []) +
            pattern.get("mitigation_controls", []) +
            pattern.get("framework_protections", [])
        )
        return len(controls) > 0

    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Prepare features for training with enhanced feature engineering."""
        logger.info("Preparing features for production training...")

        # Fill missing values
        df = df.fillna(0)

        # Create label encoders
        self.label_encoders = {}

        # Encode categorical features
        categorical_features = ['learning_type', 'framework_type']
        for feature in categorical_features:
            if feature in df.columns:
                le = LabelEncoder()
                unique_values = df[feature].fillna('unknown').astype(str)
                df[f'{feature}_encoded'] = le.fit_transform(unique_values)
                self.label_encoders[feature] = le

        # Enhanced feature engineering
        df['severity_mismatch'] = (df['claimed_severity'] != df['actual_severity']).astype(int)
        df['high_confidence'] = (df['confidence'] > 0.8).astype(int)
        df['framework_protection'] = df['has_security_controls']
        df['confidence_severity_ratio'] = df['confidence'] / (df['severity_encoded'] + 1)
        df['fabrication_score'] = (1 - df['file_exists']) + (1 - df['function_exists'])
        df['unrealistic_line_number'] = (df['line_number'] > 1000).astype(int)

        # File path analysis
        df['file_path_suspicious'] = df['file_path'].str.contains(
            'process-utils|file-operations|config-parser|endpoints', na=False
        ).astype(int)

        # Advanced features
        df['confidence_precision'] = df['confidence'].apply(
            lambda x: len(str(x).split('.')[-1]) if '.' in str(x) else 0
        )
        df['artificial_precision'] = (df['confidence_precision'] > 5).astype(int)

        # Select features for training
        feature_columns = [
            'confidence_adjustment', 'file_exists', 'function_exists',
            'has_security_controls', 'confidence', 'severity_encoded',
            'severity_mismatch', 'high_confidence', 'framework_protection',
            'confidence_severity_ratio', 'fabrication_score', 'unrealistic_line_number',
            'file_path_suspicious', 'artificial_precision'
        ]

        # Add encoded categorical features
        for feature in categorical_features:
            if f'{feature}_encoded' in df.columns:
                feature_columns.append(f'{feature}_encoded')

        # Prepare X and y
        X = df[feature_columns].values
        y = df['is_false_positive'].astype(int).values

        # Scale features
        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(X)

        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info(f"Target distribution: {np.bincount(y)}")
        logger.info(f"Features: {feature_columns}")

        return X, y, feature_columns

    def build_production_model(self, input_dim: int) -> keras.Model:
        """Build production-ready neural network model."""
        logger.info("Building production VulnHunter V4 model...")

        # Enhanced architecture with residual connections
        inputs = keras.layers.Input(shape=(input_dim,))

        # Feature extraction layers
        x = keras.layers.Dense(256, activation='relu')(inputs)
        x = keras.layers.BatchNormalization()(x)
        x = keras.layers.Dropout(self.hyperparameters["dropout_rate"])(x)

        # Residual block 1
        residual_1 = keras.layers.Dense(128, activation='relu')(x)
        residual_1 = keras.layers.BatchNormalization()(residual_1)
        residual_1 = keras.layers.Dropout(0.2)(residual_1)

        # Residual block 2
        residual_2 = keras.layers.Dense(128, activation='relu')(residual_1)
        residual_2 = keras.layers.BatchNormalization()(residual_2)
        residual_2 = keras.layers.Add()([residual_1, residual_2])  # Skip connection

        # Specialized branches
        source_validation = keras.layers.Dense(64, activation='relu', name='source_validation')(residual_2)
        framework_awareness = keras.layers.Dense(64, activation='relu', name='framework_awareness')(residual_2)
        statistical_analysis = keras.layers.Dense(64, activation='relu', name='statistical_analysis')(residual_2)

        # Attention mechanism
        attention_weights = keras.layers.Dense(3, activation='softmax')(residual_2)
        attention_weights = keras.layers.Reshape((3, 1))(attention_weights)

        # Combine specialized branches with attention
        combined_features = keras.layers.Concatenate()([source_validation, framework_awareness, statistical_analysis])
        combined_features = keras.layers.Reshape((3, 64))(combined_features)
        attended_features = keras.layers.Multiply()([combined_features, attention_weights])
        attended_features = keras.layers.GlobalAveragePooling1D()(attended_features)

        # Final classification layers
        x = keras.layers.Dense(32, activation='relu')(attended_features)
        x = keras.layers.Dropout(0.2)(x)

        outputs = keras.layers.Dense(1, activation='sigmoid', name='false_positive_detection')(x)

        model = keras.Model(inputs=inputs, outputs=outputs)

        # Custom loss function with heavy false positive penalty
        def weighted_focal_loss(y_true, y_pred):
            alpha = 0.25
            gamma = 2.0
            fp_penalty = self.config["false_positive_penalty_weight"]

            # Focal loss component
            ce_loss = keras.losses.binary_crossentropy(y_true, y_pred)
            p_t = y_true * y_pred + (1 - y_true) * (1 - y_pred)
            alpha_t = y_true * alpha + (1 - y_true) * (1 - alpha)
            focal_loss = alpha_t * tf.pow(1 - p_t, gamma) * ce_loss

            # Additional penalty for false positives (predicting negative when positive)
            fp_loss = fp_penalty * y_true * tf.math.log(1 - y_pred + 1e-7)

            return focal_loss - fp_loss

        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(
                learning_rate=self.hyperparameters["learning_rate"]
            ),
            loss=weighted_focal_loss,
            metrics=[
                'accuracy',
                'precision',
                'recall',
                keras.metrics.AUC(name='auc'),
                keras.metrics.FalsePositiveRate(name='fpr'),
                keras.metrics.FalseNegativeRate(name='fnr')
            ]
        )

        logger.info("Production model architecture:")
        model.summary()

        return model

    def train_production_model(self, X: np.ndarray, y: np.ndarray,
                             feature_names: List[str]) -> keras.Model:
        """Train the production model with advanced techniques."""
        logger.info("Starting production model training...")

        # Stratified split to maintain class balance
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=self.hyperparameters["validation_split"],
            random_state=42, stratify=y
        )

        # Build model
        model = self.build_production_model(X.shape[1])

        # Advanced callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.hyperparameters["early_stopping_patience"],
                restore_best_weights=True,
                verbose=1
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=7,
                min_lr=1e-7,
                verbose=1
            ),
            keras.callbacks.ModelCheckpoint(
                '/tmp/best_model.h5',
                monitor='val_auc',
                save_best_only=True,
                mode='max',
                verbose=1
            ),
            # Custom callback for false positive rate monitoring
            keras.callbacks.LambdaCallback(
                on_epoch_end=lambda epoch, logs: logger.info(
                    f"Epoch {epoch}: FPR={logs.get('val_fpr', 0):.4f}, "
                    f"FNR={logs.get('val_fnr', 0):.4f}, "
                    f"AUC={logs.get('val_auc', 0):.4f}"
                )
            )
        ]

        # Class weights to handle imbalance
        class_weights = {
            0: 1.0,  # True positives
            1: len(y_train[y_train == 0]) / len(y_train[y_train == 1])  # False positives
        }

        logger.info(f"Class weights: {class_weights}")

        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=self.hyperparameters["epochs"],
            batch_size=self.hyperparameters["batch_size"],
            callbacks=callbacks,
            class_weight=class_weights,
            verbose=1
        )

        # Evaluate model
        val_predictions = model.predict(X_val)
        val_predictions_binary = (val_predictions > self.config["confidence_threshold"]).astype(int)

        # Detailed evaluation
        auc_score = roc_auc_score(y_val, val_predictions)
        class_report = classification_report(y_val, val_predictions_binary)
        confusion_mat = confusion_matrix(y_val, val_predictions_binary)

        logger.info("Production Model Evaluation:")
        logger.info(f"AUC Score: {auc_score:.4f}")
        logger.info(f"Classification Report:\n{class_report}")
        logger.info(f"Confusion Matrix:\n{confusion_mat}")

        # Calculate false positive rate
        fp_rate = confusion_mat[0, 1] / (confusion_mat[0, 0] + confusion_mat[0, 1])
        logger.info(f"False Positive Rate: {fp_rate:.4f}")

        # Save training metadata
        self.training_metadata = {
            "auc_score": float(auc_score),
            "false_positive_rate": float(fp_rate),
            "training_samples": len(X_train),
            "validation_samples": len(X_val),
            "feature_names": feature_names,
            "class_weights": class_weights,
            "final_epoch": len(history.history['loss'])
        }

        return model

    def save_production_artifacts(self, model: keras.Model, feature_names: List[str]) -> str:
        """Save production model artifacts to GCS."""
        logger.info("Saving production artifacts...")

        # Local temporary directory
        local_artifacts_dir = "/tmp/vulnhunter_v4_artifacts"
        Path(local_artifacts_dir).mkdir(exist_ok=True)

        # Save model
        model_path = f"{local_artifacts_dir}/vulnhunter_v4_production_model.h5"
        model.save(model_path)

        # Save preprocessing artifacts
        scaler_path = f"{local_artifacts_dir}/feature_scaler.pkl"
        encoders_path = f"{local_artifacts_dir}/label_encoders.pkl"
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.label_encoders, encoders_path)

        # Save configuration and metadata
        config_data = {
            **self.config,
            **self.hyperparameters,
            "training_metadata": self.training_metadata,
            "feature_names": feature_names
        }

        config_path = f"{local_artifacts_dir}/production_config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2, default=str)

        # Upload to GCS
        bucket = self.storage_client.bucket(self.bucket_name)
        gcs_model_dir = f"models/vulnhunter_v4_production_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        artifacts_uploaded = []
        for file_path in [model_path, scaler_path, encoders_path, config_path]:
            file_name = Path(file_path).name
            blob = bucket.blob(f"{gcs_model_dir}/{file_name}")
            blob.upload_from_filename(file_path)

            gcs_uri = f"gs://{self.bucket_name}/{gcs_model_dir}/{file_name}"
            artifacts_uploaded.append(gcs_uri)
            logger.info(f"Uploaded {file_name} to {gcs_uri}")

        logger.info(f"All artifacts uploaded to: gs://{self.bucket_name}/{gcs_model_dir}")
        return f"gs://{self.bucket_name}/{gcs_model_dir}"

    def run_production_training(self, training_data_paths: List[str]) -> str:
        """Run complete production training pipeline."""
        logger.info("Starting VulnHunter V4 Production Training...")

        try:
            # Load training data
            df = self.download_training_data(training_data_paths)

            # Prepare features
            X, y, feature_names = self.prepare_features(df)

            # Train model
            model = self.train_production_model(X, y, feature_names)

            # Save artifacts
            artifacts_path = self.save_production_artifacts(model, feature_names)

            logger.info("Production training completed successfully!")
            logger.info(f"Model artifacts: {artifacts_path}")

            return artifacts_path

        except Exception as e:
            logger.error(f"Production training failed: {str(e)}")
            raise

def main():
    """Main training function with argument parsing."""
    parser = argparse.ArgumentParser(description="VulnHunter V4 Production Training")
    parser.add_argument("--project_id", required=True, help="Google Cloud Project ID")
    parser.add_argument("--location", default="us-central1", help="Vertex AI location")
    parser.add_argument("--bucket_name", required=True, help="GCS bucket name")
    parser.add_argument("--training_data_paths", required=True,
                       help="Comma-separated list of GCS training data paths")

    args = parser.parse_args()

    # Parse training data paths
    data_paths = [path.strip() for path in args.training_data_paths.split(',')]

    # Initialize trainer
    trainer = ProductionVulnHunterV4Trainer(
        project_id=args.project_id,
        location=args.location,
        bucket_name=args.bucket_name
    )

    # Run training
    artifacts_path = trainer.run_production_training(data_paths)

    print(f"🎉 Training completed! Artifacts saved to: {artifacts_path}")

if __name__ == "__main__":
    main()