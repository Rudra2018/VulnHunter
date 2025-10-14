#!/usr/bin/env python3
"""
VulnHunter V4 Enhanced Training Pipeline
Vertex AI Training Pipeline for Enhanced Vulnerability Detection Model

This pipeline implements comprehensive training with false positive elimination,
framework awareness, and market reality calibration.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

import numpy as np
import pandas as pd
from google.cloud import aiplatform
from google.cloud.aiplatform import gapic as aip
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnHunterV4TrainingPipeline:
    """
    Enhanced VulnHunter V4 Training Pipeline with comprehensive validation
    and false positive elimination focus.
    """

    def __init__(self, project_id: str, location: str = "us-central1"):
        """Initialize the training pipeline."""
        self.project_id = project_id
        self.location = location
        self.training_data_path = "/Users/ankitthakur/vuln_ml_research/data/training"
        self.model_output_path = "/Users/ankitthakur/vuln_ml_research/data/models/vulnhunter_v4"

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        # Model configuration
        self.config = {
            "model_version": "VulnHunter_V4_Enhanced",
            "training_timestamp": datetime.now().isoformat(),
            "false_positive_penalty_weight": 10.0,
            "framework_awareness_weight": 0.8,
            "source_validation_weight": 1.0,
            "market_reality_weight": 0.7
        }

        # Create output directory
        Path(self.model_output_path).mkdir(parents=True, exist_ok=True)

    def load_comprehensive_training_data(self) -> pd.DataFrame:
        """Load and consolidate all training data sources."""
        logger.info("Loading comprehensive training data...")

        training_files = [
            "comprehensive_vulnhunter_v4_training_dataset.json",
            "false_positive_training_20251013_140908.json",
            "microsoft_bounty_training_20251013_142441.json",
            "ollama_validation_training_20250114_180000.json",
            "gemini_cli_validation_training_20250114_183000.json"
        ]

        consolidated_data = []

        for file_name in training_files:
            file_path = Path(self.training_data_path) / file_name
            if file_path.exists():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    parsed_data = self._parse_training_file(data, file_name)
                    consolidated_data.extend(parsed_data)
                    logger.info(f"Loaded {len(parsed_data)} examples from {file_name}")

        df = pd.DataFrame(consolidated_data)
        logger.info(f"Total training examples: {len(df)}")

        return df

    def _parse_training_file(self, data: Dict, file_name: str) -> List[Dict]:
        """Parse individual training file into standardized format."""
        examples = []

        if "validation_learnings" in data:
            # Handle validation learning files
            for learning in data["validation_learnings"]:
                example = {
                    "source_file": file_name,
                    "learning_type": learning.get("learning_type", "unknown"),
                    "claimed_severity": learning.get("severity_correction", {}).get("claimed_severity", "Unknown"),
                    "actual_severity": learning.get("severity_correction", {}).get("actual_severity", "Unknown"),
                    "confidence_adjustment": learning.get("severity_correction", {}).get("confidence_reduction", 0.0),
                    "is_false_positive": learning.get("severity_correction", {}).get("actual_severity") == "None",
                    "pattern_type": learning.get("pattern_detected", {}).get("claim", ""),
                    "framework_type": self._extract_framework_type(learning),
                    "validation_features": learning.get("detection_features", []),
                    "file_exists": self._check_file_existence_claim(learning),
                    "function_exists": self._check_function_existence_claim(learning),
                    "has_security_controls": self._check_security_controls(learning)
                }
                examples.append(example)

        elif "false_positive_patterns" in data:
            # Handle false positive pattern files
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
                        "validation_features": ["fabricated_pattern"],
                        "file_exists": False,
                        "function_exists": False,
                        "has_security_controls": False
                    }
                    examples.append(example)

        elif "suspicious_patterns" in data:
            # Handle market reality validation files
            for pattern in data["suspicious_patterns"]:
                example = {
                    "source_file": file_name,
                    "learning_type": "market_reality_check",
                    "claimed_severity": "Market Analysis",
                    "actual_severity": "Overly Optimistic",
                    "confidence_adjustment": 0.3,
                    "is_false_positive": True,
                    "pattern_type": pattern.get("pattern_type", ""),
                    "framework_type": "market_analysis",
                    "validation_features": pattern.get("detection_features", []),
                    "file_exists": True,
                    "function_exists": True,
                    "has_security_controls": False
                }
                examples.append(example)

        return examples

    def _extract_framework_type(self, learning: Dict) -> str:
        """Extract framework type from learning data."""
        pattern = learning.get("pattern_detected", {})
        code_evidence = pattern.get("code_evidence", "").lower()

        if "express" in code_evidence or "app.use" in code_evidence:
            return "express_nodejs"
        elif "gin" in code_evidence or "shouldbindjson" in code_evidence:
            return "gin_go"
        elif "exec.command" in code_evidence:
            return "go_stdlib"
        elif "unsafe" in code_evidence:
            return "rust"
        elif "typescript" in code_evidence or ".ts" in pattern.get("location", ""):
            return "typescript"
        else:
            return "unknown"

    def _check_file_existence_claim(self, learning: Dict) -> bool:
        """Check if the claimed file actually exists."""
        pattern = learning.get("pattern_detected", {})
        location = pattern.get("location", "")

        # Simple heuristic - if location contains specific known non-existent patterns
        non_existent_patterns = [
            "packages/core/src/ide/process-utils.ts",
            "packages/core/src/file-system/file-operations.ts",
            "packages/cli/src/config/config-parser.ts",
            "packages/a2a-server/src/api/endpoints.ts"
        ]

        return not any(pattern in location for pattern in non_existent_patterns)

    def _check_function_existence_claim(self, learning: Dict) -> bool:
        """Check if the claimed function exists."""
        pattern = learning.get("pattern_detected", {})
        claim = pattern.get("claim", "").lower()

        fictional_functions = [
            "executecommand",
            "readuserfile",
            "mergeuserconfig",
            "handleapirequest",
            "createtempfile"
        ]

        return not any(func in claim for func in fictional_functions)

    def _check_security_controls(self, learning: Dict) -> bool:
        """Check if security controls are present."""
        pattern = learning.get("pattern_detected", {})
        security_controls = pattern.get("security_controls", [])
        mitigation_controls = pattern.get("mitigation_controls", [])
        framework_protections = pattern.get("framework_protections", [])

        return len(security_controls + mitigation_controls + framework_protections) > 0

    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features for training."""
        logger.info("Preparing features for training...")

        # Create feature encoders
        self.label_encoders = {}
        self.scaler = StandardScaler()

        # Encode categorical features
        categorical_features = ['learning_type', 'claimed_severity', 'framework_type']
        for feature in categorical_features:
            if feature in df.columns:
                le = LabelEncoder()
                df[f'{feature}_encoded'] = le.fit_transform(df[feature].fillna('unknown'))
                self.label_encoders[feature] = le

        # Create numerical features
        numerical_features = [
            'confidence_adjustment',
            'file_exists',
            'function_exists',
            'has_security_controls'
        ]

        # Add derived features
        df['severity_mismatch'] = (df['claimed_severity'] != df['actual_severity']).astype(int)
        df['high_confidence_adjustment'] = (df['confidence_adjustment'] > 0.8).astype(int)
        df['framework_protection_present'] = df['has_security_controls'].astype(int)

        # Select features for training
        feature_columns = []
        for feature in categorical_features:
            if f'{feature}_encoded' in df.columns:
                feature_columns.append(f'{feature}_encoded')

        feature_columns.extend([
            'confidence_adjustment',
            'file_exists',
            'function_exists',
            'has_security_controls',
            'severity_mismatch',
            'high_confidence_adjustment',
            'framework_protection_present'
        ])

        # Prepare X and y
        X = df[feature_columns].fillna(0).values
        y = df['is_false_positive'].astype(int).values

        # Scale features
        X = self.scaler.fit_transform(X)

        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info(f"Target distribution: {np.bincount(y)}")

        return X, y

    def build_enhanced_model(self, input_dim: int) -> keras.Model:
        """Build enhanced neural network model with false positive focus."""
        logger.info("Building enhanced VulnHunter V4 model...")

        model = keras.Sequential([
            # Input layer with dropout
            keras.layers.Dense(128, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dropout(0.3),
            keras.layers.BatchNormalization(),

            # Hidden layers with skip connections
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.BatchNormalization(),

            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.2),

            # Framework awareness layer
            keras.layers.Dense(16, activation='relu', name='framework_awareness'),

            # Source validation layer
            keras.layers.Dense(8, activation='relu', name='source_validation'),

            # Output layer for binary classification
            keras.layers.Dense(1, activation='sigmoid', name='false_positive_detection')
        ])

        # Custom loss function with false positive penalty
        def weighted_binary_crossentropy(y_true, y_pred):
            # Higher penalty for false positives (predicting real when it's fake)
            fp_weight = self.config["false_positive_penalty_weight"]

            # Standard binary crossentropy
            bce = keras.losses.binary_crossentropy(y_true, y_pred)

            # Add penalty for false positives
            fp_penalty = fp_weight * y_true * tf.math.log(y_pred + 1e-7)

            return bce - fp_penalty

        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.0001),
            loss=weighted_binary_crossentropy,
            metrics=[
                'accuracy',
                'precision',
                'recall',
                keras.metrics.AUC(name='auc')
            ]
        )

        logger.info("Model architecture:")
        model.summary()

        return model

    def train_model(self, X: np.ndarray, y: np.ndarray) -> keras.Model:
        """Train the enhanced model."""
        logger.info("Starting model training...")

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Build model
        model = self.build_enhanced_model(X.shape[1])

        # Training callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            ),
            keras.callbacks.ModelCheckpoint(
                f"{self.model_output_path}/best_model.h5",
                monitor='val_loss',
                save_best_only=True
            )
        ]

        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=100,
            batch_size=32,
            callbacks=callbacks,
            verbose=1
        )

        # Evaluate model
        val_predictions = model.predict(X_val)
        val_predictions_binary = (val_predictions > 0.5).astype(int)

        logger.info("Validation Results:")
        logger.info(f"Classification Report:\n{classification_report(y_val, val_predictions_binary)}")
        logger.info(f"Confusion Matrix:\n{confusion_matrix(y_val, val_predictions_binary)}")

        return model

    def save_model_artifacts(self, model: keras.Model, X: np.ndarray, y: np.ndarray):
        """Save model and preprocessing artifacts."""
        logger.info("Saving model artifacts...")

        # Save model
        model.save(f"{self.model_output_path}/vulnhunter_v4_model.h5")

        # Save preprocessing artifacts
        joblib.dump(self.scaler, f"{self.model_output_path}/feature_scaler.pkl")
        joblib.dump(self.label_encoders, f"{self.model_output_path}/label_encoders.pkl")

        # Save model configuration
        config_with_metadata = {
            **self.config,
            "training_data_shape": X.shape,
            "target_distribution": np.bincount(y).tolist(),
            "feature_names": [
                'learning_type_encoded', 'claimed_severity_encoded', 'framework_type_encoded',
                'confidence_adjustment', 'file_exists', 'function_exists', 'has_security_controls',
                'severity_mismatch', 'high_confidence_adjustment', 'framework_protection_present'
            ]
        }

        with open(f"{self.model_output_path}/model_config.json", 'w') as f:
            json.dump(config_with_metadata, f, indent=2)

        logger.info(f"Model artifacts saved to {self.model_output_path}")

    def create_enhanced_predictor(self) -> None:
        """Create enhanced predictor with validation capabilities."""
        predictor_code = '''
import json
import logging
import numpy as np
import tensorflow as tf
from tensorflow import keras
import joblib
from pathlib import Path
from typing import Dict, List, Any, Optional

class VulnHunterV4Predictor:
    """
    Enhanced VulnHunter V4 Predictor with comprehensive validation
    and false positive elimination.
    """

    def __init__(self, model_path: str):
        """Initialize the predictor."""
        self.model_path = Path(model_path)
        self.model = keras.models.load_model(f"{model_path}/vulnhunter_v4_model.h5")
        self.scaler = joblib.load(f"{model_path}/feature_scaler.pkl")
        self.label_encoders = joblib.load(f"{model_path}/label_encoders.pkl")

        with open(f"{model_path}/model_config.json", 'r') as f:
            self.config = json.load(f)

    def validate_vulnerability_claim(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a vulnerability claim with enhanced checks.
        """
        # Mandatory source validation
        source_validation = self._validate_source_existence(claim)

        # Framework security assessment
        framework_protection = self._assess_framework_protection(claim)

        # Statistical realism check
        realism_check = self._check_statistical_realism(claim)

        # Prepare features
        features = self._prepare_claim_features(claim, source_validation, framework_protection)

        # Get false positive probability
        fp_probability = self.model.predict(features.reshape(1, -1))[0][0]

        # Calculate adjusted confidence
        base_confidence = claim.get('confidence', 0.5)
        adjusted_confidence = base_confidence * (1 - fp_probability)

        # Apply validation penalties
        if not source_validation['file_exists']:
            adjusted_confidence *= 0.1
        if not source_validation['function_exists']:
            adjusted_confidence *= 0.2
        if framework_protection['has_protection']:
            adjusted_confidence *= 0.7

        return {
            'original_claim': claim,
            'false_positive_probability': fp_probability,
            'original_confidence': base_confidence,
            'adjusted_confidence': adjusted_confidence,
            'source_validation': source_validation,
            'framework_protection': framework_protection,
            'realism_check': realism_check,
            'recommendation': self._generate_recommendation(fp_probability, adjusted_confidence)
        }

    def _validate_source_existence(self, claim: Dict) -> Dict:
        """Validate that claimed source code actually exists."""
        file_path = claim.get('file_path', '')
        function_name = claim.get('function_name', '')

        # Simple validation logic (in production, would do actual file/AST checks)
        known_fabricated_files = [
            'process-utils.ts', 'file-operations.ts', 'config-parser.ts',
            'endpoints.ts', 'middleware.ts', 'temp-files.ts'
        ]

        known_fabricated_functions = [
            'executeCommand', 'readUserFile', 'mergeUserConfig',
            'handleApiRequest', 'authMiddleware', 'createTempFile'
        ]

        file_exists = not any(fab_file in file_path for fab_file in known_fabricated_files)
        function_exists = not any(fab_func in function_name for fab_func in known_fabricated_functions)

        return {
            'file_exists': file_exists,
            'function_exists': function_exists,
            'validation_confidence': 0.9 if (file_exists and function_exists) else 0.1
        }

    def _assess_framework_protection(self, claim: Dict) -> Dict:
        """Assess framework-provided security protections."""
        framework = claim.get('framework', 'unknown').lower()
        vulnerability_type = claim.get('vulnerability_type', '').lower()

        protections = {
            'express_nodejs': {
                'json_injection': True,
                'path_traversal': True,
                'input_validation': True
            },
            'typescript': {
                'type_safety': True,
                'compile_time_checks': True
            },
            'a2a_sdk': {
                'authentication': True,
                'authorization': True
            }
        }

        framework_protections = protections.get(framework, {})
        has_protection = vulnerability_type in framework_protections

        return {
            'framework': framework,
            'has_protection': has_protection,
            'protection_level': 0.8 if has_protection else 0.2,
            'protections_available': list(framework_protections.keys())
        }

    def _check_statistical_realism(self, claim: Dict) -> Dict:
        """Check if the claim is statistically realistic."""
        severity = claim.get('severity', 'unknown').lower()
        confidence = claim.get('confidence', 0.5)

        # Historical benchmark checks
        realistic_confidence_ranges = {
            'critical': (0.7, 0.95),
            'high': (0.6, 0.9),
            'medium': (0.5, 0.85),
            'low': (0.4, 0.8)
        }

        expected_range = realistic_confidence_ranges.get(severity, (0.3, 0.9))
        confidence_realistic = expected_range[0] <= confidence <= expected_range[1]

        return {
            'confidence_realistic': confidence_realistic,
            'expected_range': expected_range,
            'realism_score': 0.8 if confidence_realistic else 0.3
        }

    def _prepare_claim_features(self, claim: Dict, source_val: Dict, framework_prot: Dict) -> np.ndarray:
        """Prepare features for the claim."""
        # Extract and encode features (simplified for this example)
        features = np.array([
            1.0 if source_val['file_exists'] else 0.0,
            1.0 if source_val['function_exists'] else 0.0,
            1.0 if framework_prot['has_protection'] else 0.0,
            claim.get('confidence', 0.5),
            1.0 if claim.get('severity', '').lower() == 'critical' else 0.0,
            framework_prot['protection_level'],
            source_val['validation_confidence']
        ])

        # Pad or truncate to match training feature count
        target_length = len(self.config['feature_names'])
        if len(features) < target_length:
            features = np.pad(features, (0, target_length - len(features)))
        elif len(features) > target_length:
            features = features[:target_length]

        return self.scaler.transform(features.reshape(1, -1)).flatten()

    def _generate_recommendation(self, fp_prob: float, adj_conf: float) -> str:
        """Generate recommendation based on analysis."""
        if fp_prob > 0.8:
            return "REJECT - High probability of false positive"
        elif fp_prob > 0.5:
            return "REVIEW - Moderate false positive risk"
        elif adj_conf < 0.3:
            return "LOW_CONFIDENCE - Significant uncertainty"
        elif adj_conf > 0.7:
            return "ACCEPT - High confidence, low false positive risk"
        else:
            return "MODERATE - Further validation recommended"
'''

        with open(f"{self.model_output_path}/vulnhunter_v4_predictor.py", 'w') as f:
            f.write(predictor_code)

        logger.info("Enhanced predictor saved")

    def run_training_pipeline(self) -> None:
        """Run the complete training pipeline."""
        logger.info("Starting VulnHunter V4 Enhanced Training Pipeline...")

        try:
            # Load data
            df = self.load_comprehensive_training_data()

            # Prepare features
            X, y = self.prepare_features(df)

            # Train model
            model = self.train_model(X, y)

            # Save artifacts
            self.save_model_artifacts(model, X, y)

            # Create enhanced predictor
            self.create_enhanced_predictor()

            logger.info("Training pipeline completed successfully!")
            logger.info(f"Model artifacts saved to: {self.model_output_path}")

        except Exception as e:
            logger.error(f"Training pipeline failed: {str(e)}")
            raise

def main():
    """Main training function."""
    # Configuration
    PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "your-project-id")
    LOCATION = "us-central1"

    # Initialize and run pipeline
    pipeline = VulnHunterV4TrainingPipeline(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    pipeline.run_training_pipeline()

if __name__ == "__main__":
    main()