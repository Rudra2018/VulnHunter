#!/usr/bin/env python3
"""
VulnHunter V4 SageMaker Training Script
Adapted from Vertex AI trainer for AWS SageMaker
"""

import os
import json
import argparse
import tensorflow as tf
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import pickle
import boto3
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow import keras
from tensorflow.keras import layers

class VulnHunterV4SageMakerTrainer:
    """Enhanced VulnHunter V4 trainer optimized for AWS SageMaker."""

    def __init__(self, args):
        """Initialize the trainer with SageMaker parameters."""
        self.args = args
        self.model_dir = args.model_dir
        self.train_dir = args.train
        self.validation_dir = args.validation if hasattr(args, 'validation') else None

        # Training configuration
        self.config = {
            "model_name": "vulnhunter_v4_sagemaker",
            "version": "4.0.0",
            "training_date": datetime.now().isoformat(),
            "architecture": "enhanced_neural_network",
            "false_positive_penalty_weight": 15.0,
            "framework_security_features": True,
            "attention_mechanism": True
        }

        # Hyperparameters
        self.hyperparameters = {
            "learning_rate": 0.001,
            "batch_size": 32,
            "epochs": 100,
            "dropout_rate": 0.3,
            "early_stopping_patience": 15,
            "reduce_lr_patience": 10
        }

        print(f"🚀 VulnHunter V4 SageMaker Training Initialized")
        print(f"   Model Directory: {self.model_dir}")
        print(f"   Training Data: {self.train_dir}")
        print(f"   Config: {self.config}")

    def load_training_data(self):
        """Load and preprocess training data from SageMaker input channels."""
        print("📚 Loading training data...")

        all_data = []

        # Load data from train channel
        train_files = list(Path(self.train_dir).glob("*.json"))
        print(f"Found {len(train_files)} training files")

        for file_path in train_files:
            print(f"Loading: {file_path.name}")
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_data.extend(data)
                    else:
                        all_data.append(data)
            except Exception as e:
                print(f"❌ Error loading {file_path}: {e}")

        print(f"✅ Loaded {len(all_data)} total examples")
        return all_data

    def extract_features(self, example):
        """Extract enhanced features for VulnHunter V4."""
        claim = example.get('claim', '')
        vulnerability_type = example.get('vulnerability_type', 'unknown')
        source_file = example.get('source_file', '')

        features = {
            # Basic features
            'claim_length': len(claim),
            'has_line_numbers': 1 if 'line' in claim.lower() or ':' in claim else 0,
            'has_file_path': 1 if '/' in claim or '\\' in claim else 0,
            'has_function_name': 1 if 'function' in claim.lower() or '()' in claim else 0,

            # Enhanced security features
            'mentions_framework': 1 if any(fw in claim.lower() for fw in ['express', 'react', 'typescript', 'node']) else 0,
            'has_security_terms': 1 if any(term in claim.lower() for term in ['vulnerability', 'exploit', 'injection', 'xss']) else 0,
            'mentions_protection': 1 if any(term in claim.lower() for term in ['sanitize', 'validate', 'escape', 'protect']) else 0,

            # Source validation features
            'source_exists': 1 if source_file and source_file != 'unknown' else 0,
            'has_detailed_location': 1 if ':' in source_file else 0,

            # Statistical realism features
            'artificial_confidence': 1 if 'definitely' in claim.lower() or 'certainly' in claim.lower() else 0,
            'generic_description': 1 if len(set(claim.lower().split())) < len(claim.split()) * 0.7 else 0,

            # Vulnerability type encoding
            'vuln_type_injection': 1 if 'injection' in vulnerability_type.lower() else 0,
            'vuln_type_xss': 1 if 'xss' in vulnerability_type.lower() else 0,
            'vuln_type_auth': 1 if 'auth' in vulnerability_type.lower() else 0,
            'vuln_type_traversal': 1 if 'traversal' in vulnerability_type.lower() else 0,

            # Framework-specific features
            'express_specific': 1 if 'express' in claim.lower() and ('req.' in claim or 'res.' in claim) else 0,
            'typescript_specific': 1 if 'typescript' in claim.lower() or '.ts' in claim else 0
        }

        return features

    def prepare_training_data(self, raw_data):
        """Prepare training data with enhanced feature engineering."""
        print("🔧 Preparing training data...")

        features_list = []
        labels = []

        for example in raw_data:
            features = self.extract_features(example)
            features_list.append(features)

            # Label: 1 for false positive, 0 for valid vulnerability
            is_false_positive = example.get('is_false_positive', False)
            labels.append(1 if is_false_positive else 0)

        # Convert to DataFrame
        df_features = pd.DataFrame(features_list)

        # Feature scaling
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(df_features)

        y = np.array(labels)

        print(f"✅ Prepared {len(X_scaled)} examples with {X_scaled.shape[1]} features")
        print(f"   False positives: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
        print(f"   Valid vulnerabilities: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")

        return X_scaled, y, df_features.columns.tolist()

    def create_enhanced_model(self, input_dim):
        """Create enhanced neural network with attention mechanism."""
        print("🏗️ Creating enhanced neural network...")

        # Input layer
        inputs = keras.layers.Input(shape=(input_dim,), name='vulnerability_features')

        # Enhanced architecture with residual connections
        x = keras.layers.Dense(256, activation='relu', name='dense_1')(inputs)
        x = keras.layers.BatchNormalization(name='batch_norm_1')(x)
        x = keras.layers.Dropout(self.hyperparameters["dropout_rate"], name='dropout_1')(x)

        # Residual block
        residual = x
        x = keras.layers.Dense(128, activation='relu', name='dense_2')(x)
        x = keras.layers.BatchNormalization(name='batch_norm_2')(x)
        x = keras.layers.Dropout(self.hyperparameters["dropout_rate"], name='dropout_2')(x)

        # Attention mechanism
        attention_weights = keras.layers.Dense(128, activation='softmax', name='attention')(x)
        x = keras.layers.Multiply(name='attention_applied')([x, attention_weights])

        # Add residual connection
        x = keras.layers.Add(name='residual_connection')([x, keras.layers.Dense(128)(residual)])

        # Output layers
        x = keras.layers.Dense(64, activation='relu', name='dense_3')(x)
        x = keras.layers.BatchNormalization(name='batch_norm_3')(x)
        x = keras.layers.Dropout(self.hyperparameters["dropout_rate"], name='dropout_3')(x)

        # Final classification layer
        outputs = keras.layers.Dense(1, activation='sigmoid', name='false_positive_prediction')(x)

        model = keras.Model(inputs=inputs, outputs=outputs, name='vulnhunter_v4_enhanced')

        # Custom weighted focal loss
        def weighted_focal_loss(y_true, y_pred):
            alpha = 0.25
            gamma = 2.0
            fp_penalty = self.config["false_positive_penalty_weight"]

            # Standard focal loss
            focal_loss = -alpha * y_true * tf.math.pow(1 - y_pred, gamma) * tf.math.log(y_pred + 1e-7) - \
                        (1 - alpha) * (1 - y_true) * tf.math.pow(y_pred, gamma) * tf.math.log(1 - y_pred + 1e-7)

            # Additional penalty for false positives
            fp_loss = fp_penalty * y_true * tf.math.log(1 - y_pred + 1e-7)

            return focal_loss + fp_loss

        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.hyperparameters["learning_rate"]),
            loss=weighted_focal_loss,
            metrics=['accuracy', 'precision', 'recall']
        )

        print(f"✅ Model created with {model.count_params()} parameters")
        return model

    def train_model(self, X, y, feature_names):
        """Train the VulnHunter V4 model."""
        print("🎯 Training VulnHunter V4 model...")

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Create model
        model = self.create_enhanced_model(X.shape[1])

        # Callbacks
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
                patience=self.hyperparameters["reduce_lr_patience"],
                min_lr=1e-7,
                verbose=1
            ),
            keras.callbacks.ModelCheckpoint(
                filepath=os.path.join(self.model_dir, 'best_model.h5'),
                monitor='val_loss',
                save_best_only=True,
                verbose=1
            )
        ]

        # Class weights for imbalanced data
        class_weight = {
            0: 1.0,  # Valid vulnerabilities
            1: self.config["false_positive_penalty_weight"]  # False positives
        }

        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=self.hyperparameters["epochs"],
            batch_size=self.hyperparameters["batch_size"],
            callbacks=callbacks,
            class_weight=class_weight,
            verbose=1
        )

        # Evaluate model
        print("📊 Evaluating model...")
        val_predictions = model.predict(X_val)
        val_pred_binary = (val_predictions > 0.5).astype(int)

        print("\\nClassification Report:")
        print(classification_report(y_val, val_pred_binary))

        # Save model and artifacts
        self.save_model_artifacts(model, feature_names, history)

        return model, history

    def save_model_artifacts(self, model, feature_names, history):
        """Save all model artifacts for SageMaker."""
        print("💾 Saving model artifacts...")

        # Save TensorFlow model
        model_path = os.path.join(self.model_dir, 'vulnhunter_v4_sagemaker_model.h5')
        model.save(model_path)
        print(f"✅ Model saved: {model_path}")

        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'feature_scaler.pkl')
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"✅ Scaler saved: {scaler_path}")

        # Save feature names
        features_path = os.path.join(self.model_dir, 'feature_names.json')
        with open(features_path, 'w') as f:
            json.dump(feature_names, f, indent=2)
        print(f"✅ Feature names saved: {features_path}")

        # Save configuration
        config_path = os.path.join(self.model_dir, 'sagemaker_config.json')
        with open(config_path, 'w') as f:
            json.dump({
                **self.config,
                **self.hyperparameters,
                "feature_names": feature_names,
                "model_path": model_path,
                "scaler_path": scaler_path
            }, f, indent=2)
        print(f"✅ Configuration saved: {config_path}")

        # Save training history
        history_path = os.path.join(self.model_dir, 'training_history.json')
        with open(history_path, 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            history_dict = {k: [float(x) for x in v] for k, v in history.history.items()}
            json.dump(history_dict, f, indent=2)
        print(f"✅ Training history saved: {history_path}")

def main():
    """Main training function for SageMaker."""
    parser = argparse.ArgumentParser(description='VulnHunter V4 SageMaker Training')

    # SageMaker specific arguments
    parser.add_argument('--model-dir', type=str, default=os.environ.get('SM_MODEL_DIR', '/opt/ml/model'))
    parser.add_argument('--train', type=str, default=os.environ.get('SM_CHANNEL_TRAIN', '/opt/ml/input/data/train'))
    parser.add_argument('--validation', type=str, default=os.environ.get('SM_CHANNEL_VALIDATION', '/opt/ml/input/data/validation'))

    # Training hyperparameters
    parser.add_argument('--epochs', type=int, default=100)
    parser.add_argument('--batch-size', type=int, default=32)
    parser.add_argument('--learning-rate', type=float, default=0.001)

    args = parser.parse_args()

    print("🚀 Starting VulnHunter V4 SageMaker Training")
    print("=" * 50)

    # Initialize trainer
    trainer = VulnHunterV4SageMakerTrainer(args)

    # Load and prepare data
    raw_data = trainer.load_training_data()
    X, y, feature_names = trainer.prepare_training_data(raw_data)

    # Train model
    model, history = trainer.train_model(X, y, feature_names)

    print("\\n" + "=" * 50)
    print("🎉 VulnHunter V4 SageMaker Training Complete!")
    print("=" * 50)
    print(f"📁 Model artifacts saved to: {args.model_dir}")
    print(f"📊 Training examples: {len(X)}")
    print(f"🎯 Final validation accuracy: {history.history['val_accuracy'][-1]:.3f}")

if __name__ == "__main__":
    main()