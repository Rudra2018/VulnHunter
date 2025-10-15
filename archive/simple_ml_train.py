#!/usr/bin/env python3
"""
Simple ML training script for VulnHunter V5 using sklearn
"""

import os
import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import logging
import json
import pickle
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def extract_simple_features(code, language):
    """Extract simple features from code"""
    features = []

    # Basic code metrics
    features.append(len(code))  # Code length
    features.append(code.count('('))  # Function calls
    features.append(code.count('if'))  # Conditionals
    features.append(code.count('for') + code.count('while'))  # Loops
    features.append(code.count('=') - code.count('=='))  # Assignments
    features.append(code.count('\n'))  # Line count
    features.append(code.count('{'))  # Blocks
    features.append(code.count('['))  # Array access

    # Vulnerability indicators
    features.append(1.0 if 'strcpy' in code else 0.0)  # Dangerous functions
    features.append(1.0 if 'malloc' in code else 0.0)  # Memory allocation
    features.append(1.0 if 'free' in code else 0.0)  # Memory deallocation
    features.append(1.0 if 'require' in code else 0.0)  # Solidity requires
    features.append(1.0 if '.call(' in code else 0.0)  # External calls
    features.append(1.0 if 'assert' in code else 0.0)  # Assertions
    features.append(1.0 if 'overflow' in code.lower() else 0.0)  # Overflow mentions

    # Language indicators
    features.append(1.0 if language == 'solidity' else 0.0)
    features.append(1.0 if language == 'c' else 0.0)
    features.append(1.0 if language == 'python' else 0.0)

    # Pattern analysis
    features.append(code.count('++'))  # Increment operations
    features.append(code.count('--'))  # Decrement operations

    return features


def train_model(data_path, output_dir):
    """Train the vulnerability detection model"""
    logger.info(f"Starting training with data from {data_path}")

    # Load data
    df = pd.read_csv(data_path)
    logger.info(f"Loaded dataset with {len(df)} samples")
    logger.info(f"Vulnerable samples: {sum(df['is_vulnerable'])}")
    logger.info(f"Non-vulnerable samples: {len(df) - sum(df['is_vulnerable'])}")

    # Extract features
    features = []
    labels = []

    for _, row in df.iterrows():
        feature_vector = extract_simple_features(row['code'], row['language'])
        features.append(feature_vector)
        labels.append(row['is_vulnerable'])

    # Convert to numpy arrays
    X = np.array(features)
    y = np.array(labels)

    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Feature statistics:")
    logger.info(f"  Mean: {np.mean(X, axis=0)[:5]}...")  # Show first 5 feature means
    logger.info(f"  Std: {np.std(X, axis=0)[:5]}...")   # Show first 5 feature stds

    # Split data (if we have enough samples)
    if len(df) > 2:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
    else:
        # Use all data for training and testing (small dataset)
        X_train = X_test = X
        y_train = y_test = y
        logger.warning("Very small dataset - using all data for both training and testing")

    logger.info(f"Training set size: {len(X_train)}")
    logger.info(f"Test set size: {len(X_test)}")

    # Train Random Forest model
    logger.info("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'  # Handle class imbalance
    )

    model.fit(X_train, y_train)

    # Make predictions
    train_predictions = model.predict(X_train)
    test_predictions = model.predict(X_test)

    # Calculate metrics
    train_accuracy = accuracy_score(y_train, train_predictions)
    test_accuracy = accuracy_score(y_test, test_predictions)

    test_precision = precision_score(y_test, test_predictions, zero_division=0)
    test_recall = recall_score(y_test, test_predictions, zero_division=0)
    test_f1 = f1_score(y_test, test_predictions, zero_division=0)

    # Log results
    logger.info(f"Training Results:")
    logger.info(f"  Training Accuracy: {train_accuracy:.4f}")
    logger.info(f"  Test Accuracy: {test_accuracy:.4f}")
    logger.info(f"  Test Precision: {test_precision:.4f}")
    logger.info(f"  Test Recall: {test_recall:.4f}")
    logger.info(f"  Test F1 Score: {test_f1:.4f}")

    # Detailed classification report
    logger.info("Classification Report:")
    logger.info(f"\n{classification_report(y_test, test_predictions)}")

    # Feature importance
    feature_names = [
        'code_length', 'function_calls', 'conditionals', 'loops', 'assignments',
        'line_count', 'blocks', 'array_access', 'strcpy', 'malloc', 'free',
        'require', 'external_calls', 'assert', 'overflow_mention',
        'is_solidity', 'is_c', 'is_python', 'increments', 'decrements'
    ]

    feature_importance = model.feature_importances_
    logger.info("Top 10 Most Important Features:")
    for i, (name, importance) in enumerate(sorted(zip(feature_names, feature_importance),
                                                  key=lambda x: x[1], reverse=True)[:10]):
        logger.info(f"  {i+1}. {name}: {importance:.4f}")

    # Save model
    model_path = os.path.join(output_dir, 'vulnhunter_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    logger.info(f"Model saved to {model_path}")

    # Save metrics
    metrics = {
        'train_accuracy': float(train_accuracy),
        'test_accuracy': float(test_accuracy),
        'test_precision': float(test_precision),
        'test_recall': float(test_recall),
        'test_f1': float(test_f1),
        'feature_importance': {name: float(imp) for name, imp in zip(feature_names, feature_importance)},
        'dataset_size': len(df),
        'vulnerable_samples': int(sum(df['is_vulnerable'])),
        'feature_count': len(feature_names)
    }

    metrics_path = os.path.join(output_dir, 'metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved to {metrics_path}")

    # Create a simple prediction example
    if len(df) > 0:
        sample_code = df.iloc[0]['code']
        sample_features = np.array([extract_simple_features(sample_code, df.iloc[0]['language'])])
        sample_prediction = model.predict(sample_features)[0]
        sample_probability = model.predict_proba(sample_features)[0]

        logger.info(f"Sample Prediction Example:")
        logger.info(f"  Code snippet: {sample_code[:100]}...")
        logger.info(f"  Prediction: {'Vulnerable' if sample_prediction else 'Safe'}")
        logger.info(f"  Probabilities: Safe={sample_probability[0]:.3f}, Vulnerable={sample_probability[1]:.3f}")

    return metrics


def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description='VulnHunter V5 Simple ML Training')
    parser.add_argument('--data-path', type=str, required=True,
                       help='Path to training dataset CSV file')
    parser.add_argument('--output-dir', type=str, default='./outputs',
                       help='Output directory for model and metrics')

    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Check if data file exists
    if not os.path.exists(args.data_path):
        logger.error(f"Data file not found: {args.data_path}")
        return

    # Train model
    logger.info("=== VulnHunter V5 Training Started ===")
    metrics = train_model(args.data_path, args.output_dir)
    logger.info("=== VulnHunter V5 Training Completed ===")

    logger.info(f"Final Results Summary:")
    logger.info(f"  F1 Score: {metrics['test_f1']:.4f}")
    logger.info(f"  Accuracy: {metrics['test_accuracy']:.4f}")
    logger.info(f"  Dataset Size: {metrics['dataset_size']} samples")


if __name__ == "__main__":
    main()