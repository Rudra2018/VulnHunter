#!/usr/bin/env python3
"""
VulnHunter V5 CPU-optimized training script for Azure ML
Trains on the full 64K+ dataset with target F1 > 0.95
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import json
import os
import sys
import argparse
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def prepare_data(data_path: str, target_f1: float = 0.95):
    """Load and prepare the full dataset for training"""
    logger.info(f"Loading dataset from {data_path}")

    # Load the full dataset
    if data_path.endswith('.parquet'):
        df = pd.read_parquet(data_path)
    else:
        df = pd.read_csv(data_path)

    logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")

    # Separate features and target
    feature_cols = [col for col in df.columns if col not in ['is_vulnerable', 'code', 'file_path', 'language', 'vulnerability_type']]

    X = df[feature_cols]
    y = df['is_vulnerable'] if 'is_vulnerable' in df.columns else df.get('vulnerable', 0)

    # Handle categorical columns
    categorical_cols = X.select_dtypes(include=['object']).columns
    if len(categorical_cols) > 0:
        logger.info(f"Encoding categorical columns: {list(categorical_cols)}")
        le = LabelEncoder()
        for col in categorical_cols:
            X[col] = le.fit_transform(X[col].astype(str))

    # Handle missing values
    X = X.fillna(0)

    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Target distribution: {pd.Series(y).value_counts().to_dict()}")

    return X, y, feature_cols

def train_models(X, y, target_f1: float = 0.95):
    """Train multiple models and select the best one"""

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale features for some models
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        'RandomForest': {
            'model': RandomForestClassifier(random_state=42, n_jobs=-1),
            'params': {
                'n_estimators': [100, 200, 500],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            },
            'use_scaled': False
        },
        'GradientBoosting': {
            'model': GradientBoostingClassifier(random_state=42),
            'params': {
                'n_estimators': [100, 200],
                'learning_rate': [0.01, 0.1, 0.2],
                'max_depth': [3, 5, 7]
            },
            'use_scaled': False
        },
        'LogisticRegression': {
            'model': LogisticRegression(random_state=42, max_iter=1000),
            'params': {
                'C': [0.1, 1, 10],
                'penalty': ['l1', 'l2'],
                'solver': ['liblinear']
            },
            'use_scaled': True
        }
    }

    best_model = None
    best_score = 0
    best_name = ""
    model_results = {}

    for name, config in models.items():
        logger.info(f"\n🔄 Training {name}...")

        # Use appropriate data
        X_tr = X_train_scaled if config['use_scaled'] else X_train
        X_te = X_test_scaled if config['use_scaled'] else X_test

        # Grid search for best parameters
        grid_search = GridSearchCV(
            config['model'],
            config['params'],
            cv=5,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )

        grid_search.fit(X_tr, y_train)

        # Get best model
        model = grid_search.best_estimator_

        # Predictions
        y_pred = model.predict(X_te)

        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')

        model_results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'best_params': grid_search.best_params_
        }

        logger.info(f"📊 {name} Results:")
        logger.info(f"   Accuracy: {accuracy:.4f}")
        logger.info(f"   Precision: {precision:.4f}")
        logger.info(f"   Recall: {recall:.4f}")
        logger.info(f"   F1 Score: {f1:.4f}")
        logger.info(f"   Best params: {grid_search.best_params_}")

        # Track best model
        if f1 > best_score:
            best_score = f1
            best_model = model
            best_name = name

    logger.info(f"\n🏆 Best model: {best_name} with F1 score: {best_score:.4f}")

    # Final evaluation with detailed metrics
    X_te_final = X_test_scaled if models[best_name]['use_scaled'] else X_test
    y_pred_final = best_model.predict(X_te_final)

    logger.info("\n📋 Final Classification Report:")
    logger.info(f"\\n{classification_report(y_test, y_pred_final)}")

    # Feature importance (if available)
    if hasattr(best_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)

        logger.info("\\n🔍 Top 10 Most Important Features:")
        for idx, row in feature_importance.head(10).iterrows():
            logger.info(f"   {row['feature']}: {row['importance']:.4f}")

    return best_model, scaler if models[best_name]['use_scaled'] else None, model_results, best_score

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 CPU Training')
    parser.add_argument('--data-path', default='./data/production/vulnhunter_v5_full_dataset.csv', help='Path to dataset')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory')
    parser.add_argument('--target-f1', type=float, default=0.95, help='Target F1 score')

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 Starting VulnHunter V5 CPU-Optimized Training")
    logger.info("=" * 50)

    try:
        # Load and prepare data
        X, y, feature_cols = prepare_data(args.data_path, args.target_f1)

        # Train models
        best_model, scaler, model_results, final_f1 = train_models(X, y, args.target_f1)

        # Save model and artifacts
        model_path = output_dir / 'vulnhunter_v5_model.joblib'
        joblib.dump(best_model, model_path)
        logger.info(f"✅ Model saved to {model_path}")

        if scaler:
            scaler_path = output_dir / 'scaler.joblib'
            joblib.dump(scaler, scaler_path)
            logger.info(f"✅ Scaler saved to {scaler_path}")

        # Save feature names
        features_path = output_dir / 'feature_names.json'
        with open(features_path, 'w') as f:
            json.dump(list(feature_cols), f)

        # Save training results
        results = {
            'final_f1_score': final_f1,
            'target_f1_achieved': final_f1 >= args.target_f1,
            'dataset_size': len(X),
            'feature_count': len(feature_cols),
            'model_results': model_results
        }

        results_path = output_dir / 'training_results.json'
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)

        logger.info("\\n" + "=" * 50)
        logger.info("🎯 TRAINING SUMMARY")
        logger.info("=" * 50)
        logger.info(f"📊 Dataset size: {len(X):,} samples")
        logger.info(f"🔧 Features: {len(feature_cols)} total")
        logger.info(f"🎯 Final F1 Score: {final_f1:.4f}")
        logger.info(f"✅ Target F1 ({args.target_f1}) achieved: {final_f1 >= args.target_f1}")
        logger.info(f"💾 Model saved to: {model_path}")
        logger.info("=" * 50)

        # Exit with appropriate code
        if final_f1 >= args.target_f1:
            logger.info("🎉 Training completed successfully!")
            sys.exit(0)
        else:
            logger.warning(f"⚠️  Target F1 score not achieved. Got {final_f1:.4f}, wanted {args.target_f1}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"❌ Training failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()