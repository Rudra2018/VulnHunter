#!/usr/bin/env python3
"""
VulnHunter V5 Azure ML Training - Simplified for fast training
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import json
import os
import argparse
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 Azure Training')
    parser.add_argument('--data-path', default='./data/production/vulnhunter_v5_full_dataset.csv')
    parser.add_argument('--output-dir', default='./outputs')
    parser.add_argument('--target-f1', type=float, default=0.95)

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 VulnHunter V5 Azure ML Training")
    logger.info("=" * 40)

    # Load dataset
    logger.info(f"Loading {args.data_path}")
    df = pd.read_csv(args.data_path, low_memory=False)
    logger.info(f"Loaded {len(df)} samples")

    # Prepare features
    feature_cols = [col for col in df.columns if col not in ['is_vulnerable', 'code', 'file_path', 'language', 'vulnerability_type']]
    X = df[feature_cols].copy()
    y = df['is_vulnerable'] if 'is_vulnerable' in df.columns else df.get('vulnerable', 0)

    # Handle categorical data
    categorical_cols = X.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        le = LabelEncoder()
        X.loc[:, col] = le.fit_transform(X[col].astype(str))

    X = X.fillna(0)

    logger.info(f"Features: {X.shape[1]}, Samples: {len(X)}")
    logger.info(f"Target distribution: {pd.Series(y).value_counts().to_dict()}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train RandomForest (best performer from local testing)
    logger.info("🌲 Training RandomForest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')

    logger.info("📊 Results:")
    logger.info(f"   Accuracy: {accuracy:.4f}")
    logger.info(f"   Precision: {precision:.4f}")
    logger.info(f"   Recall: {recall:.4f}")
    logger.info(f"   F1 Score: {f1:.4f}")

    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    logger.info("🔍 Top 10 Features:")
    for idx, row in feature_importance.head(10).iterrows():
        logger.info(f"   {row['feature']}: {row['importance']:.4f}")

    # Save model and results
    model_path = output_dir / 'vulnhunter_v5_model.joblib'
    joblib.dump(model, model_path)

    results = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'target_f1_achieved': f1 >= args.target_f1,
        'dataset_size': len(X),
        'feature_count': len(feature_cols),
        'top_features': feature_importance.head(10).to_dict('records')
    }

    results_path = output_dir / 'training_results.json'
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)

    feature_names_path = output_dir / 'feature_names.json'
    with open(feature_names_path, 'w') as f:
        json.dump(list(X.columns), f)

    logger.info("=" * 40)
    logger.info("🎯 TRAINING COMPLETE")
    logger.info(f"📊 F1 Score: {f1:.4f}")
    logger.info(f"✅ Target achieved: {f1 >= args.target_f1}")
    logger.info(f"💾 Model: {model_path}")
    logger.info("=" * 40)

    return 0 if f1 >= args.target_f1 else 1

if __name__ == '__main__':
    exit(main())