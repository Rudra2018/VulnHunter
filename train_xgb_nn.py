#!/usr/bin/env python3
"""
VulnHunter AI - Train XGBoost and Neural Network Only
Fast training script for remaining models
"""

import numpy as np
import pandas as pd
import pickle
import logging
from datetime import datetime
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️  XGBoost not installed. Install with: pip install xgboost")

from core.huggingface_dataset_integrator import VulnGuardDatasetIntegrator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FastXGBNNTrainer:
    """Train XGBoost and Neural Network quickly"""

    def __init__(self):
        self.models = {}
        self.code_vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), analyzer='char')
        self.token_vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 2), analyzer='word')
        self.scaler = StandardScaler()

    def load_and_prepare_data(self):
        """Load HuggingFace datasets and prepare features"""
        logger.info("📂 Loading HuggingFace datasets...")

        integrator = VulnGuardDatasetIntegrator()
        if not integrator.load_all_datasets():
            logger.error("❌ Failed to load datasets")
            return False

        processed_data = integrator.process_all_datasets()
        if not processed_data:
            logger.error("❌ No data processed")
            return False

        logger.info(f"✅ Loaded {len(processed_data)} samples")

        # Extract code and labels
        code_texts = []
        labels = []

        for record in processed_data:
            code = record.get('code', '').strip()
            if code and len(code) >= 10:
                code_texts.append(code)
                labels.append(record.get('vulnerable', 1))

        logger.info(f"🔄 Preparing features from {len(code_texts)} samples...")

        # TF-IDF features (reduced for speed)
        char_tfidf = self.code_vectorizer.fit_transform(code_texts)
        token_tfidf = self.token_vectorizer.fit_transform(code_texts)

        # Combine features
        from scipy.sparse import hstack
        features = hstack([char_tfidf, token_tfidf])

        # Convert to dense and scale
        features_dense = features.toarray()
        features_scaled = self.scaler.fit_transform(features_dense)

        # Train/test split
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            features_scaled, labels, test_size=0.2, random_state=42, stratify=labels
        )

        logger.info(f"✅ Features prepared: {self.X_train.shape[1]} features")
        logger.info(f"   Training set: {len(self.X_train)} samples")
        logger.info(f"   Test set: {len(self.X_test)} samples")
        return True

    def train_xgboost(self):
        """Train XGBoost model"""
        if not XGBOOST_AVAILABLE:
            logger.warning("⚠️  Skipping XGBoost (not installed)")
            return

        logger.info("\n" + "="*60)
        logger.info("🚀 Training XGBoost...")
        logger.info("="*60)

        xgb_model = xgb.XGBClassifier(
            n_estimators=100,  # Reduced for speed
            learning_rate=0.1,
            max_depth=8,  # Reduced for speed
            random_state=42,
            verbosity=2,
            tree_method='hist',  # Faster training
            use_label_encoder=False,
            eval_metric='logloss'
        )

        logger.info("Training XGBoost (this may take 10-15 minutes)...")
        xgb_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = xgb_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        logger.info(f"\n✅ XGBoost trained successfully!")
        logger.info(f"   Accuracy: {accuracy:.4f}")
        self.models['xgboost'] = xgb_model

        # Save model
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"models/vulnguard_xgb_{timestamp}.pkl"
        with open(filename, 'wb') as f:
            pickle.dump({
                'model': xgb_model,
                'code_vectorizer': self.code_vectorizer,
                'token_vectorizer': self.token_vectorizer,
                'scaler': self.scaler,
                'accuracy': accuracy
            }, f)
        logger.info(f"💾 Saved: {filename}")

    def train_neural_network(self):
        """Train Neural Network (MLP) model"""
        logger.info("\n" + "="*60)
        logger.info("🚀 Training Neural Network (MLP)...")
        logger.info("="*60)

        nn_model = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),  # Smaller for speed
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size=256,  # Larger batches for speed
            learning_rate='adaptive',
            max_iter=30,  # Reduced for speed
            random_state=42,
            verbose=True,
            early_stopping=True,
            validation_fraction=0.1
        )

        logger.info("Training Neural Network (this may take 10-20 minutes)...")
        nn_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = nn_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        logger.info(f"\n✅ Neural Network trained successfully!")
        logger.info(f"   Accuracy: {accuracy:.4f}")
        self.models['neural_network'] = nn_model

        # Save model
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"models/vulnguard_nn_{timestamp}.pkl"
        with open(filename, 'wb') as f:
            pickle.dump({
                'model': nn_model,
                'code_vectorizer': self.code_vectorizer,
                'token_vectorizer': self.token_vectorizer,
                'scaler': self.scaler,
                'accuracy': accuracy
            }, f)
        logger.info(f"💾 Saved: {filename}")

    def train_all(self):
        """Train XGBoost and Neural Network"""
        logger.info("\n" + "="*60)
        logger.info("🚀 VulnHunter AI - Fast Training (XGBoost + NN)")
        logger.info("="*60 + "\n")

        if not self.load_and_prepare_data():
            return False

        # Train models
        self.train_xgboost()
        self.train_neural_network()

        logger.info("\n" + "="*60)
        logger.info("✅ All models trained successfully!")
        logger.info(f"📊 Total models trained: {len(self.models)}")
        logger.info("="*60)

        return True


if __name__ == "__main__":
    trainer = FastXGBNNTrainer()
    success = trainer.train_all()

    if success:
        print("\n🎉 Training complete! Check models/ directory for saved models.")
    else:
        print("\n❌ Training failed. Check logs above for details.")
