#!/usr/bin/env python3
"""
VulnGuard AI - Fast Trainer (Random Forest Only)
Optimized for quick training with excellent results
"""

import numpy as np
import pandas as pd
import pickle
import logging
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from core.huggingface_dataset_integrator import VulnGuardDatasetIntegrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FastVulnGuardTrainer:
    """Fast vulnerability detection trainer - Random Forest only"""

    def __init__(self):
        self.model = None
        self.code_vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char'
        )
        self.token_vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 2),
            analyzer='word'
        )
        self.scaler = StandardScaler()
        self.feature_data = None
        self.labels = None

        logger.info("🚀 Fast VulnGuard Trainer initialized")

    def load_data(self):
        """Load HuggingFace datasets"""
        logger.info("📂 Loading datasets...")
        integrator = VulnGuardDatasetIntegrator()

        if not integrator.load_all_datasets():
            logger.error("❌ Failed to load datasets")
            return False

        processed_data = integrator.process_all_datasets()
        if not processed_data:
            logger.error("❌ No data processed")
            return False

        self.training_data = processed_data
        logger.info(f"✅ Loaded {len(processed_data)} samples")
        return True

    def prepare_features(self):
        """Extract features from code samples"""
        logger.info("🔄 Preparing features...")

        code_texts = []
        labels = []

        for record in self.training_data:
            code = record.get('code', '').strip()
            if code and len(code) >= 10:
                code_texts.append(code)
                labels.append(record.get('vulnerable', 1))

        logger.info(f"📊 Processing {len(code_texts)} code samples")

        # TF-IDF features
        char_tfidf = self.code_vectorizer.fit_transform(code_texts)
        token_tfidf = self.token_vectorizer.fit_transform(code_texts)

        # Combine features
        char_df = pd.DataFrame(
            char_tfidf.toarray(),
            columns=[f'char_{i}' for i in range(char_tfidf.shape[1])]
        )
        token_df = pd.DataFrame(
            token_tfidf.toarray(),
            columns=[f'token_{i}' for i in range(token_tfidf.shape[1])]
        )

        combined = pd.concat([char_df, token_df], axis=1)

        X = self.scaler.fit_transform(combined.values)
        y = np.array(labels)

        self.feature_data = X
        self.labels = y

        logger.info(f"✅ Features prepared: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"📊 Vulnerable: {np.sum(y==1)}, Safe: {np.sum(y==0)}")

        return X, y

    def train(self, X, y):
        """Train Random Forest model"""
        logger.info("🌲 Training Random Forest...")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        logger.info(f"📊 Training: {len(X_train)}, Test: {len(X_test)}")

        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            verbose=1
        )

        self.model.fit(X_train, y_train)
        logger.info("✅ Random Forest trained!")

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted', zero_division=0
        )

        logger.info("\n" + "="*60)
        logger.info("📊 MODEL EVALUATION")
        logger.info("="*60)
        logger.info(f"Accuracy:  {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall:    {recall:.4f}")
        logger.info(f"F1-Score:  {f1:.4f}")
        logger.info("="*60 + "\n")

        return accuracy, precision, recall, f1

    def save_model(self, filename=None):
        """Save trained model"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnguard_rf_{timestamp}.pkl"

        model_data = {
            'model': self.model,
            'code_vectorizer': self.code_vectorizer,
            'token_vectorizer': self.token_vectorizer,
            'scaler': self.scaler,
            'feature_shape': self.feature_data.shape,
            'timestamp': datetime.now().isoformat()
        }

        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"💾 Model saved to {filename}")
        return filename

    def predict(self, code_text):
        """Predict vulnerability"""
        if not self.model:
            raise ValueError("Model not trained")

        # Extract features
        char_tfidf = self.code_vectorizer.transform([code_text])
        token_tfidf = self.token_vectorizer.transform([code_text])

        char_df = pd.DataFrame(
            char_tfidf.toarray(),
            columns=[f'char_{i}' for i in range(char_tfidf.shape[1])]
        )
        token_df = pd.DataFrame(
            token_tfidf.toarray(),
            columns=[f'token_{i}' for i in range(token_tfidf.shape[1])]
        )

        combined = pd.concat([char_df, token_df], axis=1)
        X = self.scaler.transform(combined.values)

        pred = self.model.predict(X)[0]
        prob = self.model.predict_proba(X)[0]

        return {
            'vulnerable': int(pred),
            'confidence': float(prob[1]),
            'probabilities': {'safe': float(prob[0]), 'vulnerable': float(prob[1])}
        }


def main():
    logger.info("🚀 VulnGuard AI - Fast Training Pipeline")
    logger.info("="*60)

    trainer = FastVulnGuardTrainer()

    # Load data
    if not trainer.load_data():
        return None

    # Prepare features
    X, y = trainer.prepare_features()
    if X is None:
        return None

    # Train
    metrics = trainer.train(X, y)

    # Save
    model_file = trainer.save_model()

    logger.info("\n" + "="*60)
    logger.info("🎉 TRAINING COMPLETE!")
    logger.info(f"📁 Model: {model_file}")
    logger.info("="*60)

    # Demo prediction
    test_code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE user='{username}'"
    return db.execute(query)
"""
    result = trainer.predict(test_code)
    logger.info(f"\n🧪 Test Prediction:")
    logger.info(f"   Code: SQL injection example")
    logger.info(f"   Vulnerable: {result['vulnerable']}")
    logger.info(f"   Confidence: {result['confidence']:.2%}")

    return trainer


if __name__ == "__main__":
    main()
