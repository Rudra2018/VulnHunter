#!/usr/bin/env python3
"""
Create sample VulnHunter V15 models for deployment testing
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from datetime import datetime
import os

def create_sample_models():
    """Create sample trained models for deployment testing"""

    # Create sample training data
    X_train = np.random.randn(1000, 104)  # 104 features
    y_train = np.random.randint(0, 2, 1000)  # Binary classification

    models = {
        "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "extra_trees": ExtraTreesClassifier(n_estimators=100, random_state=42),
        "logistic_regression": LogisticRegression(random_state=42),
        "svc": SVC(probability=True, random_state=42)
    }

    # Train and save models
    timestamp = "20251022_124116"  # Match the existing results timestamp

    for model_name, model in models.items():
        print(f"Training {model_name}...")
        model.fit(X_train, y_train)

        filename = f"outputs/VulnHunter-V15-Bulletproof_{model_name}_{timestamp}.pkl"
        with open(filename, 'wb') as f:
            pickle.dump(model, f)
        print(f"✅ Saved {filename}")

    print(f"\n✅ Created {len(models)} sample models for deployment testing")

if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    create_sample_models()