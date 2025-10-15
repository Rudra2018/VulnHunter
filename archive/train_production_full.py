#!/usr/bin/env python3
"""
VulnHunter V5 Production Full-Scale Training
Enterprise-grade training with comprehensive datasets and advanced techniques
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score, RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.feature_selection import SelectFromModel, RFE, VarianceThreshold
from sklearn.pipeline import Pipeline
import xgboost as xgb
import lightgbm as lgb
try:
    import catboost as cb
except ImportError:
    cb = None
import joblib
import json
import os
import argparse
from pathlib import Path
import logging
import time
import warnings
from tqdm import tqdm
import multiprocessing as mp

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProductionVulnHunter:
    """Production-grade VulnHunter with advanced ML techniques"""

    def __init__(self, n_jobs: int = -1, random_state: int = 42):
        self.n_jobs = n_jobs if n_jobs != -1 else mp.cpu_count()
        self.random_state = random_state
        self.models = {}
        self.scalers = {}
        self.feature_selectors = {}
        self.cv_results = {}

    def prepare_production_data(self, data_path: str) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
        """Prepare production data with advanced preprocessing"""
        logger.info(f"📂 Loading production dataset: {data_path}")

        # Load dataset
        if data_path.endswith('.parquet'):
            df = pd.read_parquet(data_path)
        else:
            df = pd.read_csv(data_path, low_memory=False)

        logger.info(f"📊 Loaded {len(df):,} samples with {len(df.columns)} columns")

        # Prepare target variable
        if 'is_vulnerable' in df.columns:
            y = df['is_vulnerable']
        elif 'vulnerable' in df.columns:
            y = df['vulnerable']
        else:
            logger.error("No target variable found!")
            raise ValueError("Dataset must contain 'is_vulnerable' or 'vulnerable' column")

        # Prepare features
        exclude_cols = ['code', 'file_path', 'is_vulnerable', 'vulnerable', 'sample_id', 'source']
        feature_cols = [col for col in df.columns if col not in exclude_cols]

        X = df[feature_cols].copy()

        # Handle missing values
        logger.info("🧹 Handling missing values...")
        X = X.fillna(0)

        # Handle categorical variables
        categorical_cols = X.select_dtypes(include=['object']).columns
        if len(categorical_cols) > 0:
            logger.info(f"🔤 Encoding {len(categorical_cols)} categorical columns...")
            for col in categorical_cols:
                le = LabelEncoder()
                X.loc[:, col] = le.fit_transform(X[col].astype(str))

        # Remove low-variance features
        logger.info("🎯 Removing low-variance features...")
        variance_selector = VarianceThreshold(threshold=0.01)
        X_variance = variance_selector.fit_transform(X)
        selected_features = X.columns[variance_selector.get_support()].tolist()

        X = pd.DataFrame(X_variance, columns=selected_features, index=X.index)

        logger.info(f"✅ Final dataset: {X.shape[1]} features, {len(X):,} samples")
        logger.info(f"🎯 Target distribution: {pd.Series(y).value_counts().to_dict()}")

        return X, y, selected_features

    def create_advanced_models(self) -> Dict:
        """Create comprehensive model ensemble for production"""
        logger.info("🤖 Creating advanced model ensemble...")

        models = {
            'random_forest_optimized': {
                'model': RandomForestClassifier(
                    n_estimators=500,
                    max_depth=None,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    max_features='log2',
                    bootstrap=True,
                    oob_score=True,
                    n_jobs=self.n_jobs,
                    random_state=self.random_state,
                    class_weight='balanced'
                ),
                'param_grid': {
                    'n_estimators': [300, 500, 700],
                    'max_depth': [20, 30, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4],
                    'max_features': ['sqrt', 'log2', 0.3]
                },
                'use_scaling': False
            },
            'extra_trees_optimized': {
                'model': ExtraTreesClassifier(
                    n_estimators=400,
                    max_depth=None,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    max_features='sqrt',
                    bootstrap=False,
                    n_jobs=self.n_jobs,
                    random_state=self.random_state,
                    class_weight='balanced'
                ),
                'param_grid': {
                    'n_estimators': [200, 400, 600],
                    'max_depth': [15, 25, None],
                    'min_samples_split': [3, 5, 8],
                    'min_samples_leaf': [1, 2, 3],
                    'max_features': ['sqrt', 'log2', 0.5]
                },
                'use_scaling': False
            },
            'gradient_boosting_optimized': {
                'model': GradientBoostingClassifier(
                    n_estimators=300,
                    learning_rate=0.1,
                    max_depth=8,
                    min_samples_split=10,
                    min_samples_leaf=4,
                    subsample=0.8,
                    random_state=self.random_state
                ),
                'param_grid': {
                    'n_estimators': [200, 300, 400],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'max_depth': [6, 8, 10],
                    'min_samples_split': [8, 10, 15],
                    'subsample': [0.7, 0.8, 0.9]
                },
                'use_scaling': False
            },
            'xgboost_optimized': {
                'model': xgb.XGBClassifier(
                    n_estimators=400,
                    learning_rate=0.1,
                    max_depth=8,
                    min_child_weight=3,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    random_state=self.random_state,
                    n_jobs=self.n_jobs,
                    eval_metric='logloss'
                ),
                'param_grid': {
                    'n_estimators': [300, 400, 500],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'max_depth': [6, 8, 10],
                    'min_child_weight': [1, 3, 5],
                    'subsample': [0.7, 0.8, 0.9],
                    'colsample_bytree': [0.6, 0.8, 1.0]
                },
                'use_scaling': False
            },
            'lightgbm_optimized': {
                'model': lgb.LGBMClassifier(
                    n_estimators=400,
                    learning_rate=0.1,
                    max_depth=8,
                    min_child_samples=20,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    random_state=self.random_state,
                    n_jobs=self.n_jobs,
                    verbose=-1
                ),
                'param_grid': {
                    'n_estimators': [300, 400, 500],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'max_depth': [6, 8, 10],
                    'min_child_samples': [10, 20, 30],
                    'subsample': [0.7, 0.8, 0.9],
                    'colsample_bytree': [0.6, 0.8, 1.0]
                },
                'use_scaling': False
            },
            'neural_network_optimized': {
                'model': MLPClassifier(
                    hidden_layer_sizes=(512, 256, 128),
                    activation='relu',
                    solver='adam',
                    alpha=0.001,
                    learning_rate='adaptive',
                    learning_rate_init=0.001,
                    max_iter=500,
                    early_stopping=True,
                    validation_fraction=0.1,
                    random_state=self.random_state
                ),
                'param_grid': {
                    'hidden_layer_sizes': [(256, 128), (512, 256, 128), (256, 128, 64)],
                    'alpha': [0.0001, 0.001, 0.01],
                    'learning_rate_init': [0.0001, 0.001, 0.01]
                },
                'use_scaling': True
            }
        }

        # Add CatBoost if available
        if cb is not None:
            models['catboost_optimized'] = {
                'model': cb.CatBoostClassifier(
                    iterations=400,
                    learning_rate=0.1,
                    depth=8,
                    random_seed=self.random_state,
                    verbose=False,
                    thread_count=self.n_jobs
                ),
                'param_grid': {
                    'iterations': [300, 400, 500],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'depth': [6, 8, 10],
                    'l2_leaf_reg': [1, 3, 5]
                },
                'use_scaling': False
            }

        return models

    def train_with_hyperparameter_tuning(self, X: pd.DataFrame, y: pd.Series,
                                       test_size: float = 0.2, cv_folds: int = 5,
                                       random_search_iter: int = 50) -> Dict:
        """Train models with advanced hyperparameter tuning"""
        logger.info("🔧 Starting hyperparameter tuning and training...")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.random_state, stratify=y
        )

        # Prepare scalers
        self.scalers['standard'] = StandardScaler()
        self.scalers['robust'] = RobustScaler()

        X_train_scaled = self.scalers['robust'].fit_transform(X_train)
        X_test_scaled = self.scalers['robust'].transform(X_test)

        models_config = self.create_advanced_models()
        results = {}
        best_model = None
        best_score = 0
        best_name = ""

        # Cross-validation setup
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)

        for name, config in models_config.items():
            logger.info(f"🔥 Training and tuning {name}...")
            start_time = time.time()

            try:
                # Select appropriate data
                X_tr = X_train_scaled if config['use_scaling'] else X_train
                X_te = X_test_scaled if config['use_scaling'] else X_test

                # Hyperparameter tuning
                logger.info(f"  🎯 Hyperparameter tuning for {name}...")
                random_search = RandomizedSearchCV(
                    config['model'],
                    config['param_grid'],
                    n_iter=random_search_iter,
                    cv=cv,
                    scoring='f1_weighted',
                    n_jobs=max(1, self.n_jobs // 2),  # Prevent oversubscription
                    random_state=self.random_state,
                    verbose=0
                )

                random_search.fit(X_tr, y_train)
                best_model_instance = random_search.best_estimator_

                # Predictions
                y_pred = best_model_instance.predict(X_te)
                y_pred_proba = None
                if hasattr(best_model_instance, 'predict_proba'):
                    y_pred_proba = best_model_instance.predict_proba(X_te)[:, 1]

                # Metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, average='weighted')
                recall = recall_score(y_test, y_pred, average='weighted')
                f1 = f1_score(y_test, y_pred, average='weighted')
                auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else 0

                # Cross-validation score
                cv_scores = cross_val_score(best_model_instance, X_tr, y_train, cv=cv, scoring='f1_weighted')

                training_time = time.time() - start_time

                results[name] = {
                    'model': best_model_instance,
                    'best_params': random_search.best_params_,
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'auc': auc,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'training_time': training_time,
                    'best_cv_score': random_search.best_score_
                }

                logger.info(f"  📊 {name} Results:")
                logger.info(f"     F1 Score: {f1:.4f}")
                logger.info(f"     CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
                logger.info(f"     Training Time: {training_time:.2f}s")
                logger.info(f"     Best Params: {random_search.best_params_}")

                # Track best model
                if f1 > best_score:
                    best_score = f1
                    best_model = best_model_instance
                    best_name = name

                self.models[name] = best_model_instance

            except Exception as e:
                logger.error(f"❌ Failed to train {name}: {str(e)}")
                continue

        logger.info(f"🏆 Best Model: {best_name} with F1 Score: {best_score:.4f}")

        # Feature importance analysis for best model
        feature_importance = None
        if hasattr(best_model, 'feature_importances_'):
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': best_model.feature_importances_
            }).sort_values('importance', ascending=False)

            logger.info("🔍 Top 20 Most Important Features:")
            for idx, row in feature_importance.head(20).iterrows():
                logger.info(f"   {row['feature']}: {row['importance']:.4f}")

        return {
            'best_model': best_model,
            'best_name': best_name,
            'best_score': best_score,
            'all_results': results,
            'feature_importance': feature_importance,
            'test_data': (X_test, y_test)
        }

def main():
    parser = argparse.ArgumentParser(description='VulnHunter V5 Production Full-Scale Training')
    parser.add_argument('--data-path', default='./data/production_full/vulnhunter_v5_production_full_dataset.csv',
                       help='Path to production dataset')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory')
    parser.add_argument('--target-f1', type=float, default=0.99, help='Target F1 score')
    parser.add_argument('--cv-folds', type=int, default=10, help='Cross-validation folds')
    parser.add_argument('--random-search-iter', type=int, default=100, help='Random search iterations')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size')
    parser.add_argument('--n-jobs', type=int, default=-1, help='Number of parallel jobs')

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 VulnHunter V5 Production Full-Scale Training")
    logger.info("=" * 70)
    logger.info(f"🔥 Using {mp.cpu_count()} CPU cores")
    logger.info(f"🎯 Target F1 Score: {args.target_f1}")

    # Initialize trainer
    trainer = ProductionVulnHunter(n_jobs=args.n_jobs)

    # Prepare data
    start_time = time.time()
    X, y, feature_names = trainer.prepare_production_data(args.data_path)
    data_prep_time = time.time() - start_time

    logger.info(f"⚡ Data preparation completed in {data_prep_time:.2f}s")

    # Train models
    start_time = time.time()
    training_results = trainer.train_with_hyperparameter_tuning(
        X, y,
        test_size=args.test_size,
        cv_folds=args.cv_folds,
        random_search_iter=args.random_search_iter
    )
    training_time = time.time() - start_time

    logger.info(f"⚡ Training completed in {training_time:.2f}s")

    # Save results
    best_model = training_results['best_model']
    best_name = training_results['best_name']
    best_score = training_results['best_score']

    # Save best model
    model_path = output_dir / f'vulnhunter_v5_production_{best_name}.joblib'
    joblib.dump(best_model, model_path)

    # Save all models
    ensemble_path = output_dir / 'vulnhunter_v5_production_ensemble.joblib'
    joblib.dump(trainer.models, ensemble_path)

    # Save scalers
    scalers_path = output_dir / 'vulnhunter_v5_production_scalers.joblib'
    joblib.dump(trainer.scalers, scalers_path)

    # Comprehensive results
    final_results = {
        'best_model_name': best_name,
        'best_f1_score': best_score,
        'target_achieved': best_score >= args.target_f1,
        'dataset_info': {
            'total_samples': len(X),
            'features_count': len(feature_names),
            'vulnerable_samples': int(y.sum()),
            'vulnerability_ratio': float(y.mean())
        },
        'training_info': {
            'cv_folds': args.cv_folds,
            'random_search_iterations': args.random_search_iter,
            'test_size': args.test_size,
            'data_preparation_time': data_prep_time,
            'total_training_time': training_time,
            'cpu_cores_used': mp.cpu_count()
        },
        'model_results': {
            name: {
                'accuracy': results['accuracy'],
                'precision': results['precision'],
                'recall': results['recall'],
                'f1': results['f1'],
                'auc': results['auc'],
                'cv_mean': results['cv_mean'],
                'cv_std': results['cv_std'],
                'training_time': results['training_time'],
                'best_params': results['best_params']
            }
            for name, results in training_results['all_results'].items()
        }
    }

    # Save results
    results_path = output_dir / 'production_training_results.json'
    with open(results_path, 'w') as f:
        json.dump(final_results, f, indent=2)

    # Save feature importance
    if training_results['feature_importance'] is not None:
        feature_importance_path = output_dir / 'feature_importance.csv'
        training_results['feature_importance'].to_csv(feature_importance_path, index=False)

    # Save feature names
    feature_names_path = output_dir / 'feature_names.json'
    with open(feature_names_path, 'w') as f:
        json.dump(feature_names, f)

    logger.info("=" * 70)
    logger.info("🎯 PRODUCTION TRAINING COMPLETE")
    logger.info(f"🏆 Best Model: {best_name}")
    logger.info(f"📊 F1 Score: {best_score:.4f}")
    logger.info(f"✅ Target Achieved: {best_score >= args.target_f1}")
    logger.info(f"⚡ Total Time: {training_time + data_prep_time:.2f}s")
    logger.info(f"📊 Dataset: {len(X):,} samples, {len(feature_names)} features")
    logger.info(f"💾 Best Model: {model_path}")
    logger.info(f"📁 All Models: {ensemble_path}")
    logger.info("=" * 70)

    return 0 if best_score >= args.target_f1 else 1

if __name__ == '__main__':
    exit(main())