#!/usr/bin/env python3
"""
🚀 Advanced ML Techniques for Smart Contract Security
Implementation of all the improvements you suggested
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold,
    GridSearchCV, RandomizedSearchCV
)
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    VotingClassifier, StackingClassifier
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score
)
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import joblib

class AdvancedMLTechniques:
    """Implementation of all your suggested ML improvements"""

    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_selectors = {}
        self.encoders = {}

    def improve_data_quality(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        1. Data Quality Improvements
        """
        print("🔧 1. IMPROVING DATA QUALITY")
        print("=" * 40)

        # Handle missing values
        print("   • Handling missing values...")
        df_clean = df.copy()

        # Fill numerical columns with median
        numerical_cols = df_clean.select_dtypes(include=[np.number]).columns
        for col in numerical_cols:
            if df_clean[col].isnull().sum() > 0:
                df_clean[col].fillna(df_clean[col].median(), inplace=True)
                print(f"     Filled {col} missing values with median")

        # Fill categorical columns with mode
        categorical_cols = df_clean.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if df_clean[col].isnull().sum() > 0:
                df_clean[col].fillna(df_clean[col].mode()[0], inplace=True)
                print(f"     Filled {col} missing values with mode")

        # Remove duplicates
        initial_size = len(df_clean)
        df_clean = df_clean.drop_duplicates()
        removed_duplicates = initial_size - len(df_clean)
        if removed_duplicates > 0:
            print(f"   • Removed {removed_duplicates} duplicate records")

        # Remove outliers using IQR method
        print("   • Removing outliers...")
        for col in ['bounty_amount', 'line_count', 'function_count']:
            if col in df_clean.columns:
                Q1 = df_clean[col].quantile(0.25)
                Q3 = df_clean[col].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR

                outliers = len(df_clean[(df_clean[col] < lower_bound) | (df_clean[col] > upper_bound)])
                df_clean = df_clean[(df_clean[col] >= lower_bound) & (df_clean[col] <= upper_bound)]
                print(f"     Removed {outliers} outliers from {col}")

        print(f"   ✅ Data quality improved: {initial_size} → {len(df_clean)} samples")
        return df_clean

    def feature_engineering(self, X: np.ndarray, feature_names: list) -> tuple:
        """
        2. Advanced Feature Engineering
        """
        print("\n🔧 2. ADVANCED FEATURE ENGINEERING")
        print("=" * 40)

        X_enhanced = X.copy()

        # Create interaction features
        print("   • Creating interaction features...")
        interaction_features = []
        interaction_names = []

        # Key interactions for smart contract security
        important_indices = {
            'external_calls': 8,
            'require_count': 6,
            'function_count': 2,
            'complexity': 24
        }

        for name1, idx1 in important_indices.items():
            for name2, idx2 in important_indices.items():
                if idx1 < idx2 and idx1 < X.shape[1] and idx2 < X.shape[1]:
                    interaction = X[:, idx1] * X[:, idx2]
                    interaction_features.append(interaction)
                    interaction_names.append(f"{name1}_x_{name2}")

        if interaction_features:
            interaction_matrix = np.column_stack(interaction_features)
            X_enhanced = np.column_stack([X_enhanced, interaction_matrix])
            feature_names_enhanced = feature_names + interaction_names
            print(f"     Added {len(interaction_features)} interaction features")

        # Create polynomial features for key variables
        print("   • Creating polynomial features...")
        poly_features = []
        poly_names = []

        key_features = ['external_calls', 'require_count', 'function_count']
        for feature_name in key_features:
            if feature_name in feature_names:
                idx = feature_names.index(feature_name)
                if idx < X.shape[1]:
                    # Square feature
                    squared = X[:, idx] ** 2
                    poly_features.append(squared)
                    poly_names.append(f"{feature_name}_squared")

                    # Square root (for non-negative values)
                    if np.all(X[:, idx] >= 0):
                        sqrt_feature = np.sqrt(X[:, idx])
                        poly_features.append(sqrt_feature)
                        poly_names.append(f"{feature_name}_sqrt")

        if poly_features:
            poly_matrix = np.column_stack(poly_features)
            X_enhanced = np.column_stack([X_enhanced, poly_matrix])
            feature_names_enhanced = feature_names_enhanced + poly_names
            print(f"     Added {len(poly_features)} polynomial features")

        # Domain-specific features for smart contracts
        print("   • Creating domain-specific features...")
        domain_features = []
        domain_names = []

        # Security risk ratio
        if 'external_calls' in feature_names and 'require_count' in feature_names:
            ext_idx = feature_names.index('external_calls')
            req_idx = feature_names.index('require_count')
            risk_ratio = X[:, ext_idx] / (X[:, req_idx] + 1)  # +1 to avoid division by zero
            domain_features.append(risk_ratio)
            domain_names.append('security_risk_ratio')

        # Code density
        if 'function_count' in feature_names and 'line_count' in feature_names:
            func_idx = feature_names.index('function_count')
            line_idx = feature_names.index('line_count')
            density = X[:, func_idx] / (X[:, line_idx] + 1)
            domain_features.append(density)
            domain_names.append('code_density')

        if domain_features:
            domain_matrix = np.column_stack(domain_features)
            X_enhanced = np.column_stack([X_enhanced, domain_matrix])
            feature_names_enhanced = feature_names_enhanced + domain_names
            print(f"     Added {len(domain_features)} domain-specific features")

        print(f"   ✅ Features enhanced: {X.shape[1]} → {X_enhanced.shape[1]}")
        return X_enhanced, feature_names_enhanced

    def handle_imbalanced_data(self, X: np.ndarray, y: np.ndarray) -> tuple:
        """
        3. Handle Imbalanced Data (without external dependencies)
        """
        print("\n🔧 3. HANDLING IMBALANCED DATA")
        print("=" * 40)

        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_distribution = dict(zip(unique, counts))
        print("   • Original class distribution:")
        for class_name, count in class_distribution.items():
            percentage = (count / len(y)) * 100
            print(f"     {class_name}: {count} ({percentage:.1f}%)")

        # Simple oversampling for minority classes
        print("   • Applying class balancing...")

        # Find majority class
        majority_class = max(class_distribution.items(), key=lambda x: x[1])
        majority_count = majority_class[1]

        X_balanced = []
        y_balanced = []

        for class_name in unique:
            class_indices = np.where(y == class_name)[0]
            class_X = X[class_indices]
            class_y = y[class_indices]

            current_count = len(class_indices)
            target_count = int(majority_count * 0.8)  # 80% of majority class

            if current_count < target_count:
                # Oversample minority class
                oversample_count = target_count - current_count
                oversample_indices = np.random.choice(len(class_X), oversample_count, replace=True)

                X_balanced.extend(class_X)
                X_balanced.extend(class_X[oversample_indices])
                y_balanced.extend(class_y)
                y_balanced.extend(class_y[oversample_indices])

                print(f"     Oversampled {class_name}: {current_count} → {target_count}")
            else:
                X_balanced.extend(class_X)
                y_balanced.extend(class_y)

        X_balanced = np.array(X_balanced)
        y_balanced = np.array(y_balanced)

        print(f"   ✅ Dataset balanced: {len(X)} → {len(X_balanced)} samples")
        return X_balanced, y_balanced

    def advanced_model_selection(self, X: np.ndarray, y: np.ndarray) -> dict:
        """
        4. Advanced Model Selection with Hyperparameter Tuning
        """
        print("\n🔧 4. ADVANCED MODEL SELECTION & HYPERPARAMETER TUNING")
        print("=" * 40)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        self.scalers['main'] = scaler

        # Encode labels
        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        y_test_encoded = label_encoder.transform(y_test)
        self.encoders['main'] = label_encoder

        # Define models and parameter grids
        models = {
            'random_forest': {
                'model': RandomForestClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [10, 15, 20, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4]
                }
            },
            'xgboost': {
                'model': xgb.XGBClassifier(random_state=42, eval_metric='mlogloss'),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [3, 6, 9],
                    'learning_rate': [0.01, 0.1, 0.2],
                    'subsample': [0.8, 0.9, 1.0]
                }
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [3, 5, 7],
                    'learning_rate': [0.01, 0.1, 0.2]
                }
            }
        }

        best_models = {}
        model_results = {}

        print("   • Training and tuning models...")
        for name, model_config in models.items():
            print(f"     Tuning {name}...")

            # Use RandomizedSearchCV for efficiency
            search = RandomizedSearchCV(
                model_config['model'],
                model_config['params'],
                n_iter=20,  # Reduced for speed
                cv=3,
                scoring='accuracy',
                random_state=42,
                n_jobs=-1
            )

            search.fit(X_train_scaled, y_train_encoded)
            best_model = search.best_estimator_
            best_models[name] = best_model

            # Evaluate model
            cv_scores = cross_val_score(best_model, X_train_scaled, y_train_encoded, cv=5)
            y_pred = best_model.predict(X_test_scaled)
            test_accuracy = accuracy_score(y_test_encoded, y_pred)

            model_results[name] = {
                'best_params': search.best_params_,
                'cv_score_mean': cv_scores.mean(),
                'cv_score_std': cv_scores.std(),
                'test_accuracy': test_accuracy
            }

            print(f"       Best params: {search.best_params_}")
            print(f"       CV Score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
            print(f"       Test Accuracy: {test_accuracy:.3f}")

        return best_models, model_results, X_train_scaled, X_test_scaled, y_train_encoded, y_test_encoded

    def create_ensemble_methods(self, best_models: dict, X_train: np.ndarray,
                               X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray) -> dict:
        """
        5. Advanced Ensemble Methods
        """
        print("\n🔧 5. CREATING ADVANCED ENSEMBLE METHODS")
        print("=" * 40)

        ensemble_results = {}

        # Voting Classifier
        print("   • Creating Voting Ensemble...")
        voting_classifier = VotingClassifier(
            estimators=[(name, model) for name, model in best_models.items()],
            voting='soft'
        )
        voting_classifier.fit(X_train, y_train)
        voting_pred = voting_classifier.predict(X_test)
        voting_accuracy = accuracy_score(y_test, voting_pred)

        ensemble_results['voting'] = {
            'model': voting_classifier,
            'accuracy': voting_accuracy
        }
        print(f"     Voting Ensemble Accuracy: {voting_accuracy:.3f}")

        # Stacking Classifier
        print("   • Creating Stacking Ensemble...")
        stacking_classifier = StackingClassifier(
            estimators=[(name, model) for name, model in best_models.items()],
            final_estimator=LogisticRegression(random_state=42),
            cv=3
        )
        stacking_classifier.fit(X_train, y_train)
        stacking_pred = stacking_classifier.predict(X_test)
        stacking_accuracy = accuracy_score(y_test, stacking_pred)

        ensemble_results['stacking'] = {
            'model': stacking_classifier,
            'accuracy': stacking_accuracy
        }
        print(f"     Stacking Ensemble Accuracy: {stacking_accuracy:.3f}")

        # Select best ensemble
        best_ensemble_name = max(ensemble_results.keys(),
                                key=lambda k: ensemble_results[k]['accuracy'])
        best_ensemble = ensemble_results[best_ensemble_name]['model']

        self.models['best_ensemble'] = best_ensemble
        print(f"   ✅ Best Ensemble: {best_ensemble_name} ({ensemble_results[best_ensemble_name]['accuracy']:.3f})")

        return ensemble_results

    def comprehensive_evaluation(self, model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """
        6. Comprehensive Model Evaluation
        """
        print("\n🔧 6. COMPREHENSIVE MODEL EVALUATION")
        print("=" * 40)

        # Predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test) if hasattr(model, 'predict_proba') else None

        # Cross-validation scores
        cv_scores = cross_val_score(model, X_test, y_test, cv=StratifiedKFold(5))
        print(f"   • Cross-Validation Scores: {cv_scores}")
        print(f"   • Mean CV Accuracy: {cv_scores.mean():.4f} (±{cv_scores.std() * 2:.4f})")

        # Detailed metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, support = precision_recall_fscore_support(y_test, y_pred, average='weighted')

        print(f"\n   📊 DETAILED METRICS:")
        print(f"   • Accuracy: {accuracy:.4f}")
        print(f"   • Precision: {precision:.4f}")
        print(f"   • Recall: {recall:.4f}")
        print(f"   • F1-Score: {f1:.4f}")

        # Classification report
        class_names = self.encoders['main'].classes_
        class_report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)

        print(f"\n   📋 PER-CLASS PERFORMANCE:")
        for class_name in class_names:
            if class_name in class_report:
                metrics = class_report[class_name]
                print(f"   • {class_name}:")
                print(f"     Precision: {metrics['precision']:.3f}")
                print(f"     Recall: {metrics['recall']:.3f}")
                print(f"     F1-Score: {metrics['f1-score']:.3f}")

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"\n   🔄 CONFUSION MATRIX:")
        print(f"   {cm}")

        return {
            'cv_scores': cv_scores,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'classification_report': class_report,
            'confusion_matrix': cm
        }

    def feature_importance_analysis(self, model, feature_names: list) -> dict:
        """
        7. Feature Importance Analysis
        """
        print("\n🔧 7. FEATURE IMPORTANCE ANALYSIS")
        print("=" * 40)

        feature_importance = None

        # Extract feature importance
        if hasattr(model, 'feature_importances_'):
            feature_importance = model.feature_importances_
        elif hasattr(model, 'estimators_'):
            # For ensemble models, average the feature importances
            importances = []
            for estimator in model.estimators_:
                if hasattr(estimator, 'feature_importances_'):
                    importances.append(estimator.feature_importances_)
            if importances:
                feature_importance = np.mean(importances, axis=0)

        if feature_importance is not None:
            # Create feature importance dataframe
            importance_df = pd.DataFrame({
                'feature': feature_names,
                'importance': feature_importance
            }).sort_values('importance', ascending=False)

            print("   📊 TOP 10 MOST IMPORTANT FEATURES:")
            for i, (_, row) in enumerate(importance_df.head(10).iterrows()):
                print(f"   {i+1:2d}. {row['feature']:<25} {row['importance']:.4f}")

            return importance_df.to_dict('records')
        else:
            print("   ⚠️ Feature importance not available for this model type")
            return None

    def save_advanced_models(self, timestamp: str = None):
        """
        8. Save All Advanced Models and Metadata
        """
        print("\n🔧 8. SAVING ADVANCED MODELS")
        print("=" * 40)

        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        output_dir = Path("advanced_models")
        output_dir.mkdir(exist_ok=True)

        # Save models
        for model_name, model in self.models.items():
            model_path = output_dir / f"{model_name}_{timestamp}.pkl"
            joblib.dump(model, model_path)
            print(f"   • Saved {model_name}")

        # Save preprocessors
        for scaler_name, scaler in self.scalers.items():
            scaler_path = output_dir / f"scaler_{scaler_name}_{timestamp}.pkl"
            joblib.dump(scaler, scaler_path)

        for encoder_name, encoder in self.encoders.items():
            encoder_path = output_dir / f"encoder_{encoder_name}_{timestamp}.pkl"
            joblib.dump(encoder, encoder_path)

        print(f"   ✅ All models saved with timestamp: {timestamp}")
        return timestamp

def demonstrate_advanced_techniques():
    """Demonstrate all advanced ML techniques"""
    print("🚀 ADVANCED ML TECHNIQUES FOR SMART CONTRACT SECURITY")
    print("=" * 80)

    # Load the data from our previous training
    try:
        # Load a sample dataset (you would replace this with your actual data)
        from working_smart_contract_trainer import WorkingSmartContractTrainer

        trainer = WorkingSmartContractTrainer()
        df = trainer.generate_dataset(n_samples=2000)
        X, feature_names = trainer.prepare_features(df)
        y = df['vulnerability_type'].values

        print(f"📊 Loaded dataset: {len(df)} samples, {len(feature_names)} features")

        # Initialize advanced techniques
        advanced_ml = AdvancedMLTechniques()

        # 1. Improve data quality
        df_clean = advanced_ml.improve_data_quality(df)

        # 2. Feature engineering
        X_enhanced, feature_names_enhanced = advanced_ml.feature_engineering(X, feature_names)

        # 3. Handle imbalanced data
        X_balanced, y_balanced = advanced_ml.handle_imbalanced_data(X_enhanced, y)

        # 4. Advanced model selection
        best_models, model_results, X_train, X_test, y_train, y_test = advanced_ml.advanced_model_selection(X_balanced, y_balanced)

        # 5. Create ensemble methods
        ensemble_results = advanced_ml.create_ensemble_methods(best_models, X_train, X_test, y_train, y_test)

        # 6. Comprehensive evaluation
        best_model = advanced_ml.models['best_ensemble']
        evaluation_results = advanced_ml.comprehensive_evaluation(best_model, X_test, y_test)

        # 7. Feature importance analysis
        feature_importance = advanced_ml.feature_importance_analysis(best_model, feature_names_enhanced)

        # 8. Save models
        timestamp = advanced_ml.save_advanced_models()

        print(f"\n🎉 ADVANCED ML PIPELINE COMPLETE!")
        print(f"📈 Final Model Accuracy: {evaluation_results['accuracy']:.3f}")
        print(f"📈 Final Model F1-Score: {evaluation_results['f1_score']:.3f}")
        print(f"💾 Models saved with timestamp: {timestamp}")

        return {
            'status': 'success',
            'final_accuracy': evaluation_results['accuracy'],
            'final_f1_score': evaluation_results['f1_score'],
            'feature_count': len(feature_names_enhanced),
            'timestamp': timestamp
        }

    except Exception as e:
        print(f"❌ Error: {e}")
        return {'status': 'error', 'error': str(e)}

if __name__ == "__main__":
    demonstrate_advanced_techniques()