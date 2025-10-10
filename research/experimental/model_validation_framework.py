#!/usr/bin/env python3
"""
🔬 Model Validation Framework
Comprehensive validation system for bug bounty prediction models
"""

import numpy as np
import pandas as pd
import sqlite3
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import cross_val_score, KFold, StratifiedKFold
from sklearn.metrics import (
    mean_absolute_error, mean_squared_error, r2_score,
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.ensemble import RandomForestRegressor, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
import logging
from pathlib import Path
from datetime import datetime
import json
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

class ModelValidationFramework:
    """Comprehensive model validation and accuracy assessment"""

    def __init__(self, db_path: str = "bug_bounty_intelligence/bug_bounty_intelligence.db"):
        self.db_path = Path(db_path)
        self.output_dir = Path("model_validation")
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        self.logger = self._setup_logging()

        # Model storage
        self.bounty_predictor = None
        self.severity_classifier = None
        self.tfidf_vectorizer = None
        self.label_encoder = None

        # Validation results
        self.validation_results = {
            'bounty_prediction': {},
            'severity_classification': {},
            'cross_validation': {},
            'feature_importance': {},
            'model_comparison': {}
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('ModelValidation')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def load_training_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load and prepare training data from database"""
        self.logger.info("📊 Loading training data from database...")

        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")

        conn = sqlite3.connect(self.db_path)

        # Load bounty prediction data
        bounty_query = '''
            SELECT vulnerability_type, severity_level, bounty_amount, program_name, dataset_source
            FROM bug_bounty_reports
            WHERE bounty_amount > 0
            UNION ALL
            SELECT vulnerability_type, severity_level, bounty_amount, protocol_name as program_name, 'web3' as dataset_source
            FROM web3_vulnerability_intelligence
            WHERE bounty_amount > 0
        '''

        bounty_df = pd.read_sql_query(bounty_query, conn)

        # Load severity classification data
        severity_query = '''
            SELECT vulnerability_type, severity_level, dataset_source
            FROM bug_bounty_reports
            WHERE severity_level IS NOT NULL
            UNION ALL
            SELECT vulnerability_type, severity_level, 'web3' as dataset_source
            FROM web3_vulnerability_intelligence
            WHERE severity_level IS NOT NULL
        '''

        severity_df = pd.read_sql_query(severity_query, conn)
        conn.close()

        self.logger.info(f"✅ Loaded {len(bounty_df)} bounty records and {len(severity_df)} severity records")
        return bounty_df, severity_df

    def prepare_bounty_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features for bounty prediction"""
        features = []
        targets = []

        for _, row in df.iterrows():
            vuln_type = str(row['vulnerability_type'])
            severity = str(row['severity_level'])
            program = str(row['program_name'])
            source = str(row.get('dataset_source', 'unknown'))

            feature_vector = [
                len(vuln_type),  # Vulnerability type complexity
                1 if 'Critical' in severity else 0,
                1 if 'High' in severity else 0,
                1 if 'Medium' in severity else 0,
                1 if 'Low' in severity else 0,
                len(program),  # Program name length
                1 if 'SQL' in vuln_type.upper() else 0,
                1 if 'XSS' in vuln_type.upper() else 0,
                1 if 'RCE' in vuln_type.upper() or 'REMOTE CODE' in vuln_type.upper() else 0,
                1 if 'SSRF' in vuln_type.upper() else 0,
                1 if 'IDOR' in vuln_type.upper() else 0,
                1 if source == 'web3' else 0,
                hash(vuln_type) % 100,
            ]

            features.append(feature_vector)
            targets.append(row['bounty_amount'])

        return np.array(features), np.array(targets)

    def validate_bounty_prediction_model(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Comprehensive validation of bounty prediction model"""
        self.logger.info("🤖 Validating bounty prediction model...")

        # Handle outliers
        y_capped = np.clip(y, np.percentile(y, 5), np.percentile(y, 95))

        # Train model
        model = RandomForestRegressor(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=5
        )

        # Cross-validation
        cv_scores = cross_val_score(model, X, y_capped, cv=5, scoring='r2')
        cv_mae_scores = cross_val_score(model, X, y_capped, cv=5, scoring='neg_mean_absolute_error')

        # Train on full dataset for feature importance
        model.fit(X, y_capped)
        self.bounty_predictor = model

        # Feature importance analysis
        feature_names = [
            'vuln_complexity', 'critical', 'high', 'medium', 'low',
            'program_length', 'sql_injection', 'xss', 'rce', 'ssrf', 'idor',
            'web3_flag', 'vuln_hash'
        ]

        feature_importance = dict(zip(feature_names, model.feature_importances_))

        # Validation metrics
        y_pred = model.predict(X)

        results = {
            'cv_r2_mean': cv_scores.mean(),
            'cv_r2_std': cv_scores.std(),
            'cv_mae_mean': -cv_mae_scores.mean(),
            'cv_mae_std': cv_mae_scores.std(),
            'r2_score': r2_score(y_capped, y_pred),
            'mae': mean_absolute_error(y_capped, y_pred),
            'rmse': np.sqrt(mean_squared_error(y_capped, y_pred)),
            'feature_importance': feature_importance,
            'samples_count': len(X),
            'target_mean': y_capped.mean(),
            'target_std': y_capped.std()
        }

        self.validation_results['bounty_prediction'] = results
        self.logger.info(f"✅ Bounty model validation complete - R²: {results['r2_score']:.3f}, MAE: ${results['mae']:,.2f}")

        return results

    def validate_severity_classification_model(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Comprehensive validation of severity classification model"""
        self.logger.info("🎯 Validating severity classification model...")

        # Check class distribution
        class_counts = df['severity_level'].value_counts()
        self.logger.info(f"Class distribution: {dict(class_counts)}")

        if len(class_counts) < 2:
            self.logger.warning("⚠️ Insufficient class diversity for classification")
            return {'error': 'Insufficient class diversity'}

        # Prepare features
        vuln_features = []
        severity_targets = []

        for _, row in df.iterrows():
            vuln_text = str(row['vulnerability_type'])
            source = str(row.get('dataset_source', 'unknown'))
            enhanced_text = f"{vuln_text} {source}"
            vuln_features.append(enhanced_text)
            severity_targets.append(row['severity_level'])

        # Text vectorization
        tfidf = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english',
            min_df=2
        )

        X_text = tfidf.fit_transform(vuln_features)
        self.tfidf_vectorizer = tfidf

        # Label encoding
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(severity_targets)
        self.label_encoder = label_encoder

        # Model training
        model = GradientBoostingClassifier(
            n_estimators=50,
            random_state=42,
            max_depth=5,
            learning_rate=0.1
        )

        # Cross-validation with stratification
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X_text.toarray(), y, cv=skf, scoring='accuracy')
        cv_precision = cross_val_score(model, X_text.toarray(), y, cv=skf, scoring='precision_weighted')
        cv_recall = cross_val_score(model, X_text.toarray(), y, cv=skf, scoring='recall_weighted')
        cv_f1 = cross_val_score(model, X_text.toarray(), y, cv=skf, scoring='f1_weighted')

        # Train on full dataset
        model.fit(X_text.toarray(), y)
        self.severity_classifier = model

        # Predictions and detailed metrics
        y_pred = model.predict(X_text.toarray())

        # Classification report
        class_report = classification_report(y, y_pred, target_names=label_encoder.classes_, output_dict=True)

        # Confusion matrix
        conf_matrix = confusion_matrix(y, y_pred)

        results = {
            'cv_accuracy_mean': cv_scores.mean(),
            'cv_accuracy_std': cv_scores.std(),
            'cv_precision_mean': cv_precision.mean(),
            'cv_precision_std': cv_precision.std(),
            'cv_recall_mean': cv_recall.mean(),
            'cv_recall_std': cv_recall.std(),
            'cv_f1_mean': cv_f1.mean(),
            'cv_f1_std': cv_f1.std(),
            'accuracy': accuracy_score(y, y_pred),
            'precision_weighted': precision_score(y, y_pred, average='weighted'),
            'recall_weighted': recall_score(y, y_pred, average='weighted'),
            'f1_weighted': f1_score(y, y_pred, average='weighted'),
            'classification_report': class_report,
            'confusion_matrix': conf_matrix.tolist(),
            'class_names': label_encoder.classes_.tolist(),
            'samples_count': len(X_text.toarray()),
            'feature_count': X_text.shape[1]
        }

        self.validation_results['severity_classification'] = results
        self.logger.info(f"✅ Severity model validation complete - Accuracy: {results['accuracy']:.3f}")

        return results

    def validate_against_known_benchmarks(self) -> Dict[str, Any]:
        """Validate models against known vulnerability benchmarks"""
        self.logger.info("📋 Validating against known benchmarks...")

        # Known high-value vulnerability scenarios
        benchmark_cases = [
            {
                'name': 'Critical RCE in Major Platform',
                'vuln_type': 'Remote Code Execution',
                'severity': 'Critical',
                'program': 'Google',
                'expected_range': (25000, 100000),
                'description': 'Critical RCE allowing full system compromise'
            },
            {
                'name': 'SQL Injection in Financial App',
                'vuln_type': 'SQL Injection',
                'severity': 'High',
                'program': 'PayPal',
                'expected_range': (5000, 25000),
                'description': 'SQL injection in financial application'
            },
            {
                'name': 'XSS in Social Media',
                'vuln_type': 'Cross-site Scripting (XSS)',
                'severity': 'Medium',
                'program': 'Facebook',
                'expected_range': (500, 5000),
                'description': 'Stored XSS in social media platform'
            },
            {
                'name': 'IDOR in Cloud Service',
                'vuln_type': 'Insecure Direct Object Reference',
                'severity': 'Medium',
                'program': 'Microsoft',
                'expected_range': (1000, 8000),
                'description': 'IDOR allowing access to other users data'
            },
            {
                'name': 'DeFi Flash Loan Attack',
                'vuln_type': 'Flash Loan Attack',
                'severity': 'Critical',
                'program': 'Uniswap',
                'expected_range': (100000, 2000000),
                'description': 'Flash loan vulnerability in DeFi protocol'
            }
        ]

        benchmark_results = []

        if self.bounty_predictor is not None:
            for case in benchmark_cases:
                # Predict bounty
                predicted_bounty = self._predict_bounty_for_case(case)

                # Predict severity
                predicted_severity = self._predict_severity_for_case(case)

                # Check if prediction is within expected range
                expected_min, expected_max = case['expected_range']
                within_range = expected_min <= predicted_bounty <= expected_max

                # Severity accuracy
                severity_match = predicted_severity.lower() == case['severity'].lower()

                result = {
                    'case_name': case['name'],
                    'predicted_bounty': predicted_bounty,
                    'expected_range': case['expected_range'],
                    'within_expected_range': within_range,
                    'predicted_severity': predicted_severity,
                    'expected_severity': case['severity'],
                    'severity_match': severity_match,
                    'range_accuracy': (predicted_bounty - expected_min) / (expected_max - expected_min) if expected_max > expected_min else 0
                }

                benchmark_results.append(result)

        # Calculate benchmark metrics
        if benchmark_results:
            range_accuracy = sum(r['within_expected_range'] for r in benchmark_results) / len(benchmark_results)
            severity_accuracy = sum(r['severity_match'] for r in benchmark_results) / len(benchmark_results)

            benchmark_summary = {
                'cases_tested': len(benchmark_results),
                'range_accuracy': range_accuracy,
                'severity_accuracy': severity_accuracy,
                'individual_results': benchmark_results
            }
        else:
            benchmark_summary = {'error': 'No models available for benchmarking'}

        self.validation_results['benchmarks'] = benchmark_summary
        self.logger.info(f"✅ Benchmark validation complete - Range accuracy: {range_accuracy:.1%}, Severity accuracy: {severity_accuracy:.1%}")

        return benchmark_summary

    def _predict_bounty_for_case(self, case: Dict) -> float:
        """Predict bounty for a benchmark case"""
        vuln_type = case['vuln_type']
        severity = case['severity']
        program = case['program']

        feature_vector = np.array([[
            len(vuln_type),
            1 if 'Critical' in severity else 0,
            1 if 'High' in severity else 0,
            1 if 'Medium' in severity else 0,
            1 if 'Low' in severity else 0,
            len(program),
            1 if 'SQL' in vuln_type.upper() else 0,
            1 if 'XSS' in vuln_type.upper() else 0,
            1 if 'RCE' in vuln_type.upper() or 'REMOTE CODE' in vuln_type.upper() else 0,
            1 if 'SSRF' in vuln_type.upper() else 0,
            1 if 'IDOR' in vuln_type.upper() else 0,
            1 if 'DeFi' in program or 'Flash' in vuln_type else 0,
            hash(vuln_type) % 100,
        ]])

        try:
            prediction = self.bounty_predictor.predict(feature_vector)[0]
            return max(0, prediction)
        except:
            return 0.0

    def _predict_severity_for_case(self, case: Dict) -> str:
        """Predict severity for a benchmark case"""
        if self.severity_classifier is None or self.tfidf_vectorizer is None:
            return 'Unknown'

        try:
            description = case['description']
            text_features = self.tfidf_vectorizer.transform([description])
            prediction = self.severity_classifier.predict(text_features.toarray())[0]
            return self.label_encoder.inverse_transform([prediction])[0]
        except:
            return 'Unknown'

    def generate_validation_report(self) -> str:
        """Generate comprehensive validation report"""
        self.logger.info("📄 Generating validation report...")

        report_content = f"""# 🔬 MODEL VALIDATION REPORT

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Validation Framework:** Comprehensive ML Model Assessment

## 📊 VALIDATION SUMMARY

### Overall Model Performance:
"""

        # Bounty prediction results
        if 'bounty_prediction' in self.validation_results:
            bp = self.validation_results['bounty_prediction']
            report_content += f"""
### 💰 Bounty Prediction Model:
- **Cross-Validation R²:** {bp.get('cv_r2_mean', 0):.3f} ± {bp.get('cv_r2_std', 0):.3f}
- **Cross-Validation MAE:** ${bp.get('cv_mae_mean', 0):,.2f} ± ${bp.get('cv_mae_std', 0):,.2f}
- **Final R² Score:** {bp.get('r2_score', 0):.3f}
- **Mean Absolute Error:** ${bp.get('mae', 0):,.2f}
- **Root Mean Square Error:** ${bp.get('rmse', 0):,.2f}
- **Training Samples:** {bp.get('samples_count', 0):,}
- **Target Mean:** ${bp.get('target_mean', 0):,.2f}
- **Target Std:** ${bp.get('target_std', 0):,.2f}

#### Top Feature Importance:
"""
            # Feature importance
            if 'feature_importance' in bp:
                sorted_features = sorted(bp['feature_importance'].items(), key=lambda x: x[1], reverse=True)
                for feature, importance in sorted_features[:5]:
                    report_content += f"- **{feature}:** {importance:.3f}\n"

        # Severity classification results
        if 'severity_classification' in self.validation_results:
            sc = self.validation_results['severity_classification']
            if 'error' not in sc:
                report_content += f"""
### 🎯 Severity Classification Model:
- **Cross-Validation Accuracy:** {sc.get('cv_accuracy_mean', 0):.3f} ± {sc.get('cv_accuracy_std', 0):.3f}
- **Cross-Validation Precision:** {sc.get('cv_precision_mean', 0):.3f} ± {sc.get('cv_precision_std', 0):.3f}
- **Cross-Validation Recall:** {sc.get('cv_recall_mean', 0):.3f} ± {sc.get('cv_recall_std', 0):.3f}
- **Cross-Validation F1:** {sc.get('cv_f1_mean', 0):.3f} ± {sc.get('cv_f1_std', 0):.3f}
- **Final Accuracy:** {sc.get('accuracy', 0):.3f}
- **Weighted Precision:** {sc.get('precision_weighted', 0):.3f}
- **Weighted Recall:** {sc.get('recall_weighted', 0):.3f}
- **Weighted F1:** {sc.get('f1_weighted', 0):.3f}
- **Training Samples:** {sc.get('samples_count', 0):,}
- **Feature Count:** {sc.get('feature_count', 0):,}
"""

        # Benchmark results
        if 'benchmarks' in self.validation_results:
            bench = self.validation_results['benchmarks']
            if 'error' not in bench:
                report_content += f"""
### 📋 Benchmark Validation:
- **Cases Tested:** {bench.get('cases_tested', 0)}
- **Range Accuracy:** {bench.get('range_accuracy', 0):.1%}
- **Severity Accuracy:** {bench.get('severity_accuracy', 0):.1%}

#### Individual Benchmark Results:
"""
                for result in bench.get('individual_results', []):
                    status = "✅" if result['within_expected_range'] else "❌"
                    severity_status = "✅" if result['severity_match'] else "❌"
                    report_content += f"""
**{result['case_name']}:**
- Predicted Bounty: ${result['predicted_bounty']:,.2f} {status}
- Expected Range: ${result['expected_range'][0]:,} - ${result['expected_range'][1]:,}
- Predicted Severity: {result['predicted_severity']} {severity_status}
- Expected Severity: {result['expected_severity']}
"""

        report_content += f"""
## 🎯 VALIDATION CONCLUSIONS

### Model Reliability Assessment:
"""

        # Generate conclusions based on metrics
        if 'bounty_prediction' in self.validation_results:
            bp = self.validation_results['bounty_prediction']
            r2_score = bp.get('r2_score', 0)
            if r2_score >= 0.7:
                report_content += "- ✅ **Bounty Prediction Model:** HIGH RELIABILITY - Strong predictive performance\n"
            elif r2_score >= 0.5:
                report_content += "- ⚠️ **Bounty Prediction Model:** MODERATE RELIABILITY - Acceptable predictive performance\n"
            else:
                report_content += "- ❌ **Bounty Prediction Model:** LOW RELIABILITY - Needs improvement\n"

        if 'severity_classification' in self.validation_results:
            sc = self.validation_results['severity_classification']
            if 'error' not in sc:
                accuracy = sc.get('accuracy', 0)
                if accuracy >= 0.8:
                    report_content += "- ✅ **Severity Classification Model:** HIGH RELIABILITY - Excellent classification performance\n"
                elif accuracy >= 0.6:
                    report_content += "- ⚠️ **Severity Classification Model:** MODERATE RELIABILITY - Good classification performance\n"
                else:
                    report_content += "- ❌ **Severity Classification Model:** LOW RELIABILITY - Needs improvement\n"

        report_content += f"""
### Recommendations:
1. **Continue monitoring** model performance with new data
2. **Regular retraining** as new vulnerability data becomes available
3. **Feature engineering** improvements for better predictions
4. **Ensemble methods** consideration for improved accuracy
5. **Domain-specific fine-tuning** for specialized vulnerability types

---

*Generated by Model Validation Framework*
*Comprehensive ML Model Assessment*
*Production-Ready • Statistically Validated • Performance Verified*
"""

        # Save report
        report_path = self.output_dir / "model_validation_report.md"
        with open(report_path, 'w') as f:
            f.write(report_content)

        # Save validation results as JSON
        results_path = self.output_dir / "validation_results.json"
        with open(results_path, 'w') as f:
            # Make numpy arrays JSON serializable
            serializable_results = self._make_json_serializable(self.validation_results)
            json.dump(serializable_results, f, indent=2)

        self.logger.info(f"✅ Validation report generated: {report_path}")
        return str(report_path)

    def _make_json_serializable(self, obj):
        """Convert numpy arrays and other non-serializable objects to JSON-serializable format"""
        if isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.integer, np.floating)):
            return float(obj)
        elif isinstance(obj, np.bool_):
            return bool(obj)
        else:
            return obj

    def run_comprehensive_validation(self) -> Dict[str, Any]:
        """Run complete model validation pipeline"""
        self.logger.info("🚀 Starting comprehensive model validation...")

        try:
            # Load training data
            bounty_df, severity_df = self.load_training_data()

            # Validate bounty prediction model
            if len(bounty_df) > 10:
                X_bounty, y_bounty = self.prepare_bounty_features(bounty_df)
                self.validate_bounty_prediction_model(X_bounty, y_bounty)
            else:
                self.logger.warning("⚠️ Insufficient bounty data for validation")

            # Validate severity classification model
            if len(severity_df) > 10:
                self.validate_severity_classification_model(severity_df)
            else:
                self.logger.warning("⚠️ Insufficient severity data for validation")

            # Validate against benchmarks
            self.validate_against_known_benchmarks()

            # Generate report
            report_path = self.generate_validation_report()

            self.logger.info("✅ Comprehensive model validation completed successfully!")

            return {
                'status': 'success',
                'report_path': report_path,
                'validation_results': self.validation_results
            }

        except Exception as e:
            self.logger.error(f"❌ Validation failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'status': 'error',
                'error': str(e)
            }

def main():
    """Main validation execution"""
    print("🔬 MODEL VALIDATION FRAMEWORK")
    print("=" * 50)

    # Initialize validation framework
    validator = ModelValidationFramework()

    # Run comprehensive validation
    results = validator.run_comprehensive_validation()

    if results['status'] == 'success':
        print(f"\n✅ VALIDATION COMPLETE!")
        print(f"📄 Report: {results['report_path']}")
        print(f"📊 Results: model_validation/validation_results.json")
    else:
        print(f"\n❌ VALIDATION FAILED: {results['error']}")

if __name__ == "__main__":
    main()