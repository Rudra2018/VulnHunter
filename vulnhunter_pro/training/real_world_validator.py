#!/usr/bin/env python3
"""
Real-World Model Validator for VulnHunter Professional
======================================================

Validates trained models against real-world vulnerability datasets.
Provides comprehensive performance analysis and comparisons.
"""

import os
import sys
import json
import logging
import re
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import numpy as np
import time

# ML Libraries
try:
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix
    from sklearn.feature_extraction.text import TfidfVectorizer
    import pickle
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

class RealWorldValidator:
    """Validator for real-world vulnerability detection performance"""

    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.test_results = {}

    def load_models(self, model_dir: str) -> bool:
        """Load trained models and vectorizers"""
        print(f"Loading models from {model_dir}...")

        # Check if directory exists
        if not os.path.exists(model_dir):
            print(f"Model directory not found: {model_dir}")
            return False

        # Load models
        model_files = list(Path(model_dir).glob("*_model.pkl"))
        for model_file in model_files:
            model_name = model_file.stem.replace('_model', '')
            try:
                with open(model_file, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
                print(f"Loaded model: {model_name}")
            except Exception as e:
                print(f"Error loading model {model_name}: {e}")

        # Load vectorizers
        vectorizer_files = list(Path(model_dir).glob("*vectorizer.pkl"))
        for vec_file in vectorizer_files:
            vec_name = vec_file.stem
            try:
                with open(vec_file, 'rb') as f:
                    self.vectorizers[vec_name] = pickle.load(f)
                print(f"Loaded vectorizer: {vec_name}")
            except Exception as e:
                print(f"Error loading vectorizer {vec_name}: {e}")

        print(f"Successfully loaded {len(self.models)} models and {len(self.vectorizers)} vectorizers")
        return len(self.models) > 0

    def preprocess_code(self, code: str, language: str) -> str:
        """Preprocess code for model input"""
        # Same preprocessing as training
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        code = re.sub(r'\s+', ' ', code)
        code = f"LANG_{language.upper()} " + code
        return code.strip()

    def test_on_owasp_benchmark(self, dataset_dir: str) -> Dict[str, Any]:
        """Test models on OWASP Benchmark dataset"""
        print("\n=== Testing on OWASP Benchmark ===")

        owasp_dir = os.path.join(dataset_dir, "web_owasp")
        results_file = os.path.join(owasp_dir, "expectedresults-1.2.csv")
        java_src_dir = os.path.join(owasp_dir, "src/main/java/org/owasp/benchmark/testcode")

        if not os.path.exists(results_file) or not os.path.exists(java_src_dir):
            print("OWASP Benchmark files not found")
            return {}

        # Load ground truth
        labels = {}
        with open(results_file, 'r') as f:
            import csv
            reader = csv.reader(f)
            for row in reader:
                if row[0].startswith('#') or len(row) < 4:
                    continue
                test_name, category, is_vuln, cwe = row[:4]
                labels[test_name] = {
                    'is_vulnerable': is_vuln.lower() == 'true',
                    'category': category,
                    'cwe': cwe
                }

        # Process test cases
        test_codes = []
        true_labels = []
        test_names = []

        java_files = list(Path(java_src_dir).glob("*.java"))[:500]  # Limit for testing
        print(f"Testing on {len(java_files)} OWASP Benchmark files...")

        for java_file in java_files:
            test_name = java_file.stem
            if test_name not in labels:
                continue

            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    code_content = f.read()

                processed_code = self.preprocess_code(code_content, 'java')
                test_codes.append(processed_code)
                true_labels.append(1 if labels[test_name]['is_vulnerable'] else 0)
                test_names.append(test_name)

            except Exception as e:
                continue

        if not test_codes:
            print("No valid test cases found")
            return {}

        print(f"Testing {len(test_codes)} valid cases...")

        # Test each model
        owasp_results = {}
        for model_name, model in self.models.items():
            print(f"\nTesting {model_name}...")

            # Find appropriate vectorizer
            vectorizer = None
            for vec_name, vec in self.vectorizers.items():
                if 'real_world' in vec_name or 'vectorizer' in vec_name:
                    vectorizer = vec
                    break

            if vectorizer is None:
                print(f"No vectorizer found for {model_name}")
                continue

            try:
                # Transform features
                X_test = vectorizer.transform(test_codes)

                # Make predictions
                predictions = model.predict(X_test)
                if hasattr(model, 'predict_proba'):
                    probabilities = model.predict_proba(X_test)[:, 1]
                else:
                    probabilities = predictions

                # Calculate metrics
                accuracy = accuracy_score(true_labels, predictions)
                precision, recall, f1, _ = precision_recall_fscore_support(
                    true_labels, predictions, average='weighted'
                )

                # Detailed analysis
                conf_matrix = confusion_matrix(true_labels, predictions)
                tn, fp, fn, tp = conf_matrix.ravel()

                owasp_results[model_name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'true_positives': int(tp),
                    'true_negatives': int(tn),
                    'false_positives': int(fp),
                    'false_negatives': int(fn),
                    'total_tested': len(test_codes),
                    'total_vulnerable': sum(true_labels),
                    'detected_vulnerable': int(np.sum(predictions))
                }

                print(f"  Accuracy: {accuracy:.3f}")
                print(f"  Precision: {precision:.3f}")
                print(f"  Recall: {recall:.3f}")
                print(f"  F1-Score: {f1:.3f}")
                print(f"  Detected {int(np.sum(predictions))}/{sum(true_labels)} vulnerabilities")

            except Exception as e:
                print(f"Error testing {model_name}: {e}")
                continue

        return owasp_results

    def test_on_synthetic_data(self) -> Dict[str, Any]:
        """Test models on our synthetic test suite"""
        print("\n=== Testing on VulnHunter Synthetic Test Suite ===")

        # Use the existing test framework
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from tests.test_real_vulns import RealVulnerabilityTestSuite

            test_suite = RealVulnerabilityTestSuite()
            test_cases = test_suite.create_test_cases()

            print(f"Testing on {len(test_cases)} synthetic test cases...")

            synthetic_results = {}
            for model_name, model in self.models.items():
                print(f"\nTesting {model_name} on synthetic data...")

                # Find appropriate vectorizer
                vectorizer = None
                for vec_name, vec in self.vectorizers.items():
                    if 'real_world' in vec_name or 'vectorizer' in vec_name:
                        vectorizer = vec
                        break

                if vectorizer is None:
                    continue

                correct = 0
                total = 0
                detailed_results = []

                for test_case in test_cases:
                    try:
                        # Preprocess code
                        processed_code = self.preprocess_code(test_case['code'], 'python')

                        # Transform and predict
                        X_test = vectorizer.transform([processed_code])
                        prediction = model.predict(X_test)[0]

                        # Check if prediction is correct
                        expected_vulnerable = test_case['expected_type'] != 'unknown'
                        predicted_vulnerable = prediction == 1

                        is_correct = (expected_vulnerable and predicted_vulnerable) or \
                                   (not expected_vulnerable and not predicted_vulnerable)

                        if is_correct:
                            correct += 1

                        detailed_results.append({
                            'test_name': test_case['name'],
                            'expected_vulnerable': expected_vulnerable,
                            'predicted_vulnerable': predicted_vulnerable,
                            'correct': is_correct
                        })

                        total += 1

                    except Exception as e:
                        continue

                accuracy = correct / total if total > 0 else 0

                synthetic_results[model_name] = {
                    'accuracy': accuracy,
                    'correct': correct,
                    'total': total,
                    'detailed_results': detailed_results
                }

                print(f"  Accuracy: {accuracy:.3f} ({correct}/{total})")

        except Exception as e:
            print(f"Error testing synthetic data: {e}")
            return {}

        return synthetic_results

    def generate_comprehensive_report(self, owasp_results: Dict, synthetic_results: Dict) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        print("\n=== Generating Comprehensive Validation Report ===")

        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'owasp_benchmark_results': owasp_results,
            'synthetic_test_results': synthetic_results,
            'model_comparison': {},
            'summary': {}
        }

        # Compare models
        for model_name in self.models.keys():
            model_stats = {}

            if model_name in owasp_results:
                owasp = owasp_results[model_name]
                model_stats['owasp_accuracy'] = owasp['accuracy']
                model_stats['owasp_f1'] = owasp['f1']
                model_stats['owasp_recall'] = owasp['recall']

            if model_name in synthetic_results:
                synthetic = synthetic_results[model_name]
                model_stats['synthetic_accuracy'] = synthetic['accuracy']

            report['model_comparison'][model_name] = model_stats

        # Generate summary
        if owasp_results:
            best_owasp_model = max(owasp_results.items(), key=lambda x: x[1]['accuracy'])
            report['summary']['best_owasp_model'] = {
                'name': best_owasp_model[0],
                'accuracy': best_owasp_model[1]['accuracy']
            }

        if synthetic_results:
            best_synthetic_model = max(synthetic_results.items(), key=lambda x: x[1]['accuracy'])
            report['summary']['best_synthetic_model'] = {
                'name': best_synthetic_model[0],
                'accuracy': best_synthetic_model[1]['accuracy']
            }

        # Save report
        report_path = "vulnhunter_pro/training_data/real_world_validation_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"Comprehensive report saved to: {report_path}")
        return report

    def run_validation(self, dataset_dir: str, model_dir: str) -> Dict[str, Any]:
        """Run complete validation pipeline"""
        print("=== VulnHunter Pro Real-World Model Validation ===")

        # Load models
        if not self.load_models(model_dir):
            print("Failed to load models")
            return {}

        # Test on OWASP Benchmark
        owasp_results = self.test_on_owasp_benchmark(dataset_dir)

        # Test on synthetic data
        synthetic_results = self.test_on_synthetic_data()

        # Generate comprehensive report
        report = self.generate_comprehensive_report(owasp_results, synthetic_results)

        return report

def main():
    """Main validation function"""
    logging.basicConfig(level=logging.INFO)

    if not SKLEARN_AVAILABLE:
        print("scikit-learn not available")
        return

    # Configuration
    dataset_dir = os.path.expanduser("~/dataset")
    model_dirs = [
        "models/real_world/",  # New real-world models
        "models/"              # Original models
    ]

    validator = RealWorldValidator()

    # Try each model directory
    for model_dir in model_dirs:
        if os.path.exists(model_dir):
            print(f"\n=== Validating models from {model_dir} ===")
            report = validator.run_validation(dataset_dir, model_dir)

            if report:
                print("\n=== Validation Summary ===")
                if 'summary' in report:
                    summary = report['summary']
                    if 'best_owasp_model' in summary:
                        best_owasp = summary['best_owasp_model']
                        print(f"Best OWASP Performance: {best_owasp['name']} ({best_owasp['accuracy']:.3f})")

                    if 'best_synthetic_model' in summary:
                        best_synthetic = summary['best_synthetic_model']
                        print(f"Best Synthetic Performance: {best_synthetic['name']} ({best_synthetic['accuracy']:.3f})")

                print(f"Detailed report: vulnhunter_pro/training_data/real_world_validation_report.json")
                break
        else:
            print(f"Model directory not found: {model_dir}")

if __name__ == "__main__":
    main()