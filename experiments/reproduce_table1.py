#!/usr/bin/env python3
"""
Reproduce Table 1: Performance on Comprehensive Test Suite

Generates results with confidence intervals for:
- Accuracy, Precision, Recall, F1-Score
- False Positive Rate, False Negative Rate
- Throughput, Analysis Time

Usage:
    python reproduce_table1.py --dataset data/comprehensive_test_suite.json --output results/table1.csv
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
import logging
from typing import Dict, List
import time

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix
)
from scipy import stats

from core.neural_formal_integration import TheoreticallyGroundedDetector

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def load_test_suite(dataset_path: str) -> Dict:
    """Load comprehensive test suite"""
    logger.info(f"Loading test suite from {dataset_path}")

    if not os.path.exists(dataset_path):
        logger.warning(f"Dataset not found: {dataset_path}")
        logger.info("Creating synthetic test suite for demonstration...")
        return create_synthetic_test_suite()

    with open(dataset_path, 'r') as f:
        data = json.load(f)

    logger.info(f"Loaded {len(data['samples'])} test samples")
    return data


def create_synthetic_test_suite() -> Dict:
    """Create synthetic test suite for demonstration"""
    logger.info("Generating synthetic test suite (100 samples)...")

    # Vulnerability patterns
    vulnerable_patterns = [
        # SQL Injection
        '''def query(user):
    sql = "SELECT * FROM users WHERE name = '" + user + "'"
    return db.execute(sql)''',

        # Buffer Overflow
        '''void copy(char* input) {
    char buf[64];
    strcpy(buf, input);
}''',

        # Command Injection
        '''import os
def run(cmd):
    os.system("echo " + cmd)''',

        # Path Traversal
        '''def read_file(path):
    return open(path, 'r').read()''',
    ]

    # Safe patterns
    safe_patterns = [
        # Parameterized SQL
        '''def query(user_id):
    sql = "SELECT * FROM users WHERE id = ?"
    return db.execute(sql, [user_id])''',

        # Safe strcpy
        '''void copy(char* input, size_t len) {
    char buf[64];
    strncpy(buf, input, len-1);
    buf[len-1] = '\\0';
}''',

        # Safe subprocess
        '''import subprocess
def run(cmd):
    subprocess.run(['echo', cmd], shell=False)''',

        # Path sanitization
        '''import os
def read_file(path):
    safe_path = os.path.basename(path)
    return open(safe_path, 'r').read()''',
    ]

    samples = []

    # Generate vulnerable samples (50)
    for i in range(50):
        samples.append({
            'id': f'vuln_{i}',
            'code': vulnerable_patterns[i % len(vulnerable_patterns)],
            'label': 1,
            'cwe': f'CWE-{[89, 120, 78, 22][i % 4]}',
            'severity': np.random.choice(['HIGH', 'CRITICAL'])
        })

    # Generate safe samples (50)
    for i in range(50):
        samples.append({
            'id': f'safe_{i}',
            'code': safe_patterns[i % len(safe_patterns)],
            'label': 0,
            'cwe': 'N/A',
            'severity': 'N/A'
        })

    # Shuffle
    np.random.shuffle(samples)

    return {'samples': samples}


def evaluate_model(detector: TheoreticallyGroundedDetector, test_data: Dict) -> Dict:
    """Run evaluation on test suite"""
    logger.info("Running evaluation on test suite...")

    samples = test_data['samples']
    n_samples = len(samples)

    predictions = []
    confidences = []
    true_labels = []
    inference_times = []
    formal_verifications = 0

    for i, sample in enumerate(samples):
        if (i + 1) % 10 == 0:
            logger.info(f"  Processing sample {i+1}/{n_samples}...")

        code = sample['code']
        true_label = sample['label']

        # Run prediction
        start_time = time.time()
        result = detector.predict(code, enable_verification=True)
        inference_time = time.time() - start_time

        predictions.append(result['prediction'])
        confidences.append(result['confidence'])
        true_labels.append(true_label)
        inference_times.append(inference_time)

        # Count formal verifications
        if result['formal_proof'].result.value != '?':
            formal_verifications += 1

    # Convert to numpy arrays
    predictions = np.array(predictions)
    true_labels = np.array(true_labels)
    confidences = np.array(confidences)
    inference_times = np.array(inference_times)

    # Compute metrics
    tn, fp, fn, tp = confusion_matrix(true_labels, predictions).ravel()

    metrics = {
        'accuracy': accuracy_score(true_labels, predictions),
        'precision': precision_score(true_labels, predictions, zero_division=0),
        'recall': recall_score(true_labels, predictions, zero_division=0),
        'f1_score': f1_score(true_labels, predictions, zero_division=0),
        'fpr': fp / (fp + tn) if (fp + tn) > 0 else 0,
        'fnr': fn / (fn + tp) if (fn + tp) > 0 else 0,
        'throughput': n_samples / np.sum(inference_times),  # samples/sec
        'avg_inference_time': np.mean(inference_times) * 1000,  # ms
        'verification_coverage': formal_verifications / n_samples,
        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
    }

    logger.info("Evaluation complete!")
    logger.info(f"  Accuracy: {metrics['accuracy']:.3f}")
    logger.info(f"  F1-Score: {metrics['f1_score']:.3f}")
    logger.info(f"  FPR: {metrics['fpr']:.3f}")
    logger.info(f"  Throughput: {metrics['throughput']:.2f} samples/sec")

    return metrics


def bootstrap_confidence_intervals(
    test_data: Dict,
    detector: TheoreticallyGroundedDetector,
    n_bootstrap: int = 100,
    confidence_level: float = 0.95
) -> Dict:
    """
    Compute confidence intervals using bootstrap resampling

    Since we have a fixed test set, we use bootstrap to estimate CIs
    """
    logger.info(f"Computing confidence intervals ({n_bootstrap} bootstrap samples)...")

    samples = test_data['samples']
    n_samples = len(samples)

    bootstrap_metrics = {
        'accuracy': [],
        'precision': [],
        'recall': [],
        'f1_score': [],
        'fpr': [],
        'fnr': []
    }

    for i in range(n_bootstrap):
        if (i + 1) % 20 == 0:
            logger.info(f"  Bootstrap iteration {i+1}/{n_bootstrap}...")

        # Resample with replacement
        indices = np.random.choice(n_samples, size=n_samples, replace=True)
        bootstrap_samples = [samples[idx] for idx in indices]
        bootstrap_data = {'samples': bootstrap_samples}

        # Evaluate on bootstrap sample
        metrics = evaluate_model(detector, bootstrap_data)

        for key in bootstrap_metrics.keys():
            bootstrap_metrics[key].append(metrics[key])

    # Compute CIs
    alpha = 1 - confidence_level
    ci_results = {}

    for metric_name, values in bootstrap_metrics.items():
        values = np.array(values)
        mean = np.mean(values)
        ci_lower = np.percentile(values, alpha/2 * 100)
        ci_upper = np.percentile(values, (1 - alpha/2) * 100)

        ci_results[metric_name] = {
            'mean': mean,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'margin': (ci_upper - ci_lower) / 2
        }

        logger.info(f"  {metric_name}: {mean:.4f} [{ci_lower:.4f}, {ci_upper:.4f}]")

    return ci_results


def generate_latex_table(metrics: Dict, ci_results: Dict) -> str:
    """Generate LaTeX table for paper"""

    latex = r"""\begin{table}[h]
\centering
\caption{Performance on Comprehensive Test Suite (n=100)}
\begin{tabular}{lcc}
\toprule
\textbf{Metric} & \textbf{Value} & \textbf{95\% CI} \\
\midrule
"""

    # Metrics to include
    metric_labels = {
        'accuracy': 'Accuracy',
        'precision': 'Precision',
        'recall': 'Recall',
        'f1_score': 'F1-Score',
        'fpr': 'False Positive Rate',
        'fnr': 'False Negative Rate',
    }

    for key, label in metric_labels.items():
        if key in ci_results:
            ci = ci_results[key]
            latex += f"{label} & {ci['mean']:.3f} & [{ci['ci_lower']:.3f}, {ci['ci_upper']:.3f}] \\\\\n"
        else:
            latex += f"{label} & {metrics[key]:.3f} & - \\\\\n"

    # Add throughput and time
    latex += r"\midrule" + "\n"
    latex += f"Throughput (samples/s) & {metrics['throughput']:.1f} & - \\\\\n"
    latex += f"Avg. Analysis Time (ms) & {metrics['avg_inference_time']:.1f} & - \\\\\n"
    latex += f"Verification Coverage & {metrics['verification_coverage']:.1%} & - \\\\\n"

    latex += r"""\bottomrule
\end{tabular}
\label{tab:table1}
\end{table}
"""

    return latex


def main():
    parser = argparse.ArgumentParser(description='Reproduce Table 1: Performance Metrics')
    parser.add_argument('--dataset', type=str, default='data/comprehensive_test_suite.json',
                       help='Path to test dataset')
    parser.add_argument('--output', type=str, default='results/table1',
                       help='Output path (without extension)')
    parser.add_argument('--bootstrap', type=int, default=100,
                       help='Number of bootstrap samples for CIs')
    parser.add_argument('--skip-ci', action='store_true',
                       help='Skip confidence interval computation (faster)')

    args = parser.parse_args()

    # Create output directory
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("="*70)
    logger.info("Reproducing Table 1: Performance on Comprehensive Test Suite")
    logger.info("="*70)

    # Load test data
    test_data = load_test_suite(args.dataset)

    # Initialize detector
    logger.info("Initializing neural-formal detector...")
    detector = TheoreticallyGroundedDetector(neural_model=None)

    # Run evaluation
    metrics = evaluate_model(detector, test_data)

    # Compute confidence intervals
    if not args.skip_ci:
        ci_results = bootstrap_confidence_intervals(
            test_data,
            detector,
            n_bootstrap=args.bootstrap
        )
    else:
        ci_results = {}
        logger.info("Skipping CI computation (--skip-ci flag)")

    # Save results
    logger.info(f"\nSaving results to {args.output}.*")

    # CSV
    csv_data = {
        'Metric': [],
        'Value': [],
        'CI_Lower': [],
        'CI_Upper': []
    }

    for key in ['accuracy', 'precision', 'recall', 'f1_score', 'fpr', 'fnr']:
        csv_data['Metric'].append(key)
        if key in ci_results:
            csv_data['Value'].append(ci_results[key]['mean'])
            csv_data['CI_Lower'].append(ci_results[key]['ci_lower'])
            csv_data['CI_Upper'].append(ci_results[key]['ci_upper'])
        else:
            csv_data['Value'].append(metrics[key])
            csv_data['CI_Lower'].append(None)
            csv_data['CI_Upper'].append(None)

    df = pd.DataFrame(csv_data)
    df.to_csv(f"{args.output}.csv", index=False)
    logger.info(f"  Saved CSV: {args.output}.csv")

    # JSON (detailed)
    detailed_results = {
        'metrics': metrics,
        'confidence_intervals': ci_results,
        'dataset': args.dataset,
        'n_samples': len(test_data['samples'])
    }

    with open(f"{args.output}.json", 'w') as f:
        json.dump(detailed_results, f, indent=2)
    logger.info(f"  Saved JSON: {args.output}.json")

    # LaTeX table
    latex_table = generate_latex_table(metrics, ci_results)
    with open(f"{args.output}.tex", 'w') as f:
        f.write(latex_table)
    logger.info(f"  Saved LaTeX: {args.output}.tex")

    logger.info("\n" + "="*70)
    logger.info("Table 1 reproduction complete!")
    logger.info("="*70)
    logger.info(f"\nKey Results:")
    logger.info(f"  Accuracy: {metrics['accuracy']:.1%}")
    logger.info(f"  F1-Score: {metrics['f1_score']:.1%}")
    logger.info(f"  FPR: {metrics['fpr']:.1%}")
    logger.info(f"  Throughput: {metrics['throughput']:.1f} samples/sec")

    if ci_results:
        logger.info(f"\n  (with 95% confidence intervals in output files)")

    logger.info(f"\nOutputs:")
    logger.info(f"  - {args.output}.csv")
    logger.info(f"  - {args.output}.json")
    logger.info(f"  - {args.output}.tex")


if __name__ == "__main__":
    main()
