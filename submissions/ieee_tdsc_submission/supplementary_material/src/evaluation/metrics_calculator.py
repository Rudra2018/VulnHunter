#!/usr/bin/env python3
"""
Comprehensive Metrics Calculator for Vulnerability Detection

This module provides extensive evaluation metrics including:
- Standard classification metrics
- Multi-class and multi-task metrics
- Probabilistic metrics
- Ranking metrics
- Custom vulnerability-specific metrics
- Confidence and uncertainty metrics
"""

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report, matthews_corrcoef, log_loss,
    balanced_accuracy_score, cohen_kappa_score
)
from sklearn.calibration import calibration_curve
from sklearn.preprocessing import label_binarize
from scipy import stats
from typing import Dict, List, Optional, Tuple, Union
import pandas as pd
import warnings

warnings.filterwarnings("ignore")


class MetricsCalculator:
    """Comprehensive metrics calculator for vulnerability detection evaluation"""

    def __init__(self, num_classes: int = 30, vulnerability_types: Optional[List[str]] = None):
        self.num_classes = num_classes
        self.vulnerability_types = vulnerability_types or [f"vuln_type_{i}" for i in range(num_classes)]

        # Vulnerability severity mapping (based on CVSS scores)
        self.severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'none': 0.0
        }

        # Vulnerability category weights
        self.category_weights = {
            'injection': 1.0,
            'authentication': 0.9,
            'authorization': 0.9,
            'cryptographic': 0.8,
            'memory_safety': 0.95,
            'configuration': 0.7,
            'business_logic': 0.7,
            'api_security': 0.8,
            'supply_chain': 0.95
        }

    def calculate_binary_metrics(self,
                                y_true: np.ndarray,
                                y_pred: np.ndarray,
                                y_prob: Optional[np.ndarray] = None,
                                sample_weights: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Calculate comprehensive binary classification metrics

        Args:
            y_true: True binary labels
            y_pred: Predicted binary labels
            y_prob: Predicted probabilities (optional)
            sample_weights: Sample weights (optional)

        Returns:
            Dictionary of metric name -> value
        """

        metrics = {}

        # Basic metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred, sample_weight=sample_weights)
        metrics['balanced_accuracy'] = balanced_accuracy_score(y_true, y_pred, sample_weight=sample_weights)
        metrics['precision'] = precision_score(y_true, y_pred, sample_weight=sample_weights, zero_division=0)
        metrics['recall'] = recall_score(y_true, y_pred, sample_weight=sample_weights, zero_division=0)
        metrics['f1'] = f1_score(y_true, y_pred, sample_weight=sample_weights, zero_division=0)
        metrics['mcc'] = matthews_corrcoef(y_true, y_pred)
        metrics['kappa'] = cohen_kappa_score(y_true, y_pred, sample_weight=sample_weights)

        # Probabilistic metrics (if probabilities provided)
        if y_prob is not None:
            try:
                metrics['auc_roc'] = roc_auc_score(y_true, y_prob, sample_weight=sample_weights)
                metrics['auc_pr'] = average_precision_score(y_true, y_prob, sample_weight=sample_weights)
                metrics['log_loss'] = log_loss(y_true, y_prob, sample_weight=sample_weights)

                # Brier score
                metrics['brier_score'] = np.mean((y_prob - y_true) ** 2)

                # Calibration metrics
                cal_metrics = self._calculate_calibration_metrics(y_true, y_prob)
                metrics.update(cal_metrics)

            except ValueError as e:
                print(f"Warning: Could not calculate probabilistic metrics: {e}")

        # Confusion matrix based metrics
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

        metrics['true_positive_rate'] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        metrics['negative_predictive_value'] = tn / (tn + fn) if (tn + fn) > 0 else 0.0

        # Vulnerability-specific metrics
        metrics['vulnerability_detection_rate'] = metrics['recall']  # Same as recall for vulnerabilities
        metrics['false_alarm_rate'] = metrics['false_positive_rate']

        # Risk-weighted metrics
        if sample_weights is not None:
            metrics['weighted_accuracy'] = accuracy_score(y_true, y_pred, sample_weight=sample_weights)

        return metrics

    def calculate_multiclass_metrics(self,
                                   y_true: np.ndarray,
                                   y_pred: np.ndarray,
                                   y_prob: Optional[np.ndarray] = None,
                                   average: str = 'weighted') -> Dict[str, float]:
        """
        Calculate multiclass classification metrics

        Args:
            y_true: True class labels
            y_pred: Predicted class labels
            y_prob: Predicted class probabilities
            average: Averaging strategy ('micro', 'macro', 'weighted')

        Returns:
            Dictionary of metric name -> value
        """

        metrics = {}

        # Basic multiclass metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['balanced_accuracy'] = balanced_accuracy_score(y_true, y_pred)

        # Precision, Recall, F1 with different averaging
        for avg in ['micro', 'macro', 'weighted']:
            metrics[f'precision_{avg}'] = precision_score(y_true, y_pred, average=avg, zero_division=0)
            metrics[f'recall_{avg}'] = recall_score(y_true, y_pred, average=avg, zero_division=0)
            metrics[f'f1_{avg}'] = f1_score(y_true, y_pred, average=avg, zero_division=0)

        # Per-class metrics
        per_class_precision = precision_score(y_true, y_pred, average=None, zero_division=0)
        per_class_recall = recall_score(y_true, y_pred, average=None, zero_division=0)
        per_class_f1 = f1_score(y_true, y_pred, average=None, zero_division=0)

        for i, vuln_type in enumerate(self.vulnerability_types):
            if i < len(per_class_precision):
                metrics[f'precision_{vuln_type}'] = per_class_precision[i]
                metrics[f'recall_{vuln_type}'] = per_class_recall[i]
                metrics[f'f1_{vuln_type}'] = per_class_f1[i]

        # Multiclass probabilistic metrics
        if y_prob is not None:
            try:
                # One-vs-rest AUC
                y_true_bin = label_binarize(y_true, classes=range(self.num_classes))
                metrics['auc_roc_ovr'] = roc_auc_score(y_true_bin, y_prob, average='weighted', multi_class='ovr')
                metrics['auc_roc_ovo'] = roc_auc_score(y_true, y_prob, average='weighted', multi_class='ovo')

                # Top-k accuracy
                metrics['top_1_accuracy'] = self._top_k_accuracy(y_true, y_prob, k=1)
                metrics['top_3_accuracy'] = self._top_k_accuracy(y_true, y_prob, k=3)
                metrics['top_5_accuracy'] = self._top_k_accuracy(y_true, y_prob, k=5)

                # Cross-entropy loss
                metrics['cross_entropy'] = log_loss(y_true, y_prob)

            except ValueError as e:
                print(f"Warning: Could not calculate multiclass probabilistic metrics: {e}")

        # Cohen's Kappa
        metrics['kappa'] = cohen_kappa_score(y_true, y_pred)

        return metrics

    def calculate_multitask_metrics(self,
                                  predictions: Dict[str, np.ndarray],
                                  ground_truth: Dict[str, np.ndarray],
                                  probabilities: Optional[Dict[str, np.ndarray]] = None) -> Dict[str, Dict[str, float]]:
        """
        Calculate metrics for multi-task learning

        Args:
            predictions: Dictionary of task_name -> predictions
            ground_truth: Dictionary of task_name -> true labels
            probabilities: Dictionary of task_name -> probabilities

        Returns:
            Dictionary of task_name -> metrics
        """

        task_metrics = {}

        for task_name in predictions.keys():
            if task_name not in ground_truth:
                continue

            y_pred = predictions[task_name]
            y_true = ground_truth[task_name]
            y_prob = probabilities.get(task_name) if probabilities else None

            if task_name == 'vulnerability':
                # Binary vulnerability detection
                task_metrics[task_name] = self.calculate_binary_metrics(y_true, y_pred, y_prob)

            elif task_name == 'vuln_type':
                # Multi-class vulnerability type classification
                task_metrics[task_name] = self.calculate_multiclass_metrics(y_true, y_pred, y_prob)

            elif task_name == 'severity':
                # Regression metrics for severity
                task_metrics[task_name] = self.calculate_regression_metrics(y_true, y_pred)

            elif task_name == 'exploitability':
                # Multi-class exploitability classification
                task_metrics[task_name] = self.calculate_multiclass_metrics(y_true, y_pred, y_prob)

            elif task_name == 'confidence':
                # Regression metrics for confidence
                task_metrics[task_name] = self.calculate_regression_metrics(y_true, y_pred)

        return task_metrics

    def calculate_regression_metrics(self,
                                   y_true: np.ndarray,
                                   y_pred: np.ndarray,
                                   sample_weights: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Calculate regression metrics

        Args:
            y_true: True values
            y_pred: Predicted values
            sample_weights: Sample weights

        Returns:
            Dictionary of metric name -> value
        """

        from sklearn.metrics import (
            mean_squared_error, mean_absolute_error, r2_score,
            explained_variance_score, max_error
        )

        metrics = {}

        # Basic regression metrics
        metrics['mse'] = mean_squared_error(y_true, y_pred, sample_weight=sample_weights)
        metrics['rmse'] = np.sqrt(metrics['mse'])
        metrics['mae'] = mean_absolute_error(y_true, y_pred, sample_weight=sample_weights)
        metrics['r2'] = r2_score(y_true, y_pred, sample_weight=sample_weights)
        metrics['explained_variance'] = explained_variance_score(y_true, y_pred, sample_weight=sample_weights)
        metrics['max_error'] = max_error(y_true, y_pred)

        # Additional regression metrics
        residuals = y_true - y_pred
        metrics['mean_residual'] = np.mean(residuals)
        metrics['std_residual'] = np.std(residuals)

        # Mean Absolute Percentage Error
        non_zero_mask = y_true != 0
        if np.any(non_zero_mask):
            metrics['mape'] = np.mean(np.abs((y_true[non_zero_mask] - y_pred[non_zero_mask]) / y_true[non_zero_mask])) * 100

        return metrics

    def calculate_ranking_metrics(self,
                                y_true: np.ndarray,
                                y_scores: np.ndarray,
                                k_values: List[int] = [1, 3, 5, 10]) -> Dict[str, float]:
        """
        Calculate ranking metrics for vulnerability prioritization

        Args:
            y_true: True relevance scores
            y_scores: Predicted relevance scores
            k_values: List of k values for top-k metrics

        Returns:
            Dictionary of ranking metrics
        """

        metrics = {}

        # Sort by predicted scores
        sorted_indices = np.argsort(y_scores)[::-1]
        sorted_true = y_true[sorted_indices]

        # Precision@k and Recall@k
        for k in k_values:
            if k <= len(sorted_true):
                top_k_true = sorted_true[:k]
                relevant_in_top_k = np.sum(top_k_true)
                total_relevant = np.sum(y_true)

                metrics[f'precision_at_{k}'] = relevant_in_top_k / k if k > 0 else 0.0
                metrics[f'recall_at_{k}'] = relevant_in_top_k / total_relevant if total_relevant > 0 else 0.0

        # Mean Reciprocal Rank (MRR)
        first_relevant_rank = None
        for i, is_relevant in enumerate(sorted_true):
            if is_relevant:
                first_relevant_rank = i + 1
                break

        metrics['mrr'] = 1.0 / first_relevant_rank if first_relevant_rank is not None else 0.0

        # Normalized Discounted Cumulative Gain (NDCG)
        for k in k_values:
            if k <= len(sorted_true):
                metrics[f'ndcg_at_{k}'] = self._calculate_ndcg(sorted_true[:k], k)

        return metrics

    def calculate_fairness_metrics(self,
                                 y_true: np.ndarray,
                                 y_pred: np.ndarray,
                                 sensitive_attrs: np.ndarray,
                                 y_prob: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Calculate fairness and bias metrics

        Args:
            y_true: True labels
            y_pred: Predicted labels
            sensitive_attrs: Sensitive attributes (e.g., programming language, project type)
            y_prob: Predicted probabilities

        Returns:
            Dictionary of fairness metrics
        """

        metrics = {}

        # Get unique groups
        unique_groups = np.unique(sensitive_attrs)

        # Calculate per-group metrics
        group_metrics = {}
        for group in unique_groups:
            group_mask = sensitive_attrs == group
            group_y_true = y_true[group_mask]
            group_y_pred = y_pred[group_mask]

            if len(group_y_true) > 0:
                group_metrics[group] = {
                    'accuracy': accuracy_score(group_y_true, group_y_pred),
                    'precision': precision_score(group_y_true, group_y_pred, zero_division=0),
                    'recall': recall_score(group_y_true, group_y_pred, zero_division=0),
                    'f1': f1_score(group_y_true, group_y_pred, zero_division=0)
                }

                if y_prob is not None:
                    group_y_prob = y_prob[group_mask]
                    if len(np.unique(group_y_true)) > 1:
                        group_metrics[group]['auc_roc'] = roc_auc_score(group_y_true, group_y_prob)

        # Demographic parity difference
        if len(unique_groups) >= 2:
            positive_rates = []
            for group in unique_groups:
                group_mask = sensitive_attrs == group
                positive_rate = np.mean(y_pred[group_mask]) if np.any(group_mask) else 0
                positive_rates.append(positive_rate)

            metrics['demographic_parity_diff'] = max(positive_rates) - min(positive_rates)

            # Equalized odds difference
            tpr_differences = []
            fpr_differences = []

            for i, group1 in enumerate(unique_groups):
                for group2 in unique_groups[i+1:]:
                    if group1 in group_metrics and group2 in group_metrics:
                        tpr_diff = abs(group_metrics[group1]['recall'] - group_metrics[group2]['recall'])
                        tpr_differences.append(tpr_diff)

            if tpr_differences:
                metrics['equalized_odds_diff'] = max(tpr_differences)

        return metrics

    def calculate_uncertainty_metrics(self,
                                    y_prob: np.ndarray,
                                    y_true: np.ndarray,
                                    uncertainty_estimates: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Calculate uncertainty and confidence metrics

        Args:
            y_prob: Predicted probabilities
            y_true: True labels
            uncertainty_estimates: Uncertainty estimates (e.g., from MC Dropout)

        Returns:
            Dictionary of uncertainty metrics
        """

        metrics = {}

        # Confidence-based metrics
        max_probs = np.max(y_prob, axis=1) if y_prob.ndim > 1 else y_prob
        metrics['mean_confidence'] = np.mean(max_probs)
        metrics['confidence_std'] = np.std(max_probs)

        # Entropy-based uncertainty
        if y_prob.ndim > 1:  # Multi-class case
            entropy = -np.sum(y_prob * np.log(y_prob + 1e-8), axis=1)
        else:  # Binary case
            entropy = -(y_prob * np.log(y_prob + 1e-8) + (1 - y_prob) * np.log(1 - y_prob + 1e-8))

        metrics['mean_entropy'] = np.mean(entropy)
        metrics['entropy_std'] = np.std(entropy)

        # Calibration metrics
        if y_prob.ndim == 1 or y_prob.shape[1] == 2:  # Binary case
            prob_true = y_prob if y_prob.ndim == 1 else y_prob[:, 1]
            cal_metrics = self._calculate_calibration_metrics(y_true, prob_true)
            metrics.update(cal_metrics)

        # Uncertainty-based metrics (if uncertainty estimates provided)
        if uncertainty_estimates is not None:
            metrics['mean_uncertainty'] = np.mean(uncertainty_estimates)
            metrics['uncertainty_std'] = np.std(uncertainty_estimates)

            # Correlation between uncertainty and errors
            predictions = np.argmax(y_prob, axis=1) if y_prob.ndim > 1 else (y_prob > 0.5).astype(int)
            errors = (predictions != y_true).astype(int)

            if len(np.unique(uncertainty_estimates)) > 1 and len(np.unique(errors)) > 1:
                correlation, p_value = stats.pearsonr(uncertainty_estimates, errors)
                metrics['uncertainty_error_correlation'] = correlation
                metrics['uncertainty_error_correlation_pvalue'] = p_value

        return metrics

    def _calculate_calibration_metrics(self, y_true: np.ndarray, y_prob: np.ndarray,
                                     n_bins: int = 10) -> Dict[str, float]:
        """Calculate calibration metrics"""
        try:
            fraction_of_positives, mean_predicted_value = calibration_curve(
                y_true, y_prob, n_bins=n_bins, strategy='uniform'
            )

            # Expected Calibration Error (ECE)
            bin_boundaries = np.linspace(0, 1, n_bins + 1)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]

            ece = 0
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                in_bin = (y_prob > bin_lower) & (y_prob <= bin_upper)
                prop_in_bin = in_bin.mean()

                if prop_in_bin > 0:
                    accuracy_in_bin = y_true[in_bin].mean()
                    avg_confidence_in_bin = y_prob[in_bin].mean()
                    ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

            # Reliability (average calibration error across bins)
            reliability = np.mean(np.abs(fraction_of_positives - mean_predicted_value))

            return {
                'expected_calibration_error': ece,
                'reliability': reliability
            }
        except:
            return {'expected_calibration_error': 0.0, 'reliability': 0.0}

    def _top_k_accuracy(self, y_true: np.ndarray, y_prob: np.ndarray, k: int) -> float:
        """Calculate top-k accuracy"""
        top_k_preds = np.argsort(y_prob, axis=1)[:, -k:]
        return np.mean([y_true[i] in top_k_preds[i] for i in range(len(y_true))])

    def _calculate_ndcg(self, relevance_scores: np.ndarray, k: int) -> float:
        """Calculate Normalized Discounted Cumulative Gain"""
        def dcg(scores):
            return np.sum((2**scores - 1) / np.log2(np.arange(2, len(scores) + 2)))

        actual_dcg = dcg(relevance_scores[:k])
        ideal_dcg = dcg(np.sort(relevance_scores)[::-1][:k])

        return actual_dcg / ideal_dcg if ideal_dcg > 0 else 0.0

    def generate_classification_report(self,
                                     y_true: np.ndarray,
                                     y_pred: np.ndarray,
                                     target_names: Optional[List[str]] = None) -> str:
        """Generate detailed classification report"""
        return classification_report(
            y_true, y_pred,
            target_names=target_names or self.vulnerability_types,
            zero_division=0
        )

    def calculate_confusion_matrix(self,
                                 y_true: np.ndarray,
                                 y_pred: np.ndarray,
                                 normalize: Optional[str] = None) -> np.ndarray:
        """Calculate confusion matrix"""
        return confusion_matrix(y_true, y_pred, normalize=normalize)

    def summarize_metrics(self, metrics_dict: Dict[str, Dict[str, float]]) -> pd.DataFrame:
        """Summarize metrics across tasks in a DataFrame"""
        summary_data = []

        for task_name, task_metrics in metrics_dict.items():
            for metric_name, metric_value in task_metrics.items():
                summary_data.append({
                    'Task': task_name,
                    'Metric': metric_name,
                    'Value': metric_value
                })

        return pd.DataFrame(summary_data)


def test_metrics_calculator():
    """Test the metrics calculator"""
    print("Testing Metrics Calculator...")

    # Initialize calculator
    calculator = MetricsCalculator(num_classes=5)

    # Generate sample data
    np.random.seed(42)
    n_samples = 1000

    # Binary classification data
    y_true_binary = np.random.binomial(1, 0.3, n_samples)
    y_prob_binary = np.random.beta(2, 5, n_samples)
    y_pred_binary = (y_prob_binary > 0.5).astype(int)

    print("Testing binary classification metrics...")
    binary_metrics = calculator.calculate_binary_metrics(y_true_binary, y_pred_binary, y_prob_binary)
    print(f"Binary metrics calculated: {len(binary_metrics)} metrics")
    print(f"Accuracy: {binary_metrics['accuracy']:.3f}")
    print(f"F1 Score: {binary_metrics['f1']:.3f}")
    print(f"AUC-ROC: {binary_metrics['auc_roc']:.3f}")

    # Multi-class classification data
    y_true_multi = np.random.randint(0, 5, n_samples)
    y_prob_multi = np.random.dirichlet(np.ones(5), n_samples)
    y_pred_multi = np.argmax(y_prob_multi, axis=1)

    print("\nTesting multiclass classification metrics...")
    multiclass_metrics = calculator.calculate_multiclass_metrics(y_true_multi, y_pred_multi, y_prob_multi)
    print(f"Multiclass metrics calculated: {len(multiclass_metrics)} metrics")
    print(f"Accuracy: {multiclass_metrics['accuracy']:.3f}")
    print(f"F1 (weighted): {multiclass_metrics['f1_weighted']:.3f}")

    # Regression data
    y_true_reg = np.random.normal(0.5, 0.2, n_samples)
    y_pred_reg = y_true_reg + np.random.normal(0, 0.1, n_samples)

    print("\nTesting regression metrics...")
    regression_metrics = calculator.calculate_regression_metrics(y_true_reg, y_pred_reg)
    print(f"Regression metrics calculated: {len(regression_metrics)} metrics")
    print(f"MSE: {regression_metrics['mse']:.3f}")
    print(f"R2: {regression_metrics['r2']:.3f}")

    # Multi-task metrics
    predictions = {
        'vulnerability': y_pred_binary,
        'vuln_type': y_pred_multi,
        'severity': y_pred_reg
    }

    ground_truth = {
        'vulnerability': y_true_binary,
        'vuln_type': y_true_multi,
        'severity': y_true_reg
    }

    probabilities = {
        'vulnerability': y_prob_binary,
        'vuln_type': y_prob_multi
    }

    print("\nTesting multi-task metrics...")
    multitask_metrics = calculator.calculate_multitask_metrics(predictions, ground_truth, probabilities)
    print(f"Multi-task metrics calculated for {len(multitask_metrics)} tasks")

    # Test fairness metrics
    sensitive_attrs = np.random.choice(['python', 'java', 'cpp'], n_samples)
    print("\nTesting fairness metrics...")
    fairness_metrics = calculator.calculate_fairness_metrics(
        y_true_binary, y_pred_binary, sensitive_attrs, y_prob_binary
    )
    print(f"Fairness metrics calculated: {len(fairness_metrics)} metrics")

    print("\nMetrics calculator test completed!")


if __name__ == "__main__":
    test_metrics_calculator()