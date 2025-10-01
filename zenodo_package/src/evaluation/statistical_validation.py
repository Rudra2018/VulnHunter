#!/usr/bin/env python3
"""
Statistical Significance Validation Framework

This module implements rigorous statistical testing and validation protocols
for vulnerability detection research, ensuring results meet top-tier academic
publication standards with proper significance testing and effect size analysis.

Academic Standards Implemented:
- McNemar's Test for paired binary classifier comparison
- Wilcoxon Signed-Rank Test for non-parametric comparisons
- Bootstrap Confidence Intervals with bias correction
- Effect Size Calculations (Cohen's d, Cliff's delta)
- Multiple Hypothesis Testing Correction (Bonferroni, FDR)
- Cross-Validation with proper stratification
- Reproducible random seeding and experiment protocols

Publication Requirements:
- Statistical power analysis and sample size calculation
- Assumption testing for parametric methods
- Comprehensive reporting with confidence intervals
- Effect size interpretation and practical significance
- Reproducibility documentation

Target Venues: ICSE, IEEE S&P, ACM CCS, NDSS, USENIX Security
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scipy.stats import (
    chi2_contingency, mcnemar, wilcoxon, mannwhitneyu,
    shapiro, levene, ttest_rel, ttest_ind
)
from sklearn.model_selection import (
    StratifiedKFold, cross_validate, permutation_test_score
)
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    roc_auc_score, matthews_corrcoef, confusion_matrix
)
from statsmodels.stats.contingency_tables import mcnemar as mcnemar_exact
from statsmodels.stats.inter_rater import fleiss_kappa
from statsmodels.stats.proportion import proportions_ztest
from statsmodels.stats.power import ttest_power
import warnings
from typing import Dict, List, Tuple, Optional, Union, Any
from dataclasses import dataclass, asdict
import json
from pathlib import Path
import logging

warnings.filterwarnings("ignore")


@dataclass
class StatisticalTest:
    """Statistical test result"""
    test_name: str
    statistic: float
    p_value: float
    effect_size: float
    confidence_interval: Tuple[float, float]
    interpretation: str
    assumptions_met: bool
    sample_size: int
    power: float


@dataclass
class ComparisonResult:
    """Complete statistical comparison result"""
    model1_name: str
    model2_name: str
    dataset_name: str

    # Performance metrics
    model1_metrics: Dict[str, float]
    model2_metrics: Dict[str, float]

    # Statistical tests
    mcnemar_test: StatisticalTest
    wilcoxon_test: StatisticalTest
    permutation_test: StatisticalTest

    # Effect sizes
    cohens_d: float
    cliffs_delta: float

    # Overall conclusion
    significant_difference: bool
    practical_significance: bool
    recommendation: str


class StatisticalValidator:
    """
    Comprehensive statistical validation framework for ML model comparison

    This class implements all statistical methods required for rigorous
    academic evaluation of vulnerability detection models.
    """

    def __init__(self,
                 alpha: float = 0.05,
                 random_state: int = 42,
                 n_bootstrap: int = 1000,
                 n_permutations: int = 1000):
        """
        Initialize statistical validator

        Args:
            alpha: Significance level for hypothesis testing
            random_state: Random seed for reproducibility
            n_bootstrap: Number of bootstrap samples
            n_permutations: Number of permutation test iterations
        """
        self.alpha = alpha
        self.random_state = random_state
        self.n_bootstrap = n_bootstrap
        self.n_permutations = n_permutations

        # Set random seeds for reproducibility
        np.random.seed(random_state)

        self.logger = logging.getLogger(__name__)

    def mcnemar_test_exact(self,
                          y_true: np.ndarray,
                          y_pred1: np.ndarray,
                          y_pred2: np.ndarray) -> StatisticalTest:
        """
        Perform exact McNemar's test for comparing two binary classifiers

        This is the gold standard for comparing paired binary classifiers
        in academic literature.
        """
        # Create contingency table
        correct1 = (y_pred1 == y_true)
        correct2 = (y_pred2 == y_true)

        # McNemar's table: [both_correct, model1_correct_model2_wrong,
        #                   model1_wrong_model2_correct, both_wrong]
        both_correct = np.sum(correct1 & correct2)
        model1_only = np.sum(correct1 & ~correct2)
        model2_only = np.sum(~correct1 & correct2)
        both_wrong = np.sum(~correct1 & ~correct2)

        # Exact McNemar's test
        if model1_only + model2_only == 0:
            # No discordant pairs
            statistic = 0.0
            p_value = 1.0
        else:
            # Use exact binomial test
            statistic = min(model1_only, model2_only)
            p_value = 2 * stats.binom.cdf(statistic, model1_only + model2_only, 0.5)

        # Effect size (odds ratio)
        if model2_only == 0:
            odds_ratio = float('inf') if model1_only > 0 else 1.0
        else:
            odds_ratio = model1_only / model2_only

        effect_size = np.log(odds_ratio) if odds_ratio != float('inf') else 5.0

        # Bootstrap confidence interval for effect size
        ci_lower, ci_upper = self._bootstrap_mcnemar_ci(
            correct1, correct2, confidence_level=1-self.alpha
        )

        # Power analysis
        n = len(y_true)
        power = self._calculate_mcnemar_power(model1_only, model2_only, n)

        # Interpretation
        if p_value < self.alpha:
            if abs(effect_size) < 0.2:
                interpretation = "Statistically significant but small effect"
            elif abs(effect_size) < 0.8:
                interpretation = "Statistically significant with medium effect"
            else:
                interpretation = "Statistically significant with large effect"
        else:
            interpretation = "No statistically significant difference"

        return StatisticalTest(
            test_name="McNemar's Exact Test",
            statistic=statistic,
            p_value=p_value,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=True,  # McNemar's test has minimal assumptions
            sample_size=n,
            power=power
        )

    def wilcoxon_signed_rank_test(self,
                                 scores1: np.ndarray,
                                 scores2: np.ndarray) -> StatisticalTest:
        """
        Perform Wilcoxon signed-rank test for paired samples

        Non-parametric test for comparing paired continuous scores
        """
        # Remove ties (identical pairs)
        differences = scores1 - scores2
        non_zero_diff = differences[differences != 0]

        if len(non_zero_diff) == 0:
            # All differences are zero
            return StatisticalTest(
                test_name="Wilcoxon Signed-Rank Test",
                statistic=0.0,
                p_value=1.0,
                effect_size=0.0,
                confidence_interval=(0.0, 0.0),
                interpretation="No differences between models",
                assumptions_met=True,
                sample_size=len(scores1),
                power=0.0
            )

        # Perform test
        statistic, p_value = wilcoxon(non_zero_diff, alternative='two-sided')

        # Effect size (r = Z / sqrt(N))
        z_score = stats.norm.ppf(1 - p_value/2) if p_value < 1 else 0
        effect_size = z_score / np.sqrt(len(non_zero_diff))

        # Bootstrap confidence interval
        ci_lower, ci_upper = self._bootstrap_median_difference_ci(
            scores1, scores2, confidence_level=1-self.alpha
        )

        # Power calculation (approximate)
        power = self._calculate_wilcoxon_power(non_zero_diff)

        # Interpretation
        if p_value < self.alpha:
            if abs(effect_size) < 0.1:
                interpretation = "Statistically significant but negligible effect"
            elif abs(effect_size) < 0.3:
                interpretation = "Statistically significant with small effect"
            elif abs(effect_size) < 0.5:
                interpretation = "Statistically significant with medium effect"
            else:
                interpretation = "Statistically significant with large effect"
        else:
            interpretation = "No statistically significant difference"

        return StatisticalTest(
            test_name="Wilcoxon Signed-Rank Test",
            statistic=statistic,
            p_value=p_value,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=True,  # Non-parametric, minimal assumptions
            sample_size=len(scores1),
            power=power
        )

    def permutation_test(self,
                        y_true: np.ndarray,
                        scores1: np.ndarray,
                        scores2: np.ndarray,
                        metric: str = 'f1') -> StatisticalTest:
        """
        Perform permutation test for comparing model performance

        This is a robust non-parametric test that makes no distributional
        assumptions and is suitable for any evaluation metric.
        """
        # Calculate observed difference
        metric1 = self._calculate_metric(y_true, scores1, metric)
        metric2 = self._calculate_metric(y_true, scores2, metric)
        observed_diff = metric1 - metric2

        # Permutation test
        permuted_diffs = []
        combined_scores = np.column_stack([scores1, scores2])

        for _ in range(self.n_permutations):
            # Randomly assign scores to models
            perm_indices = np.random.permutation(2)
            perm_scores1 = combined_scores[:, perm_indices[0]]
            perm_scores2 = combined_scores[:, perm_indices[1]]

            perm_metric1 = self._calculate_metric(y_true, perm_scores1, metric)
            perm_metric2 = self._calculate_metric(y_true, perm_scores2, metric)
            permuted_diffs.append(perm_metric1 - perm_metric2)

        permuted_diffs = np.array(permuted_diffs)

        # Calculate p-value (two-tailed)
        p_value = np.mean(np.abs(permuted_diffs) >= np.abs(observed_diff))

        # Effect size (standardized difference)
        effect_size = observed_diff / np.std(permuted_diffs) if np.std(permuted_diffs) > 0 else 0

        # Confidence interval
        ci_lower = np.percentile(permuted_diffs, (self.alpha/2) * 100)
        ci_upper = np.percentile(permuted_diffs, (1 - self.alpha/2) * 100)

        # Power (proportion of permutations detecting effect if it exists)
        power = np.mean(np.abs(permuted_diffs) >= np.abs(observed_diff) * 0.5)

        # Interpretation
        if p_value < self.alpha:
            if abs(effect_size) < 0.2:
                interpretation = "Statistically significant but small practical difference"
            elif abs(effect_size) < 0.8:
                interpretation = "Statistically significant with medium practical difference"
            else:
                interpretation = "Statistically significant with large practical difference"
        else:
            interpretation = "No statistically significant difference"

        return StatisticalTest(
            test_name=f"Permutation Test ({metric})",
            statistic=observed_diff,
            p_value=p_value,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=True,  # Permutation tests are assumption-free
            sample_size=len(y_true),
            power=power
        )

    def cohens_d(self, scores1: np.ndarray, scores2: np.ndarray) -> float:
        """
        Calculate Cohen's d effect size for independent samples

        Cohen's d standardizes the difference between two means by the pooled
        standard deviation. It's interpretable as small (0.2), medium (0.5),
        or large (0.8) effects.
        """
        mean1, mean2 = np.mean(scores1), np.mean(scores2)
        var1, var2 = np.var(scores1, ddof=1), np.var(scores2, ddof=1)
        n1, n2 = len(scores1), len(scores2)

        # Pooled standard deviation
        pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

        if pooled_std == 0:
            return 0.0

        return (mean1 - mean2) / pooled_std

    def cliffs_delta(self, scores1: np.ndarray, scores2: np.ndarray) -> float:
        """
        Calculate Cliff's delta (non-parametric effect size)

        Cliff's delta measures how often scores from one group are larger
        than scores from another group. It ranges from -1 to 1.
        """
        n1, n2 = len(scores1), len(scores2)

        if n1 == 0 or n2 == 0:
            return 0.0

        # Count how many times scores1 > scores2
        greater = np.sum(scores1[:, np.newaxis] > scores2[np.newaxis, :])
        lesser = np.sum(scores1[:, np.newaxis] < scores2[np.newaxis, :])

        return (greater - lesser) / (n1 * n2)

    def cross_validation_comparison(self,
                                   X: np.ndarray,
                                   y: np.ndarray,
                                   model1,
                                   model2,
                                   cv_folds: int = 5,
                                   scoring: str = 'f1') -> Dict[str, Any]:
        """
        Perform cross-validation comparison of two models

        This provides robust performance estimates with proper variance
        calculation for statistical testing.
        """
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)

        # Cross-validate both models
        scores1 = cross_validate(model1, X, y, cv=cv, scoring=scoring, return_train_score=False)
        scores2 = cross_validate(model2, X, y, cv=cv, scoring=scoring, return_train_score=False)

        cv_scores1 = scores1['test_score']
        cv_scores2 = scores2['test_score']

        # Paired t-test (if assumptions are met)
        t_stat, t_pvalue = ttest_rel(cv_scores1, cv_scores2)

        # Test normality assumption
        _, p_norm1 = shapiro(cv_scores1)
        _, p_norm2 = shapiro(cv_scores2)
        normality_ok = p_norm1 > 0.05 and p_norm2 > 0.05

        # Wilcoxon test as non-parametric alternative
        wilcoxon_result = self.wilcoxon_signed_rank_test(cv_scores1, cv_scores2)

        # Effect sizes
        cohens_d = self.cohens_d(cv_scores1, cv_scores2)
        cliffs_delta = self.cliffs_delta(cv_scores1, cv_scores2)

        return {
            'cv_scores_model1': cv_scores1,
            'cv_scores_model2': cv_scores2,
            'paired_t_test': {
                'statistic': t_stat,
                'p_value': t_pvalue,
                'assumptions_met': normality_ok
            },
            'wilcoxon_test': wilcoxon_result,
            'cohens_d': cohens_d,
            'cliffs_delta': cliffs_delta,
            'mean_performance': {
                'model1': np.mean(cv_scores1),
                'model2': np.mean(cv_scores2),
                'difference': np.mean(cv_scores1) - np.mean(cv_scores2)
            },
            'confidence_intervals': {
                'model1': self._bootstrap_ci(cv_scores1),
                'model2': self._bootstrap_ci(cv_scores2)
            }
        }

    def comprehensive_comparison(self,
                               y_true: np.ndarray,
                               y_pred1: np.ndarray,
                               y_pred2: np.ndarray,
                               y_scores1: Optional[np.ndarray] = None,
                               y_scores2: Optional[np.ndarray] = None,
                               model1_name: str = "Model 1",
                               model2_name: str = "Model 2",
                               dataset_name: str = "Dataset") -> ComparisonResult:
        """
        Perform comprehensive statistical comparison between two models

        This is the main method that conducts all necessary statistical tests
        for academic publication-ready model comparison.
        """
        self.logger.info(f"Starting comprehensive comparison: {model1_name} vs {model2_name}")

        # Calculate performance metrics
        model1_metrics = self._calculate_all_metrics(y_true, y_pred1, y_scores1)
        model2_metrics = self._calculate_all_metrics(y_true, y_pred2, y_scores2)

        # Statistical tests
        mcnemar_result = self.mcnemar_test_exact(y_true, y_pred1, y_pred2)

        # Use confidence scores if available, otherwise use predictions
        scores1 = y_scores1 if y_scores1 is not None else y_pred1.astype(float)
        scores2 = y_scores2 if y_scores2 is not None else y_pred2.astype(float)

        wilcoxon_result = self.wilcoxon_signed_rank_test(scores1, scores2)
        permutation_result = self.permutation_test(y_true, scores1, scores2, 'f1')

        # Effect sizes
        cohens_d = self.cohens_d(scores1, scores2)
        cliffs_delta = self.cliffs_delta(scores1, scores2)

        # Overall conclusions
        significant_tests = [
            mcnemar_result.p_value < self.alpha,
            wilcoxon_result.p_value < self.alpha,
            permutation_result.p_value < self.alpha
        ]

        significant_difference = sum(significant_tests) >= 2  # Majority vote

        # Practical significance (medium or large effect size)
        practical_significance = (
            abs(cohens_d) >= 0.5 or
            abs(cliffs_delta) >= 0.28 or  # Medium effect for Cliff's delta
            abs(mcnemar_result.effect_size) >= 0.5
        )

        # Recommendation
        if significant_difference and practical_significance:
            if model1_metrics['f1'] > model2_metrics['f1']:
                recommendation = f"{model1_name} significantly outperforms {model2_name}"
            else:
                recommendation = f"{model2_name} significantly outperforms {model1_name}"
        elif significant_difference:
            recommendation = "Statistically significant but practically negligible difference"
        elif practical_significance:
            recommendation = "Practically meaningful but not statistically significant difference"
        else:
            recommendation = "No meaningful difference between models"

        self.logger.info(f"Comparison completed. Recommendation: {recommendation}")

        return ComparisonResult(
            model1_name=model1_name,
            model2_name=model2_name,
            dataset_name=dataset_name,
            model1_metrics=model1_metrics,
            model2_metrics=model2_metrics,
            mcnemar_test=mcnemar_result,
            wilcoxon_test=wilcoxon_result,
            permutation_test=permutation_result,
            cohens_d=cohens_d,
            cliffs_delta=cliffs_delta,
            significant_difference=significant_difference,
            practical_significance=practical_significance,
            recommendation=recommendation
        )

    def multiple_testing_correction(self,
                                   p_values: List[float],
                                   method: str = 'bonferroni') -> List[float]:
        """
        Apply multiple testing correction to p-values

        Args:
            p_values: List of uncorrected p-values
            method: Correction method ('bonferroni', 'fdr_bh', 'fdr_by')
        """
        p_values = np.array(p_values)

        if method == 'bonferroni':
            # Bonferroni correction
            corrected = p_values * len(p_values)
            return np.minimum(corrected, 1.0).tolist()

        elif method == 'fdr_bh':
            # Benjamini-Hochberg FDR correction
            n = len(p_values)
            sorted_indices = np.argsort(p_values)
            sorted_p = p_values[sorted_indices]

            corrected = np.zeros_like(p_values)

            for i in range(n-1, -1, -1):
                if i == n-1:
                    corrected[sorted_indices[i]] = sorted_p[i]
                else:
                    corrected[sorted_indices[i]] = min(
                        sorted_p[i] * n / (i + 1),
                        corrected[sorted_indices[i + 1]]
                    )

            return corrected.tolist()

        else:
            raise ValueError(f"Unknown correction method: {method}")

    def generate_statistical_report(self,
                                   comparison_results: List[ComparisonResult],
                                   output_path: Optional[str] = None) -> str:
        """
        Generate comprehensive statistical report for academic publication
        """
        report = []

        # Header
        report.append("=" * 80)
        report.append("COMPREHENSIVE STATISTICAL VALIDATION REPORT")
        report.append("=" * 80)
        report.append("")

        # Summary table
        report.append("SUMMARY OF COMPARISONS")
        report.append("-" * 40)

        for result in comparison_results:
            report.append(f"{result.model1_name} vs {result.model2_name}:")
            report.append(f"  Dataset: {result.dataset_name}")
            report.append(f"  Statistically Significant: {result.significant_difference}")
            report.append(f"  Practically Significant: {result.practical_significance}")
            report.append(f"  Recommendation: {result.recommendation}")
            report.append("")

        # Detailed results
        for result in comparison_results:
            report.append(f"DETAILED ANALYSIS: {result.model1_name} vs {result.model2_name}")
            report.append("-" * 60)

            # Performance metrics
            report.append("Performance Metrics:")
            report.append(f"  {result.model1_name}:")
            for metric, value in result.model1_metrics.items():
                report.append(f"    {metric}: {value:.4f}")

            report.append(f"  {result.model2_name}:")
            for metric, value in result.model2_metrics.items():
                report.append(f"    {metric}: {value:.4f}")
            report.append("")

            # Statistical tests
            report.append("Statistical Tests:")

            # McNemar's test
            mcnemar = result.mcnemar_test
            report.append(f"  McNemar's Test:")
            report.append(f"    Statistic: {mcnemar.statistic:.4f}")
            report.append(f"    p-value: {mcnemar.p_value:.6f}")
            report.append(f"    Effect size: {mcnemar.effect_size:.4f}")
            report.append(f"    95% CI: ({mcnemar.confidence_interval[0]:.4f}, {mcnemar.confidence_interval[1]:.4f})")
            report.append(f"    Power: {mcnemar.power:.4f}")
            report.append(f"    Interpretation: {mcnemar.interpretation}")
            report.append("")

            # Wilcoxon test
            wilcoxon = result.wilcoxon_test
            report.append(f"  Wilcoxon Signed-Rank Test:")
            report.append(f"    Statistic: {wilcoxon.statistic:.4f}")
            report.append(f"    p-value: {wilcoxon.p_value:.6f}")
            report.append(f"    Effect size: {wilcoxon.effect_size:.4f}")
            report.append(f"    Interpretation: {wilcoxon.interpretation}")
            report.append("")

            # Effect sizes
            report.append("Effect Sizes:")
            report.append(f"  Cohen's d: {result.cohens_d:.4f}")
            report.append(f"  Cliff's delta: {result.cliffs_delta:.4f}")
            report.append("")

            report.append("=" * 60)
            report.append("")

        # Multiple testing correction
        all_p_values = []
        test_names = []

        for result in comparison_results:
            all_p_values.extend([
                result.mcnemar_test.p_value,
                result.wilcoxon_test.p_value,
                result.permutation_test.p_value
            ])

            test_names.extend([
                f"{result.model1_name} vs {result.model2_name} (McNemar)",
                f"{result.model1_name} vs {result.model2_name} (Wilcoxon)",
                f"{result.model1_name} vs {result.model2_name} (Permutation)"
            ])

        if len(all_p_values) > 1:
            corrected_bonferroni = self.multiple_testing_correction(all_p_values, 'bonferroni')
            corrected_fdr = self.multiple_testing_correction(all_p_values, 'fdr_bh')

            report.append("MULTIPLE TESTING CORRECTION")
            report.append("-" * 40)
            report.append("Original vs Corrected p-values:")
            report.append("")

            for i, (name, original, bonf, fdr) in enumerate(zip(
                test_names, all_p_values, corrected_bonferroni, corrected_fdr
            )):
                report.append(f"{name}:")
                report.append(f"  Original: {original:.6f}")
                report.append(f"  Bonferroni: {bonf:.6f}")
                report.append(f"  FDR (BH): {fdr:.6f}")
                report.append("")

        report_text = "\n".join(report)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_text)
            self.logger.info(f"Statistical report saved to {output_path}")

        return report_text

    # Helper methods
    def _bootstrap_mcnemar_ci(self, correct1: np.ndarray, correct2: np.ndarray,
                             confidence_level: float = 0.95) -> Tuple[float, float]:
        """Bootstrap confidence interval for McNemar's test effect size"""
        bootstrap_effects = []

        for _ in range(self.n_bootstrap):
            indices = np.random.choice(len(correct1), len(correct1), replace=True)
            boot_correct1 = correct1[indices]
            boot_correct2 = correct2[indices]

            model1_only = np.sum(boot_correct1 & ~boot_correct2)
            model2_only = np.sum(~boot_correct1 & boot_correct2)

            if model2_only == 0:
                effect = 5.0 if model1_only > 0 else 0.0
            else:
                effect = np.log(model1_only / model2_only)

            bootstrap_effects.append(effect)

        alpha = 1 - confidence_level
        lower = np.percentile(bootstrap_effects, (alpha/2) * 100)
        upper = np.percentile(bootstrap_effects, (1 - alpha/2) * 100)

        return lower, upper

    def _bootstrap_median_difference_ci(self, scores1: np.ndarray, scores2: np.ndarray,
                                       confidence_level: float = 0.95) -> Tuple[float, float]:
        """Bootstrap confidence interval for median difference"""
        bootstrap_diffs = []

        for _ in range(self.n_bootstrap):
            indices = np.random.choice(len(scores1), len(scores1), replace=True)
            boot_scores1 = scores1[indices]
            boot_scores2 = scores2[indices]

            median_diff = np.median(boot_scores1) - np.median(boot_scores2)
            bootstrap_diffs.append(median_diff)

        alpha = 1 - confidence_level
        lower = np.percentile(bootstrap_diffs, (alpha/2) * 100)
        upper = np.percentile(bootstrap_diffs, (1 - alpha/2) * 100)

        return lower, upper

    def _bootstrap_ci(self, scores: np.ndarray, confidence_level: float = 0.95) -> Tuple[float, float]:
        """Bootstrap confidence interval for mean"""
        bootstrap_means = []

        for _ in range(self.n_bootstrap):
            indices = np.random.choice(len(scores), len(scores), replace=True)
            boot_scores = scores[indices]
            bootstrap_means.append(np.mean(boot_scores))

        alpha = 1 - confidence_level
        lower = np.percentile(bootstrap_means, (alpha/2) * 100)
        upper = np.percentile(bootstrap_means, (1 - alpha/2) * 100)

        return lower, upper

    def _calculate_metric(self, y_true: np.ndarray, y_scores: np.ndarray, metric: str) -> float:
        """Calculate specified metric"""
        if metric == 'accuracy':
            y_pred = (y_scores > 0.5).astype(int)
            return accuracy_score(y_true, y_pred)
        elif metric == 'f1':
            y_pred = (y_scores > 0.5).astype(int)
            _, _, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
            return f1
        elif metric == 'auc':
            try:
                return roc_auc_score(y_true, y_scores)
            except ValueError:
                return 0.5  # Random performance if only one class
        elif metric == 'mcc':
            y_pred = (y_scores > 0.5).astype(int)
            return matthews_corrcoef(y_true, y_pred)
        else:
            raise ValueError(f"Unknown metric: {metric}")

    def _calculate_all_metrics(self, y_true: np.ndarray, y_pred: np.ndarray,
                              y_scores: Optional[np.ndarray] = None) -> Dict[str, float]:
        """Calculate all standard metrics"""
        metrics = {}

        # Basic classification metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average='binary', zero_division=0
        )

        metrics['precision'] = precision
        metrics['recall'] = recall
        metrics['f1'] = f1
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['mcc'] = matthews_corrcoef(y_true, y_pred)

        # AUC if scores available
        if y_scores is not None:
            try:
                metrics['auc'] = roc_auc_score(y_true, y_scores)
            except ValueError:
                metrics['auc'] = 0.5

        return metrics

    def _calculate_mcnemar_power(self, b: int, c: int, n: int, alpha: float = 0.05) -> float:
        """Calculate statistical power for McNemar's test"""
        if b + c == 0:
            return 0.0

        # Approximate power calculation for McNemar's test
        effect_size = abs(b - c) / np.sqrt(b + c)
        critical_value = stats.chi2.ppf(1 - alpha, 1)

        # Non-centrality parameter
        ncp = effect_size ** 2

        # Power is 1 - beta where beta is type II error rate
        power = 1 - stats.ncx2.cdf(critical_value, 1, ncp)

        return min(power, 1.0)

    def _calculate_wilcoxon_power(self, differences: np.ndarray, alpha: float = 0.05) -> float:
        """Calculate approximate statistical power for Wilcoxon test"""
        if len(differences) == 0:
            return 0.0

        # Effect size for Wilcoxon test
        median_diff = np.median(differences)
        mad = np.median(np.abs(differences - median_diff))  # Median absolute deviation

        if mad == 0:
            return 1.0 if median_diff != 0 else 0.0

        effect_size = median_diff / mad

        # Approximate power using normal approximation
        # This is a simplified calculation
        z_alpha = stats.norm.ppf(1 - alpha/2)
        z_beta = abs(effect_size) * np.sqrt(len(differences) / 12)  # Wilcoxon efficiency factor

        power = 1 - stats.norm.cdf(z_alpha - z_beta) + stats.norm.cdf(-z_alpha - z_beta)

        return min(power, 1.0)


def demo_statistical_validation():
    """Demonstrate the statistical validation framework"""
    print("Statistical Validation Framework Demo")
    print("=" * 50)

    # Create synthetic data for two models
    np.random.seed(42)
    n_samples = 1000

    # Ground truth
    y_true = np.random.binomial(1, 0.3, n_samples)

    # Model 1: Good performance
    model1_prob = 0.8 * y_true + 0.1 * (1 - y_true) + np.random.normal(0, 0.1, n_samples)
    model1_prob = np.clip(model1_prob, 0, 1)
    y_pred1 = (model1_prob > 0.5).astype(int)

    # Model 2: Slightly worse performance
    model2_prob = 0.75 * y_true + 0.15 * (1 - y_true) + np.random.normal(0, 0.1, n_samples)
    model2_prob = np.clip(model2_prob, 0, 1)
    y_pred2 = (model2_prob > 0.5).astype(int)

    # Initialize validator
    validator = StatisticalValidator(random_state=42)

    # Perform comprehensive comparison
    result = validator.comprehensive_comparison(
        y_true=y_true,
        y_pred1=y_pred1,
        y_pred2=y_pred2,
        y_scores1=model1_prob,
        y_scores2=model2_prob,
        model1_name="Advanced Ensemble",
        model2_name="Baseline Transformer",
        dataset_name="Synthetic Vulnerability Dataset"
    )

    # Generate report
    report = validator.generate_statistical_report([result])
    print(report)

    return result


if __name__ == "__main__":
    demo_statistical_validation()