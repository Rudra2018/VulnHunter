#!/usr/bin/env python3
"""
Statistical Evaluation and Significance Testing

This module provides rigorous statistical analysis for model evaluation:
- Statistical significance testing
- Confidence intervals
- Cross-validation with statistical analysis
- Effect size calculations
- Power analysis
- Bootstrap analysis
- Non-parametric tests
"""

import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import (
    ttest_rel, wilcoxon, friedmanchisquare, kruskal,
    chi2_contingency, fisher_exact, mannwhitneyu,
    bootstrap, norm
)
from sklearn.model_selection import (
    cross_val_score, StratifiedKFold, KFold,
    cross_validate, permutation_test_score
)
from sklearn.metrics import make_scorer
from typing import Dict, List, Optional, Tuple, Union, Callable
import warnings
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.power import ttest_power
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")


class StatisticalEvaluator:
    """Statistical evaluation and significance testing for model comparison"""

    def __init__(self, alpha: float = 0.05, n_bootstrap: int = 1000, random_state: int = 42):
        self.alpha = alpha
        self.n_bootstrap = n_bootstrap
        self.random_state = random_state
        np.random.seed(random_state)

    def compare_models_paired_ttest(self,
                                  scores1: np.ndarray,
                                  scores2: np.ndarray,
                                  metric_name: str = "Performance") -> Dict[str, float]:
        """
        Compare two models using paired t-test

        Args:
            scores1: Performance scores from model 1
            scores2: Performance scores from model 2
            metric_name: Name of the metric being compared

        Returns:
            Dictionary with test results
        """

        # Check assumptions
        normality_p1 = stats.shapiro(scores1)[1]
        normality_p2 = stats.shapiro(scores2)[1]
        differences = scores1 - scores2
        normality_diff = stats.shapiro(differences)[1]

        # Perform paired t-test
        t_stat, p_value = ttest_rel(scores1, scores2)

        # Calculate effect size (Cohen's d)
        pooled_std = np.sqrt((np.var(scores1, ddof=1) + np.var(scores2, ddof=1)) / 2)
        cohens_d = np.mean(differences) / pooled_std if pooled_std > 0 else 0

        # Confidence interval for the difference
        n = len(scores1)
        std_diff = np.std(differences, ddof=1)
        sem_diff = std_diff / np.sqrt(n)
        t_critical = stats.t.ppf(1 - self.alpha/2, n - 1)
        ci_lower = np.mean(differences) - t_critical * sem_diff
        ci_upper = np.mean(differences) + t_critical * sem_diff

        return {
            'metric': metric_name,
            'test': 'Paired t-test',
            't_statistic': t_stat,
            'p_value': p_value,
            'significant': p_value < self.alpha,
            'mean_difference': np.mean(differences),
            'cohens_d': cohens_d,
            'effect_size_interpretation': self._interpret_cohens_d(cohens_d),
            'confidence_interval_lower': ci_lower,
            'confidence_interval_upper': ci_upper,
            'normality_p_model1': normality_p1,
            'normality_p_model2': normality_p2,
            'normality_p_differences': normality_diff,
            'normality_assumption_met': normality_diff > self.alpha
        }

    def compare_models_wilcoxon(self,
                              scores1: np.ndarray,
                              scores2: np.ndarray,
                              metric_name: str = "Performance") -> Dict[str, float]:
        """
        Compare two models using Wilcoxon signed-rank test (non-parametric)

        Args:
            scores1: Performance scores from model 1
            scores2: Performance scores from model 2
            metric_name: Name of the metric being compared

        Returns:
            Dictionary with test results
        """

        # Wilcoxon signed-rank test
        stat, p_value = wilcoxon(scores1, scores2, alternative='two-sided')

        # Effect size (r = Z / sqrt(N))
        n = len(scores1)
        z_score = stats.norm.ppf(1 - p_value/2) if p_value > 0 else 0
        effect_size_r = abs(z_score) / np.sqrt(n)

        # Median difference and confidence interval
        differences = scores1 - scores2
        median_diff = np.median(differences)

        # Bootstrap confidence interval for median difference
        bootstrap_medians = []
        for _ in range(self.n_bootstrap):
            bootstrap_sample = np.random.choice(differences, size=len(differences), replace=True)
            bootstrap_medians.append(np.median(bootstrap_sample))

        ci_lower = np.percentile(bootstrap_medians, (self.alpha/2) * 100)
        ci_upper = np.percentile(bootstrap_medians, (1 - self.alpha/2) * 100)

        return {
            'metric': metric_name,
            'test': 'Wilcoxon signed-rank',
            'statistic': stat,
            'p_value': p_value,
            'significant': p_value < self.alpha,
            'median_difference': median_diff,
            'effect_size_r': effect_size_r,
            'effect_size_interpretation': self._interpret_effect_size_r(effect_size_r),
            'confidence_interval_lower': ci_lower,
            'confidence_interval_upper': ci_upper
        }

    def compare_multiple_models_friedman(self,
                                       model_scores: Dict[str, np.ndarray],
                                       metric_name: str = "Performance") -> Dict[str, Union[float, List]]:
        """
        Compare multiple models using Friedman test

        Args:
            model_scores: Dictionary of model_name -> scores array
            metric_name: Name of the metric being compared

        Returns:
            Dictionary with test results and post-hoc analysis
        """

        model_names = list(model_scores.keys())
        scores_arrays = [model_scores[name] for name in model_names]

        # Friedman test
        stat, p_value = friedmanchisquare(*scores_arrays)

        # Post-hoc pairwise comparisons (if significant)
        pairwise_results = []
        if p_value < self.alpha:
            for i, name1 in enumerate(model_names):
                for j, name2 in enumerate(model_names[i+1:], i+1):
                    wilcoxon_result = self.compare_models_wilcoxon(
                        model_scores[name1], model_scores[name2],
                        f"{name1} vs {name2}"
                    )
                    pairwise_results.append({
                        'model1': name1,
                        'model2': name2,
                        'p_value': wilcoxon_result['p_value'],
                        'significant': wilcoxon_result['significant']
                    })

        # Calculate mean ranks
        n_models = len(model_names)
        n_datasets = len(scores_arrays[0])
        ranks = np.zeros((n_datasets, n_models))

        for i in range(n_datasets):
            dataset_scores = [scores[i] for scores in scores_arrays]
            ranks[i] = stats.rankdata(dataset_scores)

        mean_ranks = np.mean(ranks, axis=0)
        rank_results = {name: rank for name, rank in zip(model_names, mean_ranks)}

        return {
            'metric': metric_name,
            'test': 'Friedman test',
            'statistic': stat,
            'p_value': p_value,
            'significant': p_value < self.alpha,
            'mean_ranks': rank_results,
            'pairwise_comparisons': pairwise_results,
            'degrees_of_freedom': n_models - 1
        }

    def cross_validate_with_stats(self,
                                estimator,
                                X: np.ndarray,
                                y: np.ndarray,
                                scoring: Union[str, Callable],
                                cv: int = 5,
                                stratify: bool = True) -> Dict[str, float]:
        """
        Perform cross-validation with statistical analysis

        Args:
            estimator: Scikit-learn estimator
            X: Features
            y: Target labels
            scoring: Scoring function
            cv: Number of cross-validation folds
            stratify: Whether to use stratified CV

        Returns:
            Dictionary with CV results and statistical analysis
        """

        # Choose CV strategy
        if stratify and len(np.unique(y)) > 1:
            cv_strategy = StratifiedKFold(n_splits=cv, shuffle=True, random_state=self.random_state)
        else:
            cv_strategy = KFold(n_splits=cv, shuffle=True, random_state=self.random_state)

        # Perform cross-validation
        cv_results = cross_validate(
            estimator, X, y,
            cv=cv_strategy,
            scoring=scoring,
            return_train_score=True,
            n_jobs=-1
        )

        test_scores = cv_results['test_score']
        train_scores = cv_results['train_score']

        # Statistical analysis
        stats_results = {
            'mean_test_score': np.mean(test_scores),
            'std_test_score': np.std(test_scores, ddof=1),
            'mean_train_score': np.mean(train_scores),
            'std_train_score': np.std(train_scores, ddof=1),
            'test_scores': test_scores,
            'train_scores': train_scores
        }

        # Confidence interval for test scores
        n = len(test_scores)
        sem = stats_results['std_test_score'] / np.sqrt(n)
        t_critical = stats.t.ppf(1 - self.alpha/2, n - 1)
        ci_lower = stats_results['mean_test_score'] - t_critical * sem
        ci_upper = stats_results['mean_test_score'] + t_critical * sem

        stats_results.update({
            'confidence_interval_lower': ci_lower,
            'confidence_interval_upper': ci_upper,
            'standard_error': sem
        })

        # Overfitting analysis
        generalization_gap = np.mean(train_scores - test_scores)
        stats_results['generalization_gap'] = generalization_gap

        # Test for normality of CV scores
        normality_p = stats.shapiro(test_scores)[1]
        stats_results['normality_p_value'] = normality_p
        stats_results['normality_assumption_met'] = normality_p > self.alpha

        return stats_results

    def permutation_test(self,
                       estimator,
                       X: np.ndarray,
                       y: np.ndarray,
                       scoring: Union[str, Callable],
                       n_permutations: int = 1000,
                       cv: int = 5) -> Dict[str, float]:
        """
        Perform permutation test to assess if model performance is above chance

        Args:
            estimator: Scikit-learn estimator
            X: Features
            y: Target labels
            scoring: Scoring function
            n_permutations: Number of permutations
            cv: Number of cross-validation folds

        Returns:
            Dictionary with permutation test results
        """

        # Perform permutation test
        score, permutation_scores, p_value = permutation_test_score(
            estimator, X, y,
            scoring=scoring,
            cv=cv,
            n_permutations=n_permutations,
            random_state=self.random_state,
            n_jobs=-1
        )

        return {
            'actual_score': score,
            'permutation_scores': permutation_scores,
            'mean_permutation_score': np.mean(permutation_scores),
            'std_permutation_score': np.std(permutation_scores),
            'p_value': p_value,
            'significant': p_value < self.alpha,
            'percentile_rank': (np.sum(permutation_scores < score) / n_permutations) * 100
        }

    def bootstrap_confidence_interval(self,
                                    data: np.ndarray,
                                    statistic_func: Callable = np.mean,
                                    confidence_level: float = 0.95) -> Dict[str, float]:
        """
        Calculate bootstrap confidence intervals

        Args:
            data: Data array
            statistic_func: Function to calculate statistic
            confidence_level: Confidence level (default 0.95)

        Returns:
            Dictionary with bootstrap results
        """

        # Bootstrap sampling
        bootstrap_stats = []
        n = len(data)

        for _ in range(self.n_bootstrap):
            bootstrap_sample = np.random.choice(data, size=n, replace=True)
            bootstrap_stats.append(statistic_func(bootstrap_sample))

        bootstrap_stats = np.array(bootstrap_stats)

        # Calculate confidence intervals
        alpha_ci = 1 - confidence_level
        ci_lower = np.percentile(bootstrap_stats, (alpha_ci/2) * 100)
        ci_upper = np.percentile(bootstrap_stats, (1 - alpha_ci/2) * 100)

        return {
            'original_statistic': statistic_func(data),
            'bootstrap_mean': np.mean(bootstrap_stats),
            'bootstrap_std': np.std(bootstrap_stats),
            'confidence_interval_lower': ci_lower,
            'confidence_interval_upper': ci_upper,
            'confidence_level': confidence_level,
            'bootstrap_samples': bootstrap_stats
        }

    def power_analysis(self,
                     effect_size: float,
                     alpha: float = None,
                     power: float = 0.8,
                     sample_size: int = None) -> Dict[str, float]:
        """
        Perform statistical power analysis

        Args:
            effect_size: Expected effect size (Cohen's d)
            alpha: Significance level (default: self.alpha)
            power: Desired statistical power
            sample_size: Sample size (if provided, calculates achieved power)

        Returns:
            Dictionary with power analysis results
        """

        if alpha is None:
            alpha = self.alpha

        if sample_size is not None:
            # Calculate achieved power
            achieved_power = ttest_power(effect_size, sample_size, alpha, alternative='two-sided')
            return {
                'effect_size': effect_size,
                'sample_size': sample_size,
                'alpha': alpha,
                'achieved_power': achieved_power,
                'adequate_power': achieved_power >= 0.8
            }
        else:
            # Calculate required sample size
            from statsmodels.stats.power import tt_solve_power
            required_n = tt_solve_power(
                effect_size=effect_size,
                power=power,
                alpha=alpha,
                alternative='two-sided'
            )
            return {
                'effect_size': effect_size,
                'required_sample_size': int(np.ceil(required_n)),
                'alpha': alpha,
                'desired_power': power
            }

    def mcnemar_test(self,
                   predictions1: np.ndarray,
                   predictions2: np.ndarray,
                   y_true: np.ndarray) -> Dict[str, float]:
        """
        McNemar's test for comparing binary classifiers

        Args:
            predictions1: Predictions from model 1
            predictions2: Predictions from model 2
            y_true: True labels

        Returns:
            Dictionary with McNemar test results
        """

        # Create contingency table
        correct1 = (predictions1 == y_true).astype(int)
        correct2 = (predictions2 == y_true).astype(int)

        # McNemar table
        both_correct = np.sum((correct1 == 1) & (correct2 == 1))
        model1_correct = np.sum((correct1 == 1) & (correct2 == 0))
        model2_correct = np.sum((correct1 == 0) & (correct2 == 1))
        both_wrong = np.sum((correct1 == 0) & (correct2 == 0))

        # McNemar test
        b = model1_correct
        c = model2_correct

        if b + c > 0:
            # Exact test for small samples
            if b + c < 25:
                p_value = 2 * stats.binom.cdf(min(b, c), b + c, 0.5)
            else:
                # Chi-square approximation with continuity correction
                chi2_stat = (abs(b - c) - 1) ** 2 / (b + c)
                p_value = 1 - stats.chi2.cdf(chi2_stat, df=1)
        else:
            p_value = 1.0

        return {
            'test': 'McNemar test',
            'both_correct': both_correct,
            'model1_only_correct': model1_correct,
            'model2_only_correct': model2_correct,
            'both_wrong': both_wrong,
            'statistic': (b - c) ** 2 / (b + c) if b + c > 0 else 0,
            'p_value': p_value,
            'significant': p_value < self.alpha
        }

    def effect_size_analysis(self,
                           group1: np.ndarray,
                           group2: np.ndarray) -> Dict[str, float]:
        """
        Calculate various effect size measures

        Args:
            group1: First group data
            group2: Second group data

        Returns:
            Dictionary with effect size measures
        """

        # Cohen's d
        pooled_std = np.sqrt((np.var(group1, ddof=1) + np.var(group2, ddof=1)) / 2)
        cohens_d = (np.mean(group1) - np.mean(group2)) / pooled_std if pooled_std > 0 else 0

        # Hedges' g (bias-corrected Cohen's d)
        n1, n2 = len(group1), len(group2)
        correction_factor = 1 - (3 / (4 * (n1 + n2) - 9))
        hedges_g = cohens_d * correction_factor

        # Glass's delta (using control group standard deviation)
        glass_delta = (np.mean(group1) - np.mean(group2)) / np.std(group2, ddof=1)

        # Cliff's delta (non-parametric effect size)
        cliffs_delta = self._calculate_cliffs_delta(group1, group2)

        # Common language effect size
        cles = self._calculate_cles(group1, group2)

        return {
            'cohens_d': cohens_d,
            'cohens_d_interpretation': self._interpret_cohens_d(cohens_d),
            'hedges_g': hedges_g,
            'glass_delta': glass_delta,
            'cliffs_delta': cliffs_delta,
            'cliffs_delta_interpretation': self._interpret_cliffs_delta(cliffs_delta),
            'common_language_effect_size': cles
        }

    def _calculate_cliffs_delta(self, group1: np.ndarray, group2: np.ndarray) -> float:
        """Calculate Cliff's delta"""
        n1, n2 = len(group1), len(group2)
        dominance = 0

        for x in group1:
            for y in group2:
                if x > y:
                    dominance += 1
                elif x < y:
                    dominance -= 1

        return dominance / (n1 * n2)

    def _calculate_cles(self, group1: np.ndarray, group2: np.ndarray) -> float:
        """Calculate Common Language Effect Size"""
        n1, n2 = len(group1), len(group2)
        greater = 0

        for x in group1:
            for y in group2:
                if x > y:
                    greater += 1

        return greater / (n1 * n2)

    def _interpret_cohens_d(self, d: float) -> str:
        """Interpret Cohen's d effect size"""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"

    def _interpret_cliffs_delta(self, delta: float) -> str:
        """Interpret Cliff's delta effect size"""
        abs_delta = abs(delta)
        if abs_delta < 0.11:
            return "negligible"
        elif abs_delta < 0.28:
            return "small"
        elif abs_delta < 0.43:
            return "medium"
        else:
            return "large"

    def _interpret_effect_size_r(self, r: float) -> str:
        """Interpret effect size r"""
        abs_r = abs(r)
        if abs_r < 0.1:
            return "small"
        elif abs_r < 0.3:
            return "medium"
        else:
            return "large"

    def generate_statistical_report(self,
                                  comparison_results: List[Dict],
                                  save_path: Optional[str] = None) -> str:
        """
        Generate comprehensive statistical report

        Args:
            comparison_results: List of comparison results
            save_path: Path to save the report

        Returns:
            Report text
        """

        report_lines = [
            "STATISTICAL EVALUATION REPORT",
            "=" * 50,
            f"Significance level (α): {self.alpha}",
            f"Number of bootstrap samples: {self.n_bootstrap}",
            ""
        ]

        for i, result in enumerate(comparison_results, 1):
            report_lines.extend([
                f"COMPARISON {i}: {result.get('metric', 'Unknown')}",
                "-" * 30,
                f"Test: {result.get('test', 'Unknown')}",
                f"P-value: {result.get('p_value', 'N/A'):.6f}",
                f"Significant: {'Yes' if result.get('significant', False) else 'No'}",
                ""
            ])

            if 'cohens_d' in result:
                report_lines.extend([
                    f"Effect size (Cohen's d): {result['cohens_d']:.4f}",
                    f"Effect size interpretation: {result['effect_size_interpretation']}",
                    f"Mean difference: {result.get('mean_difference', 'N/A'):.4f}",
                    ""
                ])

            if 'confidence_interval_lower' in result:
                report_lines.extend([
                    f"Confidence interval: [{result['confidence_interval_lower']:.4f}, "
                    f"{result['confidence_interval_upper']:.4f}]",
                    ""
                ])

            if 'normality_assumption_met' in result:
                report_lines.extend([
                    f"Normality assumption met: {'Yes' if result['normality_assumption_met'] else 'No'}",
                    ""
                ])

            report_lines.append("")

        report_text = "\n".join(report_lines)

        if save_path:
            with open(save_path, 'w') as f:
                f.write(report_text)

        return report_text


def test_statistical_evaluator():
    """Test the statistical evaluator"""
    print("Testing Statistical Evaluator...")

    evaluator = StatisticalEvaluator()

    # Generate sample data
    np.random.seed(42)
    n_samples = 100

    # Model comparison data
    model1_scores = np.random.normal(0.85, 0.1, n_samples)
    model2_scores = np.random.normal(0.82, 0.12, n_samples)

    print("Testing paired t-test...")
    ttest_result = evaluator.compare_models_paired_ttest(model1_scores, model2_scores, "Accuracy")
    print(f"T-test p-value: {ttest_result['p_value']:.6f}")
    print(f"Significant: {ttest_result['significant']}")
    print(f"Effect size: {ttest_result['cohens_d']:.4f} ({ttest_result['effect_size_interpretation']})")

    print("\nTesting Wilcoxon signed-rank test...")
    wilcoxon_result = evaluator.compare_models_wilcoxon(model1_scores, model2_scores, "Accuracy")
    print(f"Wilcoxon p-value: {wilcoxon_result['p_value']:.6f}")
    print(f"Significant: {wilcoxon_result['significant']}")

    print("\nTesting multiple model comparison...")
    model_scores = {
        'Model A': model1_scores,
        'Model B': model2_scores,
        'Model C': np.random.normal(0.78, 0.15, n_samples)
    }
    friedman_result = evaluator.compare_multiple_models_friedman(model_scores, "Accuracy")
    print(f"Friedman test p-value: {friedman_result['p_value']:.6f}")
    print(f"Significant: {friedman_result['significant']}")
    print(f"Mean ranks: {friedman_result['mean_ranks']}")

    print("\nTesting bootstrap confidence interval...")
    bootstrap_result = evaluator.bootstrap_confidence_interval(model1_scores)
    print(f"Bootstrap mean: {bootstrap_result['bootstrap_mean']:.4f}")
    print(f"95% CI: [{bootstrap_result['confidence_interval_lower']:.4f}, "
          f"{bootstrap_result['confidence_interval_upper']:.4f}]")

    print("\nTesting effect size analysis...")
    effect_result = evaluator.effect_size_analysis(model1_scores, model2_scores)
    print(f"Cohen's d: {effect_result['cohens_d']:.4f} ({effect_result['cohens_d_interpretation']})")
    print(f"Cliff's delta: {effect_result['cliffs_delta']:.4f} ({effect_result['cliffs_delta_interpretation']})")

    print("\nStatistical evaluator test completed!")


if __name__ == "__main__":
    test_statistical_evaluator()