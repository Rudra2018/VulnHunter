"""
Statistical Analysis and Results Generation for Security Research
================================================================

Advanced statistical analysis framework for generating publication-ready
results including significance testing, effect size calculations, and
comprehensive performance metrics.
"""

import numpy as np
import pandas as pd
import scipy.stats as stats
from scipy.stats import chi2_contingency, fisher_exact, mannwhitneyu
import statsmodels.stats.contingency_tables as sm_contingency
from statsmodels.stats.proportion import proportions_ztest
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any, Optional
import json
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics for security tools"""
    tool_name: str
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    specificity: float
    false_positive_rate: float
    false_negative_rate: float
    accuracy: float
    balanced_accuracy: float
    matthews_corr_coeff: float
    auc_roc: Optional[float] = None
    auc_pr: Optional[float] = None
    execution_time: Optional[float] = None
    memory_usage: Optional[float] = None


@dataclass
class StatisticalTestResult:
    """Results from statistical significance tests"""
    test_name: str
    statistic: float
    p_value: float
    significant: bool
    effect_size: float
    confidence_interval: Tuple[float, float]
    interpretation: str
    assumptions_met: bool


@dataclass
class ComparisonResult:
    """Results from tool comparison analysis"""
    baseline_tool: str
    comparison_tool: str
    performance_improvement: Dict[str, float]
    statistical_tests: List[StatisticalTestResult]
    practical_significance: bool
    recommendation: str


class AdvancedStatisticalAnalyzer:
    """Advanced statistical analysis for security tool evaluation"""

    def __init__(self, alpha: float = 0.05, bonferroni_correction: bool = True):
        self.alpha = alpha
        self.bonferroni_correction = bonferroni_correction
        self.logger = logging.getLogger(__name__)

    def calculate_comprehensive_metrics(self, predictions: List[int],
                                      ground_truth: List[int],
                                      tool_name: str,
                                      confidence_scores: Optional[List[float]] = None,
                                      execution_time: Optional[float] = None,
                                      memory_usage: Optional[float] = None) -> PerformanceMetrics:
        """
        Calculate comprehensive performance metrics

        Args:
            predictions: Binary predictions (0/1)
            ground_truth: True labels (0/1)
            tool_name: Name of the tool
            confidence_scores: Optional confidence scores for ROC/PR curves
            execution_time: Optional execution time in seconds
            memory_usage: Optional memory usage in MB

        Returns:
            PerformanceMetrics object with all calculated metrics
        """
        # Confusion matrix
        tp = sum(1 for p, t in zip(predictions, ground_truth) if p == 1 and t == 1)
        fp = sum(1 for p, t in zip(predictions, ground_truth) if p == 1 and t == 0)
        tn = sum(1 for p, t in zip(predictions, ground_truth) if p == 0 and t == 0)
        fn = sum(1 for p, t in zip(predictions, ground_truth) if p == 0 and t == 1)

        # Basic metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        balanced_accuracy = (recall + specificity) / 2

        # Matthews Correlation Coefficient
        mcc_numerator = (tp * tn) - (fp * fn)
        mcc_denominator = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        matthews_corr_coeff = mcc_numerator / mcc_denominator if mcc_denominator != 0 else 0.0

        # AUC calculations (if confidence scores provided)
        auc_roc = None
        auc_pr = None
        if confidence_scores:
            try:
                from sklearn.metrics import roc_auc_score, average_precision_score
                auc_roc = roc_auc_score(ground_truth, confidence_scores)
                auc_pr = average_precision_score(ground_truth, confidence_scores)
            except ImportError:
                self.logger.warning("scikit-learn not available for AUC calculations")

        return PerformanceMetrics(
            tool_name=tool_name,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            specificity=specificity,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            accuracy=accuracy,
            balanced_accuracy=balanced_accuracy,
            matthews_corr_coeff=matthews_corr_coeff,
            auc_roc=auc_roc,
            auc_pr=auc_pr,
            execution_time=execution_time,
            memory_usage=memory_usage
        )

    def mcnemar_test_detailed(self, tool1_predictions: List[int],
                            tool2_predictions: List[int],
                            ground_truth: List[int]) -> StatisticalTestResult:
        """
        Detailed McNemar's test with effect size and interpretation

        Args:
            tool1_predictions: Predictions from first tool
            tool2_predictions: Predictions from second tool
            ground_truth: True labels

        Returns:
            StatisticalTestResult with detailed analysis
        """
        # Create contingency table
        tool1_correct = np.array(tool1_predictions) == np.array(ground_truth)
        tool2_correct = np.array(tool2_predictions) == np.array(ground_truth)

        # McNemar's table
        b = np.sum(tool1_correct & ~tool2_correct)  # Tool1 correct, Tool2 wrong
        c = np.sum(~tool1_correct & tool2_correct)  # Tool1 wrong, Tool2 correct

        # Test statistic
        if b + c == 0:
            return StatisticalTestResult(
                test_name="McNemar's Test",
                statistic=0.0,
                p_value=1.0,
                significant=False,
                effect_size=0.0,
                confidence_interval=(0.0, 0.0),
                interpretation="No difference between tools",
                assumptions_met=True
            )

        # Continuity correction for small samples
        if b + c < 25:
            statistic = (abs(b - c) - 1) ** 2 / (b + c)
        else:
            statistic = (b - c) ** 2 / (b + c)

        p_value = 1 - stats.chi2.cdf(statistic, df=1)

        # Effect size (Odds ratio)
        if b == 0 or c == 0:
            odds_ratio = float('inf') if b > c else 0.0
            effect_size = float('inf') if b > c else float('-inf')
        else:
            odds_ratio = b / c
            effect_size = np.log(odds_ratio)

        # Confidence interval for odds ratio
        if b > 0 and c > 0:
            log_or_se = np.sqrt(1/b + 1/c)
            log_ci_lower = np.log(odds_ratio) - 1.96 * log_or_se
            log_ci_upper = np.log(odds_ratio) + 1.96 * log_or_se
            ci_lower = np.exp(log_ci_lower)
            ci_upper = np.exp(log_ci_upper)
        else:
            ci_lower, ci_upper = 0.0, float('inf')

        # Interpretation
        if p_value < self.alpha:
            if b > c:
                interpretation = "Tool 1 significantly outperforms Tool 2"
            else:
                interpretation = "Tool 2 significantly outperforms Tool 1"
        else:
            interpretation = "No significant difference between tools"

        # Check assumptions
        assumptions_met = (b + c) >= 10  # Minimum sample size for chi-square

        return StatisticalTestResult(
            test_name="McNemar's Test",
            statistic=statistic,
            p_value=p_value,
            significant=p_value < self.alpha,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=assumptions_met
        )

    def proportions_test(self, metric1: float, n1: int, metric2: float, n2: int,
                        metric_name: str) -> StatisticalTestResult:
        """
        Test for difference in proportions (e.g., precision, recall)

        Args:
            metric1: Metric value for tool 1 (e.g., 0.85)
            n1: Sample size for tool 1
            metric2: Metric value for tool 2
            n2: Sample size for tool 2
            metric_name: Name of metric being tested

        Returns:
            StatisticalTestResult
        """
        # Convert metrics to counts
        count1 = int(metric1 * n1)
        count2 = int(metric2 * n2)

        # Two-proportion z-test
        try:
            z_stat, p_value = proportions_ztest([count1, count2], [n1, n2])
        except:
            # Fallback to Fisher's exact test for small samples
            from scipy.stats import fisher_exact
            oddsratio, p_value = fisher_exact([[count1, n1-count1], [count2, n2-count2]])
            z_stat = 0.0

        # Effect size (Cohen's h)
        p1 = count1 / n1
        p2 = count2 / n2
        effect_size = 2 * (np.arcsin(np.sqrt(p1)) - np.arcsin(np.sqrt(p2)))

        # Confidence interval for difference in proportions
        p_pool = (count1 + count2) / (n1 + n2)
        se_diff = np.sqrt(p_pool * (1 - p_pool) * (1/n1 + 1/n2))
        diff = p1 - p2
        ci_lower = diff - 1.96 * se_diff
        ci_upper = diff + 1.96 * se_diff

        # Interpretation
        if abs(effect_size) < 0.2:
            magnitude = "small"
        elif abs(effect_size) < 0.5:
            magnitude = "medium"
        else:
            magnitude = "large"

        if p_value < self.alpha:
            interpretation = f"Significant {magnitude} difference in {metric_name}"
        else:
            interpretation = f"No significant difference in {metric_name}"

        return StatisticalTestResult(
            test_name=f"Proportions Test ({metric_name})",
            statistic=z_stat,
            p_value=p_value,
            significant=p_value < self.alpha,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=min(count1, n1-count1, count2, n2-count2) >= 5
        )

    def bootstrap_difference_test(self, metric1_samples: List[float],
                                metric2_samples: List[float],
                                metric_name: str,
                                n_bootstrap: int = 10000) -> StatisticalTestResult:
        """
        Bootstrap test for difference in metrics

        Args:
            metric1_samples: Samples from tool 1
            metric2_samples: Samples from tool 2
            metric_name: Name of metric
            n_bootstrap: Number of bootstrap samples

        Returns:
            StatisticalTestResult
        """
        # Observed difference
        observed_diff = np.mean(metric1_samples) - np.mean(metric2_samples)

        # Bootstrap under null hypothesis (no difference)
        combined_samples = metric1_samples + metric2_samples
        n1, n2 = len(metric1_samples), len(metric2_samples)

        bootstrap_diffs = []
        for _ in range(n_bootstrap):
            # Resample without replacement
            resampled = np.random.choice(combined_samples, n1 + n2, replace=True)
            boot_sample1 = resampled[:n1]
            boot_sample2 = resampled[n1:]
            boot_diff = np.mean(boot_sample1) - np.mean(boot_sample2)
            bootstrap_diffs.append(boot_diff)

        # P-value (two-tailed)
        p_value = np.mean(np.abs(bootstrap_diffs) >= np.abs(observed_diff))

        # Effect size (Cohen's d)
        pooled_std = np.sqrt(((n1-1)*np.var(metric1_samples, ddof=1) +
                             (n2-1)*np.var(metric2_samples, ddof=1)) / (n1+n2-2))
        effect_size = observed_diff / pooled_std if pooled_std > 0 else 0.0

        # Confidence interval
        ci_lower = np.percentile(bootstrap_diffs, 2.5)
        ci_upper = np.percentile(bootstrap_diffs, 97.5)

        # Interpretation
        if abs(effect_size) < 0.2:
            magnitude = "small"
        elif abs(effect_size) < 0.5:
            magnitude = "medium"
        else:
            magnitude = "large"

        if p_value < self.alpha:
            interpretation = f"Significant {magnitude} difference in {metric_name} (bootstrap)"
        else:
            interpretation = f"No significant difference in {metric_name} (bootstrap)"

        return StatisticalTestResult(
            test_name=f"Bootstrap Test ({metric_name})",
            statistic=observed_diff,
            p_value=p_value,
            significant=p_value < self.alpha,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            interpretation=interpretation,
            assumptions_met=True
        )


class ResultsGenerator:
    """Generate publication-ready results and tables"""

    def __init__(self, output_dir: str = "./results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def generate_performance_table(self, metrics_list: List[PerformanceMetrics],
                                 save_csv: bool = True) -> pd.DataFrame:
        """
        Generate comprehensive performance comparison table

        Args:
            metrics_list: List of PerformanceMetrics objects
            save_csv: Whether to save as CSV file

        Returns:
            DataFrame with formatted results
        """
        data = []
        for metrics in metrics_list:
            row = {
                'Tool': metrics.tool_name,
                'Precision': f"{metrics.precision:.3f}",
                'Recall': f"{metrics.recall:.3f}",
                'F1-Score': f"{metrics.f1_score:.3f}",
                'Specificity': f"{metrics.specificity:.3f}",
                'FPR': f"{metrics.false_positive_rate:.3f}",
                'FNR': f"{metrics.false_negative_rate:.3f}",
                'Accuracy': f"{metrics.accuracy:.3f}",
                'Balanced Acc.': f"{metrics.balanced_accuracy:.3f}",
                'MCC': f"{metrics.matthews_corr_coeff:.3f}",
                'TP': metrics.true_positives,
                'FP': metrics.false_positives,
                'TN': metrics.true_negatives,
                'FN': metrics.false_negatives
            }

            if metrics.auc_roc is not None:
                row['AUC-ROC'] = f"{metrics.auc_roc:.3f}"
            if metrics.auc_pr is not None:
                row['AUC-PR'] = f"{metrics.auc_pr:.3f}"
            if metrics.execution_time is not None:
                row['Time (s)'] = f"{metrics.execution_time:.2f}"
            if metrics.memory_usage is not None:
                row['Memory (MB)'] = f"{metrics.memory_usage:.1f}"

            data.append(row)

        df = pd.DataFrame(data)

        if save_csv:
            csv_path = self.output_dir / "performance_comparison.csv"
            df.to_csv(csv_path, index=False)
            self.logger.info(f"Performance table saved to {csv_path}")

        return df

    def generate_statistical_significance_table(self, comparison_results: List[ComparisonResult],
                                              save_csv: bool = True) -> pd.DataFrame:
        """
        Generate statistical significance comparison table

        Args:
            comparison_results: List of ComparisonResult objects
            save_csv: Whether to save as CSV

        Returns:
            DataFrame with statistical test results
        """
        data = []
        for result in comparison_results:
            for test in result.statistical_tests:
                row = {
                    'Baseline': result.baseline_tool,
                    'Comparison': result.comparison_tool,
                    'Test': test.test_name,
                    'Statistic': f"{test.statistic:.4f}",
                    'p-value': f"{test.p_value:.4f}",
                    'Significant': "Yes" if test.significant else "No",
                    'Effect Size': f"{test.effect_size:.3f}",
                    'CI Lower': f"{test.confidence_interval[0]:.3f}",
                    'CI Upper': f"{test.confidence_interval[1]:.3f}",
                    'Interpretation': test.interpretation,
                    'Assumptions Met': "Yes" if test.assumptions_met else "No"
                }
                data.append(row)

        df = pd.DataFrame(data)

        if save_csv:
            csv_path = self.output_dir / "statistical_significance.csv"
            df.to_csv(csv_path, index=False)
            self.logger.info(f"Statistical significance table saved to {csv_path}")

        return df

    def generate_latex_table(self, df: pd.DataFrame, caption: str, label: str) -> str:
        """
        Generate LaTeX table code for publication

        Args:
            df: DataFrame to convert
            caption: Table caption
            label: Table label for referencing

        Returns:
            LaTeX table code
        """
        latex_code = "\\begin{table}[htbp]\n"
        latex_code += "\\centering\n"
        latex_code += f"\\caption{{{caption}}}\n"
        latex_code += f"\\label{{{label}}}\n"
        latex_code += "\\begin{tabular}{" + "l" * len(df.columns) + "}\n"
        latex_code += "\\hline\n"

        # Header
        latex_code += " & ".join(df.columns) + " \\\\\n"
        latex_code += "\\hline\n"

        # Data rows
        for _, row in df.iterrows():
            latex_code += " & ".join(str(row[col]) for col in df.columns) + " \\\\\n"

        latex_code += "\\hline\n"
        latex_code += "\\end{tabular}\n"
        latex_code += "\\end{table}\n"

        # Save to file
        latex_path = self.output_dir / f"{label}.tex"
        with open(latex_path, 'w') as f:
            f.write(latex_code)

        self.logger.info(f"LaTeX table saved to {latex_path}")
        return latex_code

    def generate_executive_summary(self, metrics_list: List[PerformanceMetrics],
                                 comparison_results: List[ComparisonResult]) -> Dict[str, Any]:
        """
        Generate executive summary of results

        Args:
            metrics_list: Performance metrics for all tools
            comparison_results: Statistical comparison results

        Returns:
            Dictionary with executive summary
        """
        # Find best performing tool
        best_tool = max(metrics_list, key=lambda x: x.f1_score)
        worst_tool = min(metrics_list, key=lambda x: x.f1_score)

        # Calculate improvements
        f1_improvement = best_tool.f1_score - worst_tool.f1_score
        precision_improvement = best_tool.precision - worst_tool.precision
        recall_improvement = best_tool.recall - worst_tool.recall

        # Count significant comparisons
        significant_comparisons = sum(
            1 for result in comparison_results
            for test in result.statistical_tests
            if test.significant
        )

        total_comparisons = sum(len(result.statistical_tests) for result in comparison_results)

        # Performance categories
        high_performers = [m for m in metrics_list if m.f1_score >= 0.90]
        medium_performers = [m for m in metrics_list if 0.70 <= m.f1_score < 0.90]
        low_performers = [m for m in metrics_list if m.f1_score < 0.70]

        summary = {
            'analysis_date': datetime.now().isoformat(),
            'total_tools_evaluated': len(metrics_list),
            'best_tool': {
                'name': best_tool.tool_name,
                'f1_score': best_tool.f1_score,
                'precision': best_tool.precision,
                'recall': best_tool.recall,
                'false_positive_rate': best_tool.false_positive_rate
            },
            'worst_tool': {
                'name': worst_tool.tool_name,
                'f1_score': worst_tool.f1_score
            },
            'improvements': {
                'f1_score': f1_improvement,
                'precision': precision_improvement,
                'recall': recall_improvement
            },
            'statistical_analysis': {
                'total_comparisons': total_comparisons,
                'significant_comparisons': significant_comparisons,
                'significance_rate': significant_comparisons / total_comparisons if total_comparisons > 0 else 0
            },
            'performance_distribution': {
                'high_performers': len(high_performers),
                'medium_performers': len(medium_performers),
                'low_performers': len(low_performers)
            },
            'key_findings': [
                f"Best tool ({best_tool.tool_name}) achieves {best_tool.f1_score:.1%} F1-score",
                f"Performance improvement of {f1_improvement:.1%} over worst performer",
                f"{significant_comparisons}/{total_comparisons} comparisons statistically significant",
                f"False positive rate ranges from {min(m.false_positive_rate for m in metrics_list):.1%} to {max(m.false_positive_rate for m in metrics_list):.1%}"
            ]
        }

        # Save summary
        summary_path = self.output_dir / "executive_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        self.logger.info(f"Executive summary saved to {summary_path}")
        return summary


# Example demonstration
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)

    # Initialize analyzer and results generator
    analyzer = AdvancedStatisticalAnalyzer()
    results_gen = ResultsGenerator()

    # Mock data for demonstration
    np.random.seed(42)
    n_samples = 1000

    # Generate mock results for multiple tools
    tools_data = [
        ("Our Framework", 0.98, 0.97, 15.2, 280),
        ("Checkmarx", 0.85, 0.83, 45.2, 410),
        ("Fortify", 0.82, 0.81, 38.7, 390),
        ("CodeQL", 0.87, 0.85, 28.4, 320),
        ("SonarQube", 0.79, 0.77, 25.8, 290)
    ]

    metrics_list = []
    all_predictions = []

    for tool_name, precision, recall, exec_time, memory in tools_data:
        # Generate synthetic predictions based on precision/recall
        ground_truth = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])

        # Generate predictions to match desired precision/recall
        predictions = []
        for true_label in ground_truth:
            if true_label == 1:  # Positive case
                pred = 1 if np.random.random() < recall else 0
            else:  # Negative case
                pred = 1 if np.random.random() < (1 - precision) else 0
            predictions.append(pred)

        all_predictions.append(predictions)

        # Generate confidence scores
        confidence_scores = []
        for pred, true_label in zip(predictions, ground_truth):
            if pred == true_label:
                conf = np.random.uniform(0.7, 1.0)
            else:
                conf = np.random.uniform(0.0, 0.3)
            confidence_scores.append(conf)

        # Calculate comprehensive metrics
        metrics = analyzer.calculate_comprehensive_metrics(
            predictions=predictions,
            ground_truth=ground_truth.tolist(),
            tool_name=tool_name,
            confidence_scores=confidence_scores,
            execution_time=exec_time,
            memory_usage=memory
        )
        metrics_list.append(metrics)

    # Generate performance table
    perf_table = results_gen.generate_performance_table(metrics_list)
    print("Performance Comparison Table:")
    print(perf_table)
    print()

    # Statistical comparisons
    comparison_results = []
    for i in range(len(metrics_list)):
        for j in range(i + 1, len(metrics_list)):
            tool1_metrics = metrics_list[i]
            tool2_metrics = metrics_list[j]

            # McNemar's test
            mcnemar_result = analyzer.mcnemar_test_detailed(
                all_predictions[i], all_predictions[j], ground_truth.tolist()
            )

            # Proportions test for precision
            precision_test = analyzer.proportions_test(
                tool1_metrics.precision, n_samples,
                tool2_metrics.precision, n_samples,
                "Precision"
            )

            comparison = ComparisonResult(
                baseline_tool=tool1_metrics.tool_name,
                comparison_tool=tool2_metrics.tool_name,
                performance_improvement={
                    'f1_score': tool2_metrics.f1_score - tool1_metrics.f1_score,
                    'precision': tool2_metrics.precision - tool1_metrics.precision,
                    'recall': tool2_metrics.recall - tool1_metrics.recall
                },
                statistical_tests=[mcnemar_result, precision_test],
                practical_significance=abs(tool2_metrics.f1_score - tool1_metrics.f1_score) > 0.05,
                recommendation="Significant improvement" if mcnemar_result.significant else "No significant difference"
            )
            comparison_results.append(comparison)

    # Generate statistical significance table
    stat_table = results_gen.generate_statistical_significance_table(comparison_results)
    print("Statistical Significance Table:")
    print(stat_table.head(10))  # Show first 10 rows
    print()

    # Generate executive summary
    summary = results_gen.generate_executive_summary(metrics_list, comparison_results)
    print("Executive Summary:")
    for finding in summary['key_findings']:
        print(f"• {finding}")

    # Generate LaTeX tables
    latex_perf = results_gen.generate_latex_table(
        perf_table,
        "Performance Comparison of Vulnerability Detection Tools",
        "tab:performance_comparison"
    )

    latex_stat = results_gen.generate_latex_table(
        stat_table.head(5),  # First 5 rows for example
        "Statistical Significance Tests",
        "tab:statistical_significance"
    )

    print(f"\nAll results saved to: {results_gen.output_dir}")
    print("Files generated:")
    for file_path in results_gen.output_dir.glob("*"):
        print(f"  - {file_path.name}")