"""
Comprehensive Evaluation Framework for Vulnerability Detection

This package provides rigorous evaluation tools for:
- Multi-metric performance assessment
- Statistical significance testing
- Cross-validation and model comparison
- Robustness evaluation
- Fairness and bias analysis
- Production readiness assessment
"""

from .metrics_calculator import MetricsCalculator
from .statistical_evaluator import StatisticalEvaluator
from .model_comparator import ModelComparator
from .robustness_tester import RobustnessTester
from .benchmark_suite import BenchmarkSuite

__all__ = [
    'MetricsCalculator',
    'StatisticalEvaluator',
    'ModelComparator',
    'RobustnessTester',
    'BenchmarkSuite'
]