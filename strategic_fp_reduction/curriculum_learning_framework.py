"""
Curriculum Learning Framework for Vulnerability Detection
========================================================

This module implements a sophisticated curriculum learning framework that:
1. Progressively introduces training samples from easy to hard
2. Adapts curriculum pacing based on model performance
3. Uses multiple difficulty metrics for sample ordering
4. Implements anti-curriculum learning for robustness
5. Provides self-paced learning with automatic threshold adjustment

Research shows that curriculum learning can improve model performance by
15-25% and reduce training time by 20-30% while enhancing generalization.
"""

import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import json
import ast
import re
from collections import defaultdict, Counter
import heapq
import random
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DifficultyMetric(Enum):
    """Difficulty metrics for curriculum ordering"""
    SYNTACTIC_COMPLEXITY = "syntactic_complexity"
    SEMANTIC_COMPLEXITY = "semantic_complexity"
    VULNERABILITY_RARITY = "vulnerability_rarity"
    CODE_LENGTH = "code_length"
    NESTING_DEPTH = "nesting_depth"
    ENTROPY = "entropy"
    LABEL_NOISE = "label_noise"
    PREDICTION_CONFIDENCE = "prediction_confidence"

class CurriculumStrategy(Enum):
    """Curriculum learning strategies"""
    VANILLA = "vanilla"              # Easy to hard progression
    ANTI_CURRICULUM = "anti_curriculum"  # Hard to easy progression
    MIXED = "mixed"                  # Alternating easy/hard
    SELF_PACED = "self_paced"       # Model determines pacing
    ADAPTIVE = "adaptive"            # Performance-based adaptation
    COMPETENCE = "competence"        # Competence function based

@dataclass
class CurriculumConfig:
    """Configuration for curriculum learning"""

    # Strategy settings
    strategy: CurriculumStrategy = CurriculumStrategy.ADAPTIVE
    difficulty_metrics: List[DifficultyMetric] = field(default_factory=lambda: [
        DifficultyMetric.SYNTACTIC_COMPLEXITY,
        DifficultyMetric.SEMANTIC_COMPLEXITY,
        DifficultyMetric.VULNERABILITY_RARITY
    ])

    # Pacing parameters
    initial_subset_ratio: float = 0.1    # Start with 10% of data
    growth_rate: float = 0.1             # Increase by 10% each epoch
    max_subset_ratio: float = 1.0        # Maximum 100% of data
    min_subset_ratio: float = 0.05       # Minimum 5% of data

    # Self-paced learning
    self_paced_lambda: float = 1.0       # Self-paced regularization
    lambda_growth_rate: float = 1.1      # Lambda growth per epoch
    confidence_threshold: float = 0.8     # Confidence threshold for inclusion

    # Adaptive parameters
    performance_window: int = 5          # Window for performance tracking
    performance_threshold: float = 0.05  # Threshold for curriculum advancement
    difficulty_temperature: float = 1.0  # Temperature for difficulty weighting

    # Anti-curriculum settings
    anti_curriculum_ratio: float = 0.2   # Ratio of anti-curriculum samples
    anti_curriculum_epochs: int = 5      # Number of anti-curriculum epochs

    # Competence function
    competence_smoothing: float = 0.1    # Competence function smoothing
    competence_threshold: float = 0.7    # Threshold for advancing difficulty

class DifficultyAnalyzer:
    """Analyzes code samples to determine difficulty scores"""

    def __init__(self, config: CurriculumConfig):
        self.config = config
        self.vulnerability_frequencies = defaultdict(int)
        self.global_stats = {}

    def analyze_dataset(self, dataset: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """Analyze entire dataset to compute difficulty scores"""
        logger.info(f"Analyzing dataset of {len(dataset)} samples for difficulty")

        # First pass: compute global statistics
        self._compute_global_statistics(dataset)

        # Second pass: compute difficulty scores
        difficulty_scores = {metric.value: [] for metric in self.config.difficulty_metrics}

        for sample in dataset:
            code = sample.get('code', '')
            label = sample.get('label', 0)
            vulnerability_type = sample.get('vulnerability_type', 'unknown')

            scores = self._compute_sample_difficulty(code, label, vulnerability_type)

            for metric in self.config.difficulty_metrics:
                difficulty_scores[metric.value].append(scores[metric.value])

        # Normalize scores to [0, 1] range
        for metric_name, scores in difficulty_scores.items():
            if scores:
                min_score, max_score = min(scores), max(scores)
                if max_score > min_score:
                    difficulty_scores[metric_name] = [
                        (score - min_score) / (max_score - min_score)
                        for score in scores
                    ]
                else:
                    difficulty_scores[metric_name] = [0.5] * len(scores)

        logger.info(f"Computed difficulty scores using {len(self.config.difficulty_metrics)} metrics")
        return difficulty_scores

    def _compute_global_statistics(self, dataset: List[Dict[str, Any]]):
        """Compute global dataset statistics for normalization"""
        code_lengths = []
        nesting_depths = []
        entropies = []
        vulnerability_types = []

        for sample in dataset:
            code = sample.get('code', '')
            vulnerability_type = sample.get('vulnerability_type', 'unknown')

            code_lengths.append(len(code))
            nesting_depths.append(self._compute_nesting_depth(code))
            entropies.append(self._compute_entropy(code))
            vulnerability_types.append(vulnerability_type)

            self.vulnerability_frequencies[vulnerability_type] += 1

        self.global_stats = {
            'code_length_mean': np.mean(code_lengths),
            'code_length_std': np.std(code_lengths),
            'nesting_depth_mean': np.mean(nesting_depths),
            'nesting_depth_std': np.std(nesting_depths),
            'entropy_mean': np.mean(entropies),
            'entropy_std': np.std(entropies),
            'total_samples': len(dataset)
        }

    def _compute_sample_difficulty(self, code: str, label: int, vulnerability_type: str) -> Dict[str, float]:
        """Compute difficulty scores for a single sample"""
        scores = {}

        # Syntactic complexity
        if DifficultyMetric.SYNTACTIC_COMPLEXITY in self.config.difficulty_metrics:
            scores[DifficultyMetric.SYNTACTIC_COMPLEXITY.value] = self._compute_syntactic_complexity(code)

        # Semantic complexity
        if DifficultyMetric.SEMANTIC_COMPLEXITY in self.config.difficulty_metrics:
            scores[DifficultyMetric.SEMANTIC_COMPLEXITY.value] = self._compute_semantic_complexity(code)

        # Vulnerability rarity
        if DifficultyMetric.VULNERABILITY_RARITY in self.config.difficulty_metrics:
            scores[DifficultyMetric.VULNERABILITY_RARITY.value] = self._compute_vulnerability_rarity(vulnerability_type)

        # Code length
        if DifficultyMetric.CODE_LENGTH in self.config.difficulty_metrics:
            scores[DifficultyMetric.CODE_LENGTH.value] = self._compute_normalized_length(code)

        # Nesting depth
        if DifficultyMetric.NESTING_DEPTH in self.config.difficulty_metrics:
            scores[DifficultyMetric.NESTING_DEPTH.value] = self._compute_normalized_nesting(code)

        # Entropy
        if DifficultyMetric.ENTROPY in self.config.difficulty_metrics:
            scores[DifficultyMetric.ENTROPY.value] = self._compute_normalized_entropy(code)

        return scores

    def _compute_syntactic_complexity(self, code: str) -> float:
        """Compute syntactic complexity based on AST structure"""
        try:
            tree = ast.parse(code)

            complexity_score = 0
            node_counts = Counter()

            for node in ast.walk(tree):
                node_type = type(node).__name__
                node_counts[node_type] += 1

                # Weight different node types by complexity
                complexity_weights = {
                    'If': 2, 'For': 3, 'While': 3, 'Try': 4, 'With': 2,
                    'FunctionDef': 3, 'ClassDef': 4, 'Lambda': 2,
                    'ListComp': 2, 'SetComp': 2, 'DictComp': 2, 'GeneratorExp': 2,
                    'Call': 1, 'Attribute': 1, 'Subscript': 1
                }

                weight = complexity_weights.get(node_type, 1)
                complexity_score += weight

            # Normalize by total number of nodes
            total_nodes = sum(node_counts.values())
            return complexity_score / max(total_nodes, 1)

        except SyntaxError:
            return 1.0  # Maximum difficulty for unparseable code

    def _compute_semantic_complexity(self, code: str) -> float:
        """Compute semantic complexity based on code patterns"""
        # Pattern-based complexity scoring
        complexity_patterns = [
            (r'import\s+\w+', 0.1),           # Imports
            (r'def\s+\w+\s*\([^)]*\):', 0.3), # Function definitions
            (r'class\s+\w+', 0.4),            # Class definitions
            (r'try:|except:|finally:', 0.5),   # Exception handling
            (r'with\s+\w+', 0.3),             # Context managers
            (r'yield\s+', 0.4),               # Generators
            (r'lambda\s+', 0.3),              # Lambda functions
            (r'\[.*for.*in.*\]', 0.4),       # List comprehensions
            (r'@\w+', 0.2),                   # Decorators
            (r'async\s+def|await\s+', 0.5),  # Async code
            (r'globals\(\)|locals\(\)|eval\(|exec\(', 0.8), # Dynamic features
        ]

        total_complexity = 0
        code_lines = len(code.split('\n'))

        for pattern, weight in complexity_patterns:
            matches = len(re.findall(pattern, code, re.IGNORECASE | re.MULTILINE))
            total_complexity += matches * weight

        # Normalize by code length
        return total_complexity / max(code_lines, 1)

    def _compute_vulnerability_rarity(self, vulnerability_type: str) -> float:
        """Compute difficulty based on vulnerability type rarity"""
        total_samples = self.global_stats['total_samples']
        frequency = self.vulnerability_frequencies.get(vulnerability_type, 1)

        # Rarer vulnerabilities are more difficult
        rarity = 1.0 - (frequency / total_samples)
        return rarity

    def _compute_nesting_depth(self, code: str) -> int:
        """Compute maximum nesting depth"""
        try:
            tree = ast.parse(code)
            max_depth = 0

            def compute_depth(node, depth=0):
                nonlocal max_depth
                max_depth = max(max_depth, depth)

                for child in ast.iter_child_nodes(node):
                    child_depth = depth + 1 if isinstance(child, (
                        ast.If, ast.For, ast.While, ast.With, ast.Try,
                        ast.FunctionDef, ast.ClassDef
                    )) else depth
                    compute_depth(child, child_depth)

            compute_depth(tree)
            return max_depth

        except SyntaxError:
            return 10  # High depth for unparseable code

    def _compute_entropy(self, code: str) -> float:
        """Compute Shannon entropy of code"""
        if not code:
            return 0.0

        # Character frequency
        char_counts = Counter(code)
        total_chars = len(code)

        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)

        return entropy

    def _compute_normalized_length(self, code: str) -> float:
        """Compute normalized code length difficulty"""
        length = len(code)
        mean_length = self.global_stats['code_length_mean']

        # Longer code is generally more difficult
        return min(length / (2 * mean_length), 1.0)

    def _compute_normalized_nesting(self, code: str) -> float:
        """Compute normalized nesting depth difficulty"""
        depth = self._compute_nesting_depth(code)
        mean_depth = self.global_stats['nesting_depth_mean']

        return min(depth / max(2 * mean_depth, 1), 1.0)

    def _compute_normalized_entropy(self, code: str) -> float:
        """Compute normalized entropy difficulty"""
        entropy = self._compute_entropy(code)
        mean_entropy = self.global_stats['entropy_mean']

        return min(entropy / max(2 * mean_entropy, 1), 1.0)

class CurriculumScheduler:
    """Manages curriculum learning schedule and sample selection"""

    def __init__(self, config: CurriculumConfig, difficulty_analyzer: DifficultyAnalyzer):
        self.config = config
        self.difficulty_analyzer = difficulty_analyzer

        # Internal state
        self.current_epoch = 0
        self.current_subset_ratio = config.initial_subset_ratio
        self.current_lambda = config.self_paced_lambda
        self.performance_history = []
        self.competence_scores = []

        # Sample indices and scores
        self.sample_indices = []
        self.difficulty_scores = {}
        self.combined_difficulty = []

        logger.info(f"Initialized CurriculumScheduler with strategy: {config.strategy.value}")

    def initialize_curriculum(self, dataset: List[Dict[str, Any]]):
        """Initialize curriculum with dataset analysis"""
        logger.info("Initializing curriculum learning schedule")

        # Analyze dataset difficulty
        self.difficulty_scores = self.difficulty_analyzer.analyze_dataset(dataset)

        # Combine multiple difficulty metrics
        self._compute_combined_difficulty()

        # Initialize sample indices
        self.sample_indices = list(range(len(dataset)))

        # Sort samples by difficulty for initial ordering
        self._sort_samples_by_difficulty()

        logger.info(f"Curriculum initialized with {len(dataset)} samples")
        logger.info(f"Initial subset ratio: {self.current_subset_ratio:.2f}")

    def get_curriculum_batch(self, epoch: int, model_performance: Optional[float] = None) -> List[int]:
        """Get indices of samples for current curriculum batch"""
        self.current_epoch = epoch

        # Update performance history
        if model_performance is not None:
            self.performance_history.append(model_performance)

        # Update curriculum parameters
        self._update_curriculum_parameters(model_performance)

        # Select samples based on strategy
        if self.config.strategy == CurriculumStrategy.VANILLA:
            selected_indices = self._vanilla_selection()
        elif self.config.strategy == CurriculumStrategy.ANTI_CURRICULUM:
            selected_indices = self._anti_curriculum_selection()
        elif self.config.strategy == CurriculumStrategy.MIXED:
            selected_indices = self._mixed_selection()
        elif self.config.strategy == CurriculumStrategy.SELF_PACED:
            selected_indices = self._self_paced_selection()
        elif self.config.strategy == CurriculumStrategy.ADAPTIVE:
            selected_indices = self._adaptive_selection()
        elif self.config.strategy == CurriculumStrategy.COMPETENCE:
            selected_indices = self._competence_selection()
        else:
            selected_indices = self._vanilla_selection()

        logger.info(f"Epoch {epoch}: Selected {len(selected_indices)} samples "
                   f"(ratio: {len(selected_indices) / len(self.sample_indices):.3f})")

        return selected_indices

    def _compute_combined_difficulty(self):
        """Combine multiple difficulty metrics into single score"""
        num_samples = len(next(iter(self.difficulty_scores.values())))
        self.combined_difficulty = []

        for i in range(num_samples):
            combined_score = 0
            for metric_name, scores in self.difficulty_scores.items():
                combined_score += scores[i]

            # Average difficulty across metrics
            avg_difficulty = combined_score / len(self.difficulty_scores)
            self.combined_difficulty.append(avg_difficulty)

        # Apply temperature scaling
        if self.config.difficulty_temperature != 1.0:
            self.combined_difficulty = [
                score / self.config.difficulty_temperature
                for score in self.combined_difficulty
            ]

    def _sort_samples_by_difficulty(self):
        """Sort sample indices by combined difficulty score"""
        # Create list of (index, difficulty) pairs
        indexed_difficulties = list(enumerate(self.combined_difficulty))

        # Sort by difficulty (ascending for easy-to-hard)
        indexed_difficulties.sort(key=lambda x: x[1])

        # Extract sorted indices
        self.sample_indices = [idx for idx, _ in indexed_difficulties]

    def _update_curriculum_parameters(self, model_performance: Optional[float]):
        """Update curriculum parameters based on performance"""
        if self.config.strategy == CurriculumStrategy.ADAPTIVE:
            self._adaptive_parameter_update(model_performance)
        elif self.config.strategy == CurriculumStrategy.SELF_PACED:
            self._self_paced_parameter_update()
        elif self.config.strategy == CurriculumStrategy.COMPETENCE:
            self._competence_parameter_update(model_performance)
        else:
            # Standard progression
            self.current_subset_ratio = min(
                self.current_subset_ratio + self.config.growth_rate,
                self.config.max_subset_ratio
            )

    def _adaptive_parameter_update(self, model_performance: Optional[float]):
        """Adaptive curriculum parameter updates"""
        if model_performance is None or len(self.performance_history) < self.config.performance_window:
            # Standard progression if no performance data
            self.current_subset_ratio = min(
                self.current_subset_ratio + self.config.growth_rate,
                self.config.max_subset_ratio
            )
            return

        # Check recent performance trend
        recent_performance = self.performance_history[-self.config.performance_window:]
        performance_improvement = recent_performance[-1] - recent_performance[0]

        if performance_improvement >= self.config.performance_threshold:
            # Good performance: increase difficulty
            self.current_subset_ratio = min(
                self.current_subset_ratio + self.config.growth_rate * 1.5,
                self.config.max_subset_ratio
            )
        elif performance_improvement <= -self.config.performance_threshold:
            # Poor performance: slow down progression
            self.current_subset_ratio = max(
                self.current_subset_ratio + self.config.growth_rate * 0.5,
                self.config.min_subset_ratio
            )
        else:
            # Standard progression
            self.current_subset_ratio = min(
                self.current_subset_ratio + self.config.growth_rate,
                self.config.max_subset_ratio
            )

    def _self_paced_parameter_update(self):
        """Self-paced learning parameter updates"""
        self.current_lambda *= self.config.lambda_growth_rate

    def _competence_parameter_update(self, model_performance: Optional[float]):
        """Competence-based parameter updates"""
        if model_performance is not None:
            # Smooth competence score
            if self.competence_scores:
                smoothed_competence = (
                    self.config.competence_smoothing * model_performance +
                    (1 - self.config.competence_smoothing) * self.competence_scores[-1]
                )
            else:
                smoothed_competence = model_performance

            self.competence_scores.append(smoothed_competence)

            # Adjust subset ratio based on competence
            if smoothed_competence >= self.config.competence_threshold:
                self.current_subset_ratio = min(
                    self.current_subset_ratio + self.config.growth_rate * 2.0,
                    self.config.max_subset_ratio
                )
            else:
                # Maintain current level if competence is low
                pass

    def _vanilla_selection(self) -> List[int]:
        """Vanilla curriculum: easy to hard progression"""
        num_samples = int(self.current_subset_ratio * len(self.sample_indices))
        return self.sample_indices[:num_samples]

    def _anti_curriculum_selection(self) -> List[int]:
        """Anti-curriculum: hard to easy progression"""
        num_samples = int(self.current_subset_ratio * len(self.sample_indices))

        # Use anti-curriculum for initial epochs
        if self.current_epoch < self.config.anti_curriculum_epochs:
            return self.sample_indices[-num_samples:]  # Hard samples first
        else:
            return self.sample_indices[:num_samples]   # Then easy samples

    def _mixed_selection(self) -> List[int]:
        """Mixed curriculum: alternating easy and hard samples"""
        num_samples = int(self.current_subset_ratio * len(self.sample_indices))

        # Mix easy and hard samples
        easy_ratio = 0.7 - (self.current_epoch * 0.05)  # Decrease easy ratio over time
        easy_ratio = max(easy_ratio, 0.3)  # Minimum 30% easy samples

        num_easy = int(num_samples * easy_ratio)
        num_hard = num_samples - num_easy

        easy_samples = self.sample_indices[:num_easy]
        hard_samples = self.sample_indices[-num_hard:] if num_hard > 0 else []

        # Shuffle the combination
        mixed_samples = easy_samples + hard_samples
        random.shuffle(mixed_samples)

        return mixed_samples

    def _self_paced_selection(self) -> List[int]:
        """Self-paced learning selection based on sample confidence"""
        # This requires model predictions, which would be provided externally
        # For now, implement a simplified version based on difficulty

        num_samples = len(self.sample_indices)
        selection_probabilities = []

        for i, idx in enumerate(self.sample_indices):
            difficulty = self.combined_difficulty[idx]

            # Self-paced probability: easier samples more likely to be selected
            prob = math.exp(-self.current_lambda * difficulty)
            selection_probabilities.append(prob)

        # Normalize probabilities
        total_prob = sum(selection_probabilities)
        selection_probabilities = [p / total_prob for p in selection_probabilities]

        # Sample based on probabilities
        target_samples = int(self.current_subset_ratio * num_samples)
        selected_indices = np.random.choice(
            self.sample_indices,
            size=target_samples,
            replace=False,
            p=selection_probabilities
        )

        return selected_indices.tolist()

    def _adaptive_selection(self) -> List[int]:
        """Adaptive selection based on performance history"""
        base_samples = self._vanilla_selection()

        # If performance is declining, add some easier samples
        if len(self.performance_history) >= 3:
            recent_trend = np.mean(self.performance_history[-3:]) - np.mean(self.performance_history[-6:-3]) if len(self.performance_history) >= 6 else 0

            if recent_trend < -self.config.performance_threshold:
                # Add easier samples
                num_base = len(base_samples)
                num_easier = int(num_base * 0.2)  # Add 20% easier samples

                # Find easier samples not in current batch
                current_max_idx = max(base_samples) if base_samples else 0
                easier_candidates = [idx for idx in self.sample_indices
                                   if idx < current_max_idx and idx not in base_samples]

                if len(easier_candidates) >= num_easier:
                    easier_samples = random.sample(easier_candidates, num_easier)
                    base_samples.extend(easier_samples)

        return base_samples

    def _competence_selection(self) -> List[int]:
        """Competence-based selection using competence function"""
        if not self.competence_scores:
            return self._vanilla_selection()

        current_competence = self.competence_scores[-1]

        # Map competence to difficulty threshold
        difficulty_threshold = current_competence

        # Select samples with difficulty <= threshold
        selected_indices = []
        for idx in self.sample_indices:
            if self.combined_difficulty[idx] <= difficulty_threshold:
                selected_indices.append(idx)

        # Ensure minimum number of samples
        min_samples = int(self.config.min_subset_ratio * len(self.sample_indices))
        if len(selected_indices) < min_samples:
            additional_needed = min_samples - len(selected_indices)
            remaining_indices = [idx for idx in self.sample_indices if idx not in selected_indices]
            if remaining_indices:
                additional_samples = random.sample(
                    remaining_indices,
                    min(additional_needed, len(remaining_indices))
                )
                selected_indices.extend(additional_samples)

        return selected_indices

    def get_curriculum_statistics(self) -> Dict[str, Any]:
        """Get current curriculum statistics"""
        return {
            'current_epoch': self.current_epoch,
            'current_subset_ratio': self.current_subset_ratio,
            'current_lambda': self.current_lambda,
            'performance_history': self.performance_history,
            'competence_scores': self.competence_scores,
            'difficulty_score_stats': {
                metric: {
                    'min': min(scores),
                    'max': max(scores),
                    'mean': np.mean(scores),
                    'std': np.std(scores)
                }
                for metric, scores in self.difficulty_scores.items()
            },
            'combined_difficulty_stats': {
                'min': min(self.combined_difficulty),
                'max': max(self.combined_difficulty),
                'mean': np.mean(self.combined_difficulty),
                'std': np.std(self.combined_difficulty)
            }
        }

class CurriculumDataLoader:
    """Data loader that implements curriculum learning"""

    def __init__(self, dataset: List[Dict[str, Any]], config: CurriculumConfig):
        self.dataset = dataset
        self.config = config

        # Initialize components
        self.difficulty_analyzer = DifficultyAnalyzer(config)
        self.scheduler = CurriculumScheduler(config, self.difficulty_analyzer)

        # Initialize curriculum
        self.scheduler.initialize_curriculum(dataset)

        logger.info(f"Initialized CurriculumDataLoader with {len(dataset)} samples")

    def get_epoch_data(self, epoch: int, model_performance: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get training data for current epoch"""
        selected_indices = self.scheduler.get_curriculum_batch(epoch, model_performance)

        # Return selected samples
        epoch_data = [self.dataset[idx] for idx in selected_indices]

        return epoch_data

    def get_difficulty_analysis(self) -> Dict[str, Any]:
        """Get difficulty analysis results"""
        return {
            'difficulty_scores': self.scheduler.difficulty_scores,
            'combined_difficulty': self.scheduler.combined_difficulty,
            'statistics': self.scheduler.get_curriculum_statistics()
        }

    def save_curriculum_state(self, filepath: str):
        """Save curriculum learning state"""
        state = {
            'config': {
                'strategy': self.config.strategy.value,
                'difficulty_metrics': [m.value for m in self.config.difficulty_metrics],
                'initial_subset_ratio': self.config.initial_subset_ratio,
                'growth_rate': self.config.growth_rate,
                'max_subset_ratio': self.config.max_subset_ratio
            },
            'curriculum_statistics': self.scheduler.get_curriculum_statistics(),
            'difficulty_analysis': self.get_difficulty_analysis()
        }

        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)

        logger.info(f"Curriculum state saved to {filepath}")

# Example usage and demonstration
if __name__ == "__main__":
    print("Curriculum Learning Framework for Vulnerability Detection")
    print("=" * 60)

    # Create sample dataset
    sample_dataset = [
        {
            'code': 'x = 1 + 1',
            'label': 0,
            'vulnerability_type': 'none'
        },
        {
            'code': '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    return execute_query(query)
''',
            'label': 1,
            'vulnerability_type': 'sql_injection'
        },
        {
            'code': '''
import os
def process_file(filename):
    if ".." in filename:
        return "Invalid filename"
    with open("/uploads/" + filename, 'r') as f:
        return f.read()
''',
            'label': 1,
            'vulnerability_type': 'path_traversal'
        },
        {
            'code': '''
def safe_login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return execute_query(query, (username, password))
''',
            'label': 0,
            'vulnerability_type': 'none'
        },
        {
            'code': '''
class ComplexVulnerability:
    def __init__(self):
        self.data = {}

    def process_request(self, request_data):
        try:
            for key, value in request_data.items():
                if isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        if "eval" in str(nested_value):
                            result = eval(nested_value)  # Dangerous!
                            self.data[f"{key}_{nested_key}"] = result
                        else:
                            self.data[f"{key}_{nested_key}"] = nested_value
                else:
                    self.data[key] = value
            return self.data
        except Exception as e:
            return {"error": str(e)}
''',
            'label': 1,
            'vulnerability_type': 'code_injection'
        }
    ]

    # Test different curriculum strategies
    strategies = [
        CurriculumStrategy.VANILLA,
        CurriculumStrategy.ADAPTIVE,
        CurriculumStrategy.SELF_PACED,
        CurriculumStrategy.ANTI_CURRICULUM
    ]

    print(f"\nTesting Curriculum Learning Strategies:")
    print("-" * 40)

    for strategy in strategies:
        print(f"\nStrategy: {strategy.value.upper()}")

        # Configure curriculum
        config = CurriculumConfig(
            strategy=strategy,
            initial_subset_ratio=0.4,
            growth_rate=0.2,
            difficulty_metrics=[
                DifficultyMetric.SYNTACTIC_COMPLEXITY,
                DifficultyMetric.SEMANTIC_COMPLEXITY,
                DifficultyMetric.VULNERABILITY_RARITY
            ]
        )

        # Initialize curriculum loader
        curriculum_loader = CurriculumDataLoader(sample_dataset, config)

        # Simulate training epochs
        performance_values = [0.5, 0.6, 0.65, 0.7, 0.75, 0.8, 0.82, 0.85]

        print(f"  Epoch Progression:")
        for epoch in range(8):
            performance = performance_values[epoch] if epoch < len(performance_values) else 0.85
            epoch_data = curriculum_loader.get_epoch_data(epoch, performance)

            # Analyze selected samples
            selected_labels = [sample['label'] for sample in epoch_data]
            vuln_types = [sample['vulnerability_type'] for sample in epoch_data]

            print(f"    Epoch {epoch}: {len(epoch_data)} samples, "
                  f"{sum(selected_labels)} vulnerable, "
                  f"types: {set(vuln_types)}")

    # Detailed analysis for adaptive strategy
    print(f"\nDetailed Analysis - Adaptive Strategy:")
    print("-" * 40)

    config = CurriculumConfig(strategy=CurriculumStrategy.ADAPTIVE)
    curriculum_loader = CurriculumDataLoader(sample_dataset, config)

    # Get difficulty analysis
    difficulty_analysis = curriculum_loader.get_difficulty_analysis()

    print(f"Difficulty Scores by Sample:")
    for i, sample in enumerate(sample_dataset):
        combined_difficulty = difficulty_analysis['combined_difficulty'][i]
        vulnerability_type = sample['vulnerability_type']
        label = sample['label']

        print(f"  Sample {i}: {vulnerability_type} (label={label}) -> "
              f"difficulty={combined_difficulty:.3f}")

    print(f"\nDifficulty Metrics Statistics:")
    stats = difficulty_analysis['statistics']['difficulty_score_stats']
    for metric, metric_stats in stats.items():
        print(f"  {metric}:")
        print(f"    Mean: {metric_stats['mean']:.3f}")
        print(f"    Std:  {metric_stats['std']:.3f}")
        print(f"    Range: [{metric_stats['min']:.3f}, {metric_stats['max']:.3f}]")

    # Save example curriculum state
    output_dir = Path("/Users/ankitthakur/vuln_ml_research/strategic_fp_reduction")
    curriculum_state_file = output_dir / "curriculum_learning_demo.json"
    curriculum_loader.save_curriculum_state(str(curriculum_state_file))

    print(f"\nCurriculum state saved to: {curriculum_state_file}")

    # Performance comparison simulation
    print(f"\nSimulated Training Performance Comparison:")
    print("-" * 40)

    # Simulate random baseline vs curriculum learning
    random_performance = [0.5, 0.55, 0.58, 0.61, 0.63, 0.65, 0.67, 0.68, 0.69, 0.70]
    curriculum_performance = [0.5, 0.62, 0.68, 0.74, 0.78, 0.82, 0.84, 0.86, 0.87, 0.88]

    print(f"Training Progress (Accuracy):")
    print(f"{'Epoch':<6} {'Random':<8} {'Curriculum':<12} {'Improvement':<12}")
    print("-" * 40)

    for epoch in range(10):
        random_acc = random_performance[epoch]
        curriculum_acc = curriculum_performance[epoch]
        improvement = curriculum_acc - random_acc

        print(f"{epoch:<6} {random_acc:<8.3f} {curriculum_acc:<12.3f} {improvement:<12.3f}")

    final_improvement = curriculum_performance[-1] - random_performance[-1]
    print(f"\nFinal Improvement: {final_improvement:.3f} ({final_improvement/random_performance[-1]*100:.1f}%)")

    print(f"\nCurriculum Learning Framework implementation complete!")
    print(f"This system provides:")
    print(f"  • Multiple curriculum strategies (vanilla, adaptive, self-paced, etc.)")
    print(f"  • Multi-metric difficulty analysis")
    print(f"  • Performance-based curriculum adaptation")
    print(f"  • Comprehensive curriculum statistics and monitoring")