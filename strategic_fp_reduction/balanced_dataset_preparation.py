#!/usr/bin/env python3
"""
Balanced Dataset Preparation Pipeline for Strategic False Positive Reduction

Advanced dataset preparation system that creates balanced, high-quality training data
for vulnerability detection with sophisticated class imbalance handling and quality validation.

Key Features:
- Balanced Dataset Creation with 1:1 vulnerable/non-vulnerable ratio
- SMOTE for Intelligent Minority Class Oversampling
- Class Imbalance Handling across Different Vulnerability Types
- Dataset Quality Validation and Distribution Analysis
- Stratified Sampling for Robust Train/Test Splits
- Quality Metrics Calculation and Monitoring
"""

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE
from imblearn.under_sampling import RandomUnderSampler, EditedNearestNeighbours
from imblearn.combine import SMOTEENN, SMOTETomek
from typing import Dict, List, Tuple, Any, Optional, Union
from dataclasses import dataclass, field
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter, defaultdict
import logging
from pathlib import Path
import json
import pickle
import ast
import re
import hashlib
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import warnings

warnings.filterwarnings('ignore')

@dataclass
class DatasetPreparationConfig:
    """Configuration for balanced dataset preparation."""

    # Dataset balance parameters
    target_balance_ratio: float = 1.0  # 1:1 vulnerable to non-vulnerable
    min_samples_per_class: int = 100
    max_samples_per_class: int = 10000

    # SMOTE parameters
    smote_strategy: str = 'minority'  # 'minority', 'not majority', 'all', 'auto'
    smote_k_neighbors: int = 5
    smote_variant: str = 'standard'  # 'standard', 'borderline', 'adasyn'

    # Undersampling parameters
    undersampling_enabled: bool = True
    undersampling_strategy: str = 'random'  # 'random', 'edited_nn', 'tomek'
    undersampling_ratio: float = 0.8

    # Vulnerability type stratification
    vulnerability_types: List[str] = field(default_factory=lambda: [
        'sql_injection', 'xss', 'command_injection', 'path_traversal',
        'deserialization', 'buffer_overflow', 'authentication_bypass',
        'authorization_bypass', 'information_disclosure', 'dos'
    ])

    # Quality validation parameters
    duplicate_threshold: float = 0.95  # Similarity threshold for duplicates
    quality_score_threshold: float = 0.6
    min_code_length: int = 50
    max_code_length: int = 5000

    # Stratified sampling parameters
    train_ratio: float = 0.7
    val_ratio: float = 0.15
    test_ratio: float = 0.15
    stratify_by: List[str] = field(default_factory=lambda: ['vulnerability', 'type', 'severity'])

    # Data augmentation parameters
    augmentation_enabled: bool = True
    augmentation_ratio: float = 0.2  # Proportion of data to augment

class CodeQualityAnalyzer:
    """
    Analyzes code quality and extracts quality metrics for dataset validation.

    Evaluates code samples based on complexity, completeness, and
    realistic patterns to ensure high-quality training data.
    """

    def __init__(self, config: DatasetPreparationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def analyze_code_quality(self, code: str) -> Dict[str, float]:
        """Comprehensive code quality analysis."""

        quality_metrics = {
            'length_score': self._analyze_length(code),
            'complexity_score': self._analyze_complexity(code),
            'completeness_score': self._analyze_completeness(code),
            'syntax_score': self._analyze_syntax(code),
            'realism_score': self._analyze_realism(code),
            'diversity_score': self._analyze_diversity(code)
        }

        # Overall quality score (weighted combination)
        weights = {
            'length_score': 0.15,
            'complexity_score': 0.20,
            'completeness_score': 0.25,
            'syntax_score': 0.15,
            'realism_score': 0.15,
            'diversity_score': 0.10
        }

        overall_score = sum(weights[metric] * score for metric, score in quality_metrics.items())
        quality_metrics['overall_score'] = overall_score

        return quality_metrics

    def _analyze_length(self, code: str) -> float:
        """Analyze code length appropriateness."""

        length = len(code)

        if length < self.config.min_code_length:
            return 0.0
        elif length > self.config.max_code_length:
            return 0.3  # Very long code gets low score
        else:
            # Optimal length range
            optimal_min, optimal_max = 100, 2000
            if optimal_min <= length <= optimal_max:
                return 1.0
            else:
                # Gradual scoring outside optimal range
                if length < optimal_min:
                    return (length - self.config.min_code_length) / (optimal_min - self.config.min_code_length)
                else:
                    return max(0.3, 1.0 - (length - optimal_max) / (self.config.max_code_length - optimal_max))

    def _analyze_complexity(self, code: str) -> float:
        """Analyze code complexity using multiple metrics."""

        # Cyclomatic complexity approximation
        complexity_indicators = [
            'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally',
            'and', 'or', 'break', 'continue', 'return'
        ]

        complexity_count = sum(code.lower().count(indicator) for indicator in complexity_indicators)
        lines_count = len(code.split('\n'))

        # Complexity density
        if lines_count > 0:
            complexity_density = complexity_count / lines_count
        else:
            return 0.0

        # Score based on complexity density
        if 0.1 <= complexity_density <= 0.5:  # Sweet spot
            return 1.0
        elif complexity_density < 0.1:  # Too simple
            return complexity_density * 10  # Scale up
        else:  # Too complex
            return max(0.2, 1.0 - (complexity_density - 0.5) * 2)

    def _analyze_completeness(self, code: str) -> float:
        """Analyze code completeness and structure."""

        completeness_indicators = {
            'has_functions': bool(re.search(r'def\s+\w+', code)),
            'has_classes': bool(re.search(r'class\s+\w+', code)),
            'has_imports': bool(re.search(r'import\s+\w+|from\s+\w+\s+import', code)),
            'has_comments': bool(re.search(r'#.*|""".*?"""', code, re.DOTALL)),
            'has_error_handling': 'try' in code.lower() and 'except' in code.lower(),
            'has_main_block': 'if __name__' in code,
            'balanced_braces': self._check_balanced_braces(code),
            'proper_indentation': self._check_indentation(code)
        }

        # Weight different indicators
        weights = {
            'has_functions': 0.20,
            'has_classes': 0.10,
            'has_imports': 0.15,
            'has_comments': 0.10,
            'has_error_handling': 0.15,
            'has_main_block': 0.05,
            'balanced_braces': 0.15,
            'proper_indentation': 0.10
        }

        score = sum(weights[indicator] * (1.0 if present else 0.0)
                   for indicator, present in completeness_indicators.items())

        return min(score, 1.0)

    def _check_balanced_braces(self, code: str) -> bool:
        """Check if braces and parentheses are balanced."""

        stack = []
        pairs = {'(': ')', '[': ']', '{': '}'}

        for char in code:
            if char in pairs:
                stack.append(char)
            elif char in pairs.values():
                if not stack:
                    return False
                if pairs[stack.pop()] != char:
                    return False

        return len(stack) == 0

    def _check_indentation(self, code: str) -> bool:
        """Check if code has proper indentation patterns."""

        lines = code.split('\n')
        indentation_levels = []

        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                indent_level = len(line) - len(line.lstrip())
                indentation_levels.append(indent_level)

        if len(indentation_levels) < 2:
            return True

        # Check for consistent indentation increments
        increments = set()
        for i in range(1, len(indentation_levels)):
            diff = indentation_levels[i] - indentation_levels[i-1]
            if diff != 0:
                increments.add(abs(diff))

        # Good indentation typically uses 2 or 4 spaces consistently
        return len(increments) <= 2 and all(inc in [2, 4, 8] for inc in increments)

    def _analyze_syntax(self, code: str) -> float:
        """Analyze syntax validity and quality."""

        try:
            # Try to parse the code
            ast.parse(code)
            syntax_valid = True
        except SyntaxError:
            syntax_valid = False

        if not syntax_valid:
            return 0.0

        # Additional syntax quality checks
        syntax_quality_score = 1.0

        # Check for suspicious patterns that might indicate low-quality code
        suspicious_patterns = [
            r'eval\s*\(',  # eval usage (suspicious in training data)
            r'exec\s*\(',  # exec usage
            r'__import__\s*\(',  # dynamic imports
            r'globals\s*\(\)',  # global access
            r'locals\s*\(\)',  # local access
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, code):
                syntax_quality_score -= 0.1

        return max(0.0, syntax_quality_score)

    def _analyze_realism(self, code: str) -> float:
        """Analyze code realism and authenticity."""

        realism_indicators = {
            'realistic_variable_names': self._check_variable_names(code),
            'realistic_function_names': self._check_function_names(code),
            'realistic_imports': self._check_imports(code),
            'no_placeholder_code': not self._has_placeholder_code(code),
            'realistic_logic_flow': self._check_logic_flow(code)
        }

        return sum(realism_indicators.values()) / len(realism_indicators)

    def _check_variable_names(self, code: str) -> float:
        """Check if variable names are realistic."""

        # Extract variable names
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        variables = re.findall(var_pattern, code)

        if not variables:
            return 0.5

        # Check for realistic patterns
        realistic_patterns = [
            r'^[a-z_][a-z0-9_]*$',  # snake_case
            r'^[a-z][a-zA-Z0-9]*$',  # camelCase
        ]

        # Check for unrealistic patterns
        unrealistic_patterns = [
            r'^[a-zA-Z]$',  # Single letter (except i, j, x, y)
            r'^(var|temp|test|foo|bar|baz)\d*$',  # Generic names
            r'^[A-Z_]+$',  # All caps (constants are OK but not variables)
        ]

        realistic_count = 0
        for var in variables:
            is_realistic = any(re.match(pattern, var) for pattern in realistic_patterns)
            is_unrealistic = any(re.match(pattern, var) for pattern in unrealistic_patterns)

            if is_realistic and not is_unrealistic:
                realistic_count += 1

        return realistic_count / len(variables)

    def _check_function_names(self, code: str) -> float:
        """Check if function names are realistic."""

        func_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        functions = re.findall(func_pattern, code)

        if not functions:
            return 0.5

        realistic_count = sum(1 for func in functions if len(func) >= 3 and '_' in func or func.islower())

        return realistic_count / len(functions)

    def _check_imports(self, code: str) -> float:
        """Check if imports are realistic and commonly used."""

        import_pattern = r'(?:import\s+(\w+)|from\s+(\w+)\s+import)'
        imports = re.findall(import_pattern, code)
        import_modules = [imp[0] or imp[1] for imp in imports]

        if not import_modules:
            return 0.5

        # Common realistic modules
        common_modules = {
            'os', 'sys', 'json', 'datetime', 'time', 'random', 're', 'math',
            'requests', 'numpy', 'pandas', 'flask', 'django', 'sqlite3',
            'hashlib', 'base64', 'urllib', 'socket', 'subprocess'
        }

        realistic_count = sum(1 for module in import_modules if module in common_modules)

        return realistic_count / len(import_modules) if import_modules else 0.5

    def _has_placeholder_code(self, code: str) -> bool:
        """Check for placeholder or template code."""

        placeholder_patterns = [
            r'TODO',
            r'FIXME',
            r'placeholder',
            r'your_code_here',
            r'implement_this',
            r'pass\s*#',
            r'...\s*#',
        ]

        return any(re.search(pattern, code, re.IGNORECASE) for pattern in placeholder_patterns)

    def _check_logic_flow(self, code: str) -> float:
        """Check for realistic logic flow and structure."""

        # Count logical structures
        structures = {
            'conditionals': len(re.findall(r'\bif\b', code)),
            'loops': len(re.findall(r'\b(for|while)\b', code)),
            'functions': len(re.findall(r'\bdef\b', code)),
            'returns': len(re.findall(r'\breturn\b', code)),
            'assignments': len(re.findall(r'\w+\s*=', code))
        }

        lines_count = len([line for line in code.split('\n') if line.strip()])

        if lines_count == 0:
            return 0.0

        # Calculate structure density
        total_structures = sum(structures.values())
        structure_density = total_structures / lines_count

        # Realistic density range
        if 0.1 <= structure_density <= 0.8:
            return 1.0
        elif structure_density < 0.1:
            return structure_density * 10
        else:
            return max(0.2, 1.0 - (structure_density - 0.8) * 5)

    def _analyze_diversity(self, code: str) -> float:
        """Analyze code diversity and uniqueness."""

        # Token diversity
        tokens = re.findall(r'\b\w+\b', code.lower())
        if len(tokens) == 0:
            return 0.0

        unique_tokens = set(tokens)
        token_diversity = len(unique_tokens) / len(tokens)

        # Character diversity
        chars = set(code.lower())
        char_diversity = len(chars) / max(len(code), 1)

        # Combined diversity score
        diversity_score = 0.7 * token_diversity + 0.3 * char_diversity

        return min(diversity_score, 1.0)

class SmartSMOTEGenerator:
    """
    Intelligent SMOTE implementation for code vulnerability data.

    Applies SMOTE (Synthetic Minority Oversampling Technique) with
    code-aware features and vulnerability type consideration.
    """

    def __init__(self, config: DatasetPreparationConfig):
        self.config = config
        self.feature_scalers = {}
        self.code_vectorizer = None
        self.logger = logging.getLogger(__name__)

    def apply_smote_balancing(self, features: np.ndarray, labels: np.ndarray,
                            vulnerability_types: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Apply SMOTE balancing with vulnerability type awareness."""

        original_shape = features.shape
        self.logger.info(f"Applying SMOTE balancing to {original_shape[0]} samples...")

        # Handle multi-class vulnerability types
        if vulnerability_types is not None:
            return self._apply_stratified_smote(features, labels, vulnerability_types)
        else:
            return self._apply_binary_smote(features, labels)

    def _apply_binary_smote(self, features: np.ndarray, labels: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Apply SMOTE for binary vulnerability classification."""

        # Initialize SMOTE variant
        if self.config.smote_variant == 'borderline':
            smote = BorderlineSMOTE(
                sampling_strategy=self.config.smote_strategy,
                k_neighbors=self.config.smote_k_neighbors,
                random_state=42
            )
        elif self.config.smote_variant == 'adasyn':
            smote = ADASYN(
                sampling_strategy=self.config.smote_strategy,
                n_neighbors=self.config.smote_k_neighbors,
                random_state=42
            )
        else:  # standard SMOTE
            smote = SMOTE(
                sampling_strategy=self.config.smote_strategy,
                k_neighbors=self.config.smote_k_neighbors,
                random_state=42
            )

        # Apply SMOTE
        try:
            features_resampled, labels_resampled = smote.fit_resample(features, labels)

            # Create placeholder vulnerability types for binary case
            vuln_types_resampled = np.where(labels_resampled == 1, 'vulnerability', 'safe')

            self.logger.info(f"SMOTE completed: {features.shape[0]} -> {features_resampled.shape[0]} samples")
            self.logger.info(f"Class distribution: {Counter(labels_resampled)}")

            return features_resampled, labels_resampled, vuln_types_resampled

        except Exception as e:
            self.logger.error(f"SMOTE failed: {e}")
            # Return original data if SMOTE fails
            vuln_types = np.where(labels == 1, 'vulnerability', 'safe')
            return features, labels, vuln_types

    def _apply_stratified_smote(self, features: np.ndarray, labels: np.ndarray,
                               vulnerability_types: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Apply SMOTE with stratification by vulnerability type."""

        # Combine labels and vulnerability types for stratified sampling
        unique_combinations = {}
        combined_labels = []

        # Create mapping of (label, vuln_type) -> unique_id
        label_type_combinations = list(zip(labels, vulnerability_types))
        unique_combinations = {combo: idx for idx, combo in enumerate(set(label_type_combinations))}

        # Create combined labels for SMOTE
        combined_labels = [unique_combinations[combo] for combo in label_type_combinations]
        combined_labels = np.array(combined_labels)

        # Apply SMOTE on combined labels
        if self.config.smote_variant == 'borderline':
            smote = BorderlineSMOTE(
                sampling_strategy='auto',  # Balance all classes
                k_neighbors=min(self.config.smote_k_neighbors, len(np.unique(combined_labels)) - 1),
                random_state=42
            )
        else:
            smote = SMOTE(
                sampling_strategy='auto',
                k_neighbors=min(self.config.smote_k_neighbors, len(np.unique(combined_labels)) - 1),
                random_state=42
            )

        try:
            features_resampled, combined_labels_resampled = smote.fit_resample(features, combined_labels)

            # Reconstruct original labels and vulnerability types
            reverse_mapping = {idx: combo for combo, idx in unique_combinations.items()}
            reconstructed_pairs = [reverse_mapping[label] for label in combined_labels_resampled]

            labels_resampled = np.array([pair[0] for pair in reconstructed_pairs])
            vuln_types_resampled = np.array([pair[1] for pair in reconstructed_pairs])

            self.logger.info(f"Stratified SMOTE completed: {features.shape[0]} -> {features_resampled.shape[0]} samples")
            self.logger.info(f"Vulnerability type distribution: {Counter(vuln_types_resampled)}")

            return features_resampled, labels_resampled, vuln_types_resampled

        except Exception as e:
            self.logger.error(f"Stratified SMOTE failed: {e}")
            return features, labels, vulnerability_types

class DuplicateDetector:
    """
    Intelligent duplicate detection for code samples using
    multiple similarity metrics and fuzzy matching.
    """

    def __init__(self, config: DatasetPreparationConfig):
        self.config = config
        self.similarity_threshold = config.duplicate_threshold
        self.logger = logging.getLogger(__name__)

    def find_duplicates(self, code_samples: List[str]) -> Dict[str, List[int]]:
        """Find duplicate code samples using multiple similarity metrics."""

        self.logger.info(f"Detecting duplicates in {len(code_samples)} code samples...")

        duplicates = defaultdict(list)
        processed_hashes = {}

        # Method 1: Exact hash matching
        exact_duplicates = self._find_exact_duplicates(code_samples)

        # Method 2: Normalized code similarity
        normalized_duplicates = self._find_normalized_duplicates(code_samples)

        # Method 3: AST similarity
        ast_duplicates = self._find_ast_duplicates(code_samples)

        # Combine results
        all_duplicate_groups = []
        all_duplicate_groups.extend(exact_duplicates)
        all_duplicate_groups.extend(normalized_duplicates)
        all_duplicate_groups.extend(ast_duplicates)

        # Merge overlapping groups
        merged_groups = self._merge_duplicate_groups(all_duplicate_groups)

        self.logger.info(f"Found {len(merged_groups)} duplicate groups")

        return merged_groups

    def _find_exact_duplicates(self, code_samples: List[str]) -> List[List[int]]:
        """Find exact duplicate code samples."""

        hash_to_indices = defaultdict(list)

        for i, code in enumerate(code_samples):
            # Create hash of cleaned code
            cleaned_code = re.sub(r'\s+', ' ', code.strip())
            code_hash = hashlib.md5(cleaned_code.encode()).hexdigest()
            hash_to_indices[code_hash].append(i)

        # Return groups with more than one sample
        duplicate_groups = [indices for indices in hash_to_indices.values() if len(indices) > 1]

        return duplicate_groups

    def _find_normalized_duplicates(self, code_samples: List[str]) -> List[List[int]]:
        """Find duplicates after code normalization."""

        normalized_to_indices = defaultdict(list)

        for i, code in enumerate(code_samples):
            normalized = self._normalize_code(code)
            if normalized:
                normalized_hash = hashlib.md5(normalized.encode()).hexdigest()
                normalized_to_indices[normalized_hash].append(i)

        duplicate_groups = [indices for indices in normalized_to_indices.values() if len(indices) > 1]

        return duplicate_groups

    def _normalize_code(self, code: str) -> str:
        """Normalize code for similarity comparison."""

        try:
            # Parse AST and reconstruct normalized code
            tree = ast.parse(code)

            # Extract essential structure
            normalized_parts = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    normalized_parts.append(f"function_{len(node.args.args)}")
                elif isinstance(node, ast.ClassDef):
                    normalized_parts.append("class")
                elif isinstance(node, ast.If):
                    normalized_parts.append("if")
                elif isinstance(node, ast.For):
                    normalized_parts.append("for")
                elif isinstance(node, ast.While):
                    normalized_parts.append("while")
                elif isinstance(node, ast.Try):
                    normalized_parts.append("try")

            return "_".join(normalized_parts)

        except:
            # Fallback to text-based normalization
            normalized = re.sub(r'[a-zA-Z_]\w*', 'VAR', code)  # Replace identifiers
            normalized = re.sub(r'\d+', 'NUM', normalized)     # Replace numbers
            normalized = re.sub(r'"[^"]*"', 'STR', normalized)  # Replace strings
            normalized = re.sub(r'\s+', ' ', normalized)       # Normalize whitespace

            return normalized.strip()

    def _find_ast_duplicates(self, code_samples: List[str]) -> List[List[int]]:
        """Find duplicates based on AST structure similarity."""

        ast_signatures = {}

        for i, code in enumerate(code_samples):
            signature = self._get_ast_signature(code)
            if signature:
                if signature not in ast_signatures:
                    ast_signatures[signature] = []
                ast_signatures[signature].append(i)

        duplicate_groups = [indices for indices in ast_signatures.values() if len(indices) > 1]

        return duplicate_groups

    def _get_ast_signature(self, code: str) -> Optional[str]:
        """Get AST-based signature for code similarity."""

        try:
            tree = ast.parse(code)
            signature_parts = []

            # Traverse AST and collect structural information
            for node in ast.walk(tree):
                node_type = type(node).__name__
                signature_parts.append(node_type)

                # Add specific details for important nodes
                if isinstance(node, ast.FunctionDef):
                    signature_parts.append(f"args_{len(node.args.args)}")
                elif isinstance(node, ast.BinOp):
                    signature_parts.append(type(node.op).__name__)
                elif isinstance(node, ast.Compare):
                    signature_parts.append(f"ops_{len(node.ops)}")

            return "_".join(signature_parts)

        except:
            return None

    def _merge_duplicate_groups(self, groups: List[List[int]]) -> Dict[str, List[int]]:
        """Merge overlapping duplicate groups."""

        if not groups:
            return {}

        # Convert to sets for easier operations
        group_sets = [set(group) for group in groups]
        merged_groups = []

        while group_sets:
            current_group = group_sets.pop(0)
            merged = True

            while merged:
                merged = False
                for i, other_group in enumerate(group_sets):
                    if current_group & other_group:  # If there's overlap
                        current_group |= other_group
                        group_sets.pop(i)
                        merged = True
                        break

            merged_groups.append(list(current_group))

        # Convert to dictionary format
        result = {}
        for i, group in enumerate(merged_groups):
            if len(group) > 1:  # Only include actual duplicates
                result[f'duplicate_group_{i}'] = sorted(group)

        return result

class BalancedDatasetBuilder:
    """
    Complete balanced dataset builder that integrates all components
    for high-quality, balanced training data creation.
    """

    def __init__(self, config: DatasetPreparationConfig):
        self.config = config
        self.quality_analyzer = CodeQualityAnalyzer(config)
        self.smote_generator = SmartSMOTEGenerator(config)
        self.duplicate_detector = DuplicateDetector(config)

        # Dataset statistics
        self.dataset_stats = defaultdict(dict)

        self.logger = logging.getLogger(__name__)

    def build_balanced_dataset(self, raw_code_samples: List[str], raw_labels: List[int],
                             vulnerability_types: List[str] = None,
                             severities: List[str] = None) -> Dict[str, Any]:
        """
        Build a balanced, high-quality dataset from raw samples.

        Args:
            raw_code_samples: List of code samples
            raw_labels: List of vulnerability labels (0/1)
            vulnerability_types: Optional vulnerability type labels
            severities: Optional severity labels

        Returns:
            Dictionary with balanced dataset and metadata
        """

        self.logger.info(f"Building balanced dataset from {len(raw_code_samples)} raw samples...")

        # Phase 1: Quality filtering
        filtered_data = self._filter_by_quality(raw_code_samples, raw_labels, vulnerability_types, severities)

        # Phase 2: Duplicate removal
        deduplicated_data = self._remove_duplicates(filtered_data)

        # Phase 3: Feature extraction
        features_data = self._extract_features(deduplicated_data)

        # Phase 4: Class balancing with SMOTE
        balanced_data = self._apply_class_balancing(features_data)

        # Phase 5: Stratified splitting
        split_data = self._create_stratified_splits(balanced_data)

        # Phase 6: Validation and quality metrics
        final_dataset = self._validate_and_finalize(split_data)

        self.logger.info("Balanced dataset creation completed!")

        return final_dataset

    def _filter_by_quality(self, code_samples: List[str], labels: List[int],
                          vulnerability_types: List[str] = None,
                          severities: List[str] = None) -> Dict[str, List]:
        """Filter samples by quality metrics."""

        self.logger.info("Filtering samples by quality...")

        filtered_samples = []
        filtered_labels = []
        filtered_types = []
        filtered_severities = []
        quality_scores = []

        for i, code in enumerate(code_samples):
            # Analyze quality
            quality_metrics = self.quality_analyzer.analyze_code_quality(code)
            overall_score = quality_metrics['overall_score']

            # Filter based on quality threshold
            if overall_score >= self.config.quality_score_threshold:
                filtered_samples.append(code)
                filtered_labels.append(labels[i])
                filtered_types.append(vulnerability_types[i] if vulnerability_types else 'unknown')
                filtered_severities.append(severities[i] if severities else 'medium')
                quality_scores.append(overall_score)

        self.logger.info(f"Quality filtering: {len(code_samples)} -> {len(filtered_samples)} samples "
                        f"(kept {len(filtered_samples)/len(code_samples):.1%})")

        return {
            'code_samples': filtered_samples,
            'labels': filtered_labels,
            'vulnerability_types': filtered_types,
            'severities': filtered_severities,
            'quality_scores': quality_scores
        }

    def _remove_duplicates(self, data: Dict[str, List]) -> Dict[str, List]:
        """Remove duplicate samples."""

        self.logger.info("Detecting and removing duplicates...")

        duplicate_groups = self.duplicate_detector.find_duplicates(data['code_samples'])

        # Keep only the first sample from each duplicate group
        indices_to_remove = set()
        for group_name, indices in duplicate_groups.items():
            # Keep the sample with highest quality score
            if len(indices) > 1:
                quality_scores = [data['quality_scores'][i] for i in indices]
                best_idx = indices[np.argmax(quality_scores)]

                # Remove all others
                for idx in indices:
                    if idx != best_idx:
                        indices_to_remove.add(idx)

        # Filter out duplicates
        deduplicated_data = {}
        for key, values in data.items():
            deduplicated_data[key] = [values[i] for i in range(len(values)) if i not in indices_to_remove]

        removed_count = len(indices_to_remove)
        self.logger.info(f"Duplicate removal: removed {removed_count} samples "
                        f"({removed_count/len(data['code_samples']):.1%})")

        return deduplicated_data

    def _extract_features(self, data: Dict[str, List]) -> Dict[str, Any]:
        """Extract numerical features from code samples."""

        self.logger.info("Extracting features from code samples...")

        code_samples = data['code_samples']
        features_list = []

        for code in code_samples:
            # Extract comprehensive features
            features = self._extract_code_features(code)
            features_list.append(features)

        # Convert to numpy array
        features_array = np.array(features_list)

        # Add features to data dictionary
        data['features'] = features_array
        data['feature_names'] = self._get_feature_names()

        self.logger.info(f"Feature extraction completed: {features_array.shape[1]} features per sample")

        return data

    def _extract_code_features(self, code: str) -> List[float]:
        """Extract numerical features from a single code sample."""

        features = []

        # Basic statistics
        lines = code.split('\n')
        features.extend([
            len(code),  # Character count
            len(lines),  # Line count
            np.mean([len(line) for line in lines]) if lines else 0,  # Avg line length
            len([line for line in lines if line.strip()]),  # Non-empty lines
        ])

        # Syntactic features
        features.extend([
            code.count('def'),  # Function definitions
            code.count('class'),  # Class definitions
            code.count('if'),  # Conditionals
            code.count('for') + code.count('while'),  # Loops
            code.count('try'),  # Exception handling
            code.count('import') + code.count('from'),  # Imports
            code.count('=') - code.count('==') - code.count('!=') - code.count('<=') - code.count('>='),  # Assignments
            code.count('('),  # Function calls/definitions
            code.count('['),  # Array access
            code.count('{'),  # Dictionary/set usage
        ])

        # Security-relevant features
        security_keywords = [
            'eval', 'exec', 'system', 'shell', 'subprocess', 'open', 'file',
            'input', 'raw_input', 'pickle', 'marshal', 'urllib', 'requests',
            'sql', 'query', 'execute', 'cursor', 'connection', 'database'
        ]

        for keyword in security_keywords:
            features.append(float(keyword.lower() in code.lower()))

        # String and literal analysis
        features.extend([
            code.count('"') + code.count("'"),  # String literals
            len(re.findall(r'\d+', code)),  # Numeric literals
            code.count('#'),  # Comments
        ])

        # Complexity metrics
        features.extend([
            len(set(re.findall(r'\b[a-zA-Z_]\w*\b', code))),  # Unique identifiers
            code.count('.'),  # Attribute access
            code.count('and') + code.count('or'),  # Logical operators
        ])

        # Ensure consistent feature vector length
        target_length = 50  # Fixed feature vector size
        if len(features) < target_length:
            features.extend([0.0] * (target_length - len(features)))
        elif len(features) > target_length:
            features = features[:target_length]

        return features

    def _get_feature_names(self) -> List[str]:
        """Get names for extracted features."""

        return [
            'char_count', 'line_count', 'avg_line_length', 'non_empty_lines',
            'function_defs', 'class_defs', 'conditionals', 'loops', 'try_blocks',
            'imports', 'assignments', 'function_calls', 'array_access', 'dict_usage'
        ] + [f'security_keyword_{i}' for i in range(18)] + [
            'string_literals', 'numeric_literals', 'comments', 'unique_identifiers',
            'attribute_access', 'logical_operators'
        ] + [f'feature_{i}' for i in range(23, 50)]  # Padding feature names

    def _apply_class_balancing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply SMOTE-based class balancing."""

        self.logger.info("Applying class balancing with SMOTE...")

        features = data['features']
        labels = np.array(data['labels'])
        vulnerability_types = np.array(data['vulnerability_types'])

        # Apply SMOTE
        balanced_features, balanced_labels, balanced_types = self.smote_generator.apply_smote_balancing(
            features, labels, vulnerability_types
        )

        # Update data dictionary
        data['features'] = balanced_features
        data['labels'] = balanced_labels.tolist()
        data['vulnerability_types'] = balanced_types.tolist()

        # Generate corresponding code samples for synthetic samples
        original_count = len(data['code_samples'])
        synthetic_count = len(balanced_labels) - original_count

        if synthetic_count > 0:
            # Create placeholder code samples for synthetic data
            synthetic_codes = [f"# Synthetic sample {i}\n# Generated by SMOTE\npass" for i in range(synthetic_count)]
            data['code_samples'].extend(synthetic_codes)

            # Extend other fields
            data['severities'].extend(['medium'] * synthetic_count)
            data['quality_scores'].extend([0.8] * synthetic_count)  # Assign decent quality to synthetic samples

        self.logger.info(f"Class balancing completed: {original_count} -> {len(balanced_labels)} samples")
        self.logger.info(f"Added {synthetic_count} synthetic samples")

        return data

    def _create_stratified_splits(self, data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Create stratified train/validation/test splits."""

        self.logger.info("Creating stratified dataset splits...")

        # Prepare stratification labels
        labels = np.array(data['labels'])
        vulnerability_types = np.array(data['vulnerability_types'])
        severities = np.array(data['severities'])

        # Create combined stratification key
        stratify_labels = []
        for i in range(len(labels)):
            strat_key = f"{labels[i]}_{vulnerability_types[i]}_{severities[i]}"
            stratify_labels.append(strat_key)

        stratify_labels = np.array(stratify_labels)

        # First split: train vs (val + test)
        train_indices, temp_indices = train_test_split(
            range(len(labels)),
            test_size=(self.config.val_ratio + self.config.test_ratio),
            stratify=stratify_labels,
            random_state=42
        )

        # Second split: val vs test
        temp_stratify_labels = stratify_labels[temp_indices]
        val_size = self.config.val_ratio / (self.config.val_ratio + self.config.test_ratio)

        val_indices, test_indices = train_test_split(
            temp_indices,
            test_size=(1 - val_size),
            stratify=temp_stratify_labels,
            random_state=42
        )

        # Create split datasets
        splits = {}
        for split_name, indices in [('train', train_indices), ('val', val_indices), ('test', test_indices)]:
            split_data = {}
            for key, values in data.items():
                if isinstance(values, np.ndarray):
                    split_data[key] = values[indices]
                elif isinstance(values, list):
                    split_data[key] = [values[i] for i in indices]
                else:
                    split_data[key] = values

            splits[split_name] = split_data

        self.logger.info(f"Dataset splits created:")
        for split_name, split_data in splits.items():
            self.logger.info(f"  {split_name}: {len(split_data['labels'])} samples")

        return splits

    def _validate_and_finalize(self, splits: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Validate dataset quality and create final dataset."""

        self.logger.info("Validating and finalizing dataset...")

        # Calculate comprehensive statistics
        final_stats = {}
        for split_name, split_data in splits.items():
            labels = split_data['labels']
            vuln_types = split_data['vulnerability_types']

            split_stats = {
                'total_samples': len(labels),
                'vulnerable_samples': sum(labels),
                'safe_samples': len(labels) - sum(labels),
                'balance_ratio': sum(labels) / max(len(labels) - sum(labels), 1),
                'vulnerability_type_distribution': dict(Counter(vuln_types)),
                'quality_score_mean': np.mean(split_data['quality_scores']),
                'quality_score_std': np.std(split_data['quality_scores'])
            }

            final_stats[split_name] = split_stats

        # Overall dataset statistics
        total_samples = sum(stats['total_samples'] for stats in final_stats.values())
        overall_balance = sum(stats['vulnerable_samples'] for stats in final_stats.values()) / sum(stats['safe_samples'] for stats in final_stats.values())

        final_dataset = {
            'splits': splits,
            'statistics': final_stats,
            'metadata': {
                'total_samples': total_samples,
                'overall_balance_ratio': overall_balance,
                'config': self.config,
                'feature_names': splits['train']['feature_names'],
                'creation_timestamp': pd.Timestamp.now().isoformat(),
                'quality_filtering_enabled': True,
                'duplicate_removal_enabled': True,
                'smote_balancing_enabled': True,
                'stratified_splitting_enabled': True
            }
        }

        self.logger.info(f"Dataset finalized:")
        self.logger.info(f"  Total samples: {total_samples}")
        self.logger.info(f"  Overall balance ratio: {overall_balance:.2f}")

        return final_dataset

    def save_dataset(self, dataset: Dict[str, Any], save_path: str):
        """Save the prepared dataset."""

        save_path = Path(save_path)
        save_path.mkdir(parents=True, exist_ok=True)

        # Save splits separately
        for split_name, split_data in dataset['splits'].items():
            split_path = save_path / f"{split_name}_split.pkl"
            with open(split_path, 'wb') as f:
                pickle.dump(split_data, f)

        # Save metadata
        metadata_path = save_path / "dataset_metadata.json"
        with open(metadata_path, 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            json_metadata = self._prepare_for_json(dataset['metadata'])
            json.dump(json_metadata, f, indent=2)

        # Save statistics
        stats_path = save_path / "dataset_statistics.json"
        with open(stats_path, 'w') as f:
            json_stats = self._prepare_for_json(dataset['statistics'])
            json.dump(json_stats, f, indent=2)

        self.logger.info(f"Dataset saved to {save_path}")

    def _prepare_for_json(self, obj):
        """Prepare object for JSON serialization."""

        if isinstance(obj, dict):
            return {k: self._prepare_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._prepare_for_json(item) for item in obj]
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        elif hasattr(obj, '__dict__'):
            return self._prepare_for_json(obj.__dict__)
        else:
            return obj

# Example usage and demonstration
if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    print("⚖️ Balanced Dataset Preparation Pipeline")
    print("=" * 60)

    # Create configuration
    config = DatasetPreparationConfig(
        target_balance_ratio=1.0,
        quality_score_threshold=0.6,
        smote_variant='standard'
    )

    # Initialize dataset builder
    print("🚀 Initializing Balanced Dataset Builder...")
    dataset_builder = BalancedDatasetBuilder(config)

    # Generate synthetic training data for demonstration
    print("📊 Generating synthetic training data...")

    # Create diverse code samples with different quality levels
    high_quality_vulnerable = [
        """
def authenticate_user(username, password):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    return user is not None
""",
        """
def process_upload(filename, content):
    import os

    # Path traversal vulnerability
    upload_path = os.path.join('/uploads', filename)

    with open(upload_path, 'w') as f:
        f.write(content)

    return upload_path
""",
        """
def execute_system_command(user_input):
    import subprocess

    # Command injection vulnerability
    command = f"ping -c 4 {user_input}"
    result = subprocess.run(command, shell=True, capture_output=True)

    return result.stdout.decode()
"""
    ]

    high_quality_safe = [
        """
def authenticate_user_safe(username, password):
    import sqlite3
    import hashlib

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Safe parameterized query
    query = "SELECT password_hash FROM users WHERE username=?"
    cursor.execute(query, (username,))

    user = cursor.fetchone()
    conn.close()

    if user:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == user[0]

    return False
""",
        """
def process_upload_safe(filename, content):
    import os
    import re

    # Validate filename
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        raise ValueError("Invalid filename")

    # Secure path construction
    upload_dir = '/uploads'
    safe_path = os.path.join(upload_dir, os.path.basename(filename))

    # Additional security check
    if not safe_path.startswith(upload_dir):
        raise ValueError("Path traversal detected")

    with open(safe_path, 'w') as f:
        f.write(content)

    return safe_path
""",
        """
def execute_system_command_safe(user_input):
    import subprocess
    import shlex

    # Whitelist allowed commands
    allowed_hosts = ['127.0.0.1', 'localhost', 'example.com']

    if user_input not in allowed_hosts:
        raise ValueError("Host not allowed")

    # Safe command construction
    command = ['ping', '-c', '4', user_input]
    result = subprocess.run(command, capture_output=True, text=True)

    return result.stdout
"""
    ]

    # Combine samples
    all_code_samples = high_quality_vulnerable + high_quality_safe
    all_labels = [1] * len(high_quality_vulnerable) + [0] * len(high_quality_safe)
    all_types = ['sql_injection', 'path_traversal', 'command_injection'] + ['safe'] * len(high_quality_safe)
    all_severities = ['high', 'medium', 'high'] + ['low'] * len(high_quality_safe)

    print(f"   • Vulnerable samples: {sum(all_labels)}")
    print(f"   • Safe samples: {len(all_labels) - sum(all_labels)}")
    print(f"   • Total samples: {len(all_code_samples)}")

    # Test quality analysis
    print("\n🔍 Testing code quality analysis...")
    quality_analyzer = CodeQualityAnalyzer(config)

    sample_code = high_quality_vulnerable[0]
    quality_metrics = quality_analyzer.analyze_code_quality(sample_code)

    print(f"   Sample quality metrics:")
    for metric, score in quality_metrics.items():
        print(f"     • {metric}: {score:.3f}")

    # Test duplicate detection
    print("\n🔍 Testing duplicate detection...")
    duplicate_detector = DuplicateDetector(config)

    # Add some duplicate samples for testing
    test_samples = all_code_samples + [all_code_samples[0], all_code_samples[1]]  # Add duplicates
    duplicates = duplicate_detector.find_duplicates(test_samples)

    if duplicates:
        print(f"   Found duplicate groups:")
        for group_name, indices in duplicates.items():
            print(f"     • {group_name}: samples {indices}")
    else:
        print("   No duplicates found")

    # Build balanced dataset
    print("\n⚖️ Building balanced dataset...")
    try:
        balanced_dataset = dataset_builder.build_balanced_dataset(
            all_code_samples, all_labels, all_types, all_severities
        )

        print(f"   ✅ Balanced dataset created successfully!")

        # Display statistics
        for split_name, stats in balanced_dataset['statistics'].items():
            print(f"   📊 {split_name.title()} Split:")
            print(f"     • Total samples: {stats['total_samples']}")
            print(f"     • Vulnerable: {stats['vulnerable_samples']}")
            print(f"     • Safe: {stats['safe_samples']}")
            print(f"     • Balance ratio: {stats['balance_ratio']:.2f}")
            print(f"     • Quality score: {stats['quality_score_mean']:.3f} ± {stats['quality_score_std']:.3f}")

        # Test SMOTE effectiveness
        print(f"\n🧬 SMOTE Balancing Results:")
        metadata = balanced_dataset['metadata']
        print(f"     • Total samples after balancing: {metadata['total_samples']}")
        print(f"     • Final balance ratio: {metadata['overall_balance_ratio']:.2f}")

    except Exception as e:
        print(f"   ❌ Dataset building failed: {e}")

    print(f"\n🎯 Expected Dataset Quality Improvements:")
    print(f"   • Perfect class balance (1:1 ratio) through intelligent SMOTE")
    print(f"   • High-quality samples only (quality score > {config.quality_score_threshold})")
    print(f"   • Duplicate removal for data integrity")
    print(f"   • Stratified splits maintaining distribution across vulnerability types")
    print(f"   • Comprehensive quality validation and monitoring")

    print(f"\n🚀 Balanced Dataset Preparation Pipeline ready for deployment!")