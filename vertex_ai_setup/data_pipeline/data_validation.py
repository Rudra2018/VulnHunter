#!/usr/bin/env python3
"""
Comprehensive Data Validation and Quality Checks for VulnHunter
Implements advanced data validation, drift detection, and quality monitoring.
"""

import json
import logging
import os
import ast
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import warnings

import pandas as pd
import numpy as np
from scipy import stats
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

from google.cloud import aiplatform
from google.cloud import storage
from google.cloud import monitoring_v3
from google.api_core import exceptions

warnings.filterwarnings('ignore')

@dataclass
class ValidationRule:
    """Data validation rule definition"""
    name: str
    description: str
    check_function: str
    parameters: Dict[str, Any]
    severity: str  # 'critical', 'warning', 'info'
    enabled: bool = True

@dataclass
class ValidationResult:
    """Result of a validation check"""
    rule_name: str
    passed: bool
    score: float
    message: str
    details: Dict[str, Any]
    severity: str
    timestamp: datetime

class VulnerabilityDataValidator:
    """
    Advanced data validation for vulnerability detection datasets
    with quality scoring, drift detection, and anomaly identification.
    """

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        self.storage_client = storage.Client(project=project_id)

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        # Validation configuration
        self.validation_bucket = f"{project_id}-vulnhunter-validation"
        self.baseline_bucket = f"{project_id}-vulnhunter-baselines"

        # Define validation rules
        self.validation_rules = self._define_validation_rules()

        # Quality thresholds
        self.quality_thresholds = {
            'min_samples': 100,
            'min_vulnerable_ratio': 0.05,
            'max_vulnerable_ratio': 0.95,
            'min_code_length': 10,
            'max_code_length': 10000,
            'max_duplicate_ratio': 0.1,
            'min_feature_completeness': 0.9,
            'max_outlier_ratio': 0.05,
            'min_language_diversity': 2,
            'max_missing_ratio': 0.1
        }

        # Drift detection thresholds
        self.drift_thresholds = {
            'psi_threshold': 0.2,  # Population Stability Index
            'ks_threshold': 0.1,   # Kolmogorov-Smirnov test
            'chi2_threshold': 0.05, # Chi-square test p-value
            'jsd_threshold': 0.1   # Jensen-Shannon Divergence
        }

        self.logger = self._setup_logging()
        self._initialize_infrastructure()

    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('VulnerabilityDataValidator')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _initialize_infrastructure(self):
        """Initialize GCS buckets for validation artifacts"""
        buckets = [self.validation_bucket, self.baseline_bucket]

        for bucket_name in buckets:
            try:
                bucket = self.storage_client.bucket(bucket_name)
                if not bucket.exists():
                    bucket = self.storage_client.create_bucket(bucket_name, location=self.location)
                    self.logger.info(f"Created bucket: {bucket_name}")
            except Exception as e:
                self.logger.error(f"Error with bucket {bucket_name}: {e}")

    def _define_validation_rules(self) -> Dict[str, ValidationRule]:
        """Define comprehensive validation rules"""
        return {
            'sample_count': ValidationRule(
                name='sample_count',
                description='Validate minimum number of samples',
                check_function='check_sample_count',
                parameters={'min_samples': 100},
                severity='critical'
            ),
            'vulnerability_ratio': ValidationRule(
                name='vulnerability_ratio',
                description='Validate vulnerability label distribution',
                check_function='check_vulnerability_ratio',
                parameters={'min_ratio': 0.05, 'max_ratio': 0.95},
                severity='critical'
            ),
            'code_quality': ValidationRule(
                name='code_quality',
                description='Validate code content quality',
                check_function='check_code_quality',
                parameters={'min_length': 10, 'max_length': 10000},
                severity='warning'
            ),
            'duplicate_content': ValidationRule(
                name='duplicate_content',
                description='Check for duplicate code samples',
                check_function='check_duplicate_content',
                parameters={'max_duplicate_ratio': 0.1},
                severity='warning'
            ),
            'feature_completeness': ValidationRule(
                name='feature_completeness',
                description='Validate feature completeness',
                check_function='check_feature_completeness',
                parameters={'min_completeness': 0.9},
                severity='critical'
            ),
            'outlier_detection': ValidationRule(
                name='outlier_detection',
                description='Detect statistical outliers',
                check_function='check_outliers',
                parameters={'max_outlier_ratio': 0.05},
                severity='warning'
            ),
            'language_diversity': ValidationRule(
                name='language_diversity',
                description='Check programming language diversity',
                check_function='check_language_diversity',
                parameters={'min_languages': 2},
                severity='info'
            ),
            'temporal_consistency': ValidationRule(
                name='temporal_consistency',
                description='Validate temporal data consistency',
                check_function='check_temporal_consistency',
                parameters={},
                severity='warning'
            ),
            'label_consistency': ValidationRule(
                name='label_consistency',
                description='Check label consistency with patterns',
                check_function='check_label_consistency',
                parameters={},
                severity='critical'
            )
        }

    def validate_dataset(self, data: pd.DataFrame, baseline_data: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """
        Run comprehensive validation on vulnerability dataset

        Args:
            data: DataFrame to validate
            baseline_data: Optional baseline data for drift detection

        Returns:
            Comprehensive validation report
        """
        try:
            self.logger.info(f"Starting comprehensive validation for {len(data)} samples")

            validation_report = {
                'validation_timestamp': datetime.now().isoformat(),
                'dataset_info': {
                    'sample_count': len(data),
                    'feature_count': len(data.columns),
                    'memory_usage_mb': data.memory_usage(deep=True).sum() / 1024 / 1024
                },
                'validation_results': {},
                'quality_score': 0.0,
                'passed_validation': False,
                'critical_issues': [],
                'warnings': [],
                'recommendations': []
            }

            # Run all validation rules
            validation_results = []

            for rule_name, rule in self.validation_rules.items():
                if not rule.enabled:
                    continue

                try:
                    result = self._execute_validation_rule(data, rule)
                    validation_results.append(result)
                    validation_report['validation_results'][rule_name] = asdict(result)

                    # Collect issues by severity
                    if not result.passed:
                        if result.severity == 'critical':
                            validation_report['critical_issues'].append(result.message)
                        elif result.severity == 'warning':
                            validation_report['warnings'].append(result.message)

                except Exception as e:
                    self.logger.error(f"Error executing rule {rule_name}: {e}")
                    validation_report['validation_results'][rule_name] = {
                        'error': str(e),
                        'passed': False,
                        'severity': rule.severity
                    }

            # Calculate overall quality score
            total_weight = 0
            weighted_score = 0

            for result in validation_results:
                weight = 3 if result.severity == 'critical' else 2 if result.severity == 'warning' else 1
                total_weight += weight
                weighted_score += result.score * weight

            validation_report['quality_score'] = weighted_score / total_weight if total_weight > 0 else 0.0

            # Determine if validation passed
            critical_passed = all(r.passed for r in validation_results if r.severity == 'critical')
            validation_report['passed_validation'] = critical_passed and validation_report['quality_score'] >= 0.7

            # Drift detection if baseline provided
            if baseline_data is not None:
                drift_report = self._detect_data_drift(data, baseline_data)
                validation_report['drift_analysis'] = drift_report

            # Generate recommendations
            validation_report['recommendations'] = self._generate_recommendations(validation_report)

            # Advanced analytics
            if 'vulnerable' in data.columns and 'code' in data.columns:
                analytics_report = self._perform_advanced_analytics(data)
                validation_report['advanced_analytics'] = analytics_report

            self.logger.info(f"Validation completed - Quality Score: {validation_report['quality_score']:.2f}")
            self.logger.info(f"Validation Passed: {validation_report['passed_validation']}")

            return validation_report

        except Exception as e:
            self.logger.error(f"Error in dataset validation: {e}")
            return {'error': str(e), 'passed_validation': False}

    def _execute_validation_rule(self, data: pd.DataFrame, rule: ValidationRule) -> ValidationResult:
        """Execute a single validation rule"""
        try:
            # Get the check function
            check_func = getattr(self, rule.check_function)

            # Execute the check
            result = check_func(data, **rule.parameters)

            return ValidationResult(
                rule_name=rule.name,
                passed=result['passed'],
                score=result.get('score', 1.0 if result['passed'] else 0.0),
                message=result.get('message', ''),
                details=result.get('details', {}),
                severity=rule.severity,
                timestamp=datetime.now()
            )

        except Exception as e:
            return ValidationResult(
                rule_name=rule.name,
                passed=False,
                score=0.0,
                message=f"Rule execution failed: {str(e)}",
                details={'error': str(e)},
                severity=rule.severity,
                timestamp=datetime.now()
            )

    def check_sample_count(self, data: pd.DataFrame, min_samples: int) -> Dict[str, Any]:
        """Check minimum sample count"""
        sample_count = len(data)
        passed = sample_count >= min_samples

        return {
            'passed': passed,
            'score': min(1.0, sample_count / min_samples),
            'message': f"Sample count: {sample_count} (minimum: {min_samples})",
            'details': {
                'actual_samples': sample_count,
                'required_samples': min_samples,
                'ratio': sample_count / min_samples
            }
        }

    def check_vulnerability_ratio(self, data: pd.DataFrame, min_ratio: float, max_ratio: float) -> Dict[str, Any]:
        """Check vulnerability label distribution"""
        if 'vulnerable' not in data.columns:
            return {
                'passed': False,
                'score': 0.0,
                'message': "No 'vulnerable' column found",
                'details': {}
            }

        vuln_ratio = data['vulnerable'].mean()
        passed = min_ratio <= vuln_ratio <= max_ratio

        # Calculate score based on how close to ideal ratio (0.2-0.8 range)
        ideal_min, ideal_max = 0.2, 0.8
        if ideal_min <= vuln_ratio <= ideal_max:
            score = 1.0
        elif vuln_ratio < ideal_min:
            score = max(0.0, vuln_ratio / ideal_min)
        else:
            score = max(0.0, (1.0 - vuln_ratio) / (1.0 - ideal_max))

        return {
            'passed': passed,
            'score': score,
            'message': f"Vulnerability ratio: {vuln_ratio:.1%} (range: {min_ratio:.1%}-{max_ratio:.1%})",
            'details': {
                'vulnerability_ratio': vuln_ratio,
                'vulnerable_samples': int(data['vulnerable'].sum()),
                'safe_samples': int(len(data) - data['vulnerable'].sum()),
                'min_threshold': min_ratio,
                'max_threshold': max_ratio
            }
        }

    def check_code_quality(self, data: pd.DataFrame, min_length: int, max_length: int) -> Dict[str, Any]:
        """Check code content quality"""
        if 'code' not in data.columns:
            return {
                'passed': False,
                'score': 0.0,
                'message': "No 'code' column found",
                'details': {}
            }

        code_lengths = data['code'].str.len()
        valid_length = (code_lengths >= min_length) & (code_lengths <= max_length)
        valid_ratio = valid_length.mean()

        # Check for empty or whitespace-only code
        non_empty = data['code'].str.strip().str.len() > 0
        non_empty_ratio = non_empty.mean()

        # Check for reasonable character diversity
        avg_unique_chars = data['code'].apply(lambda x: len(set(x)) if isinstance(x, str) else 0).mean()

        passed = valid_ratio >= 0.9 and non_empty_ratio >= 0.95
        score = (valid_ratio + non_empty_ratio) / 2

        return {
            'passed': passed,
            'score': score,
            'message': f"Code quality: {valid_ratio:.1%} valid length, {non_empty_ratio:.1%} non-empty",
            'details': {
                'valid_length_ratio': valid_ratio,
                'non_empty_ratio': non_empty_ratio,
                'avg_length': float(code_lengths.mean()),
                'median_length': float(code_lengths.median()),
                'min_length_threshold': min_length,
                'max_length_threshold': max_length,
                'avg_unique_chars': avg_unique_chars
            }
        }

    def check_duplicate_content(self, data: pd.DataFrame, max_duplicate_ratio: float) -> Dict[str, Any]:
        """Check for duplicate code samples"""
        if 'code' not in data.columns:
            return {
                'passed': False,
                'score': 0.0,
                'message': "No 'code' column found",
                'details': {}
            }

        # Check exact duplicates
        duplicate_mask = data['code'].duplicated()
        duplicate_ratio = duplicate_mask.mean()

        # Check near-duplicates (by hash of normalized code)
        normalized_hashes = data['code'].apply(
            lambda x: hashlib.md5(re.sub(r'\s+', ' ', x.lower().strip()).encode()).hexdigest()
            if isinstance(x, str) else ''
        )
        near_duplicate_mask = normalized_hashes.duplicated()
        near_duplicate_ratio = near_duplicate_mask.mean()

        passed = duplicate_ratio <= max_duplicate_ratio
        score = max(0.0, 1.0 - duplicate_ratio / max_duplicate_ratio)

        return {
            'passed': passed,
            'score': score,
            'message': f"Duplicates: {duplicate_ratio:.1%} exact, {near_duplicate_ratio:.1%} near",
            'details': {
                'exact_duplicate_ratio': duplicate_ratio,
                'near_duplicate_ratio': near_duplicate_ratio,
                'exact_duplicates': int(duplicate_mask.sum()),
                'near_duplicates': int(near_duplicate_mask.sum()),
                'threshold': max_duplicate_ratio
            }
        }

    def check_feature_completeness(self, data: pd.DataFrame, min_completeness: float) -> Dict[str, Any]:
        """Check feature completeness (non-null ratios)"""
        completeness_per_column = data.notna().mean()
        overall_completeness = completeness_per_column.mean()
        passed = overall_completeness >= min_completeness

        # Identify columns with high missing rates
        low_completeness_cols = completeness_per_column[completeness_per_column < min_completeness].to_dict()

        score = min(1.0, overall_completeness / min_completeness)

        return {
            'passed': passed,
            'score': score,
            'message': f"Feature completeness: {overall_completeness:.1%} (minimum: {min_completeness:.1%})",
            'details': {
                'overall_completeness': overall_completeness,
                'completeness_per_column': completeness_per_column.to_dict(),
                'low_completeness_columns': low_completeness_cols,
                'threshold': min_completeness
            }
        }

    def check_outliers(self, data: pd.DataFrame, max_outlier_ratio: float) -> Dict[str, Any]:
        """Detect statistical outliers in numeric features"""
        numeric_columns = data.select_dtypes(include=[np.number]).columns
        if len(numeric_columns) == 0:
            return {
                'passed': True,
                'score': 1.0,
                'message': "No numeric columns to check for outliers",
                'details': {}
            }

        outlier_info = {}
        total_outliers = 0

        for col in numeric_columns:
            if data[col].notna().sum() == 0:
                continue

            # Use IQR method for outlier detection
            Q1 = data[col].quantile(0.25)
            Q3 = data[col].quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR

            outlier_mask = (data[col] < lower_bound) | (data[col] > upper_bound)
            outlier_count = outlier_mask.sum()
            outlier_ratio = outlier_count / len(data)

            outlier_info[col] = {
                'outlier_count': int(outlier_count),
                'outlier_ratio': float(outlier_ratio),
                'lower_bound': float(lower_bound),
                'upper_bound': float(upper_bound)
            }

            total_outliers += outlier_count

        overall_outlier_ratio = total_outliers / (len(data) * len(numeric_columns))
        passed = overall_outlier_ratio <= max_outlier_ratio
        score = max(0.0, 1.0 - overall_outlier_ratio / max_outlier_ratio)

        return {
            'passed': passed,
            'score': score,
            'message': f"Outlier ratio: {overall_outlier_ratio:.1%} (maximum: {max_outlier_ratio:.1%})",
            'details': {
                'overall_outlier_ratio': overall_outlier_ratio,
                'total_outliers': int(total_outliers),
                'outlier_info_per_column': outlier_info,
                'threshold': max_outlier_ratio
            }
        }

    def check_language_diversity(self, data: pd.DataFrame, min_languages: int) -> Dict[str, Any]:
        """Check programming language diversity"""
        if 'language' in data.columns:
            languages = data['language'].value_counts()
        elif 'code' in data.columns:
            # Infer languages from code patterns
            languages = self._infer_languages_from_code(data['code'])
        else:
            return {
                'passed': False,
                'score': 0.0,
                'message': "No language information or code column found",
                'details': {}
            }

        language_count = len(languages)
        passed = language_count >= min_languages
        score = min(1.0, language_count / min_languages)

        return {
            'passed': passed,
            'score': score,
            'message': f"Language diversity: {language_count} languages (minimum: {min_languages})",
            'details': {
                'language_count': language_count,
                'language_distribution': languages.to_dict() if hasattr(languages, 'to_dict') else languages,
                'threshold': min_languages
            }
        }

    def _infer_languages_from_code(self, code_series: pd.Series) -> Dict[str, int]:
        """Infer programming languages from code patterns"""
        language_patterns = {
            'python': [r'def\s+\w+\s*\(', r'import\s+\w+', r'from\s+\w+\s+import', r':\s*$'],
            'java': [r'public\s+class\s+\w+', r'public\s+static\s+void\s+main', r'System\.out\.print'],
            'c': [r'#include\s*<\w+\.h>', r'int\s+main\s*\(', r'printf\s*\('],
            'cpp': [r'#include\s*<iostream>', r'std::', r'cout\s*<<'],
            'javascript': [r'function\s+\w+\s*\(', r'var\s+\w+\s*=', r'console\.log'],
            'php': [r'<\?php', r'\$\w+', r'echo\s+'],
            'ruby': [r'def\s+\w+', r'puts\s+', r'@\w+'],
            'go': [r'func\s+\w+\s*\(', r'package\s+main', r'fmt\.Print']
        }

        language_counts = {}

        for code in code_series.dropna():
            detected_languages = []

            for lang, patterns in language_patterns.items():
                if any(re.search(pattern, str(code), re.MULTILINE | re.IGNORECASE) for pattern in patterns):
                    detected_languages.append(lang)

            # If no language detected, classify as 'unknown'
            if not detected_languages:
                detected_languages = ['unknown']

            # Count the first detected language (most confident)
            primary_lang = detected_languages[0]
            language_counts[primary_lang] = language_counts.get(primary_lang, 0) + 1

        return language_counts

    def check_temporal_consistency(self, data: pd.DataFrame) -> Dict[str, Any]:
        """Check temporal consistency in data"""
        temporal_columns = ['timestamp', 'created_at', 'updated_at', 'date']
        found_temporal_col = None

        for col in temporal_columns:
            if col in data.columns:
                found_temporal_col = col
                break

        if found_temporal_col is None:
            return {
                'passed': True,
                'score': 1.0,
                'message': "No temporal columns found - skipping temporal consistency check",
                'details': {}
            }

        try:
            # Convert to datetime
            dates = pd.to_datetime(data[found_temporal_col], errors='coerce')
            valid_dates = dates.dropna()

            if len(valid_dates) == 0:
                return {
                    'passed': False,
                    'score': 0.0,
                    'message': f"No valid dates in column {found_temporal_col}",
                    'details': {}
                }

            # Check for future dates
            now = datetime.now()
            future_dates = (valid_dates > now).sum()

            # Check for reasonable date range (not too old, not in future)
            min_reasonable_date = datetime(2000, 1, 1)
            old_dates = (valid_dates < min_reasonable_date).sum()

            # Check for temporal ordering if there's a vulnerability column
            temporal_issues = future_dates + old_dates
            temporal_ratio = temporal_issues / len(data)

            passed = temporal_ratio <= 0.05  # Less than 5% temporal issues
            score = max(0.0, 1.0 - temporal_ratio / 0.05)

            return {
                'passed': passed,
                'score': score,
                'message': f"Temporal consistency: {temporal_ratio:.1%} issues found",
                'details': {
                    'temporal_column': found_temporal_col,
                    'valid_dates': len(valid_dates),
                    'future_dates': int(future_dates),
                    'old_dates': int(old_dates),
                    'temporal_issues_ratio': temporal_ratio,
                    'date_range': {
                        'earliest': str(valid_dates.min()),
                        'latest': str(valid_dates.max())
                    }
                }
            }

        except Exception as e:
            return {
                'passed': False,
                'score': 0.0,
                'message': f"Error in temporal consistency check: {str(e)}",
                'details': {'error': str(e)}
            }

    def check_label_consistency(self, data: pd.DataFrame) -> Dict[str, Any]:
        """Check consistency between labels and code patterns"""
        if 'vulnerable' not in data.columns or 'code' not in data.columns:
            return {
                'passed': True,
                'score': 1.0,
                'message': "Required columns not found for label consistency check",
                'details': {}
            }

        # Define vulnerability patterns
        vulnerability_patterns = {
            'sql_injection': [r'(?i)(select|insert|update|delete).*%s', r'(?i)query.*\+.*user'],
            'buffer_overflow': [r'(?i)(strcpy|strcat|sprintf|gets)', r'(?i)buffer\[.*\].*=.*input'],
            'command_injection': [r'(?i)(system|exec|popen).*user', r'(?i)os\.system.*\+'],
            'xss': [r'(?i)document\.write.*user', r'(?i)innerHTML.*user'],
            'path_traversal': [r'(?i)\.\./', r'(?i)path.*\.\.'],
        }

        consistency_issues = 0
        total_checks = 0
        pattern_matches = {}

        for idx, row in data.iterrows():
            code = str(row['code'])
            vulnerable = row['vulnerable']

            # Count pattern matches
            matches = 0
            for pattern_type, patterns in vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, code):
                        matches += 1
                        pattern_matches[pattern_type] = pattern_matches.get(pattern_type, 0) + 1

            # Check consistency
            total_checks += 1
            if vulnerable == 1 and matches == 0:
                # Labeled vulnerable but no patterns found
                consistency_issues += 1
            elif vulnerable == 0 and matches > 2:
                # Labeled safe but multiple vulnerability patterns found
                consistency_issues += 1

        consistency_ratio = consistency_issues / total_checks if total_checks > 0 else 0
        passed = consistency_ratio <= 0.1  # Less than 10% inconsistency
        score = max(0.0, 1.0 - consistency_ratio / 0.1)

        return {
            'passed': passed,
            'score': score,
            'message': f"Label consistency: {consistency_ratio:.1%} inconsistencies found",
            'details': {
                'consistency_issues': consistency_issues,
                'total_checks': total_checks,
                'inconsistency_ratio': consistency_ratio,
                'pattern_matches': pattern_matches
            }
        }

    def _detect_data_drift(self, current_data: pd.DataFrame, baseline_data: pd.DataFrame) -> Dict[str, Any]:
        """Detect data drift between current and baseline data"""
        try:
            drift_report = {
                'drift_detected': False,
                'drift_tests': {},
                'overall_drift_score': 0.0,
                'drifted_features': []
            }

            numeric_columns = current_data.select_dtypes(include=[np.number]).columns
            common_columns = [col for col in numeric_columns if col in baseline_data.columns]

            if not common_columns:
                return {
                    'error': 'No common numeric columns found for drift detection',
                    'drift_detected': False
                }

            drift_scores = []

            for column in common_columns:
                current_values = current_data[column].dropna()
                baseline_values = baseline_data[column].dropna()

                if len(current_values) == 0 or len(baseline_values) == 0:
                    continue

                # Kolmogorov-Smirnov test
                ks_statistic, ks_p_value = stats.ks_2samp(baseline_values, current_values)

                # Population Stability Index (PSI)
                psi_score = self._calculate_psi(baseline_values, current_values)

                # Jensen-Shannon Divergence
                jsd_score = self._calculate_jsd(baseline_values, current_values)

                # Determine drift
                ks_drift = ks_p_value < self.drift_thresholds['chi2_threshold']
                psi_drift = psi_score > self.drift_thresholds['psi_threshold']
                jsd_drift = jsd_score > self.drift_thresholds['jsd_threshold']

                feature_drift = ks_drift or psi_drift or jsd_drift

                if feature_drift:
                    drift_report['drifted_features'].append(column)

                drift_report['drift_tests'][column] = {
                    'ks_statistic': float(ks_statistic),
                    'ks_p_value': float(ks_p_value),
                    'ks_drift': ks_drift,
                    'psi_score': float(psi_score),
                    'psi_drift': psi_drift,
                    'jsd_score': float(jsd_score),
                    'jsd_drift': jsd_drift,
                    'overall_drift': feature_drift
                }

                # Combined drift score for this feature
                feature_drift_score = (ks_statistic + psi_score + jsd_score) / 3
                drift_scores.append(feature_drift_score)

            # Calculate overall drift
            if drift_scores:
                drift_report['overall_drift_score'] = float(np.mean(drift_scores))
                drift_report['drift_detected'] = len(drift_report['drifted_features']) > len(common_columns) * 0.2

            return drift_report

        except Exception as e:
            return {
                'error': f'Error in drift detection: {str(e)}',
                'drift_detected': False
            }

    def _calculate_psi(self, baseline: pd.Series, current: pd.Series, bins: int = 10) -> float:
        """Calculate Population Stability Index"""
        try:
            # Create bins based on baseline data
            _, bin_edges = np.histogram(baseline, bins=bins)

            # Calculate distributions
            baseline_dist, _ = np.histogram(baseline, bins=bin_edges, density=True)
            current_dist, _ = np.histogram(current, bins=bin_edges, density=True)

            # Normalize to probabilities
            baseline_dist = baseline_dist / baseline_dist.sum()
            current_dist = current_dist / current_dist.sum()

            # Avoid division by zero
            baseline_dist = np.where(baseline_dist == 0, 0.0001, baseline_dist)
            current_dist = np.where(current_dist == 0, 0.0001, current_dist)

            # Calculate PSI
            psi = np.sum((current_dist - baseline_dist) * np.log(current_dist / baseline_dist))
            return float(psi)

        except:
            return 0.0

    def _calculate_jsd(self, baseline: pd.Series, current: pd.Series, bins: int = 10) -> float:
        """Calculate Jensen-Shannon Divergence"""
        try:
            # Create bins
            combined = np.concatenate([baseline, current])
            _, bin_edges = np.histogram(combined, bins=bins)

            # Calculate distributions
            p, _ = np.histogram(baseline, bins=bin_edges, density=True)
            q, _ = np.histogram(current, bins=bin_edges, density=True)

            # Normalize
            p = p / p.sum()
            q = q / q.sum()

            # Avoid log(0)
            p = np.where(p == 0, 1e-10, p)
            q = np.where(q == 0, 1e-10, q)

            # Calculate JSD
            m = (p + q) / 2
            jsd = 0.5 * stats.entropy(p, m) + 0.5 * stats.entropy(q, m)
            return float(jsd)

        except:
            return 0.0

    def _perform_advanced_analytics(self, data: pd.DataFrame) -> Dict[str, Any]:
        """Perform advanced analytics on the dataset"""
        try:
            analytics = {
                'feature_importance': {},
                'class_distribution': {},
                'correlation_analysis': {},
                'model_readiness': {}
            }

            # Class distribution analysis
            if 'vulnerable' in data.columns:
                class_counts = data['vulnerable'].value_counts()
                analytics['class_distribution'] = {
                    'safe_samples': int(class_counts.get(0, 0)),
                    'vulnerable_samples': int(class_counts.get(1, 0)),
                    'imbalance_ratio': float(class_counts.max() / class_counts.min()) if class_counts.min() > 0 else float('inf')
                }

                # Quick feature importance using mutual information
                numeric_columns = data.select_dtypes(include=[np.number]).columns
                X = data[numeric_columns].fillna(0)
                y = data['vulnerable']

                if len(X.columns) > 1:
                    try:
                        mi_scores = mutual_info_classif(X, y, random_state=42)
                        feature_importance = dict(zip(X.columns, mi_scores))
                        # Get top 10 most important features
                        top_features = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10])
                        analytics['feature_importance'] = {k: float(v) for k, v in top_features.items()}
                    except:
                        analytics['feature_importance'] = {}

                # Model readiness assessment
                analytics['model_readiness'] = {
                    'sufficient_samples': len(data) >= 1000,
                    'balanced_classes': 0.2 <= data['vulnerable'].mean() <= 0.8,
                    'sufficient_features': len(numeric_columns) >= 10,
                    'low_missing_data': data.isnull().mean().mean() <= 0.1
                }

            return analytics

        except Exception as e:
            return {'error': str(e)}

    def _generate_recommendations(self, validation_report: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []

        # Check critical issues
        if validation_report['critical_issues']:
            recommendations.append("🔴 Address critical issues before proceeding with model training")

        # Quality score recommendations
        quality_score = validation_report.get('quality_score', 0)
        if quality_score < 0.5:
            recommendations.append("📊 Data quality is poor - consider data collection improvements")
        elif quality_score < 0.7:
            recommendations.append("⚠️ Data quality is moderate - review and clean data before training")

        # Specific recommendations based on validation results
        results = validation_report.get('validation_results', {})

        if 'vulnerability_ratio' in results and not results['vulnerability_ratio'].get('passed', True):
            recommendations.append("⚖️ Improve class balance - consider data augmentation or sampling strategies")

        if 'duplicate_content' in results and not results['duplicate_content'].get('passed', True):
            recommendations.append("🔄 Remove or reduce duplicate samples to improve model generalization")

        if 'feature_completeness' in results and not results['feature_completeness'].get('passed', True):
            recommendations.append("📝 Address missing data through imputation or feature engineering")

        # Drift recommendations
        if 'drift_analysis' in validation_report and validation_report['drift_analysis'].get('drift_detected'):
            recommendations.append("📈 Data drift detected - consider model retraining or data pipeline updates")

        return recommendations

def main():
    """Demo usage of VulnerabilityDataValidator"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Initialize validator
    validator = VulnerabilityDataValidator(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    # Create sample dataset
    np.random.seed(42)
    sample_data = pd.DataFrame({
        'code': [
            'if (user_input) { system(user_input); }',  # Command injection
            'strcpy(buffer, input);',                   # Buffer overflow
            'SELECT * FROM users WHERE id = %s' % 1,   # SQL injection
            'return input;',                           # Safe code
            'open(filename, "r").read()',              # File operation
            'hash_password(password)',                  # Safe crypto
            '',                                        # Empty code (should be flagged)
            'def safe_function(): return True',        # Safe Python
        ] * 50,  # Repeat to get more samples
        'vulnerable': [1, 1, 1, 0, 0, 0, 0, 0] * 50,
        'language': ['C', 'C', 'Python', 'Python', 'Python', 'Python', 'Invalid', 'Python'] * 50,
        'severity': np.random.uniform(0, 10, 400),
        'timestamp': pd.date_range('2023-01-01', periods=400, freq='D')
    })

    # Add some data quality issues for testing
    sample_data.loc[sample_data.index[:10], 'code'] = ''  # Add empty code samples
    sample_data.loc[sample_data.index[10:15], 'vulnerable'] = None  # Add missing labels

    try:
        print("🔍 VulnHunter Data Validation Demo")

        # Run comprehensive validation
        print(f"\n📊 Running comprehensive validation on {len(sample_data)} samples...")
        validation_report = validator.validate_dataset(sample_data)

        print(f"\n✅ Validation Results:")
        print(f"   Quality Score: {validation_report['quality_score']:.2f}")
        print(f"   Validation Passed: {validation_report['passed_validation']}")
        print(f"   Critical Issues: {len(validation_report['critical_issues'])}")
        print(f"   Warnings: {len(validation_report['warnings'])}")

        # Show validation details
        print(f"\n📋 Validation Rule Results:")
        for rule_name, result in validation_report['validation_results'].items():
            if isinstance(result, dict) and 'passed' in result:
                status = "✅" if result['passed'] else "❌"
                score = result.get('score', 0)
                print(f"   {status} {rule_name}: {score:.2f}")

        # Show critical issues
        if validation_report['critical_issues']:
            print(f"\n🔴 Critical Issues:")
            for issue in validation_report['critical_issues']:
                print(f"   - {issue}")

        # Show recommendations
        if validation_report['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in validation_report['recommendations']:
                print(f"   - {rec}")

        # Advanced analytics
        if 'advanced_analytics' in validation_report:
            analytics = validation_report['advanced_analytics']
            print(f"\n🔬 Advanced Analytics:")

            if 'class_distribution' in analytics:
                dist = analytics['class_distribution']
                print(f"   Class Distribution: {dist['safe_samples']} safe, {dist['vulnerable_samples']} vulnerable")
                print(f"   Imbalance Ratio: {dist['imbalance_ratio']:.2f}")

            if 'feature_importance' in analytics and analytics['feature_importance']:
                print(f"   Top Important Features:")
                for feat, importance in list(analytics['feature_importance'].items())[:5]:
                    print(f"     - {feat}: {importance:.3f}")

        print(f"\n✅ Data validation demo completed!")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()