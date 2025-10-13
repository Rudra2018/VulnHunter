#!/usr/bin/env python3
"""
Vertex AI Feature Store for VulnHunter Code Features
Implements comprehensive feature engineering and storage for vulnerability detection.
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
import pickle

import pandas as pd
import numpy as np
from google.cloud import aiplatform
from google.cloud import storage
from google.cloud.aiplatform import feature_store
from google.api_core import exceptions
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

@dataclass
class FeatureMetadata:
    """Metadata for feature engineering"""
    feature_name: str
    feature_type: str
    description: str
    creation_time: datetime
    extraction_method: str
    dimension: int
    feature_importance: float
    data_lineage: List[str]

class CodeFeatureExtractor:
    """
    Advanced code feature extraction for vulnerability detection
    Implements AST, CFG, DFG, and textual feature extraction.
    """

    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3)
        )
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def extract_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract Abstract Syntax Tree features"""
        try:
            tree = ast.parse(code)

            features = {
                'ast_node_count': len(list(ast.walk(tree))),
                'ast_depth': self._get_ast_depth(tree),
                'ast_function_count': len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]),
                'ast_class_count': len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                'ast_if_count': len([n for n in ast.walk(tree) if isinstance(n, ast.If)]),
                'ast_loop_count': len([n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))]),
                'ast_try_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Try)]),
                'ast_call_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Call)]),
                'ast_assign_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Assign)]),
                'ast_compare_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Compare)]),
                'ast_binop_count': len([n for n in ast.walk(tree) if isinstance(n, ast.BinOp)]),
                'ast_import_count': len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]),
            }

            # Extract dangerous function calls
            dangerous_calls = self._extract_dangerous_calls(tree)
            features.update(dangerous_calls)

            return features

        except SyntaxError:
            # Return zero features for invalid syntax
            return {f'ast_{key}': 0 for key in [
                'node_count', 'depth', 'function_count', 'class_count', 'if_count',
                'loop_count', 'try_count', 'call_count', 'assign_count', 'compare_count',
                'binop_count', 'import_count', 'dangerous_exec', 'dangerous_eval',
                'dangerous_system', 'dangerous_shell', 'dangerous_file', 'dangerous_network'
            ]}
        except Exception as e:
            logging.warning(f"AST extraction error: {e}")
            return {f'ast_{key}': 0 for key in [
                'node_count', 'depth', 'function_count', 'class_count', 'if_count',
                'loop_count', 'try_count', 'call_count', 'assign_count', 'compare_count',
                'binop_count', 'import_count', 'dangerous_exec', 'dangerous_eval',
                'dangerous_system', 'dangerous_shell', 'dangerous_file', 'dangerous_network'
            ]}

    def _get_ast_depth(self, node: ast.AST, depth: int = 0) -> int:
        """Calculate AST depth recursively"""
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            max_depth = max(max_depth, self._get_ast_depth(child, depth + 1))
        return max_depth

    def _extract_dangerous_calls(self, tree: ast.AST) -> Dict[str, int]:
        """Extract dangerous function calls that might indicate vulnerabilities"""
        dangerous_patterns = {
            'dangerous_exec': ['exec', 'eval'],
            'dangerous_system': ['system', 'popen', 'subprocess', 'os.system'],
            'dangerous_shell': ['shell=True', 'shell_execute'],
            'dangerous_file': ['open', 'file', 'read', 'write'],
            'dangerous_network': ['socket', 'urllib', 'requests', 'http']
        }

        call_counts = {key: 0 for key in dangerous_patterns.keys()}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                for pattern_type, patterns in dangerous_patterns.items():
                    if any(pattern in call_name.lower() for pattern in patterns):
                        call_counts[pattern_type] += 1

        return call_counts

    def _get_call_name(self, call_node: ast.Call) -> str:
        """Extract function call name from AST node"""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr
        elif isinstance(call_node.func, ast.Call):
            return self._get_call_name(call_node.func)
        else:
            return ""

    def extract_textual_features(self, code: str) -> Dict[str, Any]:
        """Extract textual and lexical features from code"""
        features = {
            'code_length': len(code),
            'line_count': len(code.split('\n')),
            'avg_line_length': np.mean([len(line) for line in code.split('\n')]),
            'max_line_length': max([len(line) for line in code.split('\n')]),
            'whitespace_ratio': sum(1 for c in code if c.isspace()) / len(code) if code else 0,
            'comment_ratio': self._calculate_comment_ratio(code),
            'string_literal_count': len(re.findall(r'["\'].*?["\']', code)),
            'numeric_literal_count': len(re.findall(r'\b\d+\b', code)),
            'keyword_count': self._count_keywords(code),
            'complexity_score': self._calculate_complexity(code),
        }

        # Extract security-relevant patterns
        security_patterns = {
            'sql_pattern_count': len(re.findall(r'(?i)(select|insert|update|delete|union|drop)\s+', code)),
            'file_operation_count': len(re.findall(r'(?i)(open|read|write|fopen|fread|fwrite)', code)),
            'network_operation_count': len(re.findall(r'(?i)(socket|connect|bind|listen|accept)', code)),
            'crypto_operation_count': len(re.findall(r'(?i)(encrypt|decrypt|hash|md5|sha|aes)', code)),
            'authentication_count': len(re.findall(r'(?i)(password|token|auth|login|credential)', code)),
            'buffer_operation_count': len(re.findall(r'(?i)(strcpy|strcat|sprintf|gets|memcpy)', code)),
            'shell_command_count': len(re.findall(r'(?i)(system|exec|popen|shell)', code)),
        }

        features.update(security_patterns)
        return features

    def _calculate_comment_ratio(self, code: str) -> float:
        """Calculate ratio of comment lines to total lines"""
        lines = code.split('\n')
        comment_lines = sum(1 for line in lines if line.strip().startswith('#') or line.strip().startswith('//'))
        return comment_lines / len(lines) if lines else 0

    def _count_keywords(self, code: str) -> int:
        """Count programming language keywords"""
        python_keywords = [
            'def', 'class', 'if', 'else', 'elif', 'for', 'while', 'try', 'except',
            'finally', 'with', 'import', 'from', 'return', 'yield', 'lambda'
        ]
        c_keywords = [
            'int', 'char', 'float', 'double', 'void', 'struct', 'union', 'enum',
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue'
        ]

        all_keywords = set(python_keywords + c_keywords)
        words = re.findall(r'\b\w+\b', code.lower())
        return sum(1 for word in words if word in all_keywords)

    def _calculate_complexity(self, code: str) -> float:
        """Calculate cyclomatic complexity approximation"""
        # Count decision points
        decision_points = (
            len(re.findall(r'\bif\b', code)) +
            len(re.findall(r'\bwhile\b', code)) +
            len(re.findall(r'\bfor\b', code)) +
            len(re.findall(r'\bcase\b', code)) +
            len(re.findall(r'\bcatch\b', code)) +
            len(re.findall(r'\b&&\b', code)) +
            len(re.findall(r'\b\|\|\b', code))
        )
        return decision_points + 1  # Base complexity is 1

    def extract_control_flow_features(self, code: str) -> Dict[str, Any]:
        """Extract control flow graph features"""
        try:
            # Build a simple control flow representation
            lines = code.split('\n')
            control_flow_features = {
                'cf_conditional_blocks': 0,
                'cf_loop_blocks': 0,
                'cf_function_blocks': 0,
                'cf_exception_blocks': 0,
                'cf_max_nesting_depth': 0,
                'cf_average_block_size': 0,
            }

            current_depth = 0
            max_depth = 0
            block_sizes = []
            current_block_size = 0

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue

                # Count indentation depth
                indent_depth = (len(line) - len(line.lstrip())) // 4

                if indent_depth > current_depth:
                    if current_block_size > 0:
                        block_sizes.append(current_block_size)
                        current_block_size = 0
                current_depth = indent_depth
                max_depth = max(max_depth, current_depth)
                current_block_size += 1

                # Identify control structures
                if re.match(r'\s*(if|elif|else)', stripped):
                    control_flow_features['cf_conditional_blocks'] += 1
                elif re.match(r'\s*(for|while)', stripped):
                    control_flow_features['cf_loop_blocks'] += 1
                elif re.match(r'\s*(def|function)', stripped):
                    control_flow_features['cf_function_blocks'] += 1
                elif re.match(r'\s*(try|except|finally)', stripped):
                    control_flow_features['cf_exception_blocks'] += 1

            if current_block_size > 0:
                block_sizes.append(current_block_size)

            control_flow_features['cf_max_nesting_depth'] = max_depth
            control_flow_features['cf_average_block_size'] = np.mean(block_sizes) if block_sizes else 0

            return control_flow_features

        except Exception as e:
            logging.warning(f"Control flow extraction error: {e}")
            return {
                'cf_conditional_blocks': 0,
                'cf_loop_blocks': 0,
                'cf_function_blocks': 0,
                'cf_exception_blocks': 0,
                'cf_max_nesting_depth': 0,
                'cf_average_block_size': 0,
            }

class VulnHunterFeatureStore:
    """
    Comprehensive Feature Store for VulnHunter vulnerability detection
    with Vertex AI Feature Store integration and advanced feature engineering.
    """

    def __init__(self, project_id: str, location: str = "us-central1", feature_store_id: str = "vulnhunter_features"):
        self.project_id = project_id
        self.location = location
        self.feature_store_id = feature_store_id
        self.storage_client = storage.Client(project=project_id)

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        # Feature extractors
        self.code_extractor = CodeFeatureExtractor()

        # Storage configuration
        self.feature_bucket = f"{project_id}-vulnhunter-features"
        self.model_bucket = f"{project_id}-vulnhunter-models"

        # Feature configurations
        self.feature_groups = {
            'ast_features': {
                'description': 'Abstract Syntax Tree features',
                'dimension': 18,
                'extraction_method': 'ast_analysis'
            },
            'textual_features': {
                'description': 'Textual and lexical code features',
                'dimension': 17,
                'extraction_method': 'text_analysis'
            },
            'control_flow_features': {
                'description': 'Control flow graph features',
                'dimension': 6,
                'extraction_method': 'cfg_analysis'
            },
            'security_features': {
                'description': 'Security-specific pattern features',
                'dimension': 7,
                'extraction_method': 'security_pattern_matching'
            }
        }

        self.logger = self._setup_logging()
        self._initialize_infrastructure()

    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('VulnHunterFeatureStore')
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
        """Initialize GCS buckets and Feature Store"""
        # Create buckets
        buckets = [self.feature_bucket, self.model_bucket]
        for bucket_name in buckets:
            try:
                bucket = self.storage_client.bucket(bucket_name)
                if not bucket.exists():
                    bucket = self.storage_client.create_bucket(bucket_name, location=self.location)
                    self.logger.info(f"Created bucket: {bucket_name}")
            except Exception as e:
                self.logger.error(f"Error with bucket {bucket_name}: {e}")

        # Initialize Feature Store
        try:
            self.feature_store = self._get_or_create_feature_store()
            self.logger.info(f"Initialized Feature Store: {self.feature_store_id}")
        except Exception as e:
            self.logger.error(f"Error initializing Feature Store: {e}")
            raise

    def _get_or_create_feature_store(self):
        """Get existing or create new Feature Store"""
        try:
            # Try to get existing feature store
            feature_store_client = aiplatform.gapic.FeaturestoreServiceClient()
            feature_store_path = feature_store_client.featurestore_path(
                self.project_id, self.location, self.feature_store_id
            )

            try:
                existing_fs = feature_store_client.get_featurestore(name=feature_store_path)
                return existing_fs
            except exceptions.NotFound:
                pass

            # Create new feature store
            parent = f"projects/{self.project_id}/locations/{self.location}"
            feature_store = {
                "online_serving_config": {"fixed_node_count": 1},
                "labels": {
                    "project": "vulnhunter",
                    "team": "security"
                }
            }

            operation = feature_store_client.create_featurestore(
                parent=parent,
                featurestore=feature_store,
                featurestore_id=self.feature_store_id
            )

            created_fs = operation.result(timeout=300)
            self.logger.info(f"Created Feature Store: {created_fs.name}")
            return created_fs

        except Exception as e:
            self.logger.error(f"Error with Feature Store: {e}")
            raise

    def create_entity_type(self, entity_type_id: str, description: str = None):
        """Create an entity type in the Feature Store"""
        try:
            feature_store_client = aiplatform.gapic.FeaturestoreServiceClient()
            parent = feature_store_client.featurestore_path(
                self.project_id, self.location, self.feature_store_id
            )

            entity_type = {
                "description": description or f"Entity type for {entity_type_id}",
                "labels": {"project": "vulnhunter"}
            }

            try:
                operation = feature_store_client.create_entity_type(
                    parent=parent,
                    entity_type=entity_type,
                    entity_type_id=entity_type_id
                )
                result = operation.result(timeout=120)
                self.logger.info(f"Created entity type: {entity_type_id}")
                return result
            except exceptions.AlreadyExists:
                self.logger.info(f"Entity type {entity_type_id} already exists")
                return None

        except Exception as e:
            self.logger.error(f"Error creating entity type: {e}")
            raise

    def extract_all_features(self, code_samples: List[str]) -> pd.DataFrame:
        """
        Extract all features from code samples

        Args:
            code_samples: List of code strings

        Returns:
            DataFrame with extracted features
        """
        try:
            all_features = []

            self.logger.info(f"Extracting features from {len(code_samples)} code samples")

            for i, code in enumerate(code_samples):
                if i % 100 == 0:
                    self.logger.info(f"Processing sample {i}/{len(code_samples)}")

                sample_features = {}

                # Extract AST features
                ast_features = self.code_extractor.extract_ast_features(code)
                sample_features.update(ast_features)

                # Extract textual features
                textual_features = self.code_extractor.extract_textual_features(code)
                sample_features.update(textual_features)

                # Extract control flow features
                cf_features = self.code_extractor.extract_control_flow_features(code)
                sample_features.update(cf_features)

                # Add sample ID
                sample_features['sample_id'] = i
                sample_features['code_hash'] = hashlib.md5(code.encode()).hexdigest()

                all_features.append(sample_features)

            features_df = pd.DataFrame(all_features)
            self.logger.info(f"Extracted {len(features_df.columns)} features from {len(features_df)} samples")

            return features_df

        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            raise

    def store_features(self, features_df: pd.DataFrame, feature_group_name: str) -> str:
        """
        Store features in GCS and Feature Store

        Args:
            features_df: DataFrame with features
            feature_group_name: Name for the feature group

        Returns:
            GCS path where features are stored
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            feature_path = f"features/{feature_group_name}/{timestamp}/features.parquet"

            # Upload to GCS
            bucket = self.storage_client.bucket(self.feature_bucket)
            blob = bucket.blob(feature_path)

            # Convert to parquet for efficient storage
            parquet_buffer = features_df.to_parquet(index=False)
            blob.upload_from_string(parquet_buffer)

            gcs_path = f"gs://{self.feature_bucket}/{feature_path}"
            self.logger.info(f"Stored features at: {gcs_path}")

            # Store feature metadata
            metadata = {
                'feature_group_name': feature_group_name,
                'timestamp': timestamp,
                'feature_count': len(features_df.columns),
                'sample_count': len(features_df),
                'gcs_path': gcs_path,
                'feature_names': list(features_df.columns),
                'creation_time': datetime.now().isoformat()
            }

            metadata_path = f"features/{feature_group_name}/{timestamp}/metadata.json"
            metadata_blob = bucket.blob(metadata_path)
            metadata_blob.upload_from_string(json.dumps(metadata, indent=2))

            return gcs_path

        except Exception as e:
            self.logger.error(f"Error storing features: {e}")
            raise

    def load_features(self, feature_group_name: str, timestamp: str = None) -> pd.DataFrame:
        """
        Load features from GCS

        Args:
            feature_group_name: Name of the feature group
            timestamp: Specific timestamp (if None, loads latest)

        Returns:
            DataFrame with features
        """
        try:
            bucket = self.storage_client.bucket(self.feature_bucket)
            prefix = f"features/{feature_group_name}/"

            if timestamp is None:
                # Find latest timestamp
                blobs = list(bucket.list_blobs(prefix=prefix))
                timestamps = set()
                for blob in blobs:
                    parts = blob.name.split('/')
                    if len(parts) >= 3:
                        timestamps.add(parts[2])

                if not timestamps:
                    raise ValueError(f"No features found for group: {feature_group_name}")

                timestamp = max(timestamps)

            feature_path = f"features/{feature_group_name}/{timestamp}/features.parquet"
            blob = bucket.blob(feature_path)

            if not blob.exists():
                raise ValueError(f"Features not found at: {feature_path}")

            # Download and load parquet
            parquet_data = blob.download_as_bytes()
            features_df = pd.read_parquet(pd.BytesIO(parquet_data))

            self.logger.info(f"Loaded {len(features_df)} samples with {len(features_df.columns)} features")
            return features_df

        except Exception as e:
            self.logger.error(f"Error loading features: {e}")
            raise

    def create_training_dataset(self,
                              feature_groups: List[str],
                              vulnerability_labels: List[int],
                              train_ratio: float = 0.8) -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray]:
        """
        Create training dataset by combining feature groups

        Args:
            feature_groups: List of feature group names
            vulnerability_labels: List of vulnerability labels (0/1)
            train_ratio: Ratio for train/test split

        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        try:
            combined_features = []

            for group_name in feature_groups:
                features_df = self.load_features(group_name)
                combined_features.append(features_df)

            # Combine all features
            if len(combined_features) > 1:
                final_features = pd.concat(combined_features, axis=1)
                # Remove duplicate columns
                final_features = final_features.loc[:, ~final_features.columns.duplicated()]
            else:
                final_features = combined_features[0]

            # Remove non-numeric columns for training
            numeric_columns = final_features.select_dtypes(include=[np.number]).columns
            X = final_features[numeric_columns]

            # Handle missing values
            X = X.fillna(0)

            # Convert labels to numpy array
            y = np.array(vulnerability_labels)

            # Ensure same number of samples
            min_samples = min(len(X), len(y))
            X = X.iloc[:min_samples]
            y = y[:min_samples]

            # Train/test split
            split_idx = int(len(X) * train_ratio)

            X_train = X.iloc[:split_idx]
            X_test = X.iloc[split_idx:]
            y_train = y[:split_idx]
            y_test = y[split_idx:]

            self.logger.info(f"Created training dataset:")
            self.logger.info(f"  - Training samples: {len(X_train)}")
            self.logger.info(f"  - Test samples: {len(X_test)}")
            self.logger.info(f"  - Features: {len(X.columns)}")
            self.logger.info(f"  - Positive samples: {sum(y)}/{len(y)} ({sum(y)/len(y)*100:.1f}%)")

            return X_train, X_test, y_train, y_test

        except Exception as e:
            self.logger.error(f"Error creating training dataset: {e}")
            raise

    def get_feature_importance(self, model, feature_names: List[str]) -> Dict[str, float]:
        """
        Extract feature importance from trained model

        Args:
            model: Trained model with feature_importances_ attribute
            feature_names: List of feature names

        Returns:
            Dictionary mapping feature names to importance scores
        """
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_[0])
            else:
                self.logger.warning("Model does not have feature importance attributes")
                return {}

            feature_importance = dict(zip(feature_names, importances))

            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(),
                                         key=lambda x: x[1],
                                         reverse=True))

            return sorted_importance

        except Exception as e:
            self.logger.error(f"Error extracting feature importance: {e}")
            return {}

    def analyze_feature_distributions(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze feature distributions for quality assessment

        Args:
            features_df: DataFrame with features

        Returns:
            Feature distribution analysis
        """
        try:
            analysis = {
                'feature_count': len(features_df.columns),
                'sample_count': len(features_df),
                'missing_values': features_df.isnull().sum().to_dict(),
                'feature_stats': {},
                'correlation_analysis': {}
            }

            # Statistical analysis for numeric features
            numeric_cols = features_df.select_dtypes(include=[np.number]).columns

            for col in numeric_cols:
                col_stats = {
                    'mean': float(features_df[col].mean()),
                    'std': float(features_df[col].std()),
                    'min': float(features_df[col].min()),
                    'max': float(features_df[col].max()),
                    'median': float(features_df[col].median()),
                    'skewness': float(features_df[col].skew()),
                    'kurtosis': float(features_df[col].kurtosis()),
                    'unique_values': int(features_df[col].nunique()),
                    'zero_ratio': float((features_df[col] == 0).mean())
                }
                analysis['feature_stats'][col] = col_stats

            # Correlation analysis
            if len(numeric_cols) > 1:
                correlation_matrix = features_df[numeric_cols].corr()

                # Find highly correlated features
                high_corr_pairs = []
                for i in range(len(correlation_matrix.columns)):
                    for j in range(i+1, len(correlation_matrix.columns)):
                        corr_val = abs(correlation_matrix.iloc[i, j])
                        if corr_val > 0.8:  # High correlation threshold
                            high_corr_pairs.append({
                                'feature1': correlation_matrix.columns[i],
                                'feature2': correlation_matrix.columns[j],
                                'correlation': float(corr_val)
                            })

                analysis['correlation_analysis'] = {
                    'high_correlation_pairs': high_corr_pairs,
                    'avg_correlation': float(correlation_matrix.values[np.triu_indices_from(correlation_matrix.values, 1)].mean())
                }

            return analysis

        except Exception as e:
            self.logger.error(f"Error in feature analysis: {e}")
            return {'error': str(e)}

def main():
    """Demo usage of VulnHunterFeatureStore"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Initialize feature store
    feature_store = VulnHunterFeatureStore(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    # Sample vulnerable code
    code_samples = [
        # SQL Injection vulnerability
        """
def login(username, password):
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    return execute_query(query)
        """,

        # Buffer overflow vulnerability
        """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // No bounds checking
    printf("Input: %s", buffer);
}
        """,

        # Command injection vulnerability
        """
import os

def process_file(filename):
    command = "cat " + filename
    os.system(command)  # Dangerous: user input directly in command
    return "File processed"
        """,

        # Safe code
        """
def safe_login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return execute_query(query, (username, password))
        """
    ]

    vulnerability_labels = [1, 1, 1, 0]  # 1 = vulnerable, 0 = safe

    try:
        print("🚀 VulnHunter Feature Store Demo")

        # Create entity type
        print("\n📊 Creating entity type...")
        feature_store.create_entity_type("code_samples", "Code samples for vulnerability detection")

        # Extract features
        print(f"\n🔍 Extracting features from {len(code_samples)} code samples...")
        features_df = feature_store.extract_all_features(code_samples)
        print(f"✅ Extracted {len(features_df.columns)} features")

        # Store features
        print(f"\n💾 Storing features...")
        gcs_path = feature_store.store_features(features_df, "demo_features")
        print(f"✅ Features stored at: {gcs_path}")

        # Analyze feature distributions
        print(f"\n📈 Analyzing feature distributions...")
        analysis = feature_store.analyze_feature_distributions(features_df)
        print(f"✅ Feature analysis completed")
        print(f"   - Total features: {analysis['feature_count']}")
        print(f"   - Samples: {analysis['sample_count']}")
        print(f"   - High correlation pairs: {len(analysis.get('correlation_analysis', {}).get('high_correlation_pairs', []))}")

        # Create training dataset
        print(f"\n🎯 Creating training dataset...")
        X_train, X_test, y_train, y_test = feature_store.create_training_dataset(
            feature_groups=["demo_features"],
            vulnerability_labels=vulnerability_labels,
            train_ratio=0.75
        )
        print(f"✅ Training dataset created")
        print(f"   - Training samples: {len(X_train)} ({sum(y_train)}/{len(y_train)} vulnerable)")
        print(f"   - Test samples: {len(X_test)} ({sum(y_test)}/{len(y_test)} vulnerable)")

        # Show top features by variance
        feature_variance = X_train.var().sort_values(ascending=False)
        print(f"\n🔝 Top 10 features by variance:")
        for i, (feature, variance) in enumerate(feature_variance.head(10).items()):
            print(f"   {i+1:2d}. {feature}: {variance:.4f}")

        print("\n✅ Feature Store demo completed successfully!")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()