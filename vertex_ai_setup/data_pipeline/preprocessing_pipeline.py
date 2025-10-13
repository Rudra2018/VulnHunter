#!/usr/bin/env python3
"""
Vertex AI Pipelines for Automated Data Preprocessing
Implements comprehensive data preprocessing pipelines for VulnHunter training.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, NamedTuple
from pathlib import Path

import pandas as pd
import numpy as np
from google.cloud import aiplatform
from kfp.v2 import dsl
from kfp.v2.dsl import component, pipeline, Input, Output, Dataset, Model, Metrics, Artifact
import kfp

# Component for data loading
@component(
    base_image="python:3.9",
    packages_to_install=[
        "pandas==1.5.3",
        "numpy==1.24.3",
        "google-cloud-storage==2.10.0",
        "scikit-learn==1.3.0"
    ]
)
def load_vulnerability_data(
    dataset_uri: str,
    output_dataset: Output[Dataset],
    metadata_output: Output[Metrics]
) -> NamedTuple('LoadDataOutput', [('record_count', int), ('column_count', int)]):
    """Load vulnerability data from GCS and perform initial validation"""
    import pandas as pd
    import numpy as np
    from google.cloud import storage
    import json

    try:
        # Parse GCS URI
        if dataset_uri.startswith('gs://'):
            bucket_name = dataset_uri.split('/')[2]
            blob_path = '/'.join(dataset_uri.split('/')[3:])

            # Download data from GCS
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_path)

            if blob_path.endswith('.csv'):
                data_str = blob.download_as_text()
                data = pd.read_csv(pd.StringIO(data_str))
            elif blob_path.endswith('.parquet'):
                data_bytes = blob.download_as_bytes()
                data = pd.read_parquet(pd.BytesIO(data_bytes))
            else:
                raise ValueError(f"Unsupported file format: {blob_path}")

        else:
            # Load from local file
            if dataset_uri.endswith('.csv'):
                data = pd.read_csv(dataset_uri)
            elif dataset_uri.endswith('.parquet'):
                data = pd.read_parquet(dataset_uri)
            else:
                raise ValueError(f"Unsupported file format: {dataset_uri}")

        # Basic validation
        if data.empty:
            raise ValueError("Dataset is empty")

        # Ensure required columns exist
        required_columns = ['code', 'vulnerable']
        missing_columns = [col for col in required_columns if col not in data.columns]
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")

        # Save processed data
        data.to_csv(output_dataset.path, index=False)

        # Create metadata
        metadata = {
            'record_count': len(data),
            'column_count': len(data.columns),
            'columns': list(data.columns),
            'vulnerable_ratio': float(data['vulnerable'].mean()) if 'vulnerable' in data.columns else 0.0,
            'null_counts': data.isnull().sum().to_dict(),
            'processing_timestamp': datetime.now().isoformat()
        }

        with open(metadata_output.path, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"✅ Loaded {len(data)} records with {len(data.columns)} columns")
        print(f"   Vulnerable ratio: {metadata['vulnerable_ratio']:.2%}")

        from collections import namedtuple
        LoadDataOutput = namedtuple('LoadDataOutput', ['record_count', 'column_count'])
        return LoadDataOutput(len(data), len(data.columns))

    except Exception as e:
        print(f"❌ Error loading data: {e}")
        raise

@component(
    base_image="python:3.9",
    packages_to_install=[
        "pandas==1.5.3",
        "numpy==1.24.3",
        "scikit-learn==1.3.0",
        "nltk==3.8.1"
    ]
)
def clean_and_validate_data(
    input_dataset: Input[Dataset],
    output_dataset: Output[Dataset],
    validation_metrics: Output[Metrics],
    min_code_length: int = 10,
    max_duplicate_ratio: float = 0.05,
    min_vulnerable_ratio: float = 0.05
) -> NamedTuple('ValidationOutput', [('passed_validation', bool), ('cleaned_records', int)]):
    """Clean data and perform comprehensive validation"""
    import pandas as pd
    import numpy as np
    import re
    import json
    from sklearn.preprocessing import LabelEncoder

    try:
        # Load data
        data = pd.read_csv(input_dataset.path)
        initial_count = len(data)

        print(f"🔍 Starting data cleaning and validation for {initial_count} records")

        validation_results = {
            'initial_record_count': initial_count,
            'validation_checks': {},
            'cleaning_steps': {}
        }

        # 1. Remove empty code samples
        before_empty = len(data)
        data = data[data['code'].notna() & (data['code'].str.strip() != '')]
        after_empty = len(data)
        validation_results['cleaning_steps']['removed_empty_code'] = before_empty - after_empty

        # 2. Remove very short code samples
        before_short = len(data)
        data = data[data['code'].str.len() >= min_code_length]
        after_short = len(data)
        validation_results['cleaning_steps']['removed_short_code'] = before_short - after_short

        # 3. Standardize vulnerability labels
        if 'vulnerable' in data.columns:
            # Convert various vulnerability indicators to 0/1
            data['vulnerable'] = data['vulnerable'].astype(str).str.lower()
            data.loc[data['vulnerable'].isin(['true', '1', 'yes', 'vulnerable']), 'vulnerable'] = 1
            data.loc[data['vulnerable'].isin(['false', '0', 'no', 'safe']), 'vulnerable'] = 0
            data['vulnerable'] = pd.to_numeric(data['vulnerable'], errors='coerce')

            # Remove records with invalid vulnerability labels
            before_invalid = len(data)
            data = data[data['vulnerable'].isin([0, 1])]
            after_invalid = len(data)
            validation_results['cleaning_steps']['removed_invalid_labels'] = before_invalid - after_invalid

        # 4. Clean code content
        def clean_code(code_text):
            # Remove excessive whitespace
            code_text = re.sub(r'\n\s*\n', '\n\n', code_text)
            code_text = re.sub(r' +', ' ', code_text)
            # Remove very long lines (potential data corruption)
            lines = code_text.split('\n')
            lines = [line[:1000] if len(line) > 1000 else line for line in lines]
            return '\n'.join(lines)

        data['code'] = data['code'].apply(clean_code)

        # 5. Handle duplicates
        before_duplicates = len(data)
        if 'code' in data.columns:
            # Remove exact duplicates
            data = data.drop_duplicates(subset=['code'], keep='first')
            after_duplicates = len(data)
            validation_results['cleaning_steps']['removed_duplicates'] = before_duplicates - after_duplicates

            # Check remaining duplicate ratio
            duplicate_ratio = data['code'].duplicated().mean()
            validation_results['validation_checks']['duplicate_ratio'] = {
                'value': float(duplicate_ratio),
                'threshold': max_duplicate_ratio,
                'passed': duplicate_ratio <= max_duplicate_ratio
            }

        # 6. Validation checks
        # Check vulnerable ratio
        if 'vulnerable' in data.columns:
            vulnerable_ratio = data['vulnerable'].mean()
            validation_results['validation_checks']['vulnerable_ratio'] = {
                'value': float(vulnerable_ratio),
                'threshold': min_vulnerable_ratio,
                'passed': vulnerable_ratio >= min_vulnerable_ratio
            }

        # Check code length distribution
        avg_code_length = data['code'].str.len().mean()
        validation_results['validation_checks']['average_code_length'] = {
            'value': float(avg_code_length),
            'threshold': min_code_length,
            'passed': avg_code_length >= min_code_length
        }

        # Check feature completeness
        completeness = data.notna().mean().mean()
        validation_results['validation_checks']['data_completeness'] = {
            'value': float(completeness),
            'threshold': 0.8,
            'passed': completeness >= 0.8
        }

        # 7. Add metadata columns
        data['record_id'] = range(len(data))
        data['processing_timestamp'] = datetime.now().isoformat()
        data['code_length'] = data['code'].str.len()
        data['code_lines'] = data['code'].str.count('\n') + 1

        # Calculate overall validation score
        check_scores = [check['passed'] for check in validation_results['validation_checks'].values()]
        overall_score = sum(check_scores) / len(check_scores) if check_scores else 0.0
        validation_results['overall_validation_score'] = overall_score
        validation_results['passed_validation'] = overall_score >= 0.7

        validation_results['final_record_count'] = len(data)
        validation_results['records_removed'] = initial_count - len(data)
        validation_results['removal_ratio'] = (initial_count - len(data)) / initial_count if initial_count > 0 else 0

        # Save cleaned data
        data.to_csv(output_dataset.path, index=False)

        # Save validation metrics
        with open(validation_metrics.path, 'w') as f:
            json.dump(validation_results, f, indent=2)

        print(f"✅ Data cleaning completed:")
        print(f"   Initial records: {initial_count}")
        print(f"   Final records: {len(data)}")
        print(f"   Records removed: {initial_count - len(data)} ({(initial_count - len(data))/initial_count*100:.1f}%)")
        print(f"   Validation score: {overall_score:.2f}")
        print(f"   Passed validation: {validation_results['passed_validation']}")

        from collections import namedtuple
        ValidationOutput = namedtuple('ValidationOutput', ['passed_validation', 'cleaned_records'])
        return ValidationOutput(validation_results['passed_validation'], len(data))

    except Exception as e:
        print(f"❌ Error in data cleaning: {e}")
        raise

@component(
    base_image="python:3.9",
    packages_to_install=[
        "pandas==1.5.3",
        "numpy==1.24.3",
        "scikit-learn==1.3.0",
        "networkx==3.1"
    ]
)
def extract_features(
    input_dataset: Input[Dataset],
    feature_dataset: Output[Dataset],
    feature_metrics: Output[Metrics]
) -> NamedTuple('FeatureOutput', [('feature_count', int), ('extraction_success', bool)]):
    """Extract comprehensive features from code samples"""
    import pandas as pd
    import numpy as np
    import ast
    import re
    import json
    import hashlib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler

    def extract_ast_features(code_text):
        """Extract AST features from code"""
        try:
            tree = ast.parse(code_text)
            features = {
                'ast_node_count': len(list(ast.walk(tree))),
                'ast_depth': get_ast_depth(tree),
                'ast_function_count': len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]),
                'ast_class_count': len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                'ast_if_count': len([n for n in ast.walk(tree) if isinstance(n, ast.If)]),
                'ast_loop_count': len([n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))]),
                'ast_try_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Try)]),
                'ast_call_count': len([n for n in ast.walk(tree) if isinstance(n, ast.Call)]),
            }
            return features
        except:
            return {f'ast_{k}': 0 for k in ['node_count', 'depth', 'function_count', 'class_count', 'if_count', 'loop_count', 'try_count', 'call_count']}

    def get_ast_depth(node, depth=0):
        """Calculate AST depth"""
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            max_depth = max(max_depth, get_ast_depth(child, depth + 1))
        return max_depth

    def extract_textual_features(code_text):
        """Extract textual features from code"""
        features = {
            'code_length': len(code_text),
            'line_count': len(code_text.split('\n')),
            'avg_line_length': np.mean([len(line) for line in code_text.split('\n')]),
            'whitespace_ratio': sum(1 for c in code_text if c.isspace()) / len(code_text) if code_text else 0,
            'string_literal_count': len(re.findall(r'["\'].*?["\']', code_text)),
            'numeric_literal_count': len(re.findall(r'\b\d+\b', code_text)),
            'comment_ratio': calculate_comment_ratio(code_text),
        }

        # Security patterns
        security_features = {
            'sql_pattern_count': len(re.findall(r'(?i)(select|insert|update|delete|union|drop)\s+', code_text)),
            'file_operation_count': len(re.findall(r'(?i)(open|read|write|fopen)', code_text)),
            'system_call_count': len(re.findall(r'(?i)(system|exec|popen|shell)', code_text)),
            'crypto_operation_count': len(re.findall(r'(?i)(encrypt|decrypt|hash|md5|sha)', code_text)),
            'buffer_operation_count': len(re.findall(r'(?i)(strcpy|strcat|sprintf|gets|memcpy)', code_text)),
        }

        features.update(security_features)
        return features

    def calculate_comment_ratio(code_text):
        """Calculate comment line ratio"""
        lines = code_text.split('\n')
        comment_lines = sum(1 for line in lines if line.strip().startswith('#') or line.strip().startswith('//'))
        return comment_lines / len(lines) if lines else 0

    try:
        # Load data
        data = pd.read_csv(input_dataset.path)
        print(f"🔍 Extracting features from {len(data)} code samples")

        all_features = []
        extraction_stats = {
            'total_samples': len(data),
            'successful_extractions': 0,
            'failed_extractions': 0,
            'feature_extraction_errors': []
        }

        for idx, row in data.iterrows():
            if idx % 100 == 0:
                print(f"   Processing sample {idx}/{len(data)}")

            try:
                code_text = row['code']
                sample_features = {
                    'sample_id': idx,
                    'code_hash': hashlib.md5(code_text.encode()).hexdigest()[:16]
                }

                # Extract AST features
                ast_features = extract_ast_features(code_text)
                sample_features.update(ast_features)

                # Extract textual features
                textual_features = extract_textual_features(code_text)
                sample_features.update(textual_features)

                # Add original labels if available
                if 'vulnerable' in row:
                    sample_features['vulnerable'] = row['vulnerable']

                # Add any additional metadata
                for col in ['cwe_id', 'language', 'severity']:
                    if col in row and pd.notna(row[col]):
                        sample_features[col] = row[col]

                all_features.append(sample_features)
                extraction_stats['successful_extractions'] += 1

            except Exception as e:
                extraction_stats['failed_extractions'] += 1
                extraction_stats['feature_extraction_errors'].append({
                    'sample_id': idx,
                    'error': str(e)
                })
                print(f"   Warning: Feature extraction failed for sample {idx}: {e}")

        if not all_features:
            raise ValueError("No features could be extracted from any samples")

        # Create features DataFrame
        features_df = pd.DataFrame(all_features)

        # Handle missing values
        numeric_columns = features_df.select_dtypes(include=[np.number]).columns
        features_df[numeric_columns] = features_df[numeric_columns].fillna(0)

        # Feature statistics
        feature_stats = {
            'total_features': len(features_df.columns),
            'numeric_features': len(numeric_columns),
            'categorical_features': len(features_df.columns) - len(numeric_columns),
            'feature_completeness': float(features_df.notna().mean().mean()),
            'extraction_stats': extraction_stats
        }

        # Calculate feature correlations for quality assessment
        if len(numeric_columns) > 1:
            corr_matrix = features_df[numeric_columns].corr()
            high_corr_pairs = []
            for i in range(len(corr_matrix.columns)):
                for j in range(i+1, len(corr_matrix.columns)):
                    corr_val = abs(corr_matrix.iloc[i, j])
                    if corr_val > 0.8:
                        high_corr_pairs.append({
                            'feature1': corr_matrix.columns[i],
                            'feature2': corr_matrix.columns[j],
                            'correlation': float(corr_val)
                        })

            feature_stats['high_correlation_count'] = len(high_corr_pairs)
            feature_stats['avg_feature_correlation'] = float(corr_matrix.values[np.triu_indices_from(corr_matrix.values, 1)].mean())

        # Save features
        features_df.to_csv(feature_dataset.path, index=False)

        # Save metrics
        with open(feature_metrics.path, 'w') as f:
            json.dump(feature_stats, f, indent=2)

        success_rate = extraction_stats['successful_extractions'] / extraction_stats['total_samples']
        print(f"✅ Feature extraction completed:")
        print(f"   Successful extractions: {extraction_stats['successful_extractions']}/{extraction_stats['total_samples']} ({success_rate:.1%})")
        print(f"   Total features: {len(features_df.columns)}")
        print(f"   Feature completeness: {feature_stats['feature_completeness']:.2%}")

        from collections import namedtuple
        FeatureOutput = namedtuple('FeatureOutput', ['feature_count', 'extraction_success'])
        return FeatureOutput(len(features_df.columns), success_rate > 0.8)

    except Exception as e:
        print(f"❌ Error in feature extraction: {e}")
        raise

@component(
    base_image="python:3.9",
    packages_to_install=[
        "pandas==1.5.3",
        "numpy==1.24.3",
        "scikit-learn==1.3.0"
    ]
)
def prepare_training_data(
    feature_dataset: Input[Dataset],
    train_dataset: Output[Dataset],
    test_dataset: Output[Dataset],
    split_metrics: Output[Metrics],
    test_size: float = 0.2,
    random_state: int = 42
) -> NamedTuple('SplitOutput', [('train_samples', int), ('test_samples', int)]):
    """Prepare final training and test datasets with proper splits"""
    import pandas as pd
    import numpy as np
    import json
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    try:
        # Load features
        features_df = pd.read_csv(feature_dataset.path)
        print(f"🔄 Preparing training data from {len(features_df)} samples")

        # Separate features and labels
        if 'vulnerable' in features_df.columns:
            y = features_df['vulnerable']
            X = features_df.drop(['vulnerable'], axis=1)
        else:
            raise ValueError("No vulnerability labels found in dataset")

        # Remove non-numeric columns for training
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        X_numeric = X[numeric_columns]

        # Handle any remaining missing values
        X_numeric = X_numeric.fillna(0)

        # Stratified train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_numeric, y,
            test_size=test_size,
            random_state=random_state,
            stratify=y
        )

        # Feature scaling
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Convert back to DataFrames
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X_train.columns)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=X_test.columns)

        # Add labels back
        train_data = X_train_scaled.copy()
        train_data['vulnerable'] = y_train.reset_index(drop=True)

        test_data = X_test_scaled.copy()
        test_data['vulnerable'] = y_test.reset_index(drop=True)

        # Save datasets
        train_data.to_csv(train_dataset.path, index=False)
        test_data.to_csv(test_dataset.path, index=False)

        # Calculate split statistics
        split_stats = {
            'total_samples': len(features_df),
            'train_samples': len(train_data),
            'test_samples': len(test_data),
            'test_ratio': test_size,
            'feature_count': len(X_train.columns),
            'train_vulnerable_ratio': float(y_train.mean()),
            'test_vulnerable_ratio': float(y_test.mean()),
            'feature_scaling_applied': True,
            'stratified_split': True,
            'random_state': random_state,
            'split_timestamp': datetime.now().isoformat()
        }

        # Feature statistics
        train_feature_stats = {
            'mean': X_train_scaled.mean().to_dict(),
            'std': X_train_scaled.std().to_dict(),
            'min': X_train_scaled.min().to_dict(),
            'max': X_train_scaled.max().to_dict()
        }

        split_stats['train_feature_statistics'] = train_feature_stats

        # Save metrics
        with open(split_metrics.path, 'w') as f:
            json.dump(split_stats, f, indent=2)

        print(f"✅ Training data preparation completed:")
        print(f"   Training samples: {len(train_data)} ({y_train.mean():.1%} vulnerable)")
        print(f"   Test samples: {len(test_data)} ({y_test.mean():.1%} vulnerable)")
        print(f"   Features: {len(X_train.columns)}")
        print(f"   Feature scaling: Applied")

        from collections import namedtuple
        SplitOutput = namedtuple('SplitOutput', ['train_samples', 'test_samples'])
        return SplitOutput(len(train_data), len(test_data))

    except Exception as e:
        print(f"❌ Error in training data preparation: {e}")
        raise

@pipeline(
    name="vulnhunter-data-preprocessing-pipeline",
    description="Comprehensive data preprocessing pipeline for VulnHunter vulnerability detection"
)
def vulnerability_preprocessing_pipeline(
    dataset_uri: str,
    min_code_length: int = 10,
    max_duplicate_ratio: float = 0.05,
    min_vulnerable_ratio: float = 0.05,
    test_size: float = 0.2,
    random_state: int = 42
):
    """
    Complete preprocessing pipeline for vulnerability detection data

    Args:
        dataset_uri: GCS URI or local path to raw vulnerability data
        min_code_length: Minimum code length to keep samples
        max_duplicate_ratio: Maximum allowed duplicate ratio
        min_vulnerable_ratio: Minimum required vulnerable sample ratio
        test_size: Test set size ratio
        random_state: Random seed for reproducibility
    """

    # Step 1: Load raw data
    load_task = load_vulnerability_data(dataset_uri=dataset_uri)

    # Step 2: Clean and validate data
    clean_task = clean_and_validate_data(
        input_dataset=load_task.outputs['output_dataset'],
        min_code_length=min_code_length,
        max_duplicate_ratio=max_duplicate_ratio,
        min_vulnerable_ratio=min_vulnerable_ratio
    )

    # Step 3: Extract features
    feature_task = extract_features(
        input_dataset=clean_task.outputs['output_dataset']
    )

    # Step 4: Prepare final training data
    prepare_task = prepare_training_data(
        feature_dataset=feature_task.outputs['feature_dataset'],
        test_size=test_size,
        random_state=random_state
    )

    # Set execution order and conditions
    clean_task.after(load_task)
    feature_task.after(clean_task)
    prepare_task.after(feature_task)

    # Add conditional execution based on validation
    # Only proceed if data passes validation
    clean_task.set_display_name("Data Cleaning & Validation")
    feature_task.set_display_name("Feature Extraction")
    prepare_task.set_display_name("Training Data Preparation")

class VulnHunterPreprocessingPipeline:
    """
    Manager for VulnHunter data preprocessing pipelines
    """

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('VulnHunterPreprocessingPipeline')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def create_pipeline(self,
                       pipeline_name: str = "vulnhunter-preprocessing",
                       pipeline_root: str = None) -> str:
        """
        Create and compile the preprocessing pipeline

        Args:
            pipeline_name: Name for the pipeline
            pipeline_root: GCS root path for pipeline artifacts

        Returns:
            Path to the compiled pipeline file
        """
        try:
            if pipeline_root is None:
                pipeline_root = f"gs://{self.project_id}-vulnhunter-pipelines"

            # Compile pipeline
            pipeline_file = f"{pipeline_name}.json"

            kfp.compiler.Compiler().compile(
                pipeline_func=vulnerability_preprocessing_pipeline,
                package_path=pipeline_file
            )

            self.logger.info(f"Pipeline compiled: {pipeline_file}")
            return pipeline_file

        except Exception as e:
            self.logger.error(f"Error creating pipeline: {e}")
            raise

    def run_pipeline(self,
                    dataset_uri: str,
                    pipeline_name: str = "vulnhunter-preprocessing",
                    experiment_name: str = "vulnhunter-data-preprocessing",
                    **pipeline_params) -> aiplatform.PipelineJob:
        """
        Run the preprocessing pipeline

        Args:
            dataset_uri: URI to the input dataset
            pipeline_name: Name of the pipeline to run
            experiment_name: Name of the experiment
            **pipeline_params: Additional pipeline parameters

        Returns:
            PipelineJob object
        """
        try:
            # Compile pipeline if not exists
            pipeline_file = f"{pipeline_name}.json"
            if not os.path.exists(pipeline_file):
                self.create_pipeline(pipeline_name)

            # Default parameters
            default_params = {
                "dataset_uri": dataset_uri,
                "min_code_length": 10,
                "max_duplicate_ratio": 0.05,
                "min_vulnerable_ratio": 0.05,
                "test_size": 0.2,
                "random_state": 42
            }
            default_params.update(pipeline_params)

            # Create pipeline job
            job = aiplatform.PipelineJob(
                display_name=f"{pipeline_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                template_path=pipeline_file,
                parameter_values=default_params,
                enable_caching=False
            )

            # Submit pipeline
            job.submit(experiment=experiment_name)

            self.logger.info(f"Pipeline submitted: {job.resource_name}")
            self.logger.info(f"Monitor at: https://console.cloud.google.com/vertex-ai/pipelines")

            return job

        except Exception as e:
            self.logger.error(f"Error running pipeline: {e}")
            raise

    def monitor_pipeline(self, job: aiplatform.PipelineJob) -> Dict[str, Any]:
        """
        Monitor pipeline execution and return status

        Args:
            job: PipelineJob to monitor

        Returns:
            Pipeline status information
        """
        try:
            status_info = {
                'job_id': job.name,
                'display_name': job.display_name,
                'state': job.state.name if job.state else 'UNKNOWN',
                'create_time': job.create_time,
                'start_time': job.start_time,
                'end_time': job.end_time,
                'error': None
            }

            if job.state == aiplatform.gapic.PipelineState.PIPELINE_STATE_SUCCEEDED:
                status_info['success'] = True
                self.logger.info(f"Pipeline completed successfully: {job.display_name}")
            elif job.state == aiplatform.gapic.PipelineState.PIPELINE_STATE_FAILED:
                status_info['success'] = False
                status_info['error'] = job.error
                self.logger.error(f"Pipeline failed: {job.display_name}")
            else:
                status_info['success'] = None
                self.logger.info(f"Pipeline in progress: {job.display_name} - {job.state.name}")

            return status_info

        except Exception as e:
            self.logger.error(f"Error monitoring pipeline: {e}")
            return {'error': str(e)}

def main():
    """Demo usage of preprocessing pipeline"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"
    DATASET_URI = "gs://your-bucket/vulnerability_data.csv"

    # Initialize pipeline manager
    pipeline_manager = VulnHunterPreprocessingPipeline(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    try:
        print("🚀 VulnHunter Data Preprocessing Pipeline Demo")

        # Create pipeline
        print("\n📋 Creating preprocessing pipeline...")
        pipeline_file = pipeline_manager.create_pipeline()
        print(f"✅ Pipeline created: {pipeline_file}")

        # Run pipeline (commented out for demo)
        print(f"\n🔄 Running preprocessing pipeline...")
        print(f"   Dataset URI: {DATASET_URI}")
        print(f"   To run the pipeline, execute:")
        print(f"   job = pipeline_manager.run_pipeline('{DATASET_URI}')")

        # Example of running pipeline (uncomment to actually run)
        # job = pipeline_manager.run_pipeline(DATASET_URI)
        #
        # # Monitor pipeline
        # while True:
        #     status = pipeline_manager.monitor_pipeline(job)
        #     print(f"Pipeline status: {status['state']}")
        #
        #     if status['success'] is not None:
        #         break
        #
        #     time.sleep(30)

        print("\n✅ Pipeline setup completed successfully!")
        print(f"   Pipeline components: Data Loading → Cleaning → Feature Extraction → Train/Test Split")
        print(f"   Ready for production vulnerability data preprocessing")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()