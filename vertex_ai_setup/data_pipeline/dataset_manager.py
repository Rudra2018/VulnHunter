#!/usr/bin/env python3
"""
Vertex AI Dataset Management for VulnHunter Training
Implements comprehensive dataset management with versioning and lineage tracking.
"""

import json
import logging
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import numpy as np
from google.cloud import aiplatform
from google.cloud import storage
from google.cloud.aiplatform import schema
from google.api_core import exceptions
import yaml

@dataclass
class DatasetMetadata:
    """Metadata for vulnerability datasets"""
    name: str
    version: str
    source: str
    creation_time: datetime
    record_count: int
    vulnerability_types: List[str]
    quality_score: float
    feature_schema: Dict[str, str]
    data_lineage: List[str]
    checksum: str

class VulnHunterDatasetManager:
    """
    Comprehensive dataset management for VulnHunter vulnerability detection
    with Vertex AI integration and advanced data pipeline capabilities.
    """

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        self.storage_client = storage.Client(project=project_id)

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        # Dataset configuration
        self.dataset_bucket = f"{project_id}-vulnhunter-datasets"
        self.feature_bucket = f"{project_id}-vulnhunter-features"
        self.metadata_bucket = f"{project_id}-vulnhunter-metadata"

        # Supported data sources
        self.supported_sources = {
            'github': self._process_github_data,
            'cve': self._process_cve_data,
            'nvd': self._process_nvd_data,
            'manual': self._process_manual_data,
            'synthetic': self._process_synthetic_data
        }

        # Data quality thresholds
        self.quality_thresholds = {
            'min_vulnerability_ratio': 0.1,  # At least 10% vulnerable samples
            'min_code_length': 10,           # Minimum code length
            'max_duplicate_ratio': 0.05,     # Maximum 5% duplicates
            'min_feature_completeness': 0.95  # 95% feature completeness
        }

        self.logger = self._setup_logging()
        self._initialize_infrastructure()

    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('VulnHunterDatasetManager')
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
        """Initialize GCS buckets and Vertex AI datasets"""
        buckets = [self.dataset_bucket, self.feature_bucket, self.metadata_bucket]

        for bucket_name in buckets:
            try:
                bucket = self.storage_client.bucket(bucket_name)
                if not bucket.exists():
                    bucket = self.storage_client.create_bucket(bucket_name, location=self.location)
                    self.logger.info(f"Created bucket: {bucket_name}")
                else:
                    self.logger.info(f"Using existing bucket: {bucket_name}")
            except Exception as e:
                self.logger.error(f"Error with bucket {bucket_name}: {e}")
                raise

    def create_vertex_dataset(self,
                            dataset_name: str,
                            data_source_uris: List[str],
                            dataset_type: str = "TABULAR",
                            labels: Optional[Dict[str, str]] = None) -> aiplatform.TabularDataset:
        """
        Create a Vertex AI Dataset for vulnerability data

        Args:
            dataset_name: Name for the dataset
            data_source_uris: List of GCS URIs containing the data
            dataset_type: Type of dataset (TABULAR, IMAGE, TEXT, VIDEO)
            labels: Optional labels for the dataset

        Returns:
            Vertex AI Dataset object
        """
        try:
            self.logger.info(f"Creating Vertex AI dataset: {dataset_name}")

            # Default labels
            if labels is None:
                labels = {
                    'project': 'vulnhunter',
                    'team': 'security',
                    'purpose': 'vulnerability-detection'
                }

            # Create dataset based on type
            if dataset_type == "TABULAR":
                dataset = aiplatform.TabularDataset.create(
                    display_name=dataset_name,
                    gcs_source=data_source_uris,
                    labels=labels
                )
            elif dataset_type == "TEXT":
                dataset = aiplatform.TextDataset.create(
                    display_name=dataset_name,
                    gcs_source=data_source_uris,
                    labels=labels
                )
            else:
                raise ValueError(f"Unsupported dataset type: {dataset_type}")

            self.logger.info(f"Created dataset: {dataset.resource_name}")
            return dataset

        except Exception as e:
            self.logger.error(f"Error creating Vertex AI dataset: {e}")
            raise

    def upload_vulnerability_data(self,
                                data: pd.DataFrame,
                                dataset_name: str,
                                source: str,
                                version: Optional[str] = None) -> DatasetMetadata:
        """
        Upload vulnerability data to GCS with comprehensive metadata tracking

        Args:
            data: DataFrame containing vulnerability data
            dataset_name: Name for the dataset
            source: Source of the data (github, cve, nvd, etc.)
            version: Optional version string

        Returns:
            DatasetMetadata object
        """
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # Data validation and quality assessment
            quality_report = self._assess_data_quality(data)

            if quality_report['overall_score'] < 0.7:
                self.logger.warning(f"Data quality score {quality_report['overall_score']} below threshold")

            # Process data based on source
            if source in self.supported_sources:
                processed_data = self.supported_sources[source](data)
            else:
                processed_data = data

            # Generate data checksum
            data_str = processed_data.to_csv(index=False)
            checksum = hashlib.sha256(data_str.encode()).hexdigest()

            # Upload to GCS
            blob_name = f"{dataset_name}/v{version}/data.csv"
            bucket = self.storage_client.bucket(self.dataset_bucket)
            blob = bucket.blob(blob_name)
            blob.upload_from_string(data_str)

            # Create metadata
            metadata = DatasetMetadata(
                name=dataset_name,
                version=version,
                source=source,
                creation_time=datetime.now(),
                record_count=len(processed_data),
                vulnerability_types=self._extract_vulnerability_types(processed_data),
                quality_score=quality_report['overall_score'],
                feature_schema=self._extract_feature_schema(processed_data),
                data_lineage=[source],
                checksum=checksum
            )

            # Upload metadata
            self._upload_metadata(metadata)

            self.logger.info(f"Uploaded dataset {dataset_name} v{version} with {len(processed_data)} records")
            return metadata

        except Exception as e:
            self.logger.error(f"Error uploading vulnerability data: {e}")
            raise

    def _assess_data_quality(self, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Comprehensive data quality assessment for vulnerability datasets

        Args:
            data: DataFrame to assess

        Returns:
            Quality assessment report
        """
        report = {
            'timestamp': datetime.now(),
            'total_records': len(data),
            'checks': {}
        }

        try:
            # Check for required columns
            required_cols = ['code', 'vulnerable', 'cwe_id']
            missing_cols = [col for col in required_cols if col not in data.columns]
            report['checks']['required_columns'] = {
                'passed': len(missing_cols) == 0,
                'missing_columns': missing_cols,
                'score': 1.0 if len(missing_cols) == 0 else 0.0
            }

            # Check vulnerability ratio
            if 'vulnerable' in data.columns:
                vuln_ratio = data['vulnerable'].mean()
                report['checks']['vulnerability_ratio'] = {
                    'passed': vuln_ratio >= self.quality_thresholds['min_vulnerability_ratio'],
                    'ratio': vuln_ratio,
                    'score': min(1.0, vuln_ratio / self.quality_thresholds['min_vulnerability_ratio'])
                }

            # Check code quality
            if 'code' in data.columns:
                avg_code_length = data['code'].str.len().mean()
                report['checks']['code_length'] = {
                    'passed': avg_code_length >= self.quality_thresholds['min_code_length'],
                    'average_length': avg_code_length,
                    'score': min(1.0, avg_code_length / self.quality_thresholds['min_code_length'])
                }

                # Check for duplicates
                duplicate_ratio = data['code'].duplicated().mean()
                report['checks']['duplicates'] = {
                    'passed': duplicate_ratio <= self.quality_thresholds['max_duplicate_ratio'],
                    'duplicate_ratio': duplicate_ratio,
                    'score': max(0.0, 1.0 - duplicate_ratio / self.quality_thresholds['max_duplicate_ratio'])
                }

            # Check feature completeness
            completeness = data.notna().mean().mean()
            report['checks']['completeness'] = {
                'passed': completeness >= self.quality_thresholds['min_feature_completeness'],
                'completeness': completeness,
                'score': completeness
            }

            # Calculate overall score
            scores = [check['score'] for check in report['checks'].values()]
            report['overall_score'] = np.mean(scores)
            report['passed'] = report['overall_score'] >= 0.7

        except Exception as e:
            self.logger.error(f"Error in data quality assessment: {e}")
            report['error'] = str(e)
            report['overall_score'] = 0.0

        return report

    def _process_github_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Process GitHub vulnerability data"""
        # Standardize column names
        column_mapping = {
            'repository': 'repo_name',
            'commit_id': 'commit_hash',
            'file_path': 'file_name'
        }

        processed_data = data.rename(columns=column_mapping)

        # Add GitHub-specific features
        if 'repo_name' in processed_data.columns:
            processed_data['source_type'] = 'github'
            processed_data['repo_stars'] = processed_data.get('stars', 0)
            processed_data['repo_language'] = processed_data.get('language', 'unknown')

        return processed_data

    def _process_cve_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Process CVE vulnerability data"""
        processed_data = data.copy()

        # Standardize CVE information
        if 'cve_id' in processed_data.columns:
            processed_data['source_type'] = 'cve'
            processed_data['severity'] = processed_data.get('cvss_score', 0.0)

        return processed_data

    def _process_nvd_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Process NVD vulnerability data"""
        processed_data = data.copy()
        processed_data['source_type'] = 'nvd'

        # Parse CVSS scores and vectors
        if 'cvss_vector' in processed_data.columns:
            processed_data['attack_vector'] = processed_data['cvss_vector'].str.extract(r'AV:([A-Z])')
            processed_data['attack_complexity'] = processed_data['cvss_vector'].str.extract(r'AC:([A-Z])')

        return processed_data

    def _process_manual_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Process manually labeled vulnerability data"""
        processed_data = data.copy()
        processed_data['source_type'] = 'manual'
        processed_data['quality_score'] = 1.0  # Manual data assumed high quality

        return processed_data

    def _process_synthetic_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Process synthetic vulnerability data"""
        processed_data = data.copy()
        processed_data['source_type'] = 'synthetic'
        processed_data['generation_method'] = processed_data.get('method', 'unknown')

        return processed_data

    def _extract_vulnerability_types(self, data: pd.DataFrame) -> List[str]:
        """Extract unique vulnerability types from data"""
        vuln_types = set()

        if 'cwe_id' in data.columns:
            vuln_types.update(data['cwe_id'].dropna().astype(str).unique())

        if 'vulnerability_type' in data.columns:
            vuln_types.update(data['vulnerability_type'].dropna().unique())

        return sorted(list(vuln_types))

    def _extract_feature_schema(self, data: pd.DataFrame) -> Dict[str, str]:
        """Extract feature schema from DataFrame"""
        schema = {}

        for column in data.columns:
            dtype = str(data[column].dtype)
            if dtype.startswith('int'):
                schema[column] = 'integer'
            elif dtype.startswith('float'):
                schema[column] = 'float'
            elif dtype.startswith('bool'):
                schema[column] = 'boolean'
            else:
                schema[column] = 'string'

        return schema

    def _upload_metadata(self, metadata: DatasetMetadata):
        """Upload dataset metadata to GCS"""
        try:
            metadata_dict = {
                'name': metadata.name,
                'version': metadata.version,
                'source': metadata.source,
                'creation_time': metadata.creation_time.isoformat(),
                'record_count': metadata.record_count,
                'vulnerability_types': metadata.vulnerability_types,
                'quality_score': metadata.quality_score,
                'feature_schema': metadata.feature_schema,
                'data_lineage': metadata.data_lineage,
                'checksum': metadata.checksum
            }

            blob_name = f"{metadata.name}/v{metadata.version}/metadata.json"
            bucket = self.storage_client.bucket(self.metadata_bucket)
            blob = bucket.blob(blob_name)
            blob.upload_from_string(json.dumps(metadata_dict, indent=2))

            self.logger.info(f"Uploaded metadata for {metadata.name} v{metadata.version}")

        except Exception as e:
            self.logger.error(f"Error uploading metadata: {e}")
            raise

    def get_dataset_metadata(self, dataset_name: str, version: str) -> Optional[DatasetMetadata]:
        """Retrieve dataset metadata"""
        try:
            blob_name = f"{dataset_name}/v{version}/metadata.json"
            bucket = self.storage_client.bucket(self.metadata_bucket)
            blob = bucket.blob(blob_name)

            if not blob.exists():
                return None

            metadata_json = json.loads(blob.download_as_text())

            metadata = DatasetMetadata(
                name=metadata_json['name'],
                version=metadata_json['version'],
                source=metadata_json['source'],
                creation_time=datetime.fromisoformat(metadata_json['creation_time']),
                record_count=metadata_json['record_count'],
                vulnerability_types=metadata_json['vulnerability_types'],
                quality_score=metadata_json['quality_score'],
                feature_schema=metadata_json['feature_schema'],
                data_lineage=metadata_json['data_lineage'],
                checksum=metadata_json['checksum']
            )

            return metadata

        except Exception as e:
            self.logger.error(f"Error retrieving metadata: {e}")
            return None

    def list_datasets(self) -> List[Dict[str, Any]]:
        """List all available datasets with their metadata"""
        datasets = []

        try:
            bucket = self.storage_client.bucket(self.metadata_bucket)
            blobs = bucket.list_blobs()

            for blob in blobs:
                if blob.name.endswith('metadata.json'):
                    try:
                        metadata_json = json.loads(blob.download_as_text())
                        datasets.append({
                            'name': metadata_json['name'],
                            'version': metadata_json['version'],
                            'source': metadata_json['source'],
                            'creation_time': metadata_json['creation_time'],
                            'record_count': metadata_json['record_count'],
                            'quality_score': metadata_json['quality_score'],
                            'gcs_path': f"gs://{self.dataset_bucket}/{metadata_json['name']}/v{metadata_json['version']}/data.csv"
                        })
                    except Exception as e:
                        self.logger.warning(f"Error processing metadata {blob.name}: {e}")

            # Sort by creation time (newest first)
            datasets.sort(key=lambda x: x['creation_time'], reverse=True)

        except Exception as e:
            self.logger.error(f"Error listing datasets: {e}")

        return datasets

    def merge_datasets(self,
                      dataset_names: List[str],
                      versions: List[str],
                      merged_name: str,
                      remove_duplicates: bool = True) -> DatasetMetadata:
        """
        Merge multiple datasets into a single dataset

        Args:
            dataset_names: List of dataset names to merge
            versions: List of corresponding versions
            merged_name: Name for the merged dataset
            remove_duplicates: Whether to remove duplicate records

        Returns:
            Metadata for the merged dataset
        """
        try:
            merged_data = []
            data_lineage = []

            for name, version in zip(dataset_names, versions):
                # Load dataset
                blob_name = f"{name}/v{version}/data.csv"
                bucket = self.storage_client.bucket(self.dataset_bucket)
                blob = bucket.blob(blob_name)

                if blob.exists():
                    data_str = blob.download_as_text()
                    data = pd.read_csv(pd.StringIO(data_str))
                    merged_data.append(data)
                    data_lineage.append(f"{name}_v{version}")
                else:
                    self.logger.warning(f"Dataset {name} v{version} not found")

            if not merged_data:
                raise ValueError("No datasets found to merge")

            # Combine datasets
            combined_data = pd.concat(merged_data, ignore_index=True)

            # Remove duplicates if requested
            if remove_duplicates and 'code' in combined_data.columns:
                initial_count = len(combined_data)
                combined_data = combined_data.drop_duplicates(subset=['code'])
                final_count = len(combined_data)
                self.logger.info(f"Removed {initial_count - final_count} duplicate records")

            # Upload merged dataset
            metadata = self.upload_vulnerability_data(
                data=combined_data,
                dataset_name=merged_name,
                source='merged'
            )

            # Update lineage
            metadata.data_lineage = data_lineage
            self._upload_metadata(metadata)

            return metadata

        except Exception as e:
            self.logger.error(f"Error merging datasets: {e}")
            raise

    def validate_dataset_integrity(self, dataset_name: str, version: str) -> Dict[str, Any]:
        """
        Validate dataset integrity using checksums and quality checks

        Args:
            dataset_name: Name of dataset to validate
            version: Version of dataset to validate

        Returns:
            Validation report
        """
        try:
            # Load metadata
            metadata = self.get_dataset_metadata(dataset_name, version)
            if metadata is None:
                return {'valid': False, 'error': 'Metadata not found'}

            # Load actual data
            blob_name = f"{dataset_name}/v{version}/data.csv"
            bucket = self.storage_client.bucket(self.dataset_bucket)
            blob = bucket.blob(blob_name)

            if not blob.exists():
                return {'valid': False, 'error': 'Data file not found'}

            data_str = blob.download_as_text()
            data = pd.read_csv(pd.StringIO(data_str))

            # Validate checksum
            current_checksum = hashlib.sha256(data_str.encode()).hexdigest()
            checksum_valid = current_checksum == metadata.checksum

            # Validate record count
            count_valid = len(data) == metadata.record_count

            # Re-assess data quality
            quality_report = self._assess_data_quality(data)

            validation_report = {
                'valid': checksum_valid and count_valid and quality_report['passed'],
                'checksum_valid': checksum_valid,
                'count_valid': count_valid,
                'expected_count': metadata.record_count,
                'actual_count': len(data),
                'quality_report': quality_report,
                'validation_time': datetime.now().isoformat()
            }

            return validation_report

        except Exception as e:
            self.logger.error(f"Error validating dataset integrity: {e}")
            return {'valid': False, 'error': str(e)}

def main():
    """Demo usage of VulnHunterDatasetManager"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Initialize dataset manager
    dataset_manager = VulnHunterDatasetManager(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    # Create sample vulnerability data
    sample_data = pd.DataFrame({
        'code': [
            'if (user_input) { system(user_input); }',  # Command injection
            'strcpy(buffer, input);',                   # Buffer overflow
            'SELECT * FROM users WHERE id = %s' % user_id,  # SQL injection
            'return input;',                           # Safe code
        ],
        'vulnerable': [1, 1, 1, 0],
        'cwe_id': ['CWE-78', 'CWE-120', 'CWE-89', None],
        'language': ['C', 'C', 'Python', 'Python'],
        'severity': [8.1, 9.3, 7.5, 0.0]
    })

    try:
        print("🚀 VulnHunter Dataset Manager Demo")

        # Upload dataset
        print("\n📤 Uploading sample vulnerability data...")
        metadata = dataset_manager.upload_vulnerability_data(
            data=sample_data,
            dataset_name="demo_vulnerabilities",
            source="manual"
        )
        print(f"✅ Uploaded dataset: {metadata.name} v{metadata.version}")
        print(f"   Records: {metadata.record_count}")
        print(f"   Quality Score: {metadata.quality_score:.2f}")
        print(f"   Vulnerability Types: {metadata.vulnerability_types}")

        # Create Vertex AI dataset
        print(f"\n🔗 Creating Vertex AI dataset...")
        gcs_uri = f"gs://{dataset_manager.dataset_bucket}/{metadata.name}/v{metadata.version}/data.csv"
        vertex_dataset = dataset_manager.create_vertex_dataset(
            dataset_name=f"vulnhunter_{metadata.name}",
            data_source_uris=[gcs_uri]
        )
        print(f"✅ Created Vertex AI dataset: {vertex_dataset.resource_name}")

        # List datasets
        print(f"\n📋 Listing all datasets...")
        datasets = dataset_manager.list_datasets()
        for ds in datasets[:5]:  # Show first 5
            print(f"   - {ds['name']} v{ds['version']} ({ds['record_count']} records, score: {ds['quality_score']:.2f})")

        # Validate dataset
        print(f"\n🔍 Validating dataset integrity...")
        validation_report = dataset_manager.validate_dataset_integrity(
            metadata.name, metadata.version
        )
        print(f"✅ Dataset valid: {validation_report['valid']}")
        print(f"   Checksum valid: {validation_report['checksum_valid']}")
        print(f"   Record count valid: {validation_report['count_valid']}")

        print("\n✅ Dataset management demo completed successfully!")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()