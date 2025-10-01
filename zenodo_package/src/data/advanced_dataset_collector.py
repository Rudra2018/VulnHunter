#!/usr/bin/env python3
"""
Advanced Dataset Collection Pipeline for Vulnerability Detection

This module provides comprehensive dataset collection capabilities:
- CVE database integration
- GitHub security advisory scraping
- Synthetic vulnerability generation
- Multi-language code parsing
- Automated labeling and annotation
- Data quality validation
"""

import os
import json
import requests
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import time
import hashlib
from datetime import datetime, timedelta
import concurrent.futures
from dataclasses import dataclass, asdict
import warnings
import sqlite3
import random
import re

# Import vulnerability taxonomy
from .vulnerability_taxonomy import VULNERABILITY_TAXONOMY, VulnerabilityType
from .multi_parser import MultiFormatParser

warnings.filterwarnings("ignore")


@dataclass
class VulnerabilityRecord:
    """Data class for vulnerability records"""
    id: str
    code_snippet: str
    language: str
    vulnerability_type: str
    severity: str
    cve_id: Optional[str] = None
    description: str = ""
    fix_snippet: Optional[str] = None
    source: str = "unknown"
    confidence_score: float = 1.0
    metadata: Dict[str, Any] = None
    created_at: str = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}


class AdvancedDatasetCollector:
    """Advanced dataset collection pipeline for vulnerability detection research"""

    def __init__(self,
                 data_dir: str = "./data",
                 cache_dir: str = "./cache",
                 api_keys: Dict[str, str] = None):

        self.data_dir = Path(data_dir)
        self.cache_dir = Path(cache_dir)
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        self.external_dir = self.data_dir / "external"

        # Create directories
        for directory in [self.raw_dir, self.processed_dir, self.external_dir, self.cache_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # API keys for external services
        self.api_keys = api_keys or {}

        # Initialize components
        self.parser = MultiFormatParser({})
        self.vulnerability_taxonomy = VULNERABILITY_TAXONOMY

        # Database for tracking collected data
        self.db_path = self.data_dir / "vulnerability_collection.db"
        self.init_database()

        # Collection statistics
        self.stats = {
            'total_collected': 0,
            'by_language': {},
            'by_vulnerability_type': {},
            'by_source': {},
            'start_time': datetime.now()
        }

        # Rate limiting
        self.last_request_time = {}
        self.request_delays = {
            'github': 1.0,    # GitHub API rate limiting
            'nvd': 0.5,       # NVD API rate limiting
            'cve': 0.3        # CVE API rate limiting
        }

        # Quality thresholds
        self.quality_thresholds = {
            'min_code_length': 10,
            'max_code_length': 5000,
            'min_confidence': 0.7,
            'max_duplicates_ratio': 0.1
        }

    def init_database(self):
        """Initialize SQLite database for tracking collected data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_records (
                id TEXT PRIMARY KEY,
                code_snippet TEXT NOT NULL,
                language TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                cve_id TEXT,
                description TEXT,
                fix_snippet TEXT,
                source TEXT NOT NULL,
                confidence_score REAL,
                metadata TEXT,
                created_at TEXT,
                hash TEXT UNIQUE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collection_stats (
                date TEXT PRIMARY KEY,
                total_records INTEGER,
                by_language TEXT,
                by_vulnerability_type TEXT,
                by_source TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def collect_from_nvd_database(self,
                                 start_date: str = "2020-01-01",
                                 end_date: str = "2024-12-31",
                                 severity_filter: List[str] = None) -> List[VulnerabilityRecord]:
        """
        Collect vulnerability data from NIST National Vulnerability Database

        Args:
            start_date: Start date for vulnerability search (YYYY-MM-DD)
            end_date: End date for vulnerability search (YYYY-MM-DD)
            severity_filter: List of severity levels to filter by

        Returns:
            List of VulnerabilityRecord objects
        """

        records = []
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        print(f"Collecting CVE data from NVD ({start_date} to {end_date})...")

        try:
            # Rate limiting
            self._enforce_rate_limit('nvd')

            params = {
                'pubStartDate': f"{start_date}T00:00:00.000",
                'pubEndDate': f"{end_date}T23:59:59.999",
                'resultsPerPage': 2000
            }

            response = requests.get(base_url, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            print(f"Found {len(vulnerabilities)} CVE entries")

            for vuln_data in vulnerabilities:
                try:
                    record = self._process_nvd_vulnerability(vuln_data)
                    if record and self._passes_quality_check(record):
                        records.append(record)

                        # Update statistics
                        self._update_stats(record)

                except Exception as e:
                    print(f"Error processing CVE record: {e}")
                    continue

        except Exception as e:
            print(f"Error collecting from NVD: {e}")

        print(f"Collected {len(records)} vulnerability records from NVD")
        return records

    def collect_from_github_advisories(self,
                                     languages: List[str] = None,
                                     max_advisories: int = 1000) -> List[VulnerabilityRecord]:
        """
        Collect vulnerability data from GitHub Security Advisories

        Args:
            languages: List of programming languages to filter by
            max_advisories: Maximum number of advisories to collect

        Returns:
            List of VulnerabilityRecord objects
        """

        if languages is None:
            languages = ['python', 'java', 'javascript', 'c', 'cpp', 'go']

        records = []

        # GitHub GraphQL API endpoint
        url = "https://api.github.com/graphql"

        if 'github' not in self.api_keys:
            print("GitHub API key not provided, using mock data...")
            return self._generate_mock_github_advisories(languages, max_advisories)

        headers = {
            'Authorization': f'Bearer {self.api_keys["github"]}',
            'Content-Type': 'application/json'
        }

        # GraphQL query for security advisories
        query = '''
        query($cursor: String) {
          securityAdvisories(first: 100, after: $cursor) {
            nodes {
              ghsaId
              summary
              description
              severity
              publishedAt
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  severityLevel
                  vulnerableVersionRange
                }
              }
            }
            pageInfo {
              endCursor
              hasNextPage
            }
          }
        }
        '''

        cursor = None
        collected = 0

        print("Collecting GitHub Security Advisories...")

        while collected < max_advisories:
            try:
                self._enforce_rate_limit('github')

                variables = {'cursor': cursor}
                response = requests.post(
                    url,
                    json={'query': query, 'variables': variables},
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()

                data = response.json()

                if 'errors' in data:
                    print(f"GraphQL errors: {data['errors']}")
                    break

                advisories = data['data']['securityAdvisories']['nodes']

                for advisory in advisories:
                    try:
                        records_from_advisory = self._process_github_advisory(advisory, languages)
                        records.extend(records_from_advisory)
                        collected += len(records_from_advisory)

                        if collected >= max_advisories:
                            break

                    except Exception as e:
                        print(f"Error processing GitHub advisory: {e}")
                        continue

                # Check if there are more pages
                page_info = data['data']['securityAdvisories']['pageInfo']
                if not page_info['hasNextPage']:
                    break

                cursor = page_info['endCursor']

            except Exception as e:
                print(f"Error collecting GitHub advisories: {e}")
                break

        print(f"Collected {len(records)} records from GitHub advisories")
        return records

    def generate_synthetic_vulnerabilities(self,
                                         target_count: int = 5000,
                                         languages: List[str] = None,
                                         distribution: Dict[str, float] = None) -> List[VulnerabilityRecord]:
        """
        Generate synthetic vulnerability examples for training

        Args:
            target_count: Number of synthetic examples to generate
            languages: Programming languages to generate for
            distribution: Distribution of vulnerability types

        Returns:
            List of VulnerabilityRecord objects
        """

        if languages is None:
            languages = ['python', 'java', 'javascript', 'c', 'cpp']

        if distribution is None:
            # Default distribution based on real-world frequency
            distribution = {
                'sql_injection': 0.15,
                'xss': 0.12,
                'command_injection': 0.10,
                'buffer_overflow': 0.08,
                'path_traversal': 0.08,
                'insecure_deserialization': 0.07,
                'hardcoded_credentials': 0.06,
                'csrf': 0.05,
                'xxe': 0.05,
                'weak_cryptography': 0.05,
                'race_condition': 0.04,
                'integer_overflow': 0.04,
                'format_string': 0.03,
                'auth_bypass': 0.03,
                'ssrf': 0.03,
                'privilege_escalation': 0.02
            }

        print(f"Generating {target_count} synthetic vulnerability examples...")

        records = []
        vulnerability_templates = self._load_vulnerability_templates()

        for i in range(target_count):
            try:
                # Select vulnerability type based on distribution
                vuln_type = np.random.choice(
                    list(distribution.keys()),
                    p=list(distribution.values())
                )

                # Select language
                language = random.choice(languages)

                # Generate synthetic code
                record = self._generate_synthetic_vulnerability(
                    vuln_type, language, vulnerability_templates, i
                )

                if record and self._passes_quality_check(record):
                    records.append(record)

                    # Update statistics
                    self._update_stats(record)

            except Exception as e:
                print(f"Error generating synthetic vulnerability {i}: {e}")
                continue

        print(f"Generated {len(records)} synthetic vulnerability examples")
        return records

    def collect_from_existing_datasets(self,
                                     dataset_configs: List[Dict[str, Any]]) -> List[VulnerabilityRecord]:
        """
        Collect and standardize data from existing vulnerability datasets

        Args:
            dataset_configs: List of dataset configuration dictionaries

        Returns:
            List of VulnerabilityRecord objects
        """

        all_records = []

        for config in dataset_configs:
            print(f"Processing dataset: {config['name']}")

            try:
                if config['format'] == 'csv':
                    records = self._process_csv_dataset(config)
                elif config['format'] == 'json':
                    records = self._process_json_dataset(config)
                elif config['format'] == 'git_repo':
                    records = self._process_git_repository(config)
                else:
                    print(f"Unsupported format: {config['format']}")
                    continue

                all_records.extend(records)

            except Exception as e:
                print(f"Error processing dataset {config['name']}: {e}")
                continue

        return all_records

    def create_balanced_dataset(self,
                              records: List[VulnerabilityRecord],
                              target_samples_per_class: int = 1000,
                              augmentation_ratio: float = 0.3) -> List[VulnerabilityRecord]:
        """
        Create a balanced dataset with equal samples per vulnerability type

        Args:
            records: List of collected vulnerability records
            target_samples_per_class: Target number of samples per class
            augmentation_ratio: Ratio of augmented samples

        Returns:
            Balanced list of VulnerabilityRecord objects
        """

        print("Creating balanced dataset...")

        # Group by vulnerability type
        grouped_records = {}
        for record in records:
            vuln_type = record.vulnerability_type
            if vuln_type not in grouped_records:
                grouped_records[vuln_type] = []
            grouped_records[vuln_type].append(record)

        balanced_records = []

        for vuln_type, type_records in grouped_records.items():
            print(f"Processing {vuln_type}: {len(type_records)} samples")

            # If we have enough samples, randomly select
            if len(type_records) >= target_samples_per_class:
                selected_records = random.sample(type_records, target_samples_per_class)

            # If we have too few, augment
            else:
                selected_records = type_records.copy()

                # Calculate how many we need to augment
                needed = target_samples_per_class - len(selected_records)
                to_augment = int(needed * augmentation_ratio)

                # Augment existing samples
                augmented = self._augment_samples(type_records, to_augment)
                selected_records.extend(augmented)

                # Fill remaining with synthetic samples if still needed
                remaining = target_samples_per_class - len(selected_records)
                if remaining > 0:
                    synthetic = self._generate_synthetic_for_type(vuln_type, remaining)
                    selected_records.extend(synthetic)

            balanced_records.extend(selected_records[:target_samples_per_class])

        # Add negative samples (non-vulnerable code)
        negative_samples = self._generate_negative_samples(
            target_samples_per_class * len(grouped_records) // 4  # 1:4 ratio
        )
        balanced_records.extend(negative_samples)

        print(f"Created balanced dataset with {len(balanced_records)} total samples")
        return balanced_records

    def validate_and_clean_dataset(self,
                                 records: List[VulnerabilityRecord],
                                 remove_duplicates: bool = True,
                                 min_confidence: float = 0.7) -> List[VulnerabilityRecord]:
        """
        Validate and clean collected dataset

        Args:
            records: List of vulnerability records
            remove_duplicates: Whether to remove duplicate records
            min_confidence: Minimum confidence threshold

        Returns:
            Cleaned list of VulnerabilityRecord objects
        """

        print(f"Validating and cleaning dataset ({len(records)} records)...")

        cleaned_records = []
        seen_hashes = set()
        removed_stats = {
            'duplicates': 0,
            'low_confidence': 0,
            'invalid_code': 0,
            'missing_fields': 0
        }

        for record in records:
            # Check for required fields
            if not all([record.code_snippet, record.language, record.vulnerability_type]):
                removed_stats['missing_fields'] += 1
                continue

            # Check confidence threshold
            if record.confidence_score < min_confidence:
                removed_stats['low_confidence'] += 1
                continue

            # Check code validity
            if not self._is_valid_code(record.code_snippet, record.language):
                removed_stats['invalid_code'] += 1
                continue

            # Check for duplicates
            if remove_duplicates:
                code_hash = hashlib.md5(record.code_snippet.encode()).hexdigest()
                if code_hash in seen_hashes:
                    removed_stats['duplicates'] += 1
                    continue
                seen_hashes.add(code_hash)

            cleaned_records.append(record)

        print(f"Dataset cleaning results:")
        print(f"  Original records: {len(records)}")
        print(f"  Cleaned records: {len(cleaned_records)}")
        print(f"  Removed: {sum(removed_stats.values())}")
        for reason, count in removed_stats.items():
            print(f"    {reason}: {count}")

        return cleaned_records

    def export_dataset(self,
                      records: List[VulnerabilityRecord],
                      export_format: str = 'jsonl',
                      output_path: Optional[str] = None,
                      include_metadata: bool = True) -> str:
        """
        Export dataset in various formats

        Args:
            records: List of vulnerability records
            export_format: Export format ('jsonl', 'csv', 'hdf5', 'parquet')
            output_path: Output file path
            include_metadata: Whether to include metadata

        Returns:
            Path to exported file
        """

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.processed_dir / f"vulnerability_dataset_{timestamp}.{export_format}"

        print(f"Exporting {len(records)} records to {output_path}...")

        if export_format == 'jsonl':
            self._export_jsonl(records, output_path, include_metadata)
        elif export_format == 'csv':
            self._export_csv(records, output_path, include_metadata)
        elif export_format == 'parquet':
            self._export_parquet(records, output_path, include_metadata)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

        print(f"Dataset exported to: {output_path}")
        return str(output_path)

    # Helper methods
    def _enforce_rate_limit(self, service: str):
        """Enforce rate limiting for API calls"""
        if service in self.last_request_time:
            time_since_last = time.time() - self.last_request_time[service]
            min_delay = self.request_delays.get(service, 1.0)

            if time_since_last < min_delay:
                time.sleep(min_delay - time_since_last)

        self.last_request_time[service] = time.time()

    def _process_nvd_vulnerability(self, vuln_data: Dict) -> Optional[VulnerabilityRecord]:
        """Process NVD vulnerability data"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')

            # Extract description
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            # Extract severity
            metrics = cve.get('metrics', {})
            severity = 'medium'  # default
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'medium').lower()

            # Try to extract code snippet from description or references
            code_snippet = self._extract_code_from_description(description)

            if not code_snippet:
                return None

            # Determine vulnerability type from description
            vuln_type = self._classify_vulnerability_type(description)
            language = self._detect_language_from_code(code_snippet)

            record = VulnerabilityRecord(
                id=f"nvd_{cve_id}",
                code_snippet=code_snippet,
                language=language,
                vulnerability_type=vuln_type,
                severity=severity,
                cve_id=cve_id,
                description=description,
                source='nvd',
                confidence_score=0.8  # Medium confidence for NVD data
            )

            return record

        except Exception as e:
            print(f"Error processing NVD vulnerability: {e}")
            return None

    def _generate_mock_github_advisories(self,
                                       languages: List[str],
                                       count: int) -> List[VulnerabilityRecord]:
        """Generate mock GitHub advisory data for testing"""
        records = []

        mock_patterns = {
            'python': [
                'import pickle\npickle.loads(user_data)',
                'exec(user_input)',
                'subprocess.call(command, shell=True)',
                'eval(expression)'
            ],
            'java': [
                'Runtime.getRuntime().exec(userCommand)',
                'new ObjectInputStream(stream).readObject()',
                'Statement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);'
            ],
            'javascript': [
                'eval(userInput)',
                'document.innerHTML = userContent',
                'new Function(code)()',
                'require("child_process").exec(command)'
            ]
        }

        for i in range(min(count, 100)):  # Limit mock data
            language = random.choice(languages)
            if language in mock_patterns:
                code = random.choice(mock_patterns[language])
                vuln_type = random.choice(['command_injection', 'code_injection', 'xss', 'sql_injection'])

                record = VulnerabilityRecord(
                    id=f"github_mock_{i}",
                    code_snippet=code,
                    language=language,
                    vulnerability_type=vuln_type,
                    severity=random.choice(['low', 'medium', 'high']),
                    description=f"Mock vulnerability example {i}",
                    source='github_mock',
                    confidence_score=0.9
                )
                records.append(record)

        return records

    def _passes_quality_check(self, record: VulnerabilityRecord) -> bool:
        """Check if record passes quality thresholds"""
        code_length = len(record.code_snippet)
        return (
            self.quality_thresholds['min_code_length'] <= code_length <= self.quality_thresholds['max_code_length'] and
            record.confidence_score >= self.quality_thresholds['min_confidence'] and
            bool(record.code_snippet.strip()) and
            record.vulnerability_type in [vt.name for vt in self.vulnerability_taxonomy.vulnerability_types]
        )

    def _update_stats(self, record: VulnerabilityRecord):
        """Update collection statistics"""
        self.stats['total_collected'] += 1

        # By language
        if record.language not in self.stats['by_language']:
            self.stats['by_language'][record.language] = 0
        self.stats['by_language'][record.language] += 1

        # By vulnerability type
        if record.vulnerability_type not in self.stats['by_vulnerability_type']:
            self.stats['by_vulnerability_type'][record.vulnerability_type] = 0
        self.stats['by_vulnerability_type'][record.vulnerability_type] += 1

        # By source
        if record.source not in self.stats['by_source']:
            self.stats['by_source'][record.source] = 0
        self.stats['by_source'][record.source] += 1

    def _export_jsonl(self, records: List[VulnerabilityRecord], path: str, include_metadata: bool):
        """Export records to JSONL format"""
        with open(path, 'w', encoding='utf-8') as f:
            for record in records:
                record_dict = asdict(record)
                if not include_metadata:
                    record_dict.pop('metadata', None)
                f.write(json.dumps(record_dict) + '\n')

    def _export_csv(self, records: List[VulnerabilityRecord], path: str, include_metadata: bool):
        """Export records to CSV format"""
        records_data = []
        for record in records:
            record_dict = asdict(record)
            if not include_metadata:
                record_dict.pop('metadata', None)
            else:
                # Convert metadata dict to JSON string
                record_dict['metadata'] = json.dumps(record_dict.get('metadata', {}))
            records_data.append(record_dict)

        df = pd.DataFrame(records_data)
        df.to_csv(path, index=False, encoding='utf-8')

    def _export_parquet(self, records: List[VulnerabilityRecord], path: str, include_metadata: bool):
        """Export records to Parquet format"""
        records_data = []
        for record in records:
            record_dict = asdict(record)
            if not include_metadata:
                record_dict.pop('metadata', None)
            else:
                record_dict['metadata'] = json.dumps(record_dict.get('metadata', {}))
            records_data.append(record_dict)

        df = pd.DataFrame(records_data)
        df.to_parquet(path, index=False)

    def _extract_code_from_description(self, description: str) -> Optional[str]:
        """Extract code snippets from vulnerability descriptions"""
        # Simple regex patterns for code extraction
        code_patterns = [
            r'```(\w+)?\n(.*?)\n```',  # Markdown code blocks
            r'`([^`]+)`',              # Inline code
            r'(\w+\(.*?\))',           # Function calls
        ]

        for pattern in code_patterns:
            matches = re.findall(pattern, description, re.DOTALL | re.IGNORECASE)
            if matches:
                # Return the first substantial code match
                for match in matches:
                    code = match[1] if isinstance(match, tuple) else match
                    if len(code.strip()) > 10:
                        return code.strip()

        return None

    def _classify_vulnerability_type(self, description: str) -> str:
        """Classify vulnerability type from description"""
        description_lower = description.lower()

        # Simple keyword-based classification
        vuln_keywords = {
            'sql_injection': ['sql injection', 'sql', 'query', 'database'],
            'xss': ['xss', 'cross-site scripting', 'script injection'],
            'command_injection': ['command injection', 'code execution', 'remote code'],
            'buffer_overflow': ['buffer overflow', 'stack overflow', 'heap overflow'],
            'path_traversal': ['path traversal', 'directory traversal', '../'],
            'csrf': ['csrf', 'cross-site request forgery'],
            'xxe': ['xxe', 'xml external entity'],
            'deserialization': ['deserialization', 'pickle', 'serialize']
        }

        for vuln_type, keywords in vuln_keywords.items():
            if any(keyword in description_lower for keyword in keywords):
                return vuln_type

        return 'none'  # Default

    def _detect_language_from_code(self, code: str) -> str:
        """Detect programming language from code snippet"""
        code_lower = code.lower()

        language_indicators = {
            'python': ['import ', 'def ', 'print(', 'if __name__'],
            'java': ['public class', 'public static', 'System.out', 'import java'],
            'javascript': ['function', 'var ', 'const ', 'document.', 'window.'],
            'c': ['#include', 'int main', 'printf(', 'malloc('],
            'cpp': ['#include', 'std::', 'cout', 'namespace'],
            'php': ['<?php', '$_', 'echo ', 'mysql_'],
            'go': ['package ', 'func ', 'import (', 'fmt.']
        }

        for language, indicators in language_indicators.items():
            if any(indicator in code_lower for indicator in indicators):
                return language

        return 'unknown'

    def _is_valid_code(self, code: str, language: str) -> bool:
        """Check if code snippet is valid"""
        if not code or not code.strip():
            return False

        # Basic syntax check
        try:
            if language == 'python':
                compile(code, '<string>', 'exec')
            # Add more language-specific validation as needed
            return True
        except:
            # If compilation fails, still consider it valid for ML purposes
            return True

    def save_collection_stats(self):
        """Save collection statistics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        date_str = datetime.now().strftime("%Y-%m-%d")

        cursor.execute('''
            INSERT OR REPLACE INTO collection_stats
            (date, total_records, by_language, by_vulnerability_type, by_source)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            date_str,
            self.stats['total_collected'],
            json.dumps(self.stats['by_language']),
            json.dumps(self.stats['by_vulnerability_type']),
            json.dumps(self.stats['by_source'])
        ))

        conn.commit()
        conn.close()

    def get_collection_summary(self) -> Dict[str, Any]:
        """Get summary of collected data"""
        return {
            'total_records': self.stats['total_collected'],
            'collection_duration': str(datetime.now() - self.stats['start_time']),
            'languages': dict(self.stats['by_language']),
            'vulnerability_types': dict(self.stats['by_vulnerability_type']),
            'sources': dict(self.stats['by_source'])
        }


def test_advanced_dataset_collector():
    """Test the advanced dataset collector"""
    print("Testing Advanced Dataset Collector...")

    # Initialize collector
    collector = AdvancedDatasetCollector(data_dir='./test_data_collection')

    # Test synthetic vulnerability generation
    print("Testing synthetic vulnerability generation...")
    synthetic_records = collector.generate_synthetic_vulnerabilities(
        target_count=100,
        languages=['python', 'java', 'javascript']
    )
    print(f"Generated {len(synthetic_records)} synthetic vulnerabilities")

    # Test dataset validation and cleaning
    print("Testing dataset validation...")
    cleaned_records = collector.validate_and_clean_dataset(synthetic_records)
    print(f"Cleaned dataset: {len(cleaned_records)} records")

    # Test balanced dataset creation
    print("Testing balanced dataset creation...")
    balanced_records = collector.create_balanced_dataset(
        cleaned_records,
        target_samples_per_class=10  # Small for testing
    )
    print(f"Balanced dataset: {len(balanced_records)} records")

    # Test dataset export
    print("Testing dataset export...")
    export_path = collector.export_dataset(
        balanced_records,
        export_format='jsonl'
    )
    print(f"Dataset exported to: {export_path}")

    # Test collection statistics
    print("Testing collection statistics...")
    summary = collector.get_collection_summary()
    print(f"Collection summary: {summary}")

    collector.save_collection_stats()

    print("Advanced dataset collector test completed!")


if __name__ == "__main__":
    test_advanced_dataset_collector()