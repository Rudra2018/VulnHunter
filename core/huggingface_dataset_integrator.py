#!/usr/bin/env python3
"""
VulnGuard AI - Hugging Face Dataset Integrator
Advanced vulnerability dataset integration from Hugging Face Hub
"""

import logging
import pandas as pd
import numpy as np
from datasets import load_dataset
from typing import Dict, List, Any, Optional, Tuple
import json
import re
from datetime import datetime
import warnings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnGuardDatasetIntegrator:
    """Comprehensive vulnerability dataset integrator for VulnGuard AI training"""

    def __init__(self):
        self.datasets = {}
        self.processed_data = []
        self.dataset_configs = {
            'cvefixes-2022': {
                'name': 'ecwk/vulnerable-functions-and-commits_cvefixes-2022',
                'description': 'CVE fixes dataset with vulnerable functions and commits',
                'columns': ['commit', 'function', 'vulnerability', 'fix']
            },
            'vulnerable-dataset': {
                'name': 'ZhengLiu33/vulnerable-dataset',
                'description': 'General vulnerable code dataset',
                'columns': ['code', 'label', 'vulnerability_type']
            },
            'vulnerable-code': {
                'name': 'doss1232/vulnerable-code',
                'description': 'Vulnerable code snippets dataset',
                'columns': ['code', 'vulnerable', 'cwe_id']
            },
            'code-vulnerable-10000': {
                'name': 'tranquangtien15092005/code-vulnerable-10000',
                'description': '10000 vulnerable code samples',
                'columns': ['code', 'vulnerable', 'description']
            },
            'vulnerable-configs': {
                'name': 'kh4dien/vulnerable-configs',
                'description': 'Vulnerable configuration files',
                'columns': ['config', 'vulnerable', 'config_type']
            }
        }

        logger.info("🦾 VulnGuard AI Dataset Integrator initialized")

    def load_huggingface_dataset(self, dataset_key: str, subset: Optional[str] = None) -> bool:
        """Load a dataset from Hugging Face Hub"""
        try:
            config = self.dataset_configs.get(dataset_key)
            if not config:
                logger.error(f"❌ Unknown dataset key: {dataset_key}")
                return False

            logger.info(f"📂 Loading dataset: {config['name']}")
            logger.info(f"📝 Description: {config['description']}")

            # Load dataset with error handling
            try:
                if subset:
                    dataset = load_dataset(config['name'], subset)
                else:
                    dataset = load_dataset(config['name'])

                self.datasets[dataset_key] = dataset
                logger.info(f"✅ Successfully loaded {dataset_key}")

                # Log dataset structure
                if hasattr(dataset, 'num_rows'):
                    logger.info(f"📊 Rows: {dataset.num_rows}")
                elif hasattr(dataset, 'data'):
                    logger.info(f"📊 Available splits: {list(dataset.keys())}")

                return True

            except Exception as e:
                logger.warning(f"⚠️  Direct load failed for {config['name']}: {e}")
                # Try loading specific split
                try:
                    dataset = load_dataset(config['name'], split='train')
                    self.datasets[dataset_key] = dataset
                    logger.info(f"✅ Successfully loaded {dataset_key} (train split)")
                    return True
                except Exception as e2:
                    logger.error(f"❌ Failed to load {config['name']}: {e2}")
                    return False

        except Exception as e:
            logger.error(f"❌ Error loading {dataset_key}: {e}")
            return False

    def process_cvefixes_dataset(self, dataset_key: str = 'cvefixes-2022') -> List[Dict]:
        """Process CVE fixes dataset for vulnerability detection training"""
        if dataset_key not in self.datasets:
            logger.error(f"❌ Dataset {dataset_key} not loaded")
            return []

        logger.info(f"🔄 Processing {dataset_key} dataset...")
        processed = []

        try:
            dataset = self.datasets[dataset_key]

            # Handle different dataset structures
            if hasattr(dataset, 'to_pandas'):
                df = dataset.to_pandas()
            elif isinstance(dataset, dict) and 'train' in dataset:
                df = dataset['train'].to_pandas()
            else:
                logger.error(f"❌ Unsupported dataset structure for {dataset_key}")
                return []

            logger.info(f"📊 Processing {len(df)} rows from {dataset_key}")

            for idx, row in df.iterrows():
                try:
                    # Extract vulnerability information
                    record = {
                        'source': 'cvefixes-2022',
                        'index': idx,
                        'code': self._extract_code_from_row(row),
                        'vulnerable': 1,  # All records in CVE fixes are vulnerable
                        'vulnerability_type': self._extract_vulnerability_type(row),
                        'cve_id': self._extract_cve_id(row),
                        'description': self._extract_description(row),
                        'timestamp': datetime.now().isoformat()
                    }

                    if record['code']:  # Only add if we have code content
                        processed.append(record)

                except Exception as e:
                    logger.warning(f"⚠️  Error processing row {idx}: {e}")
                    continue

            logger.info(f"✅ Processed {len(processed)} vulnerable code samples from CVE fixes")
            return processed

        except Exception as e:
            logger.error(f"❌ Error processing {dataset_key}: {e}")
            return []

    def process_general_vulnerable_dataset(self, dataset_key: str) -> List[Dict]:
        """Process general vulnerable code datasets"""
        if dataset_key not in self.datasets:
            logger.error(f"❌ Dataset {dataset_key} not loaded")
            return []

        logger.info(f"🔄 Processing {dataset_key} dataset...")
        processed = []

        try:
            dataset = self.datasets[dataset_key]

            # Handle different dataset structures
            if hasattr(dataset, 'to_pandas'):
                df = dataset.to_pandas()
            elif isinstance(dataset, dict) and 'train' in dataset:
                df = dataset['train'].to_pandas()
            else:
                logger.error(f"❌ Unsupported dataset structure for {dataset_key}")
                return []

            logger.info(f"📊 Processing {len(df)} rows from {dataset_key}")

            for idx, row in df.iterrows():
                try:
                    # Extract vulnerability information with flexible column handling
                    record = {
                        'source': dataset_key,
                        'index': idx,
                        'code': self._extract_code_flexible(row),
                        'vulnerable': self._extract_vulnerability_label(row),
                        'vulnerability_type': self._extract_vulnerability_type_flexible(row),
                        'description': self._extract_description_flexible(row),
                        'timestamp': datetime.now().isoformat()
                    }

                    if record['code']:  # Only add if we have code content
                        processed.append(record)

                except Exception as e:
                    logger.warning(f"⚠️  Error processing row {idx}: {e}")
                    continue

            logger.info(f"✅ Processed {len(processed)} code samples from {dataset_key}")
            return processed

        except Exception as e:
            logger.error(f"❌ Error processing {dataset_key}: {e}")
            return []

    def _extract_code_from_row(self, row) -> str:
        """Extract code content from CVE fixes dataset row"""
        # Try different column names that might contain code
        code_columns = ['function', 'code', 'commit', 'patch', 'diff', 'vulnerable_function']

        for col in code_columns:
            if col in row and pd.notna(row[col]):
                content = str(row[col])
                if len(content.strip()) > 10:  # Filter out very short content
                    return content.strip()

        return ""

    def _extract_code_flexible(self, row) -> str:
        """Extract code content with flexible column detection"""
        # Try different column names
        code_columns = ['code', 'function', 'source', 'content', 'text', 'data', 'vulnerable_code']

        for col in code_columns:
            if col in row and pd.notna(row[col]):
                content = str(row[col])
                if len(content.strip()) > 5:  # Filter out very short content
                    return content.strip()

        # If no direct code column, try to extract from any text column
        for col in row.index:
            if pd.notna(row[col]) and isinstance(row[col], str):
                content = str(row[col]).strip()
                if len(content) > 20:  # Likely to be code if longer
                    return content

        return ""

    def _extract_vulnerability_label(self, row) -> int:
        """Extract vulnerability label (0 for safe, 1 for vulnerable)"""
        # Try different column names for vulnerability labels
        label_columns = ['vulnerable', 'label', 'is_vulnerable', 'vuln', 'target']

        for col in label_columns:
            if col in row and pd.notna(row[col]):
                value = row[col]
                # Handle different label formats
                if isinstance(value, (int, float)):
                    return int(value) if value > 0 else 0
                elif isinstance(value, str):
                    value_lower = value.lower().strip()
                    if value_lower in ['1', 'true', 'yes', 'vulnerable', 'vuln']:
                        return 1
                    elif value_lower in ['0', 'false', 'no', 'safe', 'secure']:
                        return 0

        return 1  # Default to vulnerable if unclear

    def _extract_vulnerability_type(self, row) -> str:
        """Extract vulnerability type from CVE fixes dataset"""
        # Try to extract from various columns
        type_columns = ['cwe', 'vulnerability_type', 'vuln_type', 'category']

        for col in type_columns:
            if col in row and pd.notna(row[col]):
                return str(row[col]).strip()

        # Try to extract CWE from text content
        for col in row.index:
            if pd.notna(row[col]) and isinstance(row[col], str):
                cwe_match = re.search(r'CWE[-_](\d+)', str(row[col]), re.IGNORECASE)
                if cwe_match:
                    return f"CWE-{cwe_match.group(1)}"

        return "unknown"

    def _extract_vulnerability_type_flexible(self, row) -> str:
        """Extract vulnerability type with flexible detection"""
        type_columns = ['vulnerability_type', 'cwe_id', 'cwe', 'type', 'category', 'vuln_type']

        for col in type_columns:
            if col in row and pd.notna(row[col]):
                return str(row[col]).strip()

        return "unspecified"

    def _extract_cve_id(self, row) -> str:
        """Extract CVE ID from row"""
        # Try direct CVE columns
        cve_columns = ['cve_id', 'cve', 'vulnerability_id']

        for col in cve_columns:
            if col in row and pd.notna(row[col]):
                return str(row[col]).strip()

        # Try to extract CVE from text content
        for col in row.index:
            if pd.notna(row[col]) and isinstance(row[col], str):
                cve_match = re.search(r'CVE[-_]\d{4}[-_]\d+', str(row[col]), re.IGNORECASE)
                if cve_match:
                    return cve_match.group(0)

        return ""

    def _extract_description(self, row) -> str:
        """Extract description from CVE fixes dataset"""
        desc_columns = ['description', 'summary', 'message', 'commit_message']

        for col in desc_columns:
            if col in row and pd.notna(row[col]):
                desc = str(row[col]).strip()
                if len(desc) > 10:
                    return desc

        return ""

    def _extract_description_flexible(self, row) -> str:
        """Extract description with flexible detection"""
        desc_columns = ['description', 'summary', 'details', 'explanation', 'message']

        for col in desc_columns:
            if col in row and pd.notna(row[col]):
                desc = str(row[col]).strip()
                if len(desc) > 5:
                    return desc

        return ""

    def load_all_datasets(self) -> bool:
        """Load all configured Hugging Face datasets"""
        logger.info("🚀 Loading all VulnGuard AI datasets from Hugging Face...")

        success_count = 0
        total_datasets = len(self.dataset_configs)

        for dataset_key in self.dataset_configs.keys():
            if self.load_huggingface_dataset(dataset_key):
                success_count += 1
            else:
                logger.warning(f"⚠️  Failed to load {dataset_key}")

        logger.info(f"📊 Loaded {success_count}/{total_datasets} datasets successfully")
        return success_count > 0

    def process_all_datasets(self) -> List[Dict]:
        """Process all loaded datasets into unified format"""
        logger.info("🔄 Processing all loaded datasets...")

        all_processed = []

        # Process CVE fixes dataset
        if 'cvefixes-2022' in self.datasets:
            cve_data = self.process_cvefixes_dataset('cvefixes-2022')
            all_processed.extend(cve_data)

        # Process other datasets
        other_datasets = ['vulnerable-dataset', 'vulnerable-code', 'code-vulnerable-10000', 'vulnerable-configs']
        for dataset_key in other_datasets:
            if dataset_key in self.datasets:
                dataset_data = self.process_general_vulnerable_dataset(dataset_key)
                all_processed.extend(dataset_data)

        logger.info(f"✅ Total processed samples: {len(all_processed)}")

        # Add some statistics
        vulnerable_count = sum(1 for record in all_processed if record['vulnerable'] == 1)
        safe_count = len(all_processed) - vulnerable_count

        logger.info(f"📊 Vulnerable samples: {vulnerable_count}")
        logger.info(f"📊 Safe samples: {safe_count}")

        self.processed_data = all_processed
        return all_processed

    def export_processed_data(self, filename: str = None) -> str:
        """Export processed data to JSON file"""
        if not self.processed_data:
            logger.error("❌ No processed data to export")
            return ""

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnguard_processed_data_{timestamp}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(self.processed_data, f, indent=2)

            logger.info(f"💾 Exported {len(self.processed_data)} samples to {filename}")
            return filename

        except Exception as e:
            logger.error(f"❌ Error exporting data: {e}")
            return ""

    def get_dataset_summary(self) -> Dict:
        """Get summary of all loaded and processed datasets"""
        summary = {
            'loaded_datasets': len(self.datasets),
            'processed_samples': len(self.processed_data),
            'dataset_details': {},
            'vulnerability_distribution': {},
            'source_distribution': {}
        }

        if self.processed_data:
            # Count by vulnerability type
            vuln_types = {}
            sources = {}
            for record in self.processed_data:
                vuln_type = record.get('vulnerability_type', 'unknown')
                source = record.get('source', 'unknown')

                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                sources[source] = sources.get(source, 0) + 1

            summary['vulnerability_distribution'] = vuln_types
            summary['source_distribution'] = sources

        return summary


def main():
    """Main function to demonstrate VulnGuard AI dataset integration"""
    logger.info("🚀 Starting VulnGuard AI Dataset Integration")

    # Initialize integrator
    integrator = VulnGuardDatasetIntegrator()

    # Load all datasets
    if integrator.load_all_datasets():
        # Process all datasets
        processed_data = integrator.process_all_datasets()

        if processed_data:
            # Export processed data
            export_file = integrator.export_processed_data()

            # Show summary
            summary = integrator.get_dataset_summary()
            logger.info("📊 Dataset Integration Summary:")
            logger.info(f"   Loaded datasets: {summary['loaded_datasets']}")
            logger.info(f"   Processed samples: {summary['processed_samples']}")
            logger.info(f"   Export file: {export_file}")

            logger.info("🎉 VulnGuard AI Dataset Integration Complete!")
            return export_file
        else:
            logger.error("❌ No data was processed")
            return None
    else:
        logger.error("❌ Failed to load datasets")
        return None


if __name__ == "__main__":
    main()