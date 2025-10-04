#!/usr/bin/env python3
"""
VulnGuard AI - Kaggle Dataset Integrator
Load and integrate Kaggle vulnerability datasets for enhanced training
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
import json
import re
from datetime import datetime
import os

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KaggleDatasetIntegrator:
    """Kaggle vulnerability dataset integrator for VulnGuard AI"""

    def __init__(self):
        self.datasets = {}
        self.processed_data = []

        # Kaggle dataset configurations
        self.kaggle_datasets = {
            'public-cve-2020-2024': {
                'url': 'https://www.kaggle.com/datasets/umer7arooq/public-cve-vulnerabilities-20202024',
                'description': 'Public CVE vulnerabilities from 2020-2024',
                'expected_files': ['*.csv', '*.json'],
                'type': 'cve'
            },
            'cve-data': {
                'url': 'https://www.kaggle.com/datasets/angelcortez/cve-data',
                'description': 'Comprehensive CVE data',
                'expected_files': ['*.csv', '*.json'],
                'type': 'cve'
            },
            'bug-bounty-writeups': {
                'url': 'https://www.kaggle.com/datasets/mayankkumarpoddar/bug-bounty-writeups',
                'description': 'Real bug bounty writeups and exploits',
                'expected_files': ['*.csv', '*.txt', '*.json'],
                'type': 'bug_bounty'
            },
            'cve-dataset': {
                'url': 'https://www.kaggle.com/datasets/casimireffect/cve-dataset',
                'description': 'CVE dataset with vulnerabilities',
                'expected_files': ['*.csv'],
                'type': 'cve'
            },
            'bug-bounty-openai': {
                'url': 'https://www.kaggle.com/datasets/daudthecat/bug-bounty-openai-gpt-oss-20b-by-thecat',
                'description': 'Bug bounty data from OpenAI GPT OSS',
                'expected_files': ['*.csv', '*.json', '*.txt'],
                'type': 'bug_bounty'
            }
        }

        logger.info("🦾 Kaggle Dataset Integrator initialized")
        logger.info(f"📊 Configured datasets: {len(self.kaggle_datasets)}")

    def check_kaggle_api(self) -> bool:
        """Check if Kaggle API is configured"""
        try:
            import kaggle
            logger.info("✅ Kaggle API is available")
            return True
        except ImportError:
            logger.warning("⚠️  Kaggle API not installed. Install with: pip install kaggle")
            logger.info("💡 Alternatively, manually download datasets from Kaggle")
            return False
        except OSError as e:
            logger.warning(f"⚠️  Kaggle API credentials not configured: {e}")
            logger.info("💡 Configure Kaggle API credentials at ~/.kaggle/kaggle.json")
            return False

    def download_kaggle_dataset(self, dataset_key: str, download_path: str = "./data/kaggle") -> bool:
        """Download dataset from Kaggle"""
        try:
            import kaggle

            if dataset_key not in self.kaggle_datasets:
                logger.error(f"❌ Unknown dataset: {dataset_key}")
                return False

            config = self.kaggle_datasets[dataset_key]
            logger.info(f"📥 Downloading {dataset_key}...")
            logger.info(f"📝 {config['description']}")

            # Extract dataset path from URL
            dataset_path = config['url'].split('datasets/')[-1]

            # Create download directory
            os.makedirs(download_path, exist_ok=True)
            dataset_dir = os.path.join(download_path, dataset_key)
            os.makedirs(dataset_dir, exist_ok=True)

            # Download dataset
            kaggle.api.dataset_download_files(
                dataset_path,
                path=dataset_dir,
                unzip=True
            )

            logger.info(f"✅ Downloaded {dataset_key} to {dataset_dir}")
            self.datasets[dataset_key] = {'path': dataset_dir, 'config': config}
            return True

        except Exception as e:
            logger.error(f"❌ Error downloading {dataset_key}: {e}")
            logger.info(f"💡 Manual download: {config['url']}")
            return False

    def load_local_dataset(self, dataset_key: str, dataset_path: str) -> bool:
        """Load a dataset from local path"""
        try:
            if not os.path.exists(dataset_path):
                logger.error(f"❌ Path does not exist: {dataset_path}")
                return False

            if dataset_key not in self.kaggle_datasets:
                logger.warning(f"⚠️  Adding custom dataset: {dataset_key}")
                self.kaggle_datasets[dataset_key] = {
                    'description': 'Custom local dataset',
                    'type': 'unknown'
                }

            config = self.kaggle_datasets[dataset_key]
            self.datasets[dataset_key] = {'path': dataset_path, 'config': config}

            logger.info(f"✅ Loaded local dataset: {dataset_key} from {dataset_path}")
            return True

        except Exception as e:
            logger.error(f"❌ Error loading {dataset_key}: {e}")
            return False

    def process_cve_dataset(self, dataset_key: str) -> List[Dict]:
        """Process CVE datasets"""
        if dataset_key not in self.datasets:
            logger.error(f"❌ Dataset not loaded: {dataset_key}")
            return []

        logger.info(f"🔄 Processing CVE dataset: {dataset_key}")
        processed = []

        try:
            dataset_path = self.datasets[dataset_key]['path']

            # Find CSV or JSON files in the dataset
            files = []
            for root, dirs, filenames in os.walk(dataset_path):
                for filename in filenames:
                    if filename.endswith(('.csv', '.json')):
                        files.append(os.path.join(root, filename))

            logger.info(f"📂 Found {len(files)} data files")

            for file_path in files:
                try:
                    if file_path.endswith('.csv'):
                        df = pd.read_csv(file_path, low_memory=False)
                    elif file_path.endswith('.json'):
                        df = pd.read_json(file_path, lines=True)
                    else:
                        continue

                    logger.info(f"📊 Processing {os.path.basename(file_path)}: {len(df)} rows")

                    # Process each row
                    for idx, row in df.iterrows():
                        record = self._extract_cve_record(row, dataset_key, file_path)
                        if record and record.get('code'):
                            processed.append(record)

                except Exception as e:
                    logger.warning(f"⚠️  Error processing {file_path}: {e}")
                    continue

            logger.info(f"✅ Processed {len(processed)} CVE records from {dataset_key}")
            return processed

        except Exception as e:
            logger.error(f"❌ Error processing CVE dataset {dataset_key}: {e}")
            return []

    def process_bug_bounty_dataset(self, dataset_key: str) -> List[Dict]:
        """Process bug bounty datasets"""
        if dataset_key not in self.datasets:
            logger.error(f"❌ Dataset not loaded: {dataset_key}")
            return []

        logger.info(f"🔄 Processing bug bounty dataset: {dataset_key}")
        processed = []

        try:
            dataset_path = self.datasets[dataset_key]['path']

            # Find all data files
            files = []
            for root, dirs, filenames in os.walk(dataset_path):
                for filename in filenames:
                    if filename.endswith(('.csv', '.json', '.txt')):
                        files.append(os.path.join(root, filename))

            logger.info(f"📂 Found {len(files)} data files")

            for file_path in files:
                try:
                    if file_path.endswith('.csv'):
                        df = pd.read_csv(file_path, low_memory=False)
                        logger.info(f"📊 Processing {os.path.basename(file_path)}: {len(df)} rows")

                        for idx, row in df.iterrows():
                            record = self._extract_bug_bounty_record(row, dataset_key, file_path)
                            if record and record.get('code'):
                                processed.append(record)

                    elif file_path.endswith('.json'):
                        with open(file_path, 'r') as f:
                            try:
                                data = json.load(f)
                                if isinstance(data, list):
                                    for item in data:
                                        record = self._extract_bug_bounty_from_json(item, dataset_key, file_path)
                                        if record and record.get('code'):
                                            processed.append(record)
                                elif isinstance(data, dict):
                                    record = self._extract_bug_bounty_from_json(data, dataset_key, file_path)
                                    if record and record.get('code'):
                                        processed.append(record)
                            except:
                                # Try reading as JSON lines
                                f.seek(0)
                                for line in f:
                                    try:
                                        item = json.loads(line)
                                        record = self._extract_bug_bounty_from_json(item, dataset_key, file_path)
                                        if record and record.get('code'):
                                            processed.append(record)
                                    except:
                                        continue

                    elif file_path.endswith('.txt'):
                        # Process text files (writeups)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            record = self._extract_from_writeup(content, dataset_key, file_path)
                            if record and record.get('code'):
                                processed.append(record)

                except Exception as e:
                    logger.warning(f"⚠️  Error processing {file_path}: {e}")
                    continue

            logger.info(f"✅ Processed {len(processed)} bug bounty records from {dataset_key}")
            return processed

        except Exception as e:
            logger.error(f"❌ Error processing bug bounty dataset {dataset_key}: {e}")
            return []

    def _extract_cve_record(self, row, dataset_key: str, file_path: str) -> Optional[Dict]:
        """Extract CVE record from row"""
        try:
            # Try to find CVE ID
            cve_id = self._extract_field(row, ['cve_id', 'cve', 'id', 'CVE_ID', 'vulnerability_id'])

            # Extract description/summary
            description = self._extract_field(row, [
                'description', 'summary', 'Description', 'Summary',
                'vulnerability_description', 'vuln_description'
            ])

            # Extract code/vulnerable code
            code = self._extract_field(row, [
                'vulnerable_code', 'code', 'function', 'affected_code',
                'poc', 'exploit', 'proof_of_concept', 'example'
            ])

            # If no direct code, try to extract from description
            if not code and description:
                code_blocks = re.findall(r'```[\w]*\n(.*?)```', description, re.DOTALL)
                if code_blocks:
                    code = '\n\n'.join(code_blocks)
                else:
                    # Look for inline code
                    code_inline = re.findall(r'`([^`]+)`', description)
                    if code_inline and any(len(c) > 20 for c in code_inline):
                        code = '\n'.join(code_inline)

            if not code or len(str(code).strip()) < 10:
                return None

            # Extract vulnerability type/CWE
            vuln_type = self._extract_field(row, [
                'cwe_id', 'cwe', 'vulnerability_type', 'type', 'category',
                'CWE_ID', 'weakness_type'
            ])

            # Extract severity
            severity = self._extract_field(row, [
                'severity', 'cvss_score', 'impact', 'Severity', 'CVSS'
            ])

            record = {
                'source': dataset_key,
                'file': os.path.basename(file_path),
                'cve_id': str(cve_id) if cve_id else '',
                'code': str(code).strip(),
                'vulnerable': 1,  # CVE data is always vulnerable
                'vulnerability_type': str(vuln_type) if vuln_type else 'unknown',
                'description': str(description)[:500] if description else '',
                'severity': str(severity) if severity else '',
                'timestamp': datetime.now().isoformat()
            }

            return record

        except Exception as e:
            logger.debug(f"Error extracting CVE record: {e}")
            return None

    def _extract_bug_bounty_record(self, row, dataset_key: str, file_path: str) -> Optional[Dict]:
        """Extract bug bounty record from CSV row"""
        try:
            # Extract title/summary
            title = self._extract_field(row, [
                'title', 'Title', 'summary', 'Summary', 'name', 'vulnerability_name'
            ])

            # Extract description/writeup
            description = self._extract_field(row, [
                'description', 'writeup', 'report', 'details', 'content',
                'Description', 'Writeup', 'Report'
            ])

            # Extract code/PoC
            code = self._extract_field(row, [
                'poc', 'exploit', 'code', 'payload', 'vulnerable_code',
                'proof_of_concept', 'PoC', 'Exploit'
            ])

            # Try to extract code from description
            if not code and description:
                code_blocks = re.findall(r'```[\w]*\n(.*?)```', str(description), re.DOTALL)
                if code_blocks:
                    code = '\n\n'.join(code_blocks)
                else:
                    # Look for code patterns
                    code_patterns = re.findall(r'(?:http|curl|python|javascript|php|sql)[\s\S]{20,500}', str(description))
                    if code_patterns:
                        code = '\n'.join(code_patterns[:3])  # Take first 3 patterns

            if not code or len(str(code).strip()) < 10:
                return None

            # Extract vulnerability type
            vuln_type = self._extract_field(row, [
                'vulnerability_type', 'type', 'category', 'weakness',
                'Type', 'Category', 'cwe'
            ])

            # Extract bounty amount
            bounty = self._extract_field(row, [
                'bounty', 'reward', 'amount', 'Bounty', 'Reward'
            ])

            # Extract severity
            severity = self._extract_field(row, [
                'severity', 'impact', 'Severity', 'Impact', 'rating'
            ])

            record = {
                'source': dataset_key,
                'file': os.path.basename(file_path),
                'title': str(title)[:200] if title else '',
                'code': str(code).strip(),
                'vulnerable': 1,  # Bug bounty reports are vulnerable
                'vulnerability_type': str(vuln_type) if vuln_type else 'unknown',
                'description': str(description)[:500] if description else '',
                'severity': str(severity) if severity else '',
                'bounty': str(bounty) if bounty else '',
                'timestamp': datetime.now().isoformat()
            }

            return record

        except Exception as e:
            logger.debug(f"Error extracting bug bounty record: {e}")
            return None

    def _extract_bug_bounty_from_json(self, item: Dict, dataset_key: str, file_path: str) -> Optional[Dict]:
        """Extract bug bounty record from JSON object"""
        try:
            # Try to find code in various fields
            code = None
            for field in ['poc', 'exploit', 'code', 'payload', 'vulnerable_code', 'proof_of_concept']:
                if field in item and item[field]:
                    code = item[field]
                    break

            # Try to extract from description
            if not code:
                for field in ['description', 'writeup', 'report', 'details']:
                    if field in item and item[field]:
                        code_blocks = re.findall(r'```[\w]*\n(.*?)```', str(item[field]), re.DOTALL)
                        if code_blocks:
                            code = '\n\n'.join(code_blocks)
                            break

            if not code or len(str(code).strip()) < 10:
                return None

            record = {
                'source': dataset_key,
                'file': os.path.basename(file_path),
                'title': str(item.get('title', item.get('name', '')))[:200],
                'code': str(code).strip(),
                'vulnerable': 1,
                'vulnerability_type': str(item.get('vulnerability_type', item.get('type', 'unknown'))),
                'description': str(item.get('description', ''))[:500],
                'severity': str(item.get('severity', item.get('impact', ''))),
                'bounty': str(item.get('bounty', item.get('reward', ''))),
                'timestamp': datetime.now().isoformat()
            }

            return record

        except Exception as e:
            logger.debug(f"Error extracting from JSON: {e}")
            return None

    def _extract_from_writeup(self, content: str, dataset_key: str, file_path: str) -> Optional[Dict]:
        """Extract vulnerability info from writeup text"""
        try:
            # Extract code blocks
            code_blocks = re.findall(r'```[\w]*\n(.*?)```', content, re.DOTALL)
            if not code_blocks:
                # Try to find code-like patterns
                code_blocks = re.findall(r'(?:http|curl|python|javascript|php|sql|function|def |class |import )[\s\S]{20,500}', content)

            if not code_blocks:
                return None

            code = '\n\n'.join(code_blocks[:5])  # Take first 5 code blocks

            # Try to extract title from first line or heading
            title_match = re.search(r'^#+ (.+)$', content, re.MULTILINE)
            title = title_match.group(1) if title_match else os.path.basename(file_path)

            # Try to extract vulnerability type
            vuln_keywords = {
                'XSS': r'\b(xss|cross.?site.?script)\b',
                'SQL Injection': r'\b(sql.?injection|sqli)\b',
                'CSRF': r'\b(csrf|cross.?site.?request)\b',
                'RCE': r'\b(rce|remote.?code.?execution)\b',
                'SSRF': r'\b(ssrf|server.?side.?request)\b',
                'IDOR': r'\b(idor|insecure.?direct.?object)\b',
            }

            vuln_type = 'unknown'
            for vtype, pattern in vuln_keywords.items():
                if re.search(pattern, content, re.IGNORECASE):
                    vuln_type = vtype
                    break

            record = {
                'source': dataset_key,
                'file': os.path.basename(file_path),
                'title': str(title)[:200],
                'code': code.strip(),
                'vulnerable': 1,
                'vulnerability_type': vuln_type,
                'description': content[:500],
                'timestamp': datetime.now().isoformat()
            }

            return record

        except Exception as e:
            logger.debug(f"Error extracting from writeup: {e}")
            return None

    def _extract_field(self, row, field_names: List[str]) -> Optional[str]:
        """Extract field value from row by trying multiple field names"""
        for field in field_names:
            if field in row and pd.notna(row[field]):
                value = str(row[field]).strip()
                if value and value.lower() not in ['nan', 'none', 'null', '']:
                    return value
        return None

    def process_all_datasets(self) -> List[Dict]:
        """Process all loaded datasets"""
        logger.info("🔄 Processing all loaded Kaggle datasets...")
        all_processed = []

        for dataset_key, dataset_info in self.datasets.items():
            dataset_type = dataset_info['config'].get('type', 'unknown')

            if dataset_type == 'cve':
                processed = self.process_cve_dataset(dataset_key)
            elif dataset_type == 'bug_bounty':
                processed = self.process_bug_bounty_dataset(dataset_key)
            else:
                logger.warning(f"⚠️  Unknown dataset type for {dataset_key}")
                continue

            all_processed.extend(processed)

        logger.info(f"✅ Total processed samples: {len(all_processed)}")

        # Statistics
        vulnerable_count = sum(1 for r in all_processed if r.get('vulnerable') == 1)
        logger.info(f"📊 Vulnerable samples: {vulnerable_count}")

        # Count by source
        sources = {}
        for record in all_processed:
            source = record.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1

        logger.info("📊 Samples by source:")
        for source, count in sources.items():
            logger.info(f"   {source}: {count}")

        self.processed_data = all_processed
        return all_processed

    def export_processed_data(self, filename: str = None) -> str:
        """Export processed data to JSON"""
        if not self.processed_data:
            logger.error("❌ No processed data to export")
            return ""

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"kaggle_vulnerability_data_{timestamp}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(self.processed_data, f, indent=2)

            logger.info(f"💾 Exported {len(self.processed_data)} samples to {filename}")
            return filename

        except Exception as e:
            logger.error(f"❌ Error exporting data: {e}")
            return ""

    def get_summary(self) -> Dict:
        """Get summary of processed data"""
        summary = {
            'total_datasets': len(self.datasets),
            'total_samples': len(self.processed_data),
            'datasets': {},
            'vulnerability_types': {},
            'sources': {}
        }

        if self.processed_data:
            for record in self.processed_data:
                source = record.get('source', 'unknown')
                vuln_type = record.get('vulnerability_type', 'unknown')

                summary['sources'][source] = summary['sources'].get(source, 0) + 1
                summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1

        return summary


def main():
    """Main function to demonstrate Kaggle dataset integration"""
    logger.info("🚀 Kaggle Dataset Integration Demo")

    integrator = KaggleDatasetIntegrator()

    # Check if Kaggle API is available
    has_kaggle = integrator.check_kaggle_api()

    if has_kaggle:
        logger.info("💡 You can download datasets automatically")
        logger.info("💡 Example: integrator.download_kaggle_dataset('public-cve-2020-2024')")
    else:
        logger.info("💡 Please download datasets manually from:")
        for key, config in integrator.kaggle_datasets.items():
            logger.info(f"   {key}: {config['url']}")
        logger.info("💡 Then load with: integrator.load_local_dataset('key', 'path')")

    return integrator


if __name__ == "__main__":
    main()
