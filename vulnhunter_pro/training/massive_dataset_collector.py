#!/usr/bin/env python3
"""
Massive Dataset Collector for VulnHunter Professional
====================================================

Downloads and integrates comprehensive vulnerability datasets:
- OWASP Benchmark v1.2 (2,740 samples)
- Juliet Test Suite v1.3 (64,000 samples)
- Big-Vul GitHub (10,900 real CVEs)
- CodeXGLUE Defects (27,000 samples)
- Devign C/C++ (27,000 real repos)
- CVEFixes (5,000 patched CVEs)
- SmartBugs Wild (47,000 Solidity)
- DAST runtime datasets (50,000+ traces)

Target: 250,000+ vulnerability examples for 92%+ accuracy
"""

import os
import sys
import json
import logging
import requests
import zipfile
import tarfile
import git
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import pandas as pd
import subprocess
from dataclasses import dataclass
import time

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

@dataclass
class DatasetInfo:
    """Information about a vulnerability dataset"""
    name: str
    samples: int
    focus: str
    url: str
    file_types: List[str]
    cwe_coverage: int
    download_method: str  # 'git', 'download', 'api'

class MassiveDatasetCollector:
    """Collector for massive vulnerability datasets"""

    def __init__(self, base_dir: str = "massive_datasets"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.datasets = self._define_datasets()
        self.collected_stats = {}

    def _define_datasets(self) -> List[DatasetInfo]:
        """Define all datasets to collect"""
        return [
            DatasetInfo(
                name="owasp_benchmark_full",
                samples=2740,
                focus="Java web vulnerabilities",
                url="https://github.com/OWASP-Benchmark/BenchmarkJava",
                file_types=[".java"],
                cwe_coverage=109,
                download_method="git"
            ),
            DatasetInfo(
                name="juliet_test_suite",
                samples=64000,
                focus="C/C++ NIST test cases",
                url="https://samate.nist.gov/SARD/testsuite/Juliet_Test_Suite_v1.3_for_C_Cpp.zip",
                file_types=[".c", ".cpp"],
                cwe_coverage=118,
                download_method="download"
            ),
            DatasetInfo(
                name="big_vul",
                samples=10900,
                focus="Real CVEs from GitHub",
                url="https://github.com/ZeoVulTracker/Big-Vul",
                file_types=[".c", ".cpp", ".java", ".py"],
                cwe_coverage=100,
                download_method="git"
            ),
            DatasetInfo(
                name="codexglue_defects",
                samples=27000,
                focus="GitHub defect detection",
                url="https://github.com/microsoft/CodeXGLUE",
                file_types=[".c", ".cpp"],
                cwe_coverage=50,
                download_method="git"
            ),
            DatasetInfo(
                name="devign",
                samples=27000,
                focus="C/C++ real repositories",
                url="https://github.com/microsoft/Devign",
                file_types=[".c", ".cpp"],
                cwe_coverage=100,
                download_method="git"
            ),
            DatasetInfo(
                name="cve_fixes",
                samples=5000,
                focus="Patched CVEs",
                url="https://github.com/IBM/cve-fixes",
                file_types=[".c", ".cpp", ".java", ".py"],
                cwe_coverage=80,
                download_method="git"
            ),
            DatasetInfo(
                name="smartbugs_wild",
                samples=47000,
                focus="Solidity smart contracts",
                url="https://github.com/smartbugs/smartbugs-wild",
                file_types=[".sol"],
                cwe_coverage=100,
                download_method="git"
            ),
            DatasetInfo(
                name="webgoat",
                samples=1500,
                focus="Java web application training",
                url="https://github.com/WebGoat/WebGoat",
                file_types=[".java"],
                cwe_coverage=25,
                download_method="git"
            )
        ]

    def download_git_dataset(self, dataset: DatasetInfo) -> bool:
        """Download dataset from Git repository"""
        dataset_path = self.base_dir / dataset.name

        if dataset_path.exists():
            print(f"Dataset {dataset.name} already exists, skipping...")
            return True

        print(f"Cloning {dataset.name} from {dataset.url}...")
        try:
            git.Repo.clone_from(dataset.url, dataset_path, depth=1)
            print(f"Successfully cloned {dataset.name}")
            return True
        except Exception as e:
            print(f"Error cloning {dataset.name}: {e}")
            return False

    def download_zip_dataset(self, dataset: DatasetInfo) -> bool:
        """Download dataset from ZIP file"""
        dataset_path = self.base_dir / dataset.name

        if dataset_path.exists():
            print(f"Dataset {dataset.name} already exists, skipping...")
            return True

        dataset_path.mkdir(exist_ok=True)
        zip_file = dataset_path / f"{dataset.name}.zip"

        print(f"Downloading {dataset.name} from {dataset.url}...")
        try:
            response = requests.get(dataset.url, stream=True)
            response.raise_for_status()

            with open(zip_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"Extracting {dataset.name}...")
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(dataset_path)

            os.remove(zip_file)
            print(f"Successfully downloaded and extracted {dataset.name}")
            return True
        except Exception as e:
            print(f"Error downloading {dataset.name}: {e}")
            return False

    def collect_all_datasets(self) -> Dict[str, bool]:
        """Collect all defined datasets"""
        print("=== Massive Dataset Collection Pipeline ===")
        results = {}

        for dataset in self.datasets:
            print(f"\n[{dataset.name}] Processing {dataset.samples:,} samples ({dataset.focus})")

            if dataset.download_method == "git":
                success = self.download_git_dataset(dataset)
            elif dataset.download_method == "download":
                success = self.download_zip_dataset(dataset)
            else:
                print(f"Unknown download method: {dataset.download_method}")
                success = False

            results[dataset.name] = success

            if success:
                # Count actual files
                actual_count = self._count_files(dataset)
                self.collected_stats[dataset.name] = {
                    'expected_samples': dataset.samples,
                    'actual_files': actual_count,
                    'file_types': dataset.file_types,
                    'cwe_coverage': dataset.cwe_coverage
                }

        return results

    def _count_files(self, dataset: DatasetInfo) -> int:
        """Count actual files in dataset"""
        dataset_path = self.base_dir / dataset.name
        count = 0

        for ext in dataset.file_types:
            count += len(list(dataset_path.rglob(f"*{ext}")))

        return count

    def create_unified_dataset(self, output_file: str) -> Dict[str, Any]:
        """Create unified dataset from all collected sources"""
        print("\n=== Creating Unified Massive Dataset ===")

        unified_examples = []
        processing_stats = {}

        for dataset in self.datasets:
            if dataset.name not in self.collected_stats:
                continue

            print(f"\nProcessing {dataset.name}...")
            dataset_path = self.base_dir / dataset.name

            examples = self._process_dataset(dataset, dataset_path)
            unified_examples.extend(examples)

            processing_stats[dataset.name] = {
                'processed_examples': len(examples),
                'source_info': {
                    'samples': dataset.samples,
                    'focus': dataset.focus,
                    'cwe_coverage': dataset.cwe_coverage
                }
            }

        # Save unified dataset
        print(f"\nSaving unified dataset with {len(unified_examples):,} examples...")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(unified_examples, f, indent=2)

        # Save processing stats
        stats_file = output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w') as f:
            json.dump(processing_stats, f, indent=2)

        # Generate comprehensive statistics
        total_stats = self._generate_comprehensive_stats(unified_examples, processing_stats)

        summary_file = output_file.replace('.json', '_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(total_stats, f, indent=2)

        print(f"\nUnified dataset saved to: {output_file}")
        print(f"Processing stats: {stats_file}")
        print(f"Summary statistics: {summary_file}")

        return total_stats

    def _process_dataset(self, dataset: DatasetInfo, dataset_path: Path) -> List[Dict[str, Any]]:
        """Process individual dataset based on its characteristics"""
        examples = []

        if dataset.name == "owasp_benchmark_full":
            examples = self._process_owasp_benchmark(dataset_path)
        elif dataset.name == "juliet_test_suite":
            examples = self._process_juliet_suite(dataset_path)
        elif dataset.name == "big_vul":
            examples = self._process_big_vul(dataset_path)
        elif dataset.name == "codexglue_defects":
            examples = self._process_codexglue(dataset_path)
        elif dataset.name == "devign":
            examples = self._process_devign(dataset_path)
        elif dataset.name == "cve_fixes":
            examples = self._process_cve_fixes(dataset_path)
        elif dataset.name == "smartbugs_wild":
            examples = self._process_smartbugs(dataset_path)
        elif dataset.name == "webgoat":
            examples = self._process_webgoat(dataset_path)
        else:
            examples = self._process_generic_dataset(dataset, dataset_path)

        print(f"  Processed {len(examples)} examples from {dataset.name}")
        return examples

    def _process_owasp_benchmark(self, dataset_path: Path) -> List[Dict[str, Any]]:
        """Process OWASP Benchmark dataset"""
        examples = []

        # Look for Java source files
        java_files = list(dataset_path.rglob("*.java"))

        # Try to find ground truth file
        ground_truth_files = list(dataset_path.rglob("*expectedresults*.csv"))
        ground_truth = {}

        if ground_truth_files:
            try:
                import csv
                with open(ground_truth_files[0], 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 4 and not row[0].startswith('#'):
                            test_name, category, is_vuln, cwe = row[:4]
                            ground_truth[test_name] = {
                                'is_vulnerable': is_vuln.lower() == 'true',
                                'category': category,
                                'cwe': cwe
                            }
            except Exception as e:
                print(f"Error loading ground truth: {e}")

        for java_file in java_files[:5000]:  # Limit processing
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    code_content = f.read()

                test_name = java_file.stem

                # Use ground truth if available, otherwise heuristic
                if test_name in ground_truth:
                    gt = ground_truth[test_name]
                    is_vulnerable = gt['is_vulnerable']
                    vuln_type = gt['category']
                    cwe = f"CWE-{gt['cwe']}"
                else:
                    # Heuristic analysis
                    is_vulnerable, vuln_type = self._analyze_java_code(code_content)
                    cwe = None

                examples.append({
                    'code': code_content,
                    'file_path': str(java_file),
                    'vulnerability_type': vuln_type if is_vulnerable else 'safe',
                    'is_vulnerable': is_vulnerable,
                    'cwe': cwe,
                    'severity': self._get_severity(vuln_type) if is_vulnerable else 'none',
                    'language': 'java',
                    'source_dataset': 'owasp_benchmark_full',
                    'confidence': 1.0 if test_name in ground_truth else 0.7
                })

            except Exception as e:
                continue

        return examples

    def _process_juliet_suite(self, dataset_path: Path) -> List[Dict[str, Any]]:
        """Process Juliet Test Suite dataset"""
        examples = []

        # Juliet has specific naming conventions for vulnerability types
        c_files = list(dataset_path.rglob("*.c"))
        cpp_files = list(dataset_path.rglob("*.cpp"))

        for source_file in (c_files + cpp_files)[:10000]:  # Limit processing
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()

                # Extract CWE from filename (Juliet convention)
                filename = source_file.name
                cwe_match = None
                vuln_type = 'unknown'
                is_vulnerable = True

                # Juliet naming: CWE121_Stack_Based_Buffer_Overflow__*
                if 'CWE' in filename:
                    import re
                    cwe_match = re.search(r'CWE(\d+)', filename)
                    if cwe_match:
                        cwe_num = cwe_match.group(1)
                        cwe = f"CWE-{cwe_num}"
                        vuln_type = self._cwe_to_vuln_type(cwe_num)

                # Check for good/bad variants
                if 'good' in filename.lower() or 'good' in str(source_file.parent).lower():
                    is_vulnerable = False
                    vuln_type = 'safe'

                examples.append({
                    'code': code_content,
                    'file_path': str(source_file),
                    'vulnerability_type': vuln_type,
                    'is_vulnerable': is_vulnerable,
                    'cwe': cwe if cwe_match else None,
                    'severity': self._get_severity(vuln_type) if is_vulnerable else 'none',
                    'language': 'cpp' if source_file.suffix == '.cpp' else 'c',
                    'source_dataset': 'juliet_test_suite',
                    'confidence': 1.0  # NIST ground truth
                })

            except Exception as e:
                continue

        return examples

    def _process_big_vul(self, dataset_path: Path) -> List[Dict[str, Any]]:
        """Process Big-Vul dataset"""
        examples = []

        # Look for CSV/JSON metadata files
        metadata_files = list(dataset_path.rglob("*.csv")) + list(dataset_path.rglob("*.json"))

        for metadata_file in metadata_files:
            try:
                if metadata_file.suffix == '.csv':
                    import pandas as pd
                    df = pd.read_csv(metadata_file)

                    for _, row in df.iterrows():
                        if 'func' in row and 'target' in row:
                            examples.append({
                                'code': str(row.get('func', '')),
                                'file_path': str(metadata_file),
                                'vulnerability_type': 'cve_vulnerability',
                                'is_vulnerable': bool(row.get('target', 0)),
                                'cwe': row.get('cwe', None),
                                'severity': 'high',  # CVEs are typically high severity
                                'language': self._detect_language(str(row.get('func', ''))),
                                'source_dataset': 'big_vul',
                                'confidence': 0.9  # Real CVEs
                            })

                            if len(examples) >= 5000:  # Limit processing
                                break

            except Exception as e:
                continue

        return examples

    def _process_generic_dataset(self, dataset: DatasetInfo, dataset_path: Path) -> List[Dict[str, Any]]:
        """Generic processor for other datasets"""
        examples = []

        for ext in dataset.file_types:
            source_files = list(dataset_path.rglob(f"*{ext}"))

            for source_file in source_files[:2000]:  # Limit per dataset
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()

                    # Simple heuristic analysis
                    is_vulnerable, vuln_type = self._analyze_code_heuristic(code_content, ext)

                    examples.append({
                        'code': code_content,
                        'file_path': str(source_file),
                        'vulnerability_type': vuln_type if is_vulnerable else 'safe',
                        'is_vulnerable': is_vulnerable,
                        'cwe': None,
                        'severity': self._get_severity(vuln_type) if is_vulnerable else 'none',
                        'language': self._ext_to_language(ext),
                        'source_dataset': dataset.name,
                        'confidence': 0.6  # Lower confidence for heuristic
                    })

                except Exception as e:
                    continue

        return examples

    def _analyze_java_code(self, code: str) -> Tuple[bool, str]:
        """Analyze Java code for vulnerabilities"""
        import re

        # SQL Injection patterns
        if re.search(r'executeQuery\s*\(\s*[^?]', code) or re.search(r'Statement.*execute', code):
            return True, 'sql_injection'

        # Command Injection
        if re.search(r'Runtime\.getRuntime\(\)\.exec', code) or re.search(r'ProcessBuilder', code):
            return True, 'command_injection'

        # XSS patterns
        if re.search(r'getParameter.*response\.getWriter', code):
            return True, 'reflected_xss'

        # Path traversal
        if re.search(r'getParameter.*File', code):
            return True, 'path_traversal'

        return False, 'unknown'

    def _analyze_code_heuristic(self, code: str, ext: str) -> Tuple[bool, str]:
        """Heuristic code analysis based on file extension"""
        import re

        if ext in ['.c', '.cpp']:
            # Buffer overflow
            if re.search(r'\b(strcpy|strcat|sprintf|gets)\s*\(', code):
                return True, 'buffer_overflow'
            # Use after free
            if 'free(' in code and '*' in code:
                return True, 'use_after_free'

        elif ext == '.py':
            # Command injection
            if re.search(r'\b(os\.system|subprocess\.|exec|eval)\s*\(', code):
                return True, 'command_injection'

        elif ext == '.java':
            return self._analyze_java_code(code)

        return False, 'unknown'

    def _cwe_to_vuln_type(self, cwe_num: str) -> str:
        """Map CWE number to vulnerability type"""
        mapping = {
            '78': 'command_injection',
            '79': 'reflected_xss',
            '89': 'sql_injection',
            '120': 'buffer_overflow',
            '121': 'buffer_overflow',
            '134': 'format_string',
            '190': 'integer_overflow',
            '416': 'use_after_free',
            '476': 'null_pointer_dereference',
            '502': 'unsafe_deserialization'
        }
        return mapping.get(cwe_num, 'unknown')

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity for vulnerability type"""
        high_severity = ['buffer_overflow', 'command_injection', 'sql_injection', 'use_after_free']
        medium_severity = ['reflected_xss', 'path_traversal', 'format_string']

        if vuln_type in high_severity:
            return 'critical'
        elif vuln_type in medium_severity:
            return 'high'
        else:
            return 'medium'

    def _detect_language(self, code: str) -> str:
        """Detect programming language from code"""
        if 'public class' in code or 'import java' in code:
            return 'java'
        elif '#include' in code or 'int main(' in code:
            return 'c'
        elif 'import ' in code and 'def ' in code:
            return 'python'
        else:
            return 'unknown'

    def _ext_to_language(self, ext: str) -> str:
        """Map file extension to language"""
        mapping = {
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.py': 'python',
            '.js': 'javascript',
            '.sol': 'solidity'
        }
        return mapping.get(ext, 'unknown')

    def _generate_comprehensive_stats(self, examples: List[Dict], processing_stats: Dict) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        stats = {
            'total_examples': len(examples),
            'vulnerable_examples': sum(1 for ex in examples if ex['is_vulnerable']),
            'safe_examples': sum(1 for ex in examples if not ex['is_vulnerable']),
            'dataset_distribution': {},
            'language_distribution': {},
            'vulnerability_distribution': {},
            'severity_distribution': {},
            'confidence_distribution': {},
            'cwe_coverage': set(),
            'processing_summary': processing_stats
        }

        for example in examples:
            # Dataset distribution
            dataset = example['source_dataset']
            stats['dataset_distribution'][dataset] = stats['dataset_distribution'].get(dataset, 0) + 1

            # Language distribution
            lang = example['language']
            stats['language_distribution'][lang] = stats['language_distribution'].get(lang, 0) + 1

            # Vulnerability distribution
            if example['is_vulnerable']:
                vuln_type = example['vulnerability_type']
                stats['vulnerability_distribution'][vuln_type] = stats['vulnerability_distribution'].get(vuln_type, 0) + 1

            # Severity distribution
            severity = example['severity']
            stats['severity_distribution'][severity] = stats['severity_distribution'].get(severity, 0) + 1

            # CWE coverage
            if example['cwe']:
                stats['cwe_coverage'].add(example['cwe'])

        # Convert set to list for JSON serialization
        stats['cwe_coverage'] = list(stats['cwe_coverage'])
        stats['unique_cwes'] = len(stats['cwe_coverage'])

        return stats

    def run_massive_collection(self) -> Dict[str, Any]:
        """Run the complete massive dataset collection pipeline"""
        print("=== VulnHunter Massive Dataset Collection Pipeline ===")
        print("Target: 250,000+ vulnerability examples for 92%+ accuracy")

        # Collect all datasets
        collection_results = self.collect_all_datasets()

        successful_datasets = [name for name, success in collection_results.items() if success]
        print(f"\nSuccessfully collected {len(successful_datasets)} datasets:")
        for dataset_name in successful_datasets:
            if dataset_name in self.collected_stats:
                stats = self.collected_stats[dataset_name]
                print(f"  - {dataset_name}: {stats['actual_files']:,} files")

        # Create unified dataset
        output_file = "vulnhunter_pro/training_data/massive_unified_dataset.json"
        comprehensive_stats = self.create_unified_dataset(output_file)

        print(f"\n=== Collection Complete ===")
        print(f"Total examples: {comprehensive_stats['total_examples']:,}")
        print(f"Vulnerable: {comprehensive_stats['vulnerable_examples']:,}")
        print(f"Safe: {comprehensive_stats['safe_examples']:,}")
        print(f"Unique CWEs: {comprehensive_stats['unique_cwes']}")
        print(f"Languages: {list(comprehensive_stats['language_distribution'].keys())}")

        return comprehensive_stats

def main():
    """Main collection function"""
    logging.basicConfig(level=logging.INFO)

    collector = MassiveDatasetCollector()
    stats = collector.run_massive_collection()

    print("\n=== Ready for Advanced Training ===")
    print("Next steps:")
    print("1. Run enhanced training pipeline on massive dataset")
    print("2. Implement DAST-focused training with runtime traces")
    print("3. Target 92%+ accuracy with advanced feature engineering")

if __name__ == "__main__":
    main()