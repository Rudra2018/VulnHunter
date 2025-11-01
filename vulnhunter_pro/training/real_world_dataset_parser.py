#!/usr/bin/env python3
"""
Real-World Dataset Parser for VulnHunter Professional
====================================================

Parses real-world vulnerability datasets including:
- OWASP Benchmark (Java web vulnerabilities)
- LAVA Binary Dataset (C/C++ binary vulnerabilities)
- Additional security datasets

Combines synthetic and real-world data for comprehensive training.
"""

import os
import sys
import json
import csv
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import re
from dataclasses import dataclass

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityExample:
    """Real-world vulnerability example"""
    code: str
    file_path: str
    vulnerability_type: str
    is_vulnerable: bool
    cwe: Optional[str] = None
    severity: str = "medium"
    language: str = "unknown"
    source_dataset: str = "unknown"
    confidence: float = 1.0

class RealWorldDatasetParser:
    """Parser for real-world vulnerability datasets"""

    def __init__(self, dataset_dir: str = "~/dataset"):
        self.dataset_dir = os.path.expanduser(dataset_dir)
        self.examples = []

        # CWE to vulnerability type mapping
        self.cwe_mapping = {
            "22": "path_traversal",
            "78": "command_injection",
            "79": "reflected_xss",
            "89": "sql_injection",
            "90": "ldap_injection",
            "120": "buffer_overflow",
            "134": "format_string",
            "190": "integer_overflow",
            "295": "cert_validation_bypass",
            "327": "weak_crypto",
            "328": "weak_hash",
            "330": "weak_random",
            "476": "null_pointer_dereference",
            "501": "trust_boundary_violation",
            "502": "unsafe_deserialization",
            "614": "insecure_cookie",
            "798": "hardcoded_credentials"
        }

        # Vulnerability type to severity mapping
        self.severity_mapping = {
            "command_injection": "critical",
            "sql_injection": "critical",
            "buffer_overflow": "critical",
            "unsafe_deserialization": "critical",
            "reflected_xss": "high",
            "path_traversal": "high",
            "ldap_injection": "high",
            "hardcoded_credentials": "high",
            "cert_validation_bypass": "high",
            "format_string": "high",
            "trust_boundary_violation": "medium",
            "weak_crypto": "medium",
            "weak_hash": "medium",
            "integer_overflow": "medium",
            "null_pointer_dereference": "medium",
            "weak_random": "low",
            "insecure_cookie": "low"
        }

    def parse_owasp_benchmark(self) -> List[VulnerabilityExample]:
        """Parse OWASP Benchmark dataset"""
        owasp_dir = os.path.join(self.dataset_dir, "web_owasp")
        results_file = os.path.join(owasp_dir, "expectedresults-1.2.csv")
        java_src_dir = os.path.join(owasp_dir, "src/main/java/org/owasp/benchmark/testcode")

        if not os.path.exists(results_file):
            logger.warning(f"OWASP results file not found: {results_file}")
            return []

        if not os.path.exists(java_src_dir):
            logger.warning(f"OWASP source directory not found: {java_src_dir}")
            return []

        print(f"Parsing OWASP Benchmark from {owasp_dir}...")

        # Load ground truth labels
        labels = {}
        with open(results_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row[0].startswith('#') or len(row) < 4:
                    continue
                test_name, category, is_vuln, cwe = row[:4]
                labels[test_name] = {
                    'category': category,
                    'is_vulnerable': is_vuln.lower() == 'true',
                    'cwe': cwe
                }

        print(f"Loaded {len(labels)} ground truth labels")

        examples = []
        java_files = list(Path(java_src_dir).glob("*.java"))

        print(f"Processing {len(java_files)} Java source files...")

        for java_file in java_files:
            test_name = java_file.stem

            if test_name not in labels:
                continue

            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    code_content = f.read()

                label_info = labels[test_name]
                cwe = label_info['cwe']
                vuln_type = self.cwe_mapping.get(cwe, label_info['category'])
                severity = self.severity_mapping.get(vuln_type, "medium")

                example = VulnerabilityExample(
                    code=code_content,
                    file_path=str(java_file),
                    vulnerability_type=vuln_type,
                    is_vulnerable=label_info['is_vulnerable'],
                    cwe=f"CWE-{cwe}",
                    severity=severity,
                    language="java",
                    source_dataset="owasp_benchmark",
                    confidence=1.0
                )

                examples.append(example)

            except Exception as e:
                logger.warning(f"Error processing {java_file}: {e}")
                continue

        print(f"Successfully parsed {len(examples)} OWASP Benchmark examples")
        return examples

    def parse_lava_dataset(self) -> List[VulnerabilityExample]:
        """Parse LAVA binary vulnerability dataset"""
        lava_dir = os.path.join(self.dataset_dir, "binary_lava")

        if not os.path.exists(lava_dir):
            logger.warning(f"LAVA directory not found: {lava_dir}")
            return []

        print(f"Parsing LAVA dataset from {lava_dir}...")

        examples = []

        # Find all C/C++ source files
        for ext in ['*.c', '*.cpp', '*.h']:
            c_files = list(Path(lava_dir).rglob(ext))

            for c_file in c_files:
                try:
                    with open(c_file, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()

                    # Heuristic analysis for vulnerability patterns
                    is_vulnerable, vuln_types = self._analyze_c_code(code_content)

                    for vuln_type in vuln_types:
                        severity = self.severity_mapping.get(vuln_type, "medium")

                        example = VulnerabilityExample(
                            code=code_content,
                            file_path=str(c_file),
                            vulnerability_type=vuln_type,
                            is_vulnerable=is_vulnerable,
                            cwe=None,
                            severity=severity,
                            language="c",
                            source_dataset="lava_binary",
                            confidence=0.7  # Lower confidence for heuristic analysis
                        )

                        examples.append(example)

                    # If no vulnerabilities detected, add as safe example
                    if not vuln_types:
                        example = VulnerabilityExample(
                            code=code_content,
                            file_path=str(c_file),
                            vulnerability_type="safe",
                            is_vulnerable=False,
                            cwe=None,
                            severity="none",
                            language="c",
                            source_dataset="lava_binary",
                            confidence=0.8
                        )
                        examples.append(example)

                except Exception as e:
                    logger.warning(f"Error processing {c_file}: {e}")
                    continue

        print(f"Successfully parsed {len(examples)} LAVA examples")
        return examples

    def _analyze_c_code(self, code: str) -> Tuple[bool, List[str]]:
        """Heuristic analysis of C code for vulnerability patterns"""
        vulnerabilities = []

        # Buffer overflow patterns
        if re.search(r'\b(strcpy|strcat|sprintf|gets)\s*\(', code):
            vulnerabilities.append("buffer_overflow")

        # Format string vulnerabilities
        if re.search(r'printf\s*\(\s*[^"]*\w+[^"]*\)', code):
            vulnerabilities.append("format_string")

        # Command injection patterns
        if re.search(r'\b(system|exec|popen)\s*\(', code):
            vulnerabilities.append("command_injection")

        # Memory management issues
        if re.search(r'\b(malloc|free|realloc)\s*\(', code):
            if 'free(' in code and code.count('malloc(') > code.count('free('):
                vulnerabilities.append("memory_leak")

        # Null pointer dereference patterns
        if re.search(r'\*\s*\w+\s*(?!=)', code) and 'if' not in code:
            vulnerabilities.append("null_pointer_dereference")

        # Integer overflow patterns
        if re.search(r'\+\+|\-\-|\+=|\-=', code) and 'int' in code:
            vulnerabilities.append("integer_overflow")

        return len(vulnerabilities) > 0, vulnerabilities

    def combine_with_synthetic_data(self, synthetic_file: str) -> List[Dict[str, Any]]:
        """Combine real-world data with synthetic dataset"""
        print("Loading synthetic vulnerability dataset...")

        synthetic_examples = []
        if os.path.exists(synthetic_file):
            with open(synthetic_file, 'r') as f:
                synthetic_examples = json.load(f)
            print(f"Loaded {len(synthetic_examples)} synthetic examples")

        # Parse real-world datasets
        real_examples = []
        real_examples.extend(self.parse_owasp_benchmark())
        real_examples.extend(self.parse_lava_dataset())

        print(f"Total real-world examples: {len(real_examples)}")

        # Convert real examples to dictionary format
        real_dict_examples = []
        for example in real_examples:
            real_dict_examples.append({
                'code': example.code,
                'file_path': example.file_path,
                'vulnerability_type': example.vulnerability_type,
                'is_vulnerable': example.is_vulnerable,
                'cwe': example.cwe,
                'severity': example.severity,
                'language': example.language,
                'source_dataset': example.source_dataset,
                'confidence': example.confidence
            })

        # Combine datasets
        combined_examples = synthetic_examples + real_dict_examples

        print(f"Combined dataset size: {len(combined_examples)}")
        print(f"  - Synthetic: {len(synthetic_examples)}")
        print(f"  - Real-world: {len(real_dict_examples)}")

        return combined_examples

    def generate_enhanced_dataset(self, output_file: str) -> Dict[str, Any]:
        """Generate enhanced dataset combining synthetic and real-world data"""
        print("=== Enhanced Real-World Dataset Generation ===")

        # Load synthetic data
        synthetic_file = "vulnhunter_pro/training_data/comprehensive_vulnerability_dataset.json"

        # Combine datasets
        combined_examples = self.combine_with_synthetic_data(synthetic_file)

        # Save enhanced dataset
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(combined_examples, f, indent=2)

        # Generate statistics
        stats = self._generate_dataset_stats(combined_examples)

        # Save statistics
        stats_file = output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        print(f"Enhanced dataset saved to: {output_file}")
        print(f"Dataset statistics saved to: {stats_file}")

        return stats

    def _generate_dataset_stats(self, examples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive dataset statistics"""
        stats = {
            'total_examples': len(examples),
            'vulnerable_examples': sum(1 for ex in examples if ex['is_vulnerable']),
            'safe_examples': sum(1 for ex in examples if not ex['is_vulnerable']),
            'source_distribution': {},
            'language_distribution': {},
            'vulnerability_type_distribution': {},
            'severity_distribution': {},
            'cwe_distribution': {}
        }

        # Calculate distributions
        for example in examples:
            # Source dataset distribution
            source = example.get('source_dataset', 'unknown')
            stats['source_distribution'][source] = stats['source_distribution'].get(source, 0) + 1

            # Language distribution
            lang = example.get('language', 'unknown')
            stats['language_distribution'][lang] = stats['language_distribution'].get(lang, 0) + 1

            # Vulnerability type distribution
            if example['is_vulnerable']:
                vuln_type = example['vulnerability_type']
                stats['vulnerability_type_distribution'][vuln_type] = stats['vulnerability_type_distribution'].get(vuln_type, 0) + 1

            # Severity distribution
            severity = example.get('severity', 'none')
            stats['severity_distribution'][severity] = stats['severity_distribution'].get(severity, 0) + 1

            # CWE distribution
            cwe = example.get('cwe')
            if cwe:
                stats['cwe_distribution'][cwe] = stats['cwe_distribution'].get(cwe, 0) + 1

        return stats

def main():
    """Main dataset parsing function"""
    logging.basicConfig(level=logging.INFO)

    parser = RealWorldDatasetParser()

    # Generate enhanced dataset
    output_file = "vulnhunter_pro/training_data/enhanced_real_world_dataset.json"
    stats = parser.generate_enhanced_dataset(output_file)

    print("\n=== Enhanced Dataset Statistics ===")
    print(f"Total Examples: {stats['total_examples']:,}")
    print(f"Vulnerable: {stats['vulnerable_examples']:,} ({stats['vulnerable_examples']/stats['total_examples']*100:.1f}%)")
    print(f"Safe: {stats['safe_examples']:,} ({stats['safe_examples']/stats['total_examples']*100:.1f}%)")

    print("\nSource Distribution:")
    for source, count in stats['source_distribution'].items():
        print(f"  {source}: {count:,}")

    print("\nLanguage Distribution:")
    for lang, count in stats['language_distribution'].items():
        print(f"  {lang}: {count:,}")

    print("\nTop Vulnerability Types:")
    vuln_types = sorted(stats['vulnerability_type_distribution'].items(), key=lambda x: x[1], reverse=True)
    for vuln_type, count in vuln_types[:10]:
        print(f"  {vuln_type}: {count:,}")

if __name__ == "__main__":
    main()