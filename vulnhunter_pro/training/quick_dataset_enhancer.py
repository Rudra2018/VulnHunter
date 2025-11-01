#!/usr/bin/env python3
"""
Quick Dataset Enhancer for VulnHunter Professional
=================================================

Downloads and integrates additional datasets quickly while advanced training runs.
Focuses on immediately available datasets for accuracy improvement.
"""

import os
import sys
import json
import requests
import subprocess
from pathlib import Path
from typing import List, Dict, Any

def download_owasp_benchmark_full():
    """Download complete OWASP Benchmark if not already present"""
    benchmark_dir = "datasets/owasp_benchmark_full"

    if os.path.exists(benchmark_dir):
        print(f"OWASP Benchmark already exists at {benchmark_dir}")
        return True

    print("Downloading OWASP Benchmark...")
    try:
        os.makedirs("datasets", exist_ok=True)
        result = subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/OWASP-Benchmark/BenchmarkJava",
            benchmark_dir
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ OWASP Benchmark downloaded successfully")
            return True
        else:
            print(f"❌ Error downloading OWASP Benchmark: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def download_webgoat():
    """Download OWASP WebGoat for additional training data"""
    webgoat_dir = "datasets/webgoat"

    if os.path.exists(webgoat_dir):
        print(f"WebGoat already exists at {webgoat_dir}")
        return True

    print("Downloading OWASP WebGoat...")
    try:
        result = subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/WebGoat/WebGoat",
            webgoat_dir
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ WebGoat downloaded successfully")
            return True
        else:
            print(f"❌ Error downloading WebGoat: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def enhance_existing_dataset():
    """Enhance our existing dataset with additional processing"""

    print("=== Quick Dataset Enhancement ===")

    # Load existing enhanced dataset
    enhanced_file = "vulnhunter_pro/training_data/enhanced_real_world_dataset.json"

    if not os.path.exists(enhanced_file):
        print("❌ Enhanced dataset not found")
        return False

    with open(enhanced_file, 'r') as f:
        existing_data = json.load(f)

    print(f"Loaded {len(existing_data)} existing examples")

    # Download additional datasets
    datasets_downloaded = []

    if download_owasp_benchmark_full():
        datasets_downloaded.append("owasp_benchmark_full")

    if download_webgoat():
        datasets_downloaded.append("webgoat")

    # Process additional datasets if downloaded
    new_examples = []

    for dataset_name in datasets_downloaded:
        dataset_path = f"datasets/{dataset_name}"
        if os.path.exists(dataset_path):
            examples = process_dataset(dataset_name, dataset_path)
            new_examples.extend(examples)
            print(f"Processed {len(examples)} examples from {dataset_name}")

    if new_examples:
        # Combine with existing data
        combined_data = existing_data + new_examples

        # Save enhanced dataset
        enhanced_output = "vulnhunter_pro/training_data/quick_enhanced_dataset.json"
        with open(enhanced_output, 'w') as f:
            json.dump(combined_data, f, indent=2)

        print(f"✅ Enhanced dataset saved with {len(combined_data)} total examples")
        print(f"Added {len(new_examples)} new examples")

        # Generate quick stats
        stats = generate_quick_stats(combined_data)
        stats_file = enhanced_output.replace('.json', '_stats.json')
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        print(f"Stats saved to {stats_file}")
        return True
    else:
        print("No new datasets processed")
        return False

def process_dataset(name: str, path: str) -> List[Dict[str, Any]]:
    """Process a dataset directory"""
    examples = []

    if name == "owasp_benchmark_full":
        # Process additional OWASP Benchmark files
        java_files = list(Path(path).rglob("*.java"))

        for java_file in java_files[:1000]:  # Limit for quick processing
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    code = f.read()

                # Simple heuristic analysis
                is_vulnerable, vuln_type = analyze_java_code(code)

                examples.append({
                    'code': code,
                    'file_path': str(java_file),
                    'vulnerability_type': vuln_type if is_vulnerable else 'safe',
                    'is_vulnerable': is_vulnerable,
                    'cwe': None,
                    'severity': get_severity(vuln_type) if is_vulnerable else 'none',
                    'language': 'java',
                    'source_dataset': name,
                    'confidence': 0.8
                })

            except Exception:
                continue

    elif name == "webgoat":
        # Process WebGoat Java files
        java_files = list(Path(path).rglob("*.java"))

        for java_file in java_files[:500]:  # Limit for quick processing
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    code = f.read()

                # Simple heuristic analysis
                is_vulnerable, vuln_type = analyze_java_code(code)

                examples.append({
                    'code': code,
                    'file_path': str(java_file),
                    'vulnerability_type': vuln_type if is_vulnerable else 'safe',
                    'is_vulnerable': is_vulnerable,
                    'cwe': None,
                    'severity': get_severity(vuln_type) if is_vulnerable else 'none',
                    'language': 'java',
                    'source_dataset': name,
                    'confidence': 0.7
                })

            except Exception:
                continue

    return examples

def analyze_java_code(code: str) -> tuple:
    """Simple Java vulnerability analysis"""
    import re

    # SQL Injection
    if re.search(r'(executeQuery|execute)\s*\(\s*[^?]*\+', code):
        return True, 'sql_injection'

    # Command Injection
    if re.search(r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', code):
        return True, 'command_injection'

    # XSS
    if re.search(r'getParameter.*(?:print|write)', code):
        return True, 'reflected_xss'

    # Path Traversal
    if re.search(r'getParameter.*File\s*\(', code):
        return True, 'path_traversal'

    # LDAP Injection
    if re.search(r'LdapContext.*search.*getParameter', code):
        return True, 'ldap_injection'

    return False, 'unknown'

def get_severity(vuln_type: str) -> str:
    """Get severity for vulnerability type"""
    critical = ['sql_injection', 'command_injection', 'unsafe_deserialization']
    high = ['reflected_xss', 'path_traversal', 'ldap_injection']

    if vuln_type in critical:
        return 'critical'
    elif vuln_type in high:
        return 'high'
    else:
        return 'medium'

def generate_quick_stats(data: List[Dict]) -> Dict[str, Any]:
    """Generate quick statistics"""
    stats = {
        'total_examples': len(data),
        'vulnerable_examples': sum(1 for ex in data if ex['is_vulnerable']),
        'safe_examples': sum(1 for ex in data if not ex['is_vulnerable']),
        'source_distribution': {},
        'language_distribution': {},
        'vulnerability_distribution': {}
    }

    for example in data:
        # Source distribution
        source = example.get('source_dataset', 'unknown')
        stats['source_distribution'][source] = stats['source_distribution'].get(source, 0) + 1

        # Language distribution
        lang = example.get('language', 'unknown')
        stats['language_distribution'][lang] = stats['language_distribution'].get(lang, 0) + 1

        # Vulnerability distribution
        if example['is_vulnerable']:
            vuln_type = example['vulnerability_type']
            stats['vulnerability_distribution'][vuln_type] = stats['vulnerability_distribution'].get(vuln_type, 0) + 1

    return stats

def main():
    """Main enhancement function"""
    print("=== VulnHunter Quick Dataset Enhancement ===")

    success = enhance_existing_dataset()

    if success:
        print("\n✅ Dataset enhancement complete!")
        print("Enhanced dataset available at: vulnhunter_pro/training_data/quick_enhanced_dataset.json")
        print("\nNext steps:")
        print("1. The advanced training is running on the original dataset")
        print("2. After completion, retrain on the enhanced dataset")
        print("3. Compare accuracy improvements")
    else:
        print("\n❌ Dataset enhancement failed")

if __name__ == "__main__":
    main()