#!/usr/bin/env python3
"""
VulnHunter V4 Analysis of Azure CLI Repository
"""

import os
import json
import pickle
from pathlib import Path
from typing import List, Dict, Any
from vulnhunter_v4_production_model import VulnHunterV4Model

class AzureRepositoryAnalyzer:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.model = VulnHunterV4Model()
        self.results = []

    def scan_python_files(self) -> List[Path]:
        """Find all Python files in the repository."""
        python_files = []
        for py_file in self.repo_path.rglob("*.py"):
            if not any(skip in str(py_file) for skip in ['.git', '__pycache__', '.pytest_cache', 'build', 'dist']):
                python_files.append(py_file)
        return python_files

    def analyze_file_for_vulnerabilities(self, file_path: Path) -> List[Dict]:
        """Analyze a single file for potential vulnerabilities."""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')

            # Common vulnerability patterns to check
            vulnerability_patterns = [
                {
                    'pattern': ['subprocess.call', 'os.system', 'eval(', 'exec('],
                    'type': 'command_injection',
                    'description': 'Potential command injection vulnerability'
                },
                {
                    'pattern': ['input(', 'raw_input('],
                    'type': 'input_validation',
                    'description': 'User input without validation'
                },
                {
                    'pattern': ['pickle.load', 'cPickle.load'],
                    'type': 'deserialization',
                    'description': 'Insecure deserialization'
                },
                {
                    'pattern': ['os.path.join', 'open('],
                    'type': 'path_traversal',
                    'description': 'Potential path traversal vulnerability'
                },
                {
                    'pattern': ['requests.get', 'requests.post', 'urllib.request'],
                    'type': 'ssrf',
                    'description': 'Potential SSRF vulnerability'
                },
                {
                    'pattern': ['sql', 'SELECT', 'INSERT', 'UPDATE', 'DELETE'],
                    'type': 'sql_injection',
                    'description': 'Potential SQL injection vulnerability'
                }
            ]

            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()

                for vuln_pattern in vulnerability_patterns:
                    if any(pattern.lower() in line_lower for pattern in vuln_pattern['pattern']):
                        claim = f"Potential {vuln_pattern['description']} at {file_path}:{line_num} - {line.strip()}"

                        # Use VulnHunter V4 model to analyze
                        confidence, is_false_positive, analysis = self.model.predict(
                            claim=claim,
                            vuln_type=vuln_pattern['type'],
                            source_file=str(file_path),
                            dataset_source="Azure CLI Static Analysis",
                            metadata={
                                'line_number': line_num,
                                'file_path': str(file_path),
                                'pattern_matched': vuln_pattern['pattern']
                            }
                        )

                        vulnerabilities.append({
                            'file': str(file_path),
                            'line': line_num,
                            'code': line.strip(),
                            'vulnerability_type': vuln_pattern['type'],
                            'description': vuln_pattern['description'],
                            'claim': claim,
                            'model_analysis': analysis,
                            'confidence': confidence,
                            'is_false_positive': is_false_positive
                        })

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

        return vulnerabilities

    def run_analysis(self, max_files: int = 50) -> Dict[str, Any]:
        """Run comprehensive analysis on the repository."""
        print(f"🔍 Starting VulnHunter V4 analysis of Azure CLI repository...")
        print(f"📁 Repository path: {self.repo_path}")

        # Find Python files
        python_files = self.scan_python_files()
        print(f"📋 Found {len(python_files)} Python files")

        # Limit analysis for performance
        files_to_analyze = python_files[:max_files]
        print(f"🎯 Analyzing first {len(files_to_analyze)} files...")

        all_vulnerabilities = []

        for i, file_path in enumerate(files_to_analyze, 1):
            print(f"  [{i}/{len(files_to_analyze)}] Analyzing: {file_path.name}")
            vulns = self.analyze_file_for_vulnerabilities(file_path)
            all_vulnerabilities.extend(vulns)

        # Categorize results
        real_vulnerabilities = [v for v in all_vulnerabilities if not v['is_false_positive']]
        false_positives = [v for v in all_vulnerabilities if v['is_false_positive']]

        # Generate summary
        summary = {
            'repository': 'Azure CLI',
            'model_version': self.model.version,
            'analysis_timestamp': '2025-10-15',
            'files_analyzed': len(files_to_analyze),
            'total_files_in_repo': len(python_files),
            'total_findings': len(all_vulnerabilities),
            'real_vulnerabilities': len(real_vulnerabilities),
            'false_positives': len(false_positives),
            'vulnerability_types': self._get_vulnerability_breakdown(real_vulnerabilities),
            'high_risk_findings': [v for v in real_vulnerabilities if v['confidence'] > 0.8],
            'model_info': self.model.get_model_info()
        }

        # Detailed results
        results = {
            'summary': summary,
            'real_vulnerabilities': real_vulnerabilities,
            'false_positives': false_positives,
            'all_findings': all_vulnerabilities
        }

        return results

    def _get_vulnerability_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Get breakdown of vulnerability types."""
        breakdown = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            breakdown[vuln_type] = breakdown.get(vuln_type, 0) + 1
        return breakdown

    def save_results(self, results: Dict[str, Any], output_file: str):
        """Save analysis results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"💾 Results saved to: {output_file}")

def main():
    """Main analysis function."""
    repo_path = "/tmp/azure_cli"
    output_file = "/Users/ankitthakur/vuln_ml_research/azure_cli_analysis_results.json"

    if not os.path.exists(repo_path):
        print(f"❌ Repository not found at: {repo_path}")
        return

    analyzer = AzureRepositoryAnalyzer(repo_path)
    results = analyzer.run_analysis(max_files=100)

    # Print summary
    summary = results['summary']
    print(f"\n📊 ANALYSIS COMPLETE")
    print(f"=" * 50)
    print(f"Repository: {summary['repository']}")
    print(f"Files Analyzed: {summary['files_analyzed']}")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"Real Vulnerabilities: {summary['real_vulnerabilities']}")
    print(f"False Positives: {summary['false_positives']}")
    print(f"High Risk Findings: {len(summary['high_risk_findings'])}")

    print(f"\n🎯 VULNERABILITY BREAKDOWN:")
    for vuln_type, count in summary['vulnerability_types'].items():
        print(f"  {vuln_type}: {count}")

    print(f"\n🚨 HIGH RISK FINDINGS:")
    for finding in summary['high_risk_findings'][:5]:  # Show top 5
        print(f"  {finding['file']}:{finding['line']} - {finding['description']}")
        print(f"    Confidence: {finding['confidence']:.3f}")
        print(f"    Risk: {finding['model_analysis']['risk_assessment']}")

    # Save results
    analyzer.save_results(results, output_file)

    return results

if __name__ == "__main__":
    results = main()