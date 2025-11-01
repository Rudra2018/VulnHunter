#!/usr/bin/env python3
"""
VulnHunter Ωmega - Simplified Version for Testing
Works without PyTorch dependencies using pattern-based detection
"""

import sys
import os
import argparse
import json
import time
from pathlib import Path

class SimpleVulnDetector:
    """Simplified vulnerability detector using pattern matching"""

    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': {
                'patterns': ['select', 'insert', 'update', 'delete', 'union', 'drop', 'create'],
                'indicators': ['+', 'concat', '||', 'format'],
                'safe_patterns': ['?', 'prepare', 'parameterized']
            },
            'command_injection': {
                'patterns': ['exec', 'system', 'subprocess', 'popen', 'shell'],
                'indicators': ['+', 'format', 'shell=true'],
                'safe_patterns': ['shlex', 'quote', 'sanitize']
            },
            'xss': {
                'patterns': ['innerhtml', 'document.write', 'eval', 'script'],
                'indicators': ['+', 'format', '<script>', 'javascript:'],
                'safe_patterns': ['escape', 'html.escape', 'cgi.escape']
            },
            'path_traversal': {
                'patterns': ['open', 'file', 'read', 'write'],
                'indicators': ['../', '..\\', '+', 'format'],
                'safe_patterns': ['join', 'abspath', 'realpath']
            }
        }

        self.stats = {
            'files_analyzed': 0,
            'vulnerabilities_found': 0,
            'total_analysis_time': 0.0
        }

    def analyze_code(self, code: str, filename: str = 'code') -> dict:
        """Analyze code for vulnerabilities"""
        start_time = time.time()

        vulnerabilities = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower().strip()

            if not line_lower or line_lower.startswith('#') or line_lower.startswith('//'):
                continue

            # Check each vulnerability type
            for vuln_type, config in self.vulnerability_patterns.items():
                vuln_result = self._check_vulnerability(line, line_lower, vuln_type, config, line_num)
                if vuln_result:
                    vulnerabilities.append(vuln_result)

        analysis_time = time.time() - start_time
        self.stats['total_analysis_time'] += analysis_time
        self.stats['files_analyzed'] += 1
        self.stats['vulnerabilities_found'] += len(vulnerabilities)

        return {
            'filename': filename,
            'vulnerabilities': vulnerabilities,
            'analysis_time_ms': analysis_time * 1000,
            'lines_analyzed': len(lines),
            'safe': len(vulnerabilities) == 0
        }

    def _check_vulnerability(self, line: str, line_lower: str, vuln_type: str, config: dict, line_num: int) -> dict:
        """Check if line contains a specific vulnerability type"""

        # Check if any vulnerability patterns are present
        has_vuln_pattern = any(pattern in line_lower for pattern in config['patterns'])
        if not has_vuln_pattern:
            return None

        # Check if any risk indicators are present
        has_indicator = any(indicator in line for indicator in config['indicators'])
        if not has_indicator:
            return None

        # Check if safe patterns are present (reduces risk)
        has_safe_pattern = any(safe in line_lower for safe in config['safe_patterns'])

        # Calculate confidence and severity
        confidence = 0.8 if has_indicator and not has_safe_pattern else 0.5
        if has_safe_pattern:
            confidence *= 0.3  # Significantly reduce confidence if safe patterns found

        if confidence < 0.3:
            return None  # Too low confidence

        severity = self._calculate_severity(vuln_type, confidence)

        return {
            'type': vuln_type,
            'line': line_num,
            'line_content': line.strip(),
            'severity': severity,
            'confidence': confidence,
            'description': self._get_description(vuln_type),
            'remediation': self._get_remediation(vuln_type),
            'cwe_id': self._get_cwe_id(vuln_type),
            'risk_score': confidence * {'low': 3, 'medium': 6, 'high': 8, 'critical': 10}[severity]
        }

    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calculate vulnerability severity"""
        severity_map = {
            'sql_injection': 'high',
            'command_injection': 'critical',
            'xss': 'medium',
            'path_traversal': 'medium'
        }

        base_severity = severity_map.get(vuln_type, 'medium')

        if confidence > 0.8:
            return base_severity
        elif confidence > 0.6:
            return 'medium' if base_severity == 'critical' else base_severity
        else:
            return 'low'

    def _get_description(self, vuln_type: str) -> str:
        """Get vulnerability description"""
        descriptions = {
            'sql_injection': 'SQL injection vulnerability - user input may be directly incorporated into SQL queries',
            'command_injection': 'Command injection vulnerability - user input may be passed to system commands',
            'xss': 'Cross-site scripting (XSS) vulnerability - user input rendered without proper escaping',
            'path_traversal': 'Path traversal vulnerability - file paths may be manipulated to access unauthorized files'
        }
        return descriptions.get(vuln_type, f'{vuln_type} vulnerability detected')

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice"""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'command_injection': 'Validate and sanitize user inputs, use allow-lists for commands',
            'xss': 'Escape user inputs when rendering, implement Content Security Policy',
            'path_traversal': 'Validate file paths, use path canonicalization and allow-lists'
        }
        return remediations.get(vuln_type, 'Follow secure coding practices')

    def _get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'xss': 'CWE-79',
            'path_traversal': 'CWE-22'
        }
        return cwe_map.get(vuln_type, 'CWE-000')

    def analyze_directory(self, directory_path: str) -> dict:
        """Analyze all files in a directory"""
        results = {'files': [], 'summary': {}}

        supported_extensions = ['.py', '.js', '.php', '.java', '.c', '.cpp', '.sol']

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in supported_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()

                        file_result = self.analyze_code(code, file_path)
                        results['files'].append(file_result)

                    except Exception as e:
                        results['files'].append({
                            'filename': file_path,
                            'error': str(e),
                            'vulnerabilities': []
                        })

        # Generate summary
        total_vulns = sum(len(f.get('vulnerabilities', [])) for f in results['files'])
        results['summary'] = {
            'files_analyzed': len(results['files']),
            'total_vulnerabilities': total_vulns,
            'files_with_vulnerabilities': len([f for f in results['files'] if f.get('vulnerabilities', [])]),
            'analysis_stats': self.stats
        }

        return results

def main():
    parser = argparse.ArgumentParser(description='VulnHunter Ωmega - Simplified Vulnerability Scanner')
    parser.add_argument('--target', '-t', required=True, help='Target file or directory to analyze')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')

    args = parser.parse_args()

    if args.verbose:
        print("🚀 VulnHunter Ωmega - Simplified Vulnerability Scanner")
        print(f"📁 Target: {args.target}")
        print("🔍 Using pattern-based detection (PyTorch-free)")

    detector = SimpleVulnDetector()

    try:
        if os.path.isfile(args.target):
            with open(args.target, 'r', encoding='utf-8') as f:
                code = f.read()
            results = detector.analyze_code(code, args.target)

        elif os.path.isdir(args.target):
            results = detector.analyze_directory(args.target)

        else:
            print(f"❌ Error: {args.target} not found")
            return 1

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"📄 Results saved to {args.output}")
        else:
            if args.format == 'json':
                print(json.dumps(results, indent=2))
            else:
                # Text output
                if 'files' in results:  # Directory analysis
                    print("\n🔍 Directory Analysis Results:")
                    summary = results['summary']
                    print(f"📊 Files analyzed: {summary['files_analyzed']}")
                    print(f"🚨 Total vulnerabilities: {summary['total_vulnerabilities']}")
                    print(f"📁 Files with vulnerabilities: {summary['files_with_vulnerabilities']}")

                    # Show vulnerabilities by file
                    for file_result in results['files']:
                        vulns = file_result.get('vulnerabilities', [])
                        if vulns:
                            print(f"\n📄 {file_result['filename']}:")
                            for i, vuln in enumerate(vulns, 1):
                                print(f"  🚨 #{i} {vuln['severity'].upper()}: {vuln['type']} at line {vuln['line']}")
                                print(f"     📊 Confidence: {vuln['confidence']:.3f} | 🎯 Risk Score: {vuln['risk_score']:.1f}")
                                if args.verbose:
                                    print(f"     💡 {vuln['description']}")
                                    print(f"     🔧 {vuln['remediation']}")

                else:  # Single file analysis
                    print("\n🔍 Vulnerability Analysis Results:")
                    vulnerabilities = results.get('vulnerabilities', [])

                    if not vulnerabilities:
                        print("  ✅ No vulnerabilities detected")
                    else:
                        for i, vuln in enumerate(vulnerabilities, 1):
                            print(f"  🚨 #{i} {vuln['severity'].upper()}: {vuln['type']} at line {vuln['line']}")
                            print(f"     📊 Confidence: {vuln['confidence']:.3f} | 🎯 Risk Score: {vuln['risk_score']:.1f}")
                            print(f"     📍 CWE ID: {vuln['cwe_id']}")

                            if args.verbose:
                                print(f"     📝 Line: {vuln['line_content']}")
                                print(f"     💡 {vuln['description']}")
                                print(f"     🔧 {vuln['remediation']}")

                    print(f"\n📊 Analysis completed in {results.get('analysis_time_ms', 0):.1f}ms")

        return 0

    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())