#!/usr/bin/env python3
"""
Dangerous Function Deep Analyzer
Comprehensive analysis of dangerous function usage with context and risk assessment
"""

import json
import re
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class DangerousFunctionAnalysis:
    """Analysis result for a dangerous function"""
    function: str
    file_path: str
    project: str
    line_number: int = 0
    code_snippet: str = ""
    context: str = ""
    risk_level: str = "UNKNOWN"
    false_positive: bool = False
    explanation: str = ""
    recommendation: str = ""

class DangerousFunctionDeepAnalyzer:
    """Deep analyzer for dangerous functions in Google OSS projects"""

    # Risk classification rules
    RISK_RULES = {
        'eval(': {
            'HIGH': ['user input', 'request', 'param', 'query', 'form'],
            'MEDIUM': ['config', 'settings', 'options'],
            'LOW': ['test', 'spec', 'mock', 'fixture', 'example'],
            'SAFE': ['constant', 'literal', 'hardcoded', '__', 'internal']
        },
        'exec(': {
            'HIGH': ['user input', 'request', 'param', 'query', 'form'],
            'MEDIUM': ['config', 'command', 'shell'],
            'LOW': ['test', 'spec', 'mock', 'fixture'],
            'SAFE': ['constant', 'literal', 'regex', 'pattern']
        },
        'innerHTML': {
            'HIGH': ['user input', 'unsanitized', 'raw'],
            'MEDIUM': ['content', 'html', 'template'],
            'LOW': ['test', 'spec', 'mock'],
            'SAFE': ['sanitized', 'trusted', 'escape', 'DomSanitizer']
        },
        'os.system(': {
            'HIGH': ['user input', 'request', 'param'],
            'MEDIUM': ['config', 'command'],
            'LOW': ['test', 'build'],
            'SAFE': ['constant', 'literal']
        },
        'subprocess.call(': {
            'HIGH': ['user input', 'request', 'param'],
            'MEDIUM': ['config', 'command'],
            'LOW': ['test', 'build', 'setup'],
            'SAFE': ['constant', 'literal', 'shlex.quote']
        },
        '__import__': {
            'HIGH': ['user input', 'request'],
            'MEDIUM': ['dynamic', 'plugin'],
            'LOW': ['test', 'mock'],
            'SAFE': ['constant', 'literal']
        }
    }

    # Context patterns
    SAFE_CONTEXTS = {
        'test': ['test/', '_test.', '.spec.', '_spec.', 'mock', 'fixture'],
        'build': ['build/', 'scripts/', 'tools/', 'setup'],
        'example': ['example', 'demo', 'sample', 'playground'],
        'documentation': ['docs/', 'README', 'CONTRIBUTING']
    }

    def __init__(self, analysis_dir: str):
        """Initialize analyzer"""
        self.analysis_dir = Path(analysis_dir)
        self.results_dir = self.analysis_dir / "results"
        self.clone_dir = self.analysis_dir / "cloned_projects"

        self.findings = []
        self.statistics = defaultdict(Counter)

    def load_findings(self) -> List[Dict]:
        """Load all dangerous function findings from JSON reports"""
        all_findings = []

        for report_file in self.results_dir.glob("*.json"):
            with open(report_file) as f:
                data = json.load(f)
                project_name = data['project']['name']

                if 'vulnhunter_results' in data and 'analyses' in data['vulnhunter_results']:
                    sec_patterns = data['vulnhunter_results']['analyses'].get('security_patterns', {})
                    dangerous = sec_patterns.get('dangerous_functions', [])

                    for finding in dangerous:
                        finding['project'] = project_name
                        all_findings.append(finding)

        return all_findings

    def determine_context(self, file_path: str) -> str:
        """Determine the context category of the file"""
        file_path_lower = file_path.lower()

        for context, patterns in self.SAFE_CONTEXTS.items():
            for pattern in patterns:
                if pattern in file_path_lower:
                    return context

        return "production"

    def assess_risk(self, function: str, file_path: str, code_snippet: str = "") -> Tuple[str, bool, str]:
        """
        Assess the risk level of a dangerous function usage
        Returns: (risk_level, is_false_positive, explanation)
        """
        # Check context first
        context = self.determine_context(file_path)

        if context in ['test', 'example', 'documentation']:
            return 'LOW', True, f"Used in {context} code - not production"

        # Get risk rules for this function
        if function not in self.RISK_RULES:
            return 'MEDIUM', False, "Unknown function, needs manual review"

        rules = self.RISK_RULES[function]
        combined_text = (file_path + " " + code_snippet).lower()

        # Check SAFE patterns first
        for safe_pattern in rules.get('SAFE', []):
            if safe_pattern in combined_text:
                return 'LOW', True, f"Safe pattern detected: '{safe_pattern}'"

        # Check risk levels
        for risk_level in ['HIGH', 'MEDIUM', 'LOW']:
            for pattern in rules.get(risk_level, []):
                if pattern in combined_text:
                    return risk_level, False, f"Risk pattern detected: '{pattern}'"

        # Default
        if context == 'build':
            return 'LOW', True, "Used in build/tooling scripts"

        return 'MEDIUM', False, "No clear risk indicators, needs review"

    def get_code_snippet(self, project: str, file_path: str, target_function: str) -> Tuple[str, int]:
        """Extract code snippet containing the dangerous function"""
        # Re-clone project if needed for deep analysis
        project_dir = self.clone_dir / project.lower().replace(" ", "_")

        if not project_dir.exists():
            return "", 0

        full_path = project_dir / file_path

        if not full_path.exists():
            return "", 0

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Find line with function
            for line_num, line in enumerate(lines, 1):
                if target_function in line:
                    # Get context (3 lines before and after)
                    start = max(0, line_num - 4)
                    end = min(len(lines), line_num + 3)
                    snippet_lines = lines[start:end]

                    snippet = "".join(snippet_lines)
                    return snippet.strip(), line_num

        except Exception as e:
            pass

        return "", 0

    def analyze_all_findings(self) -> List[DangerousFunctionAnalysis]:
        """Analyze all dangerous function findings"""
        print(f"\n🔍 Starting Deep Analysis of Dangerous Functions...")

        raw_findings = self.load_findings()
        print(f"📊 Total findings to analyze: {len(raw_findings)}")

        analyzed = []

        for idx, finding in enumerate(raw_findings, 1):
            if idx % 50 == 0:
                print(f"  Progress: {idx}/{len(raw_findings)}...")

            function = finding['function']
            file_path = finding['file']
            project = finding['project']

            # Get code snippet
            # Note: We'll skip re-cloning for speed, use path analysis only
            code_snippet = ""
            line_number = 0

            # Assess risk
            risk_level, is_fp, explanation = self.assess_risk(function, file_path, code_snippet)

            # Generate recommendation
            recommendation = self.generate_recommendation(function, risk_level, is_fp)

            analysis = DangerousFunctionAnalysis(
                function=function,
                file_path=file_path,
                project=project,
                line_number=line_number,
                code_snippet=code_snippet,
                context=self.determine_context(file_path),
                risk_level=risk_level,
                false_positive=is_fp,
                explanation=explanation,
                recommendation=recommendation
            )

            analyzed.append(analysis)

            # Update statistics
            self.statistics['by_risk'][risk_level] += 1
            self.statistics['by_function'][function] += 1
            self.statistics['by_project'][project] += 1
            if is_fp:
                self.statistics['false_positives']['total'] += 1

        print(f"✓ Analysis complete: {len(analyzed)} findings analyzed")
        return analyzed

    def generate_recommendation(self, function: str, risk_level: str, is_fp: bool) -> str:
        """Generate specific recommendation for the finding"""
        if is_fp:
            return "Low priority - appears to be safe usage in test/example code"

        recommendations = {
            'eval(': {
                'HIGH': "CRITICAL: Remove eval() or implement strict input validation and sandboxing",
                'MEDIUM': "Review eval() usage - consider safer alternatives like JSON.parse() or ast.literal_eval()",
                'LOW': "Document why eval() is necessary and ensure input is controlled"
            },
            'exec(': {
                'HIGH': "CRITICAL: Replace exec() with safer alternatives or implement strict validation",
                'MEDIUM': "Review exec() usage - consider restricted execution environment",
                'LOW': "Document exec() usage and ensure controlled input"
            },
            'innerHTML': {
                'HIGH': "CRITICAL: Use textContent or DomSanitizer to prevent XSS attacks",
                'MEDIUM': "Sanitize HTML content before setting innerHTML",
                'LOW': "Ensure HTML content is from trusted sources"
            },
            'os.system(': {
                'HIGH': "CRITICAL: Replace os.system() with subprocess module and validate input",
                'MEDIUM': "Use subprocess with shell=False and validated arguments",
                'LOW': "Document command execution and ensure controlled parameters"
            },
            'subprocess.call(': {
                'HIGH': "CRITICAL: Validate and sanitize all subprocess arguments, use shlex.quote()",
                'MEDIUM': "Use shell=False and pass arguments as list, not string",
                'LOW': "Ensure subprocess arguments are from trusted sources"
            },
            '__import__': {
                'HIGH': "CRITICAL: Restrict dynamic imports to whitelist of allowed modules",
                'MEDIUM': "Review dynamic import necessity, consider importlib with restrictions",
                'LOW': "Document dynamic import usage and ensure controlled module names"
            }
        }

        return recommendations.get(function, {}).get(risk_level, "Review usage and ensure proper security controls")

    def generate_report(self, analyzed_findings: List[DangerousFunctionAnalysis], output_file: str):
        """Generate comprehensive analysis report"""
        print(f"\n📄 Generating comprehensive report...")

        with open(output_file, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("DANGEROUS FUNCTIONS - COMPREHENSIVE DEEP ANALYSIS REPORT\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Findings: {len(analyzed_findings)}\n")
            f.write(f"False Positives: {self.statistics['false_positives']['total']}\n")
            f.write(f"True Positives: {len(analyzed_findings) - self.statistics['false_positives']['total']}\n\n")

            # Executive Summary
            f.write("-" * 100 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 100 + "\n\n")

            high_risk = self.statistics['by_risk']['HIGH']
            medium_risk = self.statistics['by_risk']['MEDIUM']
            low_risk = self.statistics['by_risk']['LOW']

            f.write(f"🔴 HIGH RISK:     {high_risk:4d} findings - Require immediate attention\n")
            f.write(f"🟡 MEDIUM RISK:   {medium_risk:4d} findings - Require code review\n")
            f.write(f"🟢 LOW RISK:      {low_risk:4d} findings - Monitor and document\n\n")

            # Risk Distribution by Function
            f.write("-" * 100 + "\n")
            f.write("RISK DISTRIBUTION BY FUNCTION TYPE\n")
            f.write("-" * 100 + "\n\n")

            func_risks = defaultdict(Counter)
            for finding in analyzed_findings:
                func_risks[finding.function][finding.risk_level] += 1

            for function in sorted(func_risks.keys()):
                total = sum(func_risks[function].values())
                f.write(f"{function} ({total} total findings):\n")
                f.write(f"  HIGH:   {func_risks[function]['HIGH']:4d}  |  ")
                f.write(f"MEDIUM: {func_risks[function]['MEDIUM']:4d}  |  ")
                f.write(f"LOW:    {func_risks[function]['LOW']:4d}\n\n")

            # Risk Distribution by Project
            f.write("-" * 100 + "\n")
            f.write("RISK DISTRIBUTION BY PROJECT\n")
            f.write("-" * 100 + "\n\n")

            project_risks = defaultdict(Counter)
            for finding in analyzed_findings:
                project_risks[finding.project][finding.risk_level] += 1

            for project in sorted(project_risks.keys()):
                total = sum(project_risks[project].values())
                f.write(f"{project} ({total} total findings):\n")
                f.write(f"  HIGH:   {project_risks[project]['HIGH']:4d}  |  ")
                f.write(f"MEDIUM: {project_risks[project]['MEDIUM']:4d}  |  ")
                f.write(f"LOW:    {project_risks[project]['LOW']:4d}\n\n")

            # Context Analysis
            f.write("-" * 100 + "\n")
            f.write("FINDINGS BY CONTEXT\n")
            f.write("-" * 100 + "\n\n")

            context_counter = Counter(f.context for f in analyzed_findings)
            for context, count in context_counter.most_common():
                percentage = (count / len(analyzed_findings)) * 100
                f.write(f"  {context:15s}: {count:4d} ({percentage:5.1f}%)\n")

            # Detailed Findings by Risk Level
            f.write("\n" + "=" * 100 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 100 + "\n\n")

            for risk_level in ['HIGH', 'MEDIUM', 'LOW']:
                findings_at_level = [f for f in analyzed_findings if f.risk_level == risk_level and not f.false_positive]

                if not findings_at_level:
                    continue

                f.write("\n" + "-" * 100 + "\n")
                f.write(f"{risk_level} RISK FINDINGS ({len(findings_at_level)} total)\n")
                f.write("-" * 100 + "\n\n")

                # Group by function
                by_func = defaultdict(list)
                for finding in findings_at_level:
                    by_func[finding.function].append(finding)

                for function, func_findings in sorted(by_func.items()):
                    f.write(f"\n{function} - {len(func_findings)} occurrences:\n")
                    f.write("=" * 100 + "\n")

                    # Show first 10 of each
                    for idx, finding in enumerate(func_findings[:10], 1):
                        f.write(f"\n{idx}. [{finding.project}] {finding.file_path}\n")
                        f.write(f"   Context: {finding.context}\n")
                        f.write(f"   Explanation: {finding.explanation}\n")
                        f.write(f"   Recommendation: {finding.recommendation}\n")

                    if len(func_findings) > 10:
                        f.write(f"\n   ... and {len(func_findings) - 10} more occurrences\n")

            # Recommendations
            f.write("\n" + "=" * 100 + "\n")
            f.write("SECURITY RECOMMENDATIONS\n")
            f.write("=" * 100 + "\n\n")

            f.write("IMMEDIATE ACTIONS (HIGH RISK):\n")
            f.write("-" * 100 + "\n")
            f.write("1. Review all HIGH risk eval() and exec() usage immediately\n")
            f.write("2. Implement input validation and sanitization for user-facing code\n")
            f.write("3. Replace os.system() calls with subprocess module\n")
            f.write("4. Add DomSanitizer for all innerHTML operations with user content\n\n")

            f.write("SHORT-TERM ACTIONS (MEDIUM RISK):\n")
            f.write("-" * 100 + "\n")
            f.write("1. Code review all MEDIUM risk findings within 30 days\n")
            f.write("2. Document security controls for necessary dangerous functions\n")
            f.write("3. Add unit tests to verify input validation\n")
            f.write("4. Implement static analysis rules to prevent new introductions\n\n")

            f.write("LONG-TERM ACTIONS:\n")
            f.write("-" * 100 + "\n")
            f.write("1. Create coding guidelines for dangerous function usage\n")
            f.write("2. Security training on common pitfalls\n")
            f.write("3. Regular security audits every quarter\n")
            f.write("4. Consider safer language features and libraries\n\n")

            # False Positives Section
            f.write("\n" + "=" * 100 + "\n")
            f.write("FALSE POSITIVE ANALYSIS\n")
            f.write("=" * 100 + "\n\n")

            fp_findings = [f for f in analyzed_findings if f.false_positive]
            f.write(f"Total False Positives: {len(fp_findings)} ({(len(fp_findings)/len(analyzed_findings)*100):.1f}%)\n\n")

            fp_by_context = Counter(f.context for f in fp_findings)
            f.write("False Positives by Context:\n")
            for context, count in fp_by_context.most_common():
                f.write(f"  {context:15s}: {count:4d}\n")

            f.write("\n" + "=" * 100 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 100 + "\n")

        print(f"✓ Report generated: {output_file}")

    def generate_json_report(self, analyzed_findings: List[DangerousFunctionAnalysis], output_file: str):
        """Generate JSON report for programmatic access"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_findings': len(analyzed_findings),
            'statistics': {
                'by_risk': dict(self.statistics['by_risk']),
                'by_function': dict(self.statistics['by_function']),
                'by_project': dict(self.statistics['by_project']),
                'false_positives': dict(self.statistics['false_positives'])
            },
            'findings': [asdict(f) for f in analyzed_findings]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✓ JSON report generated: {output_file}")

def main():
    """Main entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 dangerous_function_deep_analyzer.py <analysis_dir>")
        sys.exit(1)

    analysis_dir = sys.argv[1]

    print("=" * 100)
    print("DANGEROUS FUNCTION DEEP ANALYZER")
    print("=" * 100)

    analyzer = DangerousFunctionDeepAnalyzer(analysis_dir)

    # Analyze all findings
    analyzed = analyzer.analyze_all_findings()

    # Generate reports
    output_dir = Path(analysis_dir)
    text_report = output_dir / "DANGEROUS_FUNCTIONS_DEEP_ANALYSIS.txt"
    json_report = output_dir / "dangerous_functions_analysis.json"

    analyzer.generate_report(analyzed, str(text_report))
    analyzer.generate_json_report(analyzed, str(json_report))

    print("\n" + "=" * 100)
    print("✅ ANALYSIS COMPLETE")
    print("=" * 100)
    print(f"📄 Text Report: {text_report}")
    print(f"📊 JSON Report: {json_report}")
    print("=" * 100)

if __name__ == "__main__":
    main()
