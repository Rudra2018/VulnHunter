#!/usr/bin/env python3
"""
VulnHunter V4 Critical Issues Analysis
Comprehensive analysis and classification of all critical security findings
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

class CriticalIssuesAnalyzer:
    """Analyze and classify critical security issues from VulnHunter V4 findings."""

    def __init__(self):
        self.severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }

    def analyze_findings(self, correlation_results_path: str) -> Dict[str, Any]:
        """Analyze correlation results to identify critical issues."""

        # Load correlation results
        with open(correlation_results_path, 'r') as f:
            data = json.load(f)

        findings = data.get('findings_details', [])

        print("🚨 VulnHunter V4 Critical Issues Analysis")
        print("=" * 60)
        print(f"📊 Total verified findings: {len(findings)}")
        print()

        # Classify issues by severity and type
        issue_classification = self._classify_issues(findings)

        # Identify critical patterns
        critical_patterns = self._identify_critical_patterns(findings)

        # Generate security impact assessment
        security_impact = self._assess_security_impact(findings)

        # Create actionable recommendations
        recommendations = self._generate_recommendations(findings, critical_patterns)

        return {
            'analysis_summary': {
                'total_findings': len(findings),
                'analysis_timestamp': datetime.now().isoformat(),
                'repository': data.get('correlation_demo', {}).get('repository', 'Unknown'),
                'verification_rate': data.get('correlation_demo', {}).get('success_rate', 0)
            },
            'issue_classification': issue_classification,
            'critical_patterns': critical_patterns,
            'security_impact': security_impact,
            'recommendations': recommendations,
            'detailed_findings': self._format_detailed_findings(findings)
        }

    def _classify_issues(self, findings: List[Dict]) -> Dict[str, Any]:
        """Classify issues by type and severity."""

        classification = {
            'by_type': {},
            'by_severity': {},
            'by_component': {},
            'high_risk_areas': []
        }

        for finding in findings:
            vuln_type = finding['vulnerability_type']
            file_path = finding['file_path']

            # Classify by type
            if vuln_type not in classification['by_type']:
                classification['by_type'][vuln_type] = []
            classification['by_type'][vuln_type].append(finding)

            # Determine severity based on context and type
            severity = self._determine_severity(finding)

            if severity not in classification['by_severity']:
                classification['by_severity'][severity] = []
            classification['by_severity'][severity].append(finding)

            # Classify by component
            component = self._extract_component(file_path)
            if component not in classification['by_component']:
                classification['by_component'][component] = []
            classification['by_component'][component].append(finding)

        # Identify high-risk areas
        for component, component_findings in classification['by_component'].items():
            if len(component_findings) >= 3:  # Multiple vulnerabilities in same component
                risk_score = sum(
                    self.severity_weights[self._determine_severity(f)]
                    for f in component_findings
                )
                classification['high_risk_areas'].append({
                    'component': component,
                    'finding_count': len(component_findings),
                    'risk_score': risk_score,
                    'vulnerability_types': list(set(f['vulnerability_type'] for f in component_findings))
                })

        # Sort high-risk areas by risk score
        classification['high_risk_areas'].sort(key=lambda x: x['risk_score'], reverse=True)

        return classification

    def _identify_critical_patterns(self, findings: List[Dict]) -> Dict[str, Any]:
        """Identify critical security patterns across findings."""

        patterns = {
            'file_system_operations': [],
            'path_construction': [],
            'command_execution': [],
            'configuration_loading': [],
            'extension_handling': []
        }

        for finding in findings:
            actual_line = finding['verification_details']['actual_line']
            file_path = finding['file_path']

            # File system operations
            if any(op in actual_line for op in ['readFileSync', 'writeFileSync', 'existsSync']):
                patterns['file_system_operations'].append({
                    'finding': finding,
                    'pattern': 'File system access',
                    'risk': 'Direct file system manipulation'
                })

            # Path construction
            if 'path.join' in actual_line:
                patterns['path_construction'].append({
                    'finding': finding,
                    'pattern': 'Dynamic path construction',
                    'risk': 'Potential path traversal vulnerability'
                })

            # Command execution
            if any(cmd in actual_line for cmd in ['spawn', 'exec', 'pty.spawn']):
                patterns['command_execution'].append({
                    'finding': finding,
                    'pattern': 'Command execution',
                    'risk': 'Code injection and command injection'
                })

            # Configuration loading
            if 'config' in file_path.lower() and 'readFileSync' in actual_line:
                patterns['configuration_loading'].append({
                    'finding': finding,
                    'pattern': 'Configuration file loading',
                    'risk': 'Configuration tampering'
                })

            # Extension handling
            if 'extension' in file_path.lower():
                patterns['extension_handling'].append({
                    'finding': finding,
                    'pattern': 'Extension system operation',
                    'risk': 'Plugin/extension security bypass'
                })

        return patterns

    def _assess_security_impact(self, findings: List[Dict]) -> Dict[str, Any]:
        """Assess overall security impact of findings."""

        impact_assessment = {
            'overall_risk_level': 'MEDIUM',
            'attack_vectors': [],
            'potential_exploits': [],
            'business_impact': [],
            'technical_impact': []
        }

        # Analyze attack vectors
        attack_vectors = set()
        for finding in findings:
            if finding['vulnerability_type'] == 'path_traversal':
                attack_vectors.add('File system access manipulation')
            elif finding['vulnerability_type'] == 'command_injection':
                attack_vectors.add('Command execution control')

        impact_assessment['attack_vectors'] = list(attack_vectors)

        # Potential exploits
        path_traversal_count = sum(1 for f in findings if f['vulnerability_type'] == 'path_traversal')
        command_injection_count = sum(1 for f in findings if f['vulnerability_type'] == 'command_injection')

        if path_traversal_count > 10:
            impact_assessment['potential_exploits'].append({
                'type': 'Mass Path Traversal',
                'description': f'{path_traversal_count} path traversal vulnerabilities could allow unauthorized file access',
                'severity': 'HIGH'
            })

        if command_injection_count > 0:
            impact_assessment['potential_exploits'].append({
                'type': 'Command Injection',
                'description': f'{command_injection_count} command injection points could allow arbitrary code execution',
                'severity': 'CRITICAL'
            })

        # Business impact
        impact_assessment['business_impact'] = [
            'Unauthorized access to configuration files',
            'Potential data exfiltration through file system access',
            'System compromise through command injection',
            'Extension system manipulation'
        ]

        # Technical impact
        impact_assessment['technical_impact'] = [
            'File system traversal and unauthorized access',
            'Configuration tampering and system manipulation',
            'Command execution with application privileges',
            'Extension loading and security bypass'
        ]

        # Determine overall risk level
        if command_injection_count > 0:
            impact_assessment['overall_risk_level'] = 'CRITICAL'
        elif path_traversal_count > 15:
            impact_assessment['overall_risk_level'] = 'HIGH'
        else:
            impact_assessment['overall_risk_level'] = 'MEDIUM'

        return impact_assessment

    def _generate_recommendations(self, findings: List[Dict], patterns: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate actionable security recommendations."""

        recommendations = []

        # Path traversal mitigations
        path_count = len(patterns['path_construction'])
        if path_count > 5:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Path Security',
                'title': 'Implement Path Validation',
                'description': f'Found {path_count} instances of dynamic path construction. Implement strict path validation and sanitization.',
                'action': 'Add path.resolve() and validate against allowed directories before file operations'
            })

        # Command injection mitigations
        cmd_count = len(patterns['command_execution'])
        if cmd_count > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Command Security',
                'title': 'Secure Command Execution',
                'description': f'Found {cmd_count} command execution points. Implement strict input validation.',
                'action': 'Use parameterized command execution and validate all user inputs'
            })

        # File system security
        fs_count = len(patterns['file_system_operations'])
        if fs_count > 10:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'File System Security',
                'title': 'Implement File Access Controls',
                'description': f'Found {fs_count} file system operations. Implement access controls.',
                'action': 'Add file access validation and restrict operations to allowed directories'
            })

        # Configuration security
        config_count = len(patterns['configuration_loading'])
        if config_count > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Configuration Security',
                'title': 'Secure Configuration Loading',
                'description': f'Found {config_count} configuration loading operations.',
                'action': 'Validate configuration file paths and implement integrity checks'
            })

        # Extension security
        ext_count = len(patterns['extension_handling'])
        if ext_count > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Extension Security',
                'title': 'Extension System Hardening',
                'description': f'Found {ext_count} extension operations.',
                'action': 'Implement extension validation and sandboxing mechanisms'
            })

        return recommendations

    def _determine_severity(self, finding: Dict) -> str:
        """Determine severity based on vulnerability type and context."""

        vuln_type = finding['vulnerability_type']
        file_path = finding['file_path']
        actual_line = finding['verification_details']['actual_line']

        # Command injection is always critical
        if vuln_type == 'command_injection':
            return 'critical'

        # Path traversal severity depends on context
        if vuln_type == 'path_traversal':
            if 'config' in file_path.lower():
                return 'high'  # Configuration access
            elif 'extension' in file_path.lower():
                return 'medium'  # Extension system
            else:
                return 'medium'

        return 'medium'

    def _extract_component(self, file_path: str) -> str:
        """Extract component name from file path."""

        parts = file_path.split('/')

        if 'integration-tests' in parts:
            return 'Testing Framework'
        elif 'a2a-server' in parts:
            if 'config' in parts:
                return 'Configuration System'
            else:
                return 'A2A Server'
        elif 'packages' in parts:
            return f"Package: {parts[1] if len(parts) > 1 else 'Unknown'}"
        else:
            return 'Core System'

    def _format_detailed_findings(self, findings: List[Dict]) -> List[Dict]:
        """Format detailed findings for reporting."""

        detailed = []

        for i, finding in enumerate(findings, 1):
            severity = self._determine_severity(finding)
            component = self._extract_component(finding['file_path'])

            detailed.append({
                'id': f"VULN-{i:03d}",
                'severity': severity.upper(),
                'type': finding['vulnerability_type'].replace('_', ' ').title(),
                'component': component,
                'location': f"{finding['file_path']}:{finding['line_number']}",
                'code': finding['verification_details']['actual_line'],
                'confidence': f"{finding['confidence'] * 100:.0f}%",
                'verification': 'VERIFIED' if finding['verified'] else 'UNVERIFIED',
                'context': finding['verification_details']['context'][-3:] if finding['verification_details']['context'] else []
            })

        return detailed

def generate_critical_issues_report():
    """Generate comprehensive critical issues report."""

    analyzer = CriticalIssuesAnalyzer()

    # Analyze correlation results
    correlation_file = '/Users/ankitthakur/vuln_ml_research/realistic_correlation_results.json'

    if not Path(correlation_file).exists():
        print("❌ Correlation results file not found. Please run the correlation demo first.")
        return

    analysis = analyzer.analyze_findings(correlation_file)

    # Print summary
    print("🚨 CRITICAL ISSUES SUMMARY")
    print("=" * 60)
    print(f"📊 Total Verified Findings: {analysis['analysis_summary']['total_findings']}")
    print(f"🎯 Repository: {Path(analysis['analysis_summary']['repository']).name}")
    print(f"📈 Verification Rate: {analysis['analysis_summary']['verification_rate']:.1f}%")
    print()

    # Print severity breakdown
    print("🔥 SEVERITY BREAKDOWN:")
    for severity, findings in analysis['issue_classification']['by_severity'].items():
        count = len(findings)
        print(f"   {severity.upper()}: {count} findings")
    print()

    # Print vulnerability types
    print("🎯 VULNERABILITY TYPES:")
    for vuln_type, findings in analysis['issue_classification']['by_type'].items():
        count = len(findings)
        print(f"   {vuln_type.replace('_', ' ').title()}: {count} findings")
    print()

    # Print high-risk areas
    print("⚠️  HIGH-RISK COMPONENTS:")
    for area in analysis['issue_classification']['high_risk_areas'][:5]:
        print(f"   {area['component']}: {area['finding_count']} findings (Risk Score: {area['risk_score']})")
    print()

    # Print critical patterns
    print("🔍 CRITICAL PATTERNS IDENTIFIED:")
    for pattern_name, pattern_findings in analysis['critical_patterns'].items():
        if pattern_findings:
            count = len(pattern_findings)
            print(f"   {pattern_name.replace('_', ' ').title()}: {count} instances")
    print()

    # Print security impact
    print("💥 SECURITY IMPACT ASSESSMENT:")
    impact = analysis['security_impact']
    print(f"   Overall Risk Level: {impact['overall_risk_level']}")
    print(f"   Attack Vectors: {len(impact['attack_vectors'])}")
    print(f"   Potential Exploits: {len(impact['potential_exploits'])}")
    print()

    # Print top recommendations
    print("🛠️  PRIORITY RECOMMENDATIONS:")
    for rec in analysis['recommendations'][:3]:
        print(f"   [{rec['priority']}] {rec['title']}")
        print(f"        {rec['description']}")
        print(f"        Action: {rec['action']}")
        print()

    # Print critical findings
    print("🚨 CRITICAL FINDINGS (Top 10):")
    critical_findings = [f for f in analysis['detailed_findings'] if f['severity'] in ['CRITICAL', 'HIGH']]

    for finding in critical_findings[:10]:
        print(f"   {finding['id']} [{finding['severity']}] {finding['type']}")
        print(f"        Location: {finding['location']}")
        print(f"        Code: {finding['code']}")
        print(f"        Component: {finding['component']}")
        print()

    # Save detailed report
    with open('/Users/ankitthakur/vuln_ml_research/critical_issues_analysis.json', 'w') as f:
        json.dump(analysis, f, indent=2)

    print("📁 Detailed analysis saved to: critical_issues_analysis.json")

    return analysis

if __name__ == "__main__":
    generate_critical_issues_report()