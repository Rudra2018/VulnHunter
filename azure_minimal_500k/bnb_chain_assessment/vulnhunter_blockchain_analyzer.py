#!/usr/bin/env python3
"""
VulnHunter Blockchain Security Analyzer
Specialized security assessment tool for BNB Chain bug bounty program
"""

import sys
import os
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / 'src'))

try:
    from vulnforge_production_ensemble import VulnForgeProductionEnsemble
    from vulnhunter_unified_production import VulnHunterUnified
except ImportError as e:
    print(f"Warning: Could not import VulnHunter modules: {e}")
    print("Continuing with static analysis...")

class BNBChainSecurityAnalyzer:
    """Specialized security analyzer for BNB Chain smart contracts and blockchain code"""

    def __init__(self):
        self.analysis_results = []
        self.critical_patterns = self._load_blockchain_patterns()
        self.report_timestamp = datetime.now().isoformat()

        # Try to initialize VulnHunter if available
        self.vulnhunter = None
        try:
            self.vulnhunter = VulnHunterUnified()
            print("✅ VulnHunter Enterprise initialized for blockchain analysis")
        except Exception as e:
            print(f"⚠️  VulnHunter not available, using static analysis: {e}")

    def _load_blockchain_patterns(self) -> Dict:
        """Load blockchain-specific vulnerability patterns"""
        return {
            'reentrancy': [
                r'\.call\s*\(',
                r'\.delegatecall\s*\(',
                r'\.send\s*\(',
                r'external\s+.*\s+payable',
                r'msg\.sender\.call'
            ],
            'integer_overflow': [
                r'\+\+',
                r'--',
                r'\s+\+\s+',
                r'\s+-\s+',
                r'\s+\*\s+',
                r'SafeMath',
                r'unchecked\s*\{'
            ],
            'access_control': [
                r'onlyOwner',
                r'require\s*\(\s*msg\.sender',
                r'modifier\s+\w+',
                r'_checkRole',
                r'hasRole'
            ],
            'staking_vulnerabilities': [
                r'stake',
                r'reward',
                r'validator',
                r'delegation',
                r'slashing',
                r'unbond'
            ],
            'governance_vulnerabilities': [
                r'governance',
                r'voting',
                r'proposal',
                r'quorum',
                r'timelock',
                r'execute'
            ],
            'token_vulnerabilities': [
                r'mint',
                r'burn',
                r'transfer',
                r'approve',
                r'allowance',
                r'totalSupply'
            ],
            'upgrade_vulnerabilities': [
                r'proxy',
                r'implementation',
                r'upgrade',
                r'initialize',
                r'beacon'
            ]
        }

    def analyze_smart_contract(self, file_path: str, content: str) -> Dict:
        """Analyze a single smart contract for vulnerabilities"""
        findings = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }

        # Static pattern analysis
        static_findings = self._static_pattern_analysis(content)
        findings['vulnerabilities'].extend(static_findings)

        # VulnHunter analysis if available
        if self.vulnhunter:
            try:
                vh_result = self.vulnhunter.analyze_code(
                    code_sample=content[:2000],  # Limit for API
                    app_type='blockchain',
                    deep_analysis=True
                )

                vulnhunter_findings = self._extract_vulnhunter_findings(vh_result)
                findings['vulnerabilities'].extend(vulnhunter_findings)
                findings['vulnhunter_assessment'] = vh_result.get('unified_assessment', {})

            except Exception as e:
                print(f"VulnHunter analysis failed for {file_path}: {e}")

        # Calculate overall risk score
        findings['risk_score'] = self._calculate_risk_score(findings['vulnerabilities'])

        # Generate recommendations
        findings['recommendations'] = self._generate_recommendations(findings['vulnerabilities'])

        return findings

    def _static_pattern_analysis(self, content: str) -> List[Dict]:
        """Perform static analysis using predefined patterns"""
        findings = []

        for vuln_type, patterns in self.critical_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    finding = {
                        'type': 'static_analysis',
                        'vulnerability_category': vuln_type,
                        'pattern': pattern,
                        'line_number': line_num,
                        'matched_text': match.group(),
                        'severity': self._assess_pattern_severity(vuln_type, pattern),
                        'description': self._get_vulnerability_description(vuln_type)
                    }
                    findings.append(finding)

        return findings

    def _extract_vulnhunter_findings(self, vh_result: Dict) -> List[Dict]:
        """Extract findings from VulnHunter analysis"""
        findings = []

        if 'unified_assessment' in vh_result:
            assessment = vh_result['unified_assessment']

            finding = {
                'type': 'vulnhunter_analysis',
                'vulnerability_category': 'ml_detected',
                'risk_score': assessment.get('overall_risk_score', 0),
                'confidence': assessment.get('overall_confidence', 0),
                'risk_level': assessment.get('overall_risk_level', 'UNKNOWN'),
                'threat_indicators': assessment.get('threat_indicators', {}),
                'severity': assessment.get('overall_risk_level', 'MEDIUM'),
                'description': 'AI-powered vulnerability detection using 29 Azure ML models'
            }
            findings.append(finding)

        # Extract recommendations if available
        if 'recommendations' in vh_result:
            for rec in vh_result['recommendations']:
                finding = {
                    'type': 'recommendation',
                    'vulnerability_category': 'security_improvement',
                    'priority': rec.get('priority', 'MEDIUM'),
                    'category': rec.get('category', 'General'),
                    'action': rec.get('action', 'Review required'),
                    'timeline': rec.get('timeline', 'TBD'),
                    'severity': rec.get('priority', 'MEDIUM'),
                    'description': f"Recommendation: {rec.get('action', 'Security review needed')}"
                }
                findings.append(finding)

        return findings

    def _assess_pattern_severity(self, vuln_type: str, pattern: str) -> str:
        """Assess severity based on vulnerability type and pattern"""
        high_risk_patterns = {
            'reentrancy': ['call(', 'delegatecall(', 'send('],
            'integer_overflow': ['unchecked'],
            'access_control': ['msg.sender'],
            'staking_vulnerabilities': ['stake', 'reward'],
            'governance_vulnerabilities': ['execute', 'timelock']
        }

        for category, high_patterns in high_risk_patterns.items():
            if vuln_type == category:
                for high_pattern in high_patterns:
                    if high_pattern in pattern:
                        return 'HIGH'

        critical_types = ['reentrancy', 'staking_vulnerabilities', 'governance_vulnerabilities']
        if vuln_type in critical_types:
            return 'MEDIUM'

        return 'LOW'

    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'reentrancy': 'Potential reentrancy vulnerability - external calls before state changes',
            'integer_overflow': 'Potential integer overflow/underflow vulnerability',
            'access_control': 'Access control mechanism detected - verify proper implementation',
            'staking_vulnerabilities': 'Staking-related code - critical for reward distribution',
            'governance_vulnerabilities': 'Governance mechanism - critical for protocol control',
            'token_vulnerabilities': 'Token operation - verify mint/burn controls',
            'upgrade_vulnerabilities': 'Upgrade mechanism - verify access controls'
        }
        return descriptions.get(vuln_type, 'Unknown vulnerability pattern detected')

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0

        severity_weights = {'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.2}
        total_score = 0

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            weight = severity_weights.get(severity, 0.2)
            total_score += weight

        # Normalize to 0-1 scale
        max_possible = len(vulnerabilities) * 0.8
        return min(1.0, total_score / max_possible) if max_possible > 0 else 0.0

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        vuln_types = set(v.get('vulnerability_category') for v in vulnerabilities)

        if 'reentrancy' in vuln_types:
            recommendations.append("Implement reentrancy guards for external calls")
            recommendations.append("Follow checks-effects-interactions pattern")

        if 'staking_vulnerabilities' in vuln_types:
            recommendations.append("Implement comprehensive staking security controls")
            recommendations.append("Add slashing protection mechanisms")
            recommendations.append("Verify reward calculation accuracy")

        if 'governance_vulnerabilities' in vuln_types:
            recommendations.append("Implement timelock for governance actions")
            recommendations.append("Add multi-signature requirements for critical functions")

        if 'access_control' in vuln_types:
            recommendations.append("Verify role-based access control implementation")
            recommendations.append("Add proper access control testing")

        if not recommendations:
            recommendations.append("Conduct comprehensive security audit")
            recommendations.append("Implement formal verification for critical functions")

        return recommendations

    def analyze_repository(self, repo_path: str) -> Dict:
        """Analyze entire repository"""
        print(f"🔍 Analyzing repository: {repo_path}")

        results = {
            'repository': repo_path,
            'analysis_timestamp': self.report_timestamp,
            'summary': {},
            'files_analyzed': [],
            'high_risk_findings': [],
            'recommendations': set()
        }

        # Find and analyze Solidity files
        sol_files = list(Path(repo_path).rglob("*.sol"))

        for sol_file in sol_files:
            try:
                with open(sol_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                file_analysis = self.analyze_smart_contract(str(sol_file), content)
                results['files_analyzed'].append(file_analysis)

                # Collect high-risk findings
                high_risk = [v for v in file_analysis['vulnerabilities']
                           if v.get('severity') == 'HIGH']
                results['high_risk_findings'].extend(high_risk)

                # Collect recommendations
                results['recommendations'].update(file_analysis['recommendations'])

                print(f"  📄 Analyzed: {sol_file.name} - Risk Score: {file_analysis['risk_score']:.2f}")

            except Exception as e:
                print(f"  ❌ Error analyzing {sol_file}: {e}")

        # Generate summary
        results['summary'] = self._generate_summary(results)
        results['recommendations'] = list(results['recommendations'])

        return results

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate analysis summary"""
        files_analyzed = results['files_analyzed']

        summary = {
            'total_files': len(files_analyzed),
            'high_risk_files': len([f for f in files_analyzed if f['risk_score'] > 0.7]),
            'medium_risk_files': len([f for f in files_analyzed if 0.3 < f['risk_score'] <= 0.7]),
            'low_risk_files': len([f for f in files_analyzed if f['risk_score'] <= 0.3]),
            'total_vulnerabilities': sum(len(f['vulnerabilities']) for f in files_analyzed),
            'high_severity_vulns': len(results['high_risk_findings']),
            'average_risk_score': sum(f['risk_score'] for f in files_analyzed) / len(files_analyzed) if files_analyzed else 0
        }

        return summary

    def generate_report(self, analysis_results: Dict, output_file: str):
        """Generate comprehensive security report"""
        report = {
            'assessment_info': {
                'target': 'BNB Chain Bug Bounty Program',
                'analyzer': 'VulnHunter Enterprise Blockchain Security Analyzer',
                'timestamp': self.report_timestamp,
                'methodology': 'Static analysis + AI-powered vulnerability detection'
            },
            'executive_summary': {
                'scope': analysis_results.get('repository', 'Unknown'),
                'files_analyzed': analysis_results['summary']['total_files'],
                'vulnerabilities_found': analysis_results['summary']['total_vulnerabilities'],
                'high_risk_findings': analysis_results['summary']['high_severity_vulns'],
                'overall_risk_level': self._assess_overall_risk(analysis_results['summary'])
            },
            'detailed_findings': analysis_results,
            'recommendations': analysis_results.get('recommendations', []),
            'next_steps': [
                'Conduct manual code review of high-risk findings',
                'Implement recommended security controls',
                'Perform formal verification of critical functions',
                'Set up continuous security monitoring'
            ]
        }

        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📋 Security report saved: {output_file}")
        return report

    def _assess_overall_risk(self, summary: Dict) -> str:
        """Assess overall risk level"""
        if summary['high_risk_files'] > 0:
            return 'HIGH'
        elif summary['medium_risk_files'] > summary['low_risk_files']:
            return 'MEDIUM'
        else:
            return 'LOW'

def main():
    """Main analysis execution"""
    print("🚀 VulnHunter Blockchain Security Analyzer")
    print("🎯 Target: BNB Chain Bug Bounty Program")
    print("=" * 60)

    analyzer = BNBChainSecurityAnalyzer()

    # Analyze each repository
    repositories = [
        'reconnaissance/bsc-genesis-contract',
        'reconnaissance/bsc',
        'reconnaissance/node-dump'
    ]

    all_results = {}

    for repo in repositories:
        if Path(repo).exists():
            print(f"\n🔍 Starting analysis of {repo}")
            results = analyzer.analyze_repository(repo)
            all_results[repo] = results

            # Generate individual report
            report_file = f"results/{Path(repo).name}_security_report.json"
            analyzer.generate_report(results, report_file)
        else:
            print(f"❌ Repository not found: {repo}")

    # Generate combined report
    combined_report = {
        'analysis_timestamp': analyzer.report_timestamp,
        'repositories_analyzed': all_results,
        'combined_summary': analyzer._generate_combined_summary(all_results)
    }

    with open('results/bnb_chain_combined_security_report.json', 'w') as f:
        json.dump(combined_report, f, indent=2)

    print("\n✅ BNB Chain Security Analysis Complete!")
    print("📊 Reports generated in results/ directory")
    print("🔍 Review high-risk findings for potential bug bounty submissions")

if __name__ == "__main__":
    main()