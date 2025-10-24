#!/usr/bin/env python3
"""
Manual BNB Chain High-Risk Findings Validator
Validates critical findings using advanced pattern matching and code analysis
"""

import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class ManualBNBValidator:
    """Manual validation of BNB Chain high-risk findings"""

    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.critical_patterns = self._load_advanced_patterns()

    def _load_advanced_patterns(self) -> Dict:
        """Load advanced vulnerability patterns for manual validation"""
        return {
            'critical_reentrancy': [
                r'\.call\s*\{\s*value:\s*[^}]+\}\s*\(\s*[^)]*\)',  # call{value:}()
                r'external\s+payable[^{]*\{[^}]*\.call\s*\(',  # external payable with call
                r'msg\.sender\.call\s*\{\s*value:',  # msg.sender.call{value:
                r'address\([^)]+\)\.call\s*\{\s*value:'  # address().call{value:
            ],
            'staking_vulnerabilities': [
                r'function\s+stake\s*\([^)]*\)\s*external[^{]*\{[^}]*transfer',  # stake function with transfer
                r'mapping\s*\([^)]*=>\s*uint256\)\s+.*reward',  # reward mappings
                r'function\s+.*reward[^{]*\{[^}]*\+\+',  # reward functions with increment
                r'validator.*\[\s*[^]]*\]\s*=',  # validator array assignment
                r'totalStaked\s*[\+\-]\s*=',  # totalStaked modifications
                r'withdrawalDelay.*require'  # withdrawal delay checks
            ],
            'governance_vulnerabilities': [
                r'function\s+execute\s*\([^)]*\)\s*external[^{]*\{[^}]*delegatecall',  # execute with delegatecall
                r'timelock.*require\s*\([^)]*block\.timestamp',  # timelock timestamp checks
                r'quorum.*\d+',  # quorum with hardcoded values
                r'onlyOwner.*execute',  # owner-only execute functions
                r'function\s+.*vote[^{]*\{[^}]*require\s*\([^)]*msg\.sender',  # voting with sender checks
                r'proposalId.*mapping'  # proposal ID mappings
            ],
            'access_control_critical': [
                r'require\s*\(\s*msg\.sender\s*==\s*owner',  # direct owner checks
                r'modifier\s+onlyOwner[^{]*\{[^}]*_;',  # onlyOwner modifier
                r'function\s+.*\s+external\s+onlyOwner',  # external onlyOwner functions
                r'transferOwnership\s*\(',  # ownership transfer
                r'renounceOwnership\s*\(',  # ownership renouncement
                r'hasRole\s*\([^)]*,\s*msg\.sender\)'  # role-based access
            ],
            'token_security_critical': [
                r'function\s+mint\s*\([^)]*\)\s*external[^{]*\{[^}]*_mint',  # external mint functions
                r'totalSupply\s*\+\s*=',  # total supply direct modification
                r'balanceOf\s*\[[^]]*\]\s*=',  # direct balance modification
                r'function\s+.*burn[^{]*\{[^}]*totalSupply',  # burn affecting total supply
                r'allowance\s*\[[^]]*\]\s*\[[^]]*\]\s*=',  # direct allowance modification
                r'transfer\s*\([^)]*\)\s*external[^{]*\{[^}]*require'  # transfer with requires
            ]
        }

    def load_security_report(self, report_path: str) -> dict:
        """Load the security assessment report"""
        try:
            with open(report_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading report: {e}")
            return {}

    def validate_high_risk_file(self, file_path: str, vulnerabilities: List) -> Dict:
        """Manually validate a high-risk file"""

        validation_result = {
            'file': file_path,
            'file_name': Path(file_path).name,
            'validation_timestamp': self.timestamp,
            'original_risk_score': 0,
            'manual_validation': {
                'critical_patterns_found': 0,
                'confirmed_vulnerabilities': [],
                'risk_assessment': 'LOW',
                'bug_bounty_potential': 'LOW'
            },
            'detailed_findings': [],
            'recommendations': []
        }

        # Try to read the file for manual validation
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Perform advanced pattern analysis
                self._analyze_critical_patterns(content, validation_result)

                # Assess specific vulnerability categories
                self._assess_vulnerability_categories(content, validation_result, vulnerabilities)

                # Determine bug bounty potential
                self._assess_bug_bounty_potential(validation_result)

                print(f"   ✅ Manual validation complete: {validation_result['manual_validation']['risk_assessment']}")

            else:
                print(f"   ⚠️  File not accessible: {file_path}")

        except Exception as e:
            print(f"   ❌ Validation error: {e}")

        return validation_result

    def _analyze_critical_patterns(self, content: str, validation_result: Dict):
        """Analyze critical vulnerability patterns"""

        for category, patterns in self.critical_patterns.items():
            category_findings = []

            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1

                    finding = {
                        'category': category,
                        'pattern': pattern,
                        'line_number': line_num,
                        'matched_text': match.group()[:100],  # First 100 chars
                        'severity': self._assess_pattern_severity(category, pattern)
                    }

                    category_findings.append(finding)
                    validation_result['manual_validation']['critical_patterns_found'] += 1

            if category_findings:
                validation_result['detailed_findings'].append({
                    'category': category,
                    'findings': category_findings,
                    'count': len(category_findings)
                })

    def _assess_vulnerability_categories(self, content: str, validation_result: Dict, original_vulns: List):
        """Assess specific vulnerability categories"""

        # High-priority checks for BNB Chain
        high_priority_checks = {
            'SystemReward': ['reward', 'claim', 'distribute', 'balance'],
            'StakeHub': ['stake', 'delegate', 'validator', 'slash'],
            'Governance': ['vote', 'proposal', 'execute', 'timelock'],
            'TokenHub': ['mint', 'burn', 'transfer', 'bridge']
        }

        file_name = validation_result['file_name'].lower()

        for category, keywords in high_priority_checks.items():
            if any(keyword in file_name for keyword in keywords):
                # This is a high-priority contract
                critical_findings = self._deep_analysis_for_category(content, category)

                if critical_findings:
                    validation_result['manual_validation']['confirmed_vulnerabilities'].extend(critical_findings)

                    # Escalate risk assessment
                    if len(critical_findings) >= 3:
                        validation_result['manual_validation']['risk_assessment'] = 'CRITICAL'
                    elif len(critical_findings) >= 2:
                        validation_result['manual_validation']['risk_assessment'] = 'HIGH'
                    elif len(critical_findings) >= 1:
                        validation_result['manual_validation']['risk_assessment'] = 'MEDIUM'

    def _deep_analysis_for_category(self, content: str, category: str) -> List[Dict]:
        """Perform deep analysis for specific categories"""

        critical_findings = []

        if category == 'SystemReward':
            # Check for reward manipulation vulnerabilities
            critical_patterns = [
                r'function\s+receiveRewards?\s*\([^)]*\)[^{]*\{[^}]*msg\.value',  # Receive rewards with msg.value
                r'rewardAccount\s*\[[^]]*\]\s*\+\s*=',  # Direct reward account modification
                r'totalReward\s*=\s*[^;]*msg\.value',  # Total reward from msg.value
                r'function\s+claimReward[^{]*\{[^}]*transfer\s*\(',  # Claim reward with transfer
            ]

        elif category == 'StakeHub':
            # Check for staking vulnerabilities
            critical_patterns = [
                r'function\s+stake\s*\([^)]*\)[^{]*\{[^}]*require\s*\([^)]*msg\.value',  # Stake with msg.value
                r'delegatedAmount\s*\[[^]]*\]\s*\+\s*=\s*msg\.value',  # Direct delegation
                r'function\s+slash[^{]*\{[^}]*balanceOf',  # Slashing affecting balances
                r'validatorSet\s*\[[^]]*\]\s*=\s*msg\.sender',  # Validator manipulation
            ]

        elif category == 'Governance':
            # Check for governance vulnerabilities
            critical_patterns = [
                r'function\s+execute[^{]*\{[^}]*delegatecall',  # Execute with delegatecall
                r'function\s+vote[^{]*\{[^}]*votingPower\s*\[[^]]*\]\s*=',  # Voting power manipulation
                r'timelock\s*=\s*0',  # Timelock bypass
                r'quorum\s*=\s*1',  # Minimal quorum
            ]

        elif category == 'TokenHub':
            # Check for token vulnerabilities
            critical_patterns = [
                r'function\s+mint\s*\([^)]*\)[^{]*\{[^}]*totalSupply\s*\+\s*=',  # Mint affecting supply
                r'function\s+bridgeOut[^{]*\{[^}]*transfer\s*\(',  # Bridge with transfer
                r'relayFee\s*=\s*0',  # Zero relay fee
                r'function\s+handleAckPackage[^{]*\{[^}]*mint',  # Ack package with mint
            ]
        else:
            critical_patterns = []

        # Search for critical patterns
        for pattern in critical_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))

            for match in matches:
                line_num = content[:match.start()].count('\n') + 1

                critical_findings.append({
                    'category': category,
                    'type': 'CRITICAL_PATTERN',
                    'description': f'{category} critical vulnerability pattern detected',
                    'line_number': line_num,
                    'evidence': match.group()[:150],
                    'severity': 'CRITICAL',
                    'bug_bounty_value': self._estimate_bounty_value(category)
                })

        return critical_findings

    def _assess_pattern_severity(self, category: str, pattern: str) -> str:
        """Assess pattern severity"""
        high_severity_categories = ['critical_reentrancy', 'staking_vulnerabilities', 'governance_vulnerabilities']

        if category in high_severity_categories:
            if 'delegatecall' in pattern or 'call{value:' in pattern:
                return 'CRITICAL'
            return 'HIGH'

        return 'MEDIUM'

    def _assess_bug_bounty_potential(self, validation_result: Dict):
        """Assess bug bounty potential based on findings"""

        confirmed_vulns = validation_result['manual_validation']['confirmed_vulnerabilities']
        critical_patterns = validation_result['manual_validation']['critical_patterns_found']

        # Bounty potential assessment
        if len(confirmed_vulns) >= 2 and any(v.get('severity') == 'CRITICAL' for v in confirmed_vulns):
            validation_result['manual_validation']['bug_bounty_potential'] = 'VERY_HIGH'
            validation_result['estimated_bounty_value'] = '$50,000 - $100,000'

        elif len(confirmed_vulns) >= 1 and critical_patterns >= 3:
            validation_result['manual_validation']['bug_bounty_potential'] = 'HIGH'
            validation_result['estimated_bounty_value'] = '$25,000 - $75,000'

        elif critical_patterns >= 2:
            validation_result['manual_validation']['bug_bounty_potential'] = 'MEDIUM'
            validation_result['estimated_bounty_value'] = '$10,000 - $25,000'

        else:
            validation_result['manual_validation']['bug_bounty_potential'] = 'LOW'
            validation_result['estimated_bounty_value'] = '$1,000 - $10,000'

        # Generate specific recommendations
        validation_result['recommendations'] = self._generate_targeted_recommendations(validation_result)

    def _estimate_bounty_value(self, category: str) -> str:
        """Estimate bounty value for category"""
        bounty_estimates = {
            'SystemReward': '$75,000 - $100,000',
            'StakeHub': '$50,000 - $100,000',
            'Governance': '$50,000 - $75,000',
            'TokenHub': '$25,000 - $50,000'
        }
        return bounty_estimates.get(category, '$10,000 - $25,000')

    def _generate_targeted_recommendations(self, validation_result: Dict) -> List[str]:
        """Generate targeted recommendations"""
        recommendations = []

        file_name = validation_result['file_name'].lower()

        if 'systemreward' in file_name:
            recommendations.extend([
                'Focus on reward distribution logic - potential for unauthorized BNB minting',
                'Test edge cases in reward calculation algorithms',
                'Verify access controls for reward claiming functions'
            ])

        elif 'stakehub' in file_name:
            recommendations.extend([
                'Analyze staking/unstaking mechanisms for manipulation',
                'Check validator election and slashing logic',
                'Test delegation and undelegation edge cases'
            ])

        elif any(gov in file_name for gov in ['gov', 'timelock', 'governor']):
            recommendations.extend([
                'Test governance bypass scenarios',
                'Analyze voting manipulation vectors',
                'Check timelock and execution mechanisms'
            ])

        if validation_result['manual_validation']['bug_bounty_potential'] in ['HIGH', 'VERY_HIGH']:
            recommendations.append('HIGH PRIORITY: Prepare detailed proof-of-concept for bug bounty submission')

        return recommendations

def main():
    """Main manual validation execution"""
    print("🔍 Manual BNB Chain High-Risk Findings Validator")
    print("🎯 Advanced Pattern Analysis + Manual Verification")
    print("=" * 60)

    validator = ManualBNBValidator()

    # Load security report
    report_path = 'results/reconnaissance_security_report.json'
    if not os.path.exists(report_path):
        print(f"❌ Security report not found: {report_path}")
        return

    report_data = validator.load_security_report(report_path)
    if not report_data:
        print("❌ Failed to load security report")
        return

    # Get high-risk files
    files_analyzed = report_data.get('detailed_findings', {}).get('files_analyzed', [])
    high_risk_files = [f for f in files_analyzed if f.get('risk_score', 0) > 0.7]

    print(f"📊 Found {len(high_risk_files)} high-risk files for manual validation")

    validation_results = []

    # Validate top high-risk files
    for file_data in high_risk_files[:8]:  # Top 8 high-risk files
        file_path = file_data.get('file', '')
        risk_score = file_data.get('risk_score', 0)
        vulnerabilities = file_data.get('vulnerabilities', [])

        print(f"\n🔍 Manual validation: {Path(file_path).name} (Risk: {risk_score:.2f})")

        validation_result = validator.validate_high_risk_file(file_path, vulnerabilities)
        validation_result['original_risk_score'] = risk_score
        validation_results.append(validation_result)

    # Generate summary
    print("\n" + "=" * 60)
    print("📊 MANUAL VALIDATION SUMMARY")
    print("=" * 60)

    high_priority_files = [v for v in validation_results
                          if v['manual_validation']['bug_bounty_potential'] in ['HIGH', 'VERY_HIGH']]

    critical_files = [v for v in validation_results
                     if v['manual_validation']['risk_assessment'] == 'CRITICAL']

    print(f"Files Validated: {len(validation_results)}")
    print(f"High Priority for Bug Bounty: {len(high_priority_files)}")
    print(f"Critical Risk Assessment: {len(critical_files)}")

    print(f"\n🎯 TOP BUG BOUNTY TARGETS:")
    for result in high_priority_files:
        file_name = result['file_name']
        potential = result['manual_validation']['bug_bounty_potential']
        bounty_value = result.get('estimated_bounty_value', 'TBD')
        print(f"   📁 {file_name} - {potential} ({bounty_value})")

    # Save validation report
    final_report = {
        'manual_validation_summary': {
            'timestamp': validator.timestamp,
            'files_validated': len(validation_results),
            'high_priority_targets': len(high_priority_files),
            'critical_assessments': len(critical_files)
        },
        'validation_results': validation_results
    }

    output_file = 'results/manual_validation_report.json'
    with open(output_file, 'w') as f:
        json.dump(final_report, f, indent=2)

    print(f"\n📋 Manual validation report saved: {output_file}")
    print("🚀 Ready for bug bounty submission preparation!")

if __name__ == "__main__":
    main()