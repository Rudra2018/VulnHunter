#!/usr/bin/env python3
"""
Covenant Smart Contract Security Analysis
Using VulnHunter 7-Layer Verification Engine

Focuses on Code4rena audit contest requirements:
- LatentSwap Invariant vulnerabilities
- Market asset isolation issues
- Re-entrancy attack vectors
- Oracle price manipulation
- Token minting/redemption exploits
"""

import asyncio
import os
import sys
from pathlib import Path

# Add verification engine to path
sys.path.append('/Users/ankitthakur/vuln_ml_research')
from vulnhunter_verification_engine import VulnHunterVerificationEngine, VerificationConfig

class CovenantSecurityAnalyzer:
    """Specialized analyzer for Covenant smart contract security"""

    def __init__(self):
        self.covenant_path = Path("/Users/ankitthakur/vuln_ml_research/2025-10-covenant")
        self.config = VerificationConfig(
            feature_completeness_threshold=0.1,
            ensemble_confidence_threshold=0.3,
            final_confidence_threshold=0.4,
            nvd_api_key=None
        )
        self.engine = VulnHunterVerificationEngine(self.config)

        # Key contract files from scope
        self.key_contracts = [
            "src/Covenant.sol",
            "src/lex/latentswap/LatentSwapLEX.sol",
            "src/curators/CovenantCurator.sol",
            "src/synths/SynthToken.sol",
            "src/lex/latentswap/libraries/LatentMath.sol",
            "src/lex/latentswap/libraries/LatentSwapLogic.sol",
            "src/curators/oracles/BaseAdapter.sol",
            "src/curators/oracles/CrossAdapter.sol"
        ]

        # Critical vulnerability patterns for Covenant
        self.covenant_patterns = {
            'latent_swap_invariant': [
                r'require.*invariant', r'assert.*invariant', r'_checkInvariant',
                r'amountOut.*calculation', r'price.*manipulation'
            ],
            'reentrancy_vectors': [
                r'external.*call', r'delegatecall', r'call\.value',
                r'transfer.*before.*update', r'mint.*before.*check'
            ],
            'oracle_manipulation': [
                r'getPrice', r'oracle\.price', r'price.*feed',
                r'manipulate.*price', r'flash.*loan.*price'
            ],
            'market_isolation': [
                r'marketId.*access', r'cross.*market', r'isolation.*breach',
                r'market.*state.*modify'
            ],
            'token_economic_exploit': [
                r'mint.*unlimited', r'burn.*negative', r'supply.*manipulation',
                r'totalSupply.*exploit'
            ]
        }

    async def analyze_covenant_contracts(self):
        """Analyze all key Covenant contracts for vulnerabilities"""
        print("🔍 Covenant Smart Contract Security Analysis")
        print("=" * 60)
        print(f"Target: Code4rena Contest - $43,000 USDC Prize Pool")
        print(f"Framework: Solidity Smart Contracts")
        print()

        analysis_results = {}

        for contract_path in self.key_contracts:
            full_path = self.covenant_path / contract_path

            if not full_path.exists():
                print(f"⚠️  Contract not found: {contract_path}")
                continue

            print(f"📄 Analyzing: {contract_path}")
            print("-" * 40)

            try:
                # Read contract source
                with open(full_path, 'r', encoding='utf-8') as f:
                    contract_code = f.read()

                # Run VulnHunter verification
                result = await self.engine.verify_vulnerabilities(contract_code, 'solidity')

                # Add Covenant-specific pattern analysis
                covenant_findings = self._analyze_covenant_patterns(contract_code, contract_path)
                result['covenant_specific_findings'] = covenant_findings

                analysis_results[contract_path] = result

                # Display key results
                confidence = result.get('overall_confidence', 0)
                print(f"  Overall Confidence: {confidence:.1%}")
                print(f"  Status: {result.get('validation_status', 'unknown')}")
                print(f"  Findings: {len(result.get('verified_findings', []))}")
                print(f"  Covenant Patterns: {len(covenant_findings)} detected")

                if result.get('remediation_recommendations'):
                    print("  Top Recommendations:")
                    for i, rec in enumerate(result['remediation_recommendations'][:2], 1):
                        print(f"    {i}. {rec}")

                print()

            except Exception as e:
                print(f"❌ Analysis failed for {contract_path}: {e}")
                analysis_results[contract_path] = {'error': str(e)}

        # Generate comprehensive analysis report
        await self._generate_covenant_report(analysis_results)

        return analysis_results

    def _analyze_covenant_patterns(self, contract_code: str, contract_path: str) -> list:
        """Analyze Covenant-specific vulnerability patterns"""
        findings = []

        for pattern_type, patterns in self.covenant_patterns.items():
            for pattern in patterns:
                import re
                matches = re.findall(pattern, contract_code, re.IGNORECASE)
                if matches:
                    findings.append({
                        'type': pattern_type,
                        'pattern': pattern,
                        'matches': len(matches),
                        'contract': contract_path,
                        'severity': self._assess_covenant_severity(pattern_type, contract_path)
                    })

        return findings

    def _assess_covenant_severity(self, pattern_type: str, contract_path: str) -> str:
        """Assess severity of Covenant-specific patterns"""
        # Critical patterns for core contracts
        if 'Covenant.sol' in contract_path or 'LatentSwapLEX.sol' in contract_path:
            if pattern_type in ['latent_swap_invariant', 'reentrancy_vectors']:
                return 'CRITICAL'
            elif pattern_type in ['oracle_manipulation', 'token_economic_exploit']:
                return 'HIGH'

        # Oracle contracts
        if 'oracle' in contract_path.lower():
            if pattern_type == 'oracle_manipulation':
                return 'CRITICAL'

        # Default severity
        return 'MEDIUM'

    async def _generate_covenant_report(self, analysis_results: dict):
        """Generate comprehensive Covenant security analysis report"""
        report_content = [
            "# 🛡️ Covenant Smart Contract Security Analysis Report",
            "",
            "**Contest**: Code4rena - Covenant Audit",
            "**Prize Pool**: $43,000 USDC",
            "**Analysis Date**: October 23, 2025",
            "**Analyzer**: VulnHunter 7-Layer Verification Engine",
            "",
            "## 🎯 Executive Summary",
            "",
            f"Analyzed **{len(self.key_contracts)}** critical smart contracts from the Covenant protocol.",
            "Focus areas: LatentSwap invariants, market isolation, oracle security, token economics.",
            "",
            "## 📊 Analysis Results by Contract",
            ""
        ]

        high_severity_count = 0
        medium_severity_count = 0
        total_findings = 0

        for contract_path, result in analysis_results.items():
            if 'error' in result:
                report_content.extend([
                    f"### ❌ {contract_path}",
                    f"**Status**: Analysis Error",
                    f"**Error**: {result['error']}",
                    ""
                ])
                continue

            covenant_findings = result.get('covenant_specific_findings', [])
            confidence = result.get('overall_confidence', 0)

            report_content.extend([
                f"### 📄 {contract_path}",
                f"**Overall Confidence**: {confidence:.1%}",
                f"**Validation Status**: {result.get('validation_status', 'unknown')}",
                f"**Covenant-Specific Patterns**: {len(covenant_findings)} detected",
                ""
            ])

            if covenant_findings:
                report_content.append("**Key Findings**:")
                for finding in covenant_findings:
                    severity = finding['severity']
                    if severity == 'CRITICAL' or severity == 'HIGH':
                        high_severity_count += 1
                    else:
                        medium_severity_count += 1
                    total_findings += 1

                    report_content.append(
                        f"- **{severity}**: {finding['type']} ({finding['matches']} matches)"
                    )
                report_content.append("")

            # Add recommendations
            if result.get('remediation_recommendations'):
                report_content.append("**Recommendations**:")
                for rec in result['remediation_recommendations'][:3]:
                    report_content.append(f"- {rec}")
                report_content.append("")

        # Summary statistics
        report_content.extend([
            "## 📈 Security Assessment Summary",
            "",
            f"- **Total Contracts Analyzed**: {len(analysis_results)}",
            f"- **Total Security Patterns Found**: {total_findings}",
            f"- **High/Critical Severity**: {high_severity_count}",
            f"- **Medium Severity**: {medium_severity_count}",
            "",
            "## 🚨 Priority Focus Areas for Code4rena Contest",
            "",
            "### 1. LatentSwap Invariant Verification",
            "- Focus on `LatentSwapLEX.sol` and `LatentMath.sol`",
            "- Verify token value relationships maintain correctness",
            "- Check for potential value extraction through invariant manipulation",
            "",
            "### 2. Market Isolation Security",
            "- Analyze `Covenant.sol` market state management",
            "- Verify cross-market contamination prevention",
            "- Check market-specific asset isolation",
            "",
            "### 3. Oracle Price Manipulation",
            "- Review oracle adapter implementations",
            "- Analyze price feed validation logic",
            "- Check for flash loan price manipulation vectors",
            "",
            "### 4. Re-entrancy Protection",
            "- Verify state lock mechanisms in core contracts",
            "- Check external call safety patterns",
            "- Analyze mint/redeem flow security",
            "",
            "## 🎯 Recommended Proof of Concept Focus",
            "",
            "Based on analysis, prioritize PoC development for:",
            "1. **LatentSwap invariant breaks** leading to value extraction",
            "2. **Cross-market asset contamination** exploits",
            "3. **Oracle price manipulation** during mint/redeem",
            "4. **Re-entrancy attacks** in token operations",
            "",
            "---",
            "",
            "*Report generated by VulnHunter 7-Layer Verification Engine*",
            f"*Analysis completed on {len(self.key_contracts)} Covenant smart contracts*"
        ])

        # Save report
        report_path = Path("covenant_security_analysis_report.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_content))

        print(f"📄 Comprehensive report saved: {report_path}")
        print(f"🎯 Total findings: {total_findings} ({high_severity_count} high/critical)")
        print("🚀 Ready for Code4rena PoC development!")

async def main():
    """Main analysis execution"""
    analyzer = CovenantSecurityAnalyzer()
    results = await analyzer.analyze_covenant_contracts()

    print("\n🏆 Covenant Security Analysis Complete!")
    print("Focus on highest severity findings for maximum contest impact.")

if __name__ == "__main__":
    asyncio.run(main())