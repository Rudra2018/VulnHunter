#!/usr/bin/env python3
"""
Sui Protocol VulnHunter Analysis
Comprehensive security analysis of Sui blockchain using VulnHunter Combined Model
Bug Bounty Program: https://hackenproof.com/programs/sui-protocol
"""

import os
import sys
import pickle
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Any
import logging

# Add the current directory to the path to import our model
sys.path.append('/Users/ankitthakur/vuln_ml_research')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SuiProtocolVulnHunter:
    """
    Sui Protocol vulnerability scanner using VulnHunter Combined Model
    """

    def __init__(self):
        self.model = None
        self.sui_repo_path = "/Users/ankitthakur/vuln_ml_research/sui"
        self.scan_results = {
            "timestamp": datetime.now().isoformat(),
            "target": "Sui Protocol",
            "bug_bounty_program": "https://hackenproof.com/programs/sui-protocol",
            "findings": [],
            "statistics": {},
            "recommendations": []
        }
        self.load_vulnhunter_model()

    def load_vulnhunter_model(self):
        """Load the VulnHunter Combined Model"""
        model_path = "/Users/ankitthakur/vuln_ml_research/vulnhunter_combined_v12_v13_2025-10-22_04-33-57.pkl"

        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logging.info("✅ VulnHunter Combined Model loaded successfully")
        except Exception as e:
            logging.error(f"❌ Failed to load VulnHunter model: {e}")
            raise

    def analyze_sui_critical_vulnerabilities(self) -> List[Dict]:
        """
        Analyze for critical vulnerabilities based on Sui bug bounty scope
        """
        logging.info("🔍 Analyzing Sui Protocol for critical vulnerabilities")

        critical_patterns = [
            # Token Supply Vulnerabilities ($500k)
            {
                "category": "Token Supply Overflow",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"total_supply\s*\+\s*",
                    r"mint\s*\(\s*[^)]*\+",
                    r"supply\s*=\s*[^;]*\+",
                    r"coin::mint\s*\(",
                    r"balance\s*\+=\s*[^;]*without.*check"
                ]
            },
            # Governance Attacks ($500k)
            {
                "category": "Governance Compromise",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"validator\s*voting\s*power",
                    r"stake\s*manipulation",
                    r"bft\s*assumption",
                    r"consensus\s*bypass",
                    r"voting\s*weight\s*[^;]*\*\s*20"
                ]
            },
            # Remote Code Execution ($500k)
            {
                "category": "Remote Code Execution",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"unsafe\s*\{[^}]*exec",
                    r"eval\s*\(",
                    r"system\s*\(",
                    r"process::Command",
                    r"std::process::spawn"
                ]
            },
            # Move Bytecode Verifier Bypass ($500k)
            {
                "category": "Move Verifier Bypass",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"bytecode\s*verifier\s*bypass",
                    r"move\s*verification\s*skip",
                    r"object\s*creation\s*without\s*verify",
                    r"transfer\s*without\s*auth",
                    r"destroy\s*object\s*bypass"
                ]
            },
            # Address Collision ($500k)
            {
                "category": "Address Collision",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"address\s*collision",
                    r"hash\s*collision",
                    r"authentication\s*scheme\s*bypass",
                    r"sui\s*address\s*generation",
                    r"duplicate\s*address"
                ]
            }
        ]

        findings = []

        for vuln_type in critical_patterns:
            category_findings = self.scan_for_patterns(vuln_type["patterns"], vuln_type)
            findings.extend(category_findings)

        return findings

    def analyze_sui_high_severity(self) -> List[Dict]:
        """
        Analyze for high severity vulnerabilities ($50k)
        """
        logging.info("🔍 Analyzing for high severity vulnerabilities")

        high_severity_patterns = [
            {
                "category": "Network Shutdown",
                "severity": "HIGH",
                "reward": "$50,000",
                "patterns": [
                    r"network\s*shutdown",
                    r"consensus\s*halt",
                    r"validator\s*crash",
                    r"panic!\s*\(",
                    r"abort\s*\(",
                    r"unreachable!\s*\("
                ]
            }
        ]

        findings = []
        for vuln_type in high_severity_patterns:
            category_findings = self.scan_for_patterns(vuln_type["patterns"], vuln_type)
            findings.extend(category_findings)

        return findings

    def analyze_sui_medium_severity(self) -> List[Dict]:
        """
        Analyze for medium severity vulnerabilities ($10k)
        """
        logging.info("🔍 Analyzing for medium severity vulnerabilities")

        medium_severity_patterns = [
            {
                "category": "Smart Contract Logic",
                "severity": "MEDIUM",
                "reward": "$10,000",
                "patterns": [
                    r"unintended\s*behavior",
                    r"token\s*burn\s*unintended",
                    r"partial\s*node\s*shutdown",
                    r"unwrap\s*\(\s*\)\s*without\s*check",
                    r"expect\s*\(\s*[^)]*\)\s*without\s*validation"
                ]
            }
        ]

        findings = []
        for vuln_type in medium_severity_patterns:
            category_findings = self.scan_for_patterns(vuln_type["patterns"], vuln_type)
            findings.extend(category_findings)

        return findings

    def scan_for_patterns(self, patterns: List[str], vuln_info: Dict) -> List[Dict]:
        """
        Scan codebase for specific vulnerability patterns
        """
        findings = []

        # Key directories to focus on
        target_dirs = [
            "crates",           # Core Sui implementation
            "consensus",        # Consensus mechanisms
            "bridge",          # Cross-chain bridge
            "sdk",             # SDK implementations
            "apps",            # Applications
        ]

        for target_dir in target_dirs:
            dir_path = os.path.join(self.sui_repo_path, target_dir)
            if os.path.exists(dir_path):
                findings.extend(self.scan_directory(dir_path, patterns, vuln_info))

        return findings

    def scan_directory(self, directory: str, patterns: List[str], vuln_info: Dict) -> List[Dict]:
        """
        Scan a directory for vulnerability patterns
        """
        findings = []

        for root, dirs, files in os.walk(directory):
            # Focus on Rust and Move files
            for file in files:
                if file.endswith(('.rs', '.move')):
                    file_path = os.path.join(root, file)
                    file_findings = self.scan_file(file_path, patterns, vuln_info)
                    findings.extend(file_findings)

        return findings

    def scan_file(self, file_path: str, patterns: List[str], vuln_info: Dict) -> List[Dict]:
        """
        Scan individual file for vulnerability patterns
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                for match in matches:
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Use VulnHunter model to validate
                    vulnerability_score = self.validate_with_vulnhunter(line_content, pattern)

                    if vulnerability_score > 0:  # 0=safe, 1=vulnerable, 2=forensics
                        finding = {
                            "category": vuln_info["category"],
                            "severity": vuln_info["severity"],
                            "reward": vuln_info["reward"],
                            "file": file_path.replace(self.sui_repo_path, ""),
                            "line": line_num,
                            "code": line_content,
                            "pattern": pattern,
                            "vulnhunter_score": vulnerability_score,
                            "confidence": "High" if vulnerability_score == 1 else "Medium"
                        }
                        findings.append(finding)

        except Exception as e:
            logging.warning(f"Error scanning file {file_path}: {e}")

        return findings

    def validate_with_vulnhunter(self, code_snippet: str, pattern: str) -> int:
        """
        Use VulnHunter Combined Model to validate potential vulnerabilities
        """
        try:
            # Combine code snippet with pattern context for better analysis
            analysis_input = f"{code_snippet} {pattern}"
            prediction = self.model.predict([analysis_input])[0]
            return prediction
        except Exception as e:
            logging.warning(f"VulnHunter validation error: {e}")
            return 0  # Default to safe if model fails

    def analyze_sui_move_contracts(self) -> List[Dict]:
        """
        Special analysis for Move smart contracts
        """
        logging.info("🔍 Analyzing Move smart contracts")

        move_specific_patterns = [
            {
                "category": "Move Resource Safety",
                "severity": "HIGH",
                "reward": "$50,000",
                "patterns": [
                    r"resource\s+struct\s+.*\{[^}]*without\s+drop",
                    r"move_to\s*\<[^>]*\>\s*\([^)]*without\s+check",
                    r"move_from\s*\<[^>]*\>\s*\([^)]*unchecked",
                    r"borrow_global\s*\<[^>]*\>\s*\([^)]*unsafe"
                ]
            },
            {
                "category": "Move Capability Abuse",
                "severity": "CRITICAL",
                "reward": "$500,000",
                "patterns": [
                    r"capability\s+.*\s+admin",
                    r"signer\s+bypass",
                    r"@sui\s+.*\s+unauthorized",
                    r"publish\s+.*\s+without\s+auth"
                ]
            }
        ]

        findings = []
        for vuln_type in move_specific_patterns:
            category_findings = self.scan_for_patterns(vuln_type["patterns"], vuln_type)
            findings.extend(category_findings)

        return findings

    def run_comprehensive_scan(self) -> Dict:
        """
        Run comprehensive vulnerability scan of Sui Protocol
        """
        logging.info("🚀 Starting comprehensive Sui Protocol security analysis")

        all_findings = []

        # Critical vulnerabilities ($500k)
        critical_findings = self.analyze_sui_critical_vulnerabilities()
        all_findings.extend(critical_findings)

        # High severity ($50k)
        high_findings = self.analyze_sui_high_severity()
        all_findings.extend(high_findings)

        # Medium severity ($10k)
        medium_findings = self.analyze_sui_medium_severity()
        all_findings.extend(medium_findings)

        # Move contract specific
        move_findings = self.analyze_sui_move_contracts()
        all_findings.extend(move_findings)

        # Compile results
        self.scan_results["findings"] = all_findings
        self.scan_results["statistics"] = self.compile_statistics(all_findings)
        self.scan_results["recommendations"] = self.generate_recommendations(all_findings)

        return self.scan_results

    def compile_statistics(self, findings: List[Dict]) -> Dict:
        """
        Compile scan statistics
        """
        stats = {
            "total_findings": len(findings),
            "by_severity": {},
            "by_category": {},
            "potential_rewards": 0,
            "files_scanned": len(set(f["file"] for f in findings)),
            "high_confidence_findings": len([f for f in findings if f.get("confidence") == "High"])
        }

        for finding in findings:
            # Count by severity
            severity = finding["severity"]
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Count by category
            category = finding["category"]
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            # Calculate potential rewards (simplified)
            if "500,000" in finding["reward"]:
                stats["potential_rewards"] += 500000
            elif "50,000" in finding["reward"]:
                stats["potential_rewards"] += 50000
            elif "10,000" in finding["reward"]:
                stats["potential_rewards"] += 10000

        return stats

    def generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """
        Generate security recommendations
        """
        recommendations = [
            "🔍 Focus on high-confidence findings first",
            "🧪 Create proof-of-concept exploits for critical findings",
            "📝 Follow HackenProof reporting guidelines",
            "⏰ Report within 24 hours of discovery",
            "🔒 Test exploits only on local testnet environments",
            "📋 Document all reproduction steps clearly"
        ]

        if any(f["severity"] == "CRITICAL" for f in findings):
            recommendations.insert(0, "🚨 CRITICAL vulnerabilities found - prioritize immediate investigation")

        return recommendations

    def save_results(self, filename: str = None):
        """
        Save scan results to file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sui_protocol_vulnhunter_scan_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2)

        logging.info(f"📊 Scan results saved to {filename}")

    def print_summary(self):
        """
        Print scan summary
        """
        print("\n" + "="*80)
        print("🤖 VulnHunter Sui Protocol Security Analysis")
        print("="*80)

        stats = self.scan_results["statistics"]
        findings = self.scan_results["findings"]

        print(f"\n📊 Scan Statistics:")
        print(f"   Total Findings: {stats['total_findings']}")
        print(f"   High Confidence: {stats['high_confidence_findings']}")
        print(f"   Files Scanned: {stats['files_scanned']}")
        print(f"   Potential Rewards: ${stats['potential_rewards']:,}")

        print(f"\n🎯 Findings by Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"   {severity}: {count}")

        print(f"\n📋 Top Findings:")
        for i, finding in enumerate(findings[:5], 1):
            print(f"   {i}. {finding['category']} ({finding['severity']})")
            print(f"      File: {finding['file']}:{finding['line']}")
            print(f"      Reward: {finding['reward']}")

        print(f"\n💡 Recommendations:")
        for rec in self.scan_results["recommendations"]:
            print(f"   {rec}")

        print(f"\n🎯 Bug Bounty Program: https://hackenproof.com/programs/sui-protocol")
        print("="*80)

def main():
    """
    Main function to run Sui Protocol vulnerability scan
    """
    scanner = SuiProtocolVulnHunter()
    results = scanner.run_comprehensive_scan()

    scanner.print_summary()
    scanner.save_results()

    print(f"\n🚀 Sui Protocol security analysis complete!")
    print(f"📁 Results saved for HackenProof submission")

if __name__ == "__main__":
    main()