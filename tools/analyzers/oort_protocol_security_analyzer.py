#!/usr/bin/env python3
"""
Comprehensive Security Testing Suite for Oort Protocol Blockchain Project

This analyzer applies VulnHunter AI capabilities to perform blockchain-specific
vulnerability detection on the Oort Protocol (Olympus) codebase.

Target Repository: https://github.com/oort-tech/Olympus
Languages: C++ (279 files), Solidity (272 files), JavaScript (71 files)

Attack Surface Analysis:
- EVM Implementation (libevm/, libinterpreter/)
- P2P Network Layer (mcp/p2p/, mcp/node/)
- Consensus Mechanism (mcp/consensus/)
- Storage Layer (mcp/db/)
- RPC Interface (mcp/rpc/)
- Smart Contract Support (test/contracts/)
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Set
from datetime import datetime
import re
import hashlib

# Add our VulnHunter AI core to path
sys.path.append('/Users/ankitthakur/vuln_ml_research/src')

class OortProtocolSecurityAnalyzer:
    """
    Comprehensive security analyzer for Oort Protocol blockchain implementation.

    Focus Areas:
    1. Blockchain-specific vulnerabilities
    2. Smart contract security issues
    3. Consensus mechanism flaws
    4. P2P network security
    5. Cryptographic implementations
    6. Economic attack vectors
    """

    def __init__(self, repo_path: str = "/tmp/oort_olympus"):
        self.repo_path = Path(repo_path)
        self.analysis_results = {
            "metadata": {
                "target": "Oort Protocol Olympus",
                "analysis_date": datetime.now().isoformat(),
                "analyzer_version": "VulnHunter AI v2.0 - Blockchain Security Suite"
            },
            "attack_surface": {},
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "blockchain_specific": {
                "smart_contracts": [],
                "consensus": [],
                "p2p_network": [],
                "cryptographic": [],
                "economic": []
            },
            "statistics": {}
        }

        # Define vulnerability patterns for blockchain-specific issues
        self.blockchain_patterns = self._initialize_blockchain_patterns()

    def _initialize_blockchain_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize blockchain-specific vulnerability patterns."""
        return {
            "smart_contract": [
                {
                    "name": "Reentrancy Vulnerability",
                    "pattern": r"\.call\s*\([^)]*\).*(?:msg\.sender|tx\.origin)",
                    "severity": "critical",
                    "description": "Potential reentrancy attack vector"
                },
                {
                    "name": "Integer Overflow/Underflow",
                    "pattern": r"(?:uint|int)\d*\s+\w+.*[\+\-\*\/].*(?:unchecked|SafeMath)",
                    "severity": "high",
                    "description": "Potential integer overflow/underflow without SafeMath"
                },
                {
                    "name": "Unsafe External Call",
                    "pattern": r"\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(",
                    "severity": "medium",
                    "description": "External call without proper error handling"
                },
                {
                    "name": "tx.origin Authentication",
                    "pattern": r"tx\.origin\s*==|require\s*\(.*tx\.origin",
                    "severity": "high",
                    "description": "Use of tx.origin for authentication (phishing vulnerability)"
                }
            ],
            "consensus": [
                {
                    "name": "Timestamp Dependency",
                    "pattern": r"block\.timestamp|now\s*[\+\-\*\/]",
                    "severity": "medium",
                    "description": "Consensus logic dependent on block timestamp"
                },
                {
                    "name": "Block Hash Manipulation",
                    "pattern": r"blockhash\s*\(|block\.hash",
                    "severity": "medium",
                    "description": "Potential block hash manipulation vulnerability"
                },
                {
                    "name": "Difficulty Adjustment Flaw",
                    "pattern": r"difficulty.*adjust|target.*difficulty",
                    "severity": "high",
                    "description": "Potential difficulty adjustment manipulation"
                }
            ],
            "p2p_network": [
                {
                    "name": "Buffer Overflow in Network Code",
                    "pattern": r"recv\s*\(|send\s*\(.*sizeof.*strcpy|memcpy.*buffer",
                    "severity": "critical",
                    "description": "Potential buffer overflow in network message handling"
                },
                {
                    "name": "Unvalidated Network Input",
                    "pattern": r"socket.*read|recv.*without.*validation",
                    "severity": "high",
                    "description": "Network input without proper validation"
                },
                {
                    "name": "DoS Vector in Message Processing",
                    "pattern": r"while.*message|for.*packet.*unlimited",
                    "severity": "medium",
                    "description": "Potential DoS through resource exhaustion"
                }
            ],
            "cryptographic": [
                {
                    "name": "Weak Random Number Generation",
                    "pattern": r"rand\s*\(|random.*seed.*time",
                    "severity": "high",
                    "description": "Weak random number generation for cryptographic purposes"
                },
                {
                    "name": "Hash Collision Vulnerability",
                    "pattern": r"sha1|md5.*hash|weak.*hash",
                    "severity": "medium",
                    "description": "Use of weak cryptographic hash functions"
                },
                {
                    "name": "Private Key Exposure",
                    "pattern": r"private.*key.*log|debug.*private|console.*private",
                    "severity": "critical",
                    "description": "Potential private key exposure in logs or debug output"
                }
            ],
            "economic": [
                {
                    "name": "Flash Loan Attack Vector",
                    "pattern": r"flashloan|flash.*borrow|atomic.*arbitrage",
                    "severity": "high",
                    "description": "Potential flash loan attack vulnerability"
                },
                {
                    "name": "Price Oracle Manipulation",
                    "pattern": r"price.*oracle|external.*price.*feed",
                    "severity": "high",
                    "description": "Price oracle manipulation vulnerability"
                },
                {
                    "name": "MEV (Maximal Extractable Value) Exploit",
                    "pattern": r"mempool.*front.*run|sandwich.*attack|mev",
                    "severity": "medium",
                    "description": "MEV extraction vulnerability"
                }
            ]
        }

    def analyze_repository_structure(self) -> Dict:
        """Analyze the repository structure and map attack surface."""
        print("🔍 Analyzing Oort Protocol repository structure...")

        attack_surface = {
            "core_components": {
                "evm_implementation": {
                    "path": "libevm/",
                    "files": list(self.repo_path.glob("libevm/**/*")),
                    "risk_level": "critical",
                    "description": "EVM implementation - core execution environment"
                },
                "vm_interpreter": {
                    "path": "libinterpreter/",
                    "files": list(self.repo_path.glob("libinterpreter/**/*")),
                    "risk_level": "critical",
                    "description": "Virtual machine interpreter - execution engine"
                },
                "consensus_layer": {
                    "path": "mcp/consensus/",
                    "files": list(self.repo_path.glob("mcp/consensus/**/*")),
                    "risk_level": "critical",
                    "description": "Consensus mechanism implementation"
                },
                "p2p_network": {
                    "path": "mcp/p2p/",
                    "files": list(self.repo_path.glob("mcp/p2p/**/*")),
                    "risk_level": "high",
                    "description": "Peer-to-peer networking layer"
                },
                "storage_layer": {
                    "path": "mcp/db/",
                    "files": list(self.repo_path.glob("mcp/db/**/*")),
                    "risk_level": "high",
                    "description": "Database and storage implementation"
                },
                "rpc_interface": {
                    "path": "mcp/rpc/",
                    "files": list(self.repo_path.glob("mcp/rpc/**/*")),
                    "risk_level": "medium",
                    "description": "RPC API interface"
                },
                "smart_contracts": {
                    "path": "test/contracts/",
                    "files": list(self.repo_path.glob("test/contracts/**/*.sol")),
                    "risk_level": "high",
                    "description": "Smart contract implementations (primarily test contracts)"
                }
            }
        }

        # Count files by language and component
        for component, info in attack_surface["core_components"].items():
            cpp_files = [f for f in info["files"] if f.suffix in ['.cpp', '.h', '.hpp']]
            sol_files = [f for f in info["files"] if f.suffix == '.sol']
            js_files = [f for f in info["files"] if f.suffix == '.js']

            info["file_counts"] = {
                "cpp": len(cpp_files),
                "solidity": len(sol_files),
                "javascript": len(js_files),
                "total": len(info["files"])
            }

        self.analysis_results["attack_surface"] = attack_surface
        return attack_surface

    def scan_for_blockchain_vulnerabilities(self) -> Dict:
        """Scan for blockchain-specific vulnerability patterns."""
        print("🛡️ Scanning for blockchain-specific vulnerabilities...")

        vulnerabilities_found = []

        # Scan each component for vulnerabilities
        for component_name, component_info in self.analysis_results["attack_surface"]["core_components"].items():
            print(f"  📁 Scanning {component_name}...")

            for file_path in component_info["files"]:
                if file_path.is_file() and file_path.suffix in ['.cpp', '.h', '.hpp', '.sol', '.js']:
                    vulns = self._scan_file_for_patterns(file_path, component_name)
                    vulnerabilities_found.extend(vulns)

        # Categorize vulnerabilities by severity and type
        for vuln in vulnerabilities_found:
            severity = vuln["severity"]
            category = vuln["category"]

            self.analysis_results["vulnerabilities"][severity].append(vuln)

            # Map category names for blockchain_specific storage
            bc_category = vuln["category"]
            if bc_category not in self.analysis_results["blockchain_specific"]:
                self.analysis_results["blockchain_specific"][bc_category] = []
            self.analysis_results["blockchain_specific"][bc_category].append(vuln)

        return self.analysis_results["vulnerabilities"]

    def _scan_file_for_patterns(self, file_path: Path, component: str) -> List[Dict]:
        """Scan a single file for vulnerability patterns."""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                # Scan for each pattern category
                for category, patterns in self.blockchain_patterns.items():
                    # Map category names correctly
                    category_name = category.replace("_", "")
                    if category == "smart_contract":
                        category_name = "smart_contracts"

                    for pattern_info in patterns:
                        matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE | re.MULTILINE)

                        for match in matches:
                            # Find line number
                            line_num = content[:match.start()].count('\n') + 1
                            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                            vulnerability = {
                                "name": pattern_info["name"],
                                "severity": pattern_info["severity"],
                                "category": category_name,
                                "component": component,
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "code_snippet": line_content,
                                "description": pattern_info["description"],
                                "match": match.group(0),
                                "confidence": self._calculate_confidence(pattern_info, match, content)
                            }
                            vulnerabilities.append(vulnerability)

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

        return vulnerabilities

    def _calculate_confidence(self, pattern_info: Dict, match: re.Match, content: str) -> float:
        """Calculate confidence score for vulnerability detection."""
        confidence = 0.7  # Base confidence

        # Adjust based on context
        context = content[max(0, match.start()-100):match.end()+100]

        # Higher confidence for certain patterns
        if "critical" in pattern_info["severity"]:
            confidence += 0.2

        # Check for mitigation patterns nearby
        mitigation_patterns = ["require(", "assert(", "SafeMath", "try", "catch"]
        if any(pattern in context for pattern in mitigation_patterns):
            confidence -= 0.3

        return max(0.1, min(1.0, confidence))

    def analyze_smart_contracts(self) -> Dict:
        """Perform specialized smart contract analysis."""
        print("📜 Analyzing smart contracts...")

        smart_contract_analysis = {
            "total_contracts": 0,
            "high_risk_contracts": [],
            "vulnerability_summary": {},
            "gas_optimization_issues": [],
            "access_control_issues": []
        }

        contract_files = list(self.repo_path.glob("test/contracts/**/*.sol"))
        smart_contract_analysis["total_contracts"] = len(contract_files)

        for contract_file in contract_files:
            print(f"  📄 Analyzing {contract_file.name}...")

            # Read contract content
            try:
                with open(contract_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Check for high-risk patterns
                high_risk_indicators = [
                    "delegatecall",
                    "assembly",
                    "selfdestruct",
                    "suicide",
                    "tx.origin",
                    ".call(",
                    "msg.value"
                ]

                risk_score = 0
                found_indicators = []

                for indicator in high_risk_indicators:
                    if indicator in content:
                        risk_score += 1
                        found_indicators.append(indicator)

                if risk_score >= 3:
                    smart_contract_analysis["high_risk_contracts"].append({
                        "file": str(contract_file.relative_to(self.repo_path)),
                        "risk_score": risk_score,
                        "indicators": found_indicators
                    })

                # Check for access control issues
                if "onlyOwner" not in content and "require(" in content:
                    smart_contract_analysis["access_control_issues"].append({
                        "file": str(contract_file.relative_to(self.repo_path)),
                        "issue": "Missing proper access control modifiers"
                    })

            except Exception as e:
                print(f"Error analyzing contract {contract_file}: {e}")

        return smart_contract_analysis

    def analyze_consensus_mechanism(self) -> Dict:
        """Analyze consensus mechanism for vulnerabilities."""
        print("⚖️ Analyzing consensus mechanism...")

        consensus_analysis = {
            "consensus_type": "Unknown",
            "potential_issues": [],
            "timestamp_dependencies": [],
            "difficulty_adjustments": [],
            "fork_choice_rules": []
        }

        consensus_files = list(self.repo_path.glob("mcp/consensus/**/*"))

        for file_path in consensus_files:
            if file_path.is_file() and file_path.suffix in ['.cpp', '.h', '.hpp']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for consensus type indicators
                    if "proof_of_work" in content.lower() or "pow" in content.lower():
                        consensus_analysis["consensus_type"] = "Proof of Work"
                    elif "proof_of_stake" in content.lower() or "pos" in content.lower():
                        consensus_analysis["consensus_type"] = "Proof of Stake"
                    elif "pbft" in content.lower() or "byzantine" in content.lower():
                        consensus_analysis["consensus_type"] = "Byzantine Fault Tolerant"

                    # Check for timestamp dependencies
                    timestamp_patterns = [
                        r"block\.timestamp",
                        r"now\s*[\+\-\*\/]",
                        r"time.*based.*consensus"
                    ]

                    for pattern in timestamp_patterns:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        if matches:
                            consensus_analysis["timestamp_dependencies"].append({
                                "file": str(file_path.relative_to(self.repo_path)),
                                "matches": len(matches),
                                "pattern": pattern
                            })

                except Exception as e:
                    print(f"Error analyzing consensus file {file_path}: {e}")

        return consensus_analysis

    def analyze_p2p_network(self) -> Dict:
        """Analyze P2P network implementation for security issues."""
        print("🌐 Analyzing P2P network layer...")

        p2p_analysis = {
            "network_protocols": [],
            "message_handling": [],
            "dos_vectors": [],
            "eclipse_attack_resistance": "Unknown",
            "sybil_protection": "Unknown"
        }

        p2p_files = list(self.repo_path.glob("mcp/p2p/**/*")) + list(self.repo_path.glob("mcp/node/**/*"))

        for file_path in p2p_files:
            if file_path.is_file() and file_path.suffix in ['.cpp', '.h', '.hpp']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for network protocols
                    protocol_indicators = ["tcp", "udp", "websocket", "rpc", "jsonrpc"]
                    for protocol in protocol_indicators:
                        if protocol in content.lower():
                            p2p_analysis["network_protocols"].append(protocol)

                    # Check for message handling vulnerabilities
                    unsafe_patterns = [
                        r"recv.*without.*validation",
                        r"buffer.*overflow",
                        r"memcpy.*unchecked",
                        r"unlimited.*loop"
                    ]

                    for pattern in unsafe_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            p2p_analysis["dos_vectors"].append({
                                "file": str(file_path.relative_to(self.repo_path)),
                                "pattern": pattern,
                                "risk": "high"
                            })

                    # Check for eclipse attack resistance
                    if "peer.*diversity" in content.lower() or "connection.*limit" in content.lower():
                        p2p_analysis["eclipse_attack_resistance"] = "Present"

                    # Check for sybil protection
                    if "reputation" in content.lower() or "trust.*score" in content.lower():
                        p2p_analysis["sybil_protection"] = "Present"

                except Exception as e:
                    print(f"Error analyzing P2P file {file_path}: {e}")

        # Remove duplicates
        p2p_analysis["network_protocols"] = list(set(p2p_analysis["network_protocols"]))

        return p2p_analysis

    def generate_security_report(self) -> str:
        """Generate comprehensive security analysis report."""
        print("📊 Generating comprehensive security report...")

        # Calculate statistics
        total_vulns = sum(len(vulns) for vulns in self.analysis_results["vulnerabilities"].values())
        critical_count = len(self.analysis_results["vulnerabilities"]["critical"])
        high_count = len(self.analysis_results["vulnerabilities"]["high"])

        self.analysis_results["statistics"] = {
            "total_vulnerabilities": total_vulns,
            "critical_severity": critical_count,
            "high_severity": high_count,
            "medium_severity": len(self.analysis_results["vulnerabilities"]["medium"]),
            "low_severity": len(self.analysis_results["vulnerabilities"]["low"]),
            "files_analyzed": self._count_analyzed_files(),
            "attack_surface_components": len(self.analysis_results["attack_surface"]["core_components"])
        }

        # Generate report
        report = self._format_security_report()

        # Save to file
        report_path = f"/Users/ankitthakur/vuln_ml_research/data/results/oort_protocol_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)

        print(f"📄 Security report saved to: {report_path}")
        return report

    def _count_analyzed_files(self) -> int:
        """Count total files analyzed."""
        total = 0
        for component in self.analysis_results["attack_surface"]["core_components"].values():
            total += component["file_counts"]["total"]
        return total

    def _format_security_report(self) -> str:
        """Format the security analysis into a readable report."""
        stats = self.analysis_results["statistics"]

        report = f"""
🔒 OORT PROTOCOL SECURITY ANALYSIS REPORT
==========================================

📊 EXECUTIVE SUMMARY
Target: Oort Protocol Olympus Blockchain
Repository: https://github.com/oort-tech/Olympus
Analysis Date: {self.analysis_results['metadata']['analysis_date']}
Analyzer: {self.analysis_results['metadata']['analyzer_version']}

📈 SECURITY METRICS
Total Files Analyzed: {stats['files_analyzed']}
Total Vulnerabilities Found: {stats['total_vulnerabilities']}

Severity Breakdown:
  🚨 Critical: {stats['critical_severity']}
  ⚠️  High: {stats['high_severity']}
  🟡 Medium: {stats['medium_severity']}
  🔵 Low: {stats['low_severity']}

🎯 ATTACK SURFACE ANALYSIS
Core Components Analyzed: {stats['attack_surface_components']}
"""

        # Add component-specific findings
        for component, info in self.analysis_results["attack_surface"]["core_components"].items():
            report += f"\n📁 {component.upper()}: {info['file_counts']['total']} files ({info['risk_level']} risk)"

        # Add vulnerability highlights
        if self.analysis_results["vulnerabilities"]["critical"]:
            report += "\n\n🚨 CRITICAL VULNERABILITIES FOUND:\n"
            for vuln in self.analysis_results["vulnerabilities"]["critical"][:5]:  # Top 5
                report += f"  • {vuln['name']} in {vuln['file']}:{vuln['line']}\n"

        if self.analysis_results["vulnerabilities"]["high"]:
            report += "\n\n⚠️ HIGH SEVERITY VULNERABILITIES:\n"
            for vuln in self.analysis_results["vulnerabilities"]["high"][:5]:  # Top 5
                report += f"  • {vuln['name']} in {vuln['file']}:{vuln['line']}\n"

        report += f"\n\n📄 Full detailed report available in JSON format."
        return report

    def run_comprehensive_analysis(self) -> Dict:
        """Run complete security analysis of Oort Protocol."""
        print("🚀 Starting comprehensive security analysis of Oort Protocol...\n")

        # Step 1: Repository structure analysis
        self.analyze_repository_structure()

        # Step 2: Blockchain vulnerability scanning
        self.scan_for_blockchain_vulnerabilities()

        # Step 3: Smart contract analysis
        smart_contract_results = self.analyze_smart_contracts()
        self.analysis_results["smart_contract_analysis"] = smart_contract_results

        # Step 4: Consensus mechanism analysis
        consensus_results = self.analyze_consensus_mechanism()
        self.analysis_results["consensus_analysis"] = consensus_results

        # Step 5: P2P network analysis
        p2p_results = self.analyze_p2p_network()
        self.analysis_results["p2p_analysis"] = p2p_results

        # Step 6: Generate final report
        report = self.generate_security_report()

        print("\n✅ Comprehensive security analysis completed!")
        print(report)

        return self.analysis_results

def main():
    """Main execution function."""
    print("🔒 VulnHunter AI - Oort Protocol Security Analysis Suite")
    print("=" * 60)

    # Initialize analyzer
    analyzer = OortProtocolSecurityAnalyzer()

    # Run comprehensive analysis
    try:
        results = analyzer.run_comprehensive_analysis()

        print(f"\n📊 Analysis Summary:")
        print(f"Total Vulnerabilities: {results['statistics']['total_vulnerabilities']}")
        print(f"Critical Issues: {results['statistics']['critical_severity']}")
        print(f"High Severity Issues: {results['statistics']['high_severity']}")

        return results

    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return None

if __name__ == "__main__":
    main()