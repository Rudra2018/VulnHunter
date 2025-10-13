#!/usr/bin/env python3
"""
Blockchain Static Analysis Tool with Multi-Tool Integration

This tool integrates multiple blockchain security scanners and static analysis tools
to provide comprehensive security coverage for blockchain projects.

Supported Tools:
- Slither (Solidity static analysis)
- Mythril (Security analysis for Ethereum smart contracts)
- Semgrep (Custom rules for blockchain patterns)
- Cppcheck (C++ static analysis)
- Clang Static Analyzer
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import yaml

class BlockchainStaticAnalyzer:
    """
    Multi-tool blockchain security analyzer that integrates various static analysis tools.
    """

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.results = {
            "metadata": {
                "target": str(target_path),
                "analysis_date": datetime.now().isoformat(),
                "tools_used": [],
                "scan_duration": 0
            },
            "tool_results": {},
            "unified_findings": [],
            "summary": {}
        }
        self.temp_dir = None

    def setup_analysis_environment(self) -> bool:
        """Set up the analysis environment and check tool availability."""
        print("🔧 Setting up blockchain static analysis environment...")

        # Create temporary directory for analysis
        self.temp_dir = tempfile.mkdtemp(prefix="blockchain_analysis_")
        print(f"📁 Created temporary analysis directory: {self.temp_dir}")

        # Check tool availability
        tools_status = self._check_tool_availability()

        available_tools = [tool for tool, available in tools_status.items() if available]
        self.results["metadata"]["tools_used"] = available_tools

        if not available_tools:
            print("❌ No supported analysis tools found. Please install at least one:")
            self._print_installation_instructions()
            return False

        print(f"✅ Available tools: {', '.join(available_tools)}")
        return True

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which analysis tools are available."""
        tools = {
            "slither": self._check_command("slither"),
            "mythril": self._check_command("myth"),
            "semgrep": self._check_command("semgrep"),
            "cppcheck": self._check_command("cppcheck"),
            "clang-analyzer": self._check_command("scan-build")
        }
        return tools

    def _check_command(self, command: str) -> bool:
        """Check if a command is available in PATH."""
        try:
            subprocess.run([command, "--version"],
                         capture_output=True,
                         check=False,
                         timeout=10)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run_slither_analysis(self) -> Dict:
        """Run Slither analysis on Solidity contracts."""
        print("🐍 Running Slither analysis...")

        solidity_files = list(self.target_path.glob("**/*.sol"))
        if not solidity_files:
            print("ℹ️ No Solidity files found for Slither analysis")
            return {"status": "skipped", "reason": "No Solidity files found"}

        try:
            # Run Slither with comprehensive checks
            cmd = [
                "slither", str(self.target_path),
                "--json", f"{self.temp_dir}/slither_report.json",
                "--detect", "all",
                "--print", "all",
                "--exclude-informational",
                "--exclude-optimization"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse Slither results
            slither_results = {
                "status": "completed",
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "findings": []
            }

            # Load JSON report if available
            json_report_path = Path(f"{self.temp_dir}/slither_report.json")
            if json_report_path.exists():
                with open(json_report_path, 'r') as f:
                    json_data = json.load(f)
                    slither_results["raw_json"] = json_data
                    slither_results["findings"] = self._parse_slither_findings(json_data)

            return slither_results

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Slither analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_slither_findings(self, slither_json: Dict) -> List[Dict]:
        """Parse Slither JSON output into standardized format."""
        findings = []

        if "results" in slither_json and "detectors" in slither_json["results"]:
            for detector_result in slither_json["results"]["detectors"]:
                finding = {
                    "tool": "slither",
                    "check": detector_result.get("check", "unknown"),
                    "impact": detector_result.get("impact", "unknown"),
                    "confidence": detector_result.get("confidence", "unknown"),
                    "description": detector_result.get("description", ""),
                    "elements": detector_result.get("elements", []),
                    "severity": self._map_slither_severity(
                        detector_result.get("impact", ""),
                        detector_result.get("confidence", "")
                    )
                }
                findings.append(finding)

        return findings

    def _map_slither_severity(self, impact: str, confidence: str) -> str:
        """Map Slither impact/confidence to standardized severity."""
        impact_lower = impact.lower()
        confidence_lower = confidence.lower()

        if impact_lower == "critical" or impact_lower == "high":
            if confidence_lower == "high":
                return "critical"
            elif confidence_lower == "medium":
                return "high"
            else:
                return "medium"
        elif impact_lower == "medium":
            return "medium" if confidence_lower == "high" else "low"
        else:
            return "low"

    def run_mythril_analysis(self) -> Dict:
        """Run Mythril analysis on smart contracts."""
        print("🔮 Running Mythril analysis...")

        solidity_files = list(self.target_path.glob("**/*.sol"))
        if not solidity_files:
            return {"status": "skipped", "reason": "No Solidity files found"}

        mythril_results = {
            "status": "completed",
            "findings": [],
            "file_results": {}
        }

        # Analyze each Solidity file with Mythril
        for sol_file in solidity_files[:10]:  # Limit to first 10 files for performance
            try:
                print(f"  📄 Analyzing {sol_file.name}...")

                cmd = [
                    "myth", "analyze",
                    str(sol_file),
                    "--output", "json",
                    "--execution-timeout", "60",
                    "--solver-timeout", "10"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                file_result = {
                    "file": str(sol_file.relative_to(self.target_path)),
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }

                # Parse JSON output if available
                try:
                    if result.stdout.strip():
                        mythril_json = json.loads(result.stdout)
                        file_result["issues"] = mythril_json.get("issues", [])

                        # Convert to standardized format
                        for issue in mythril_json.get("issues", []):
                            finding = {
                                "tool": "mythril",
                                "file": str(sol_file.relative_to(self.target_path)),
                                "title": issue.get("title", "Unknown Issue"),
                                "description": issue.get("description", ""),
                                "severity": issue.get("severity", "Medium").lower(),
                                "swc_id": issue.get("swc-id", ""),
                                "locations": issue.get("locations", [])
                            }
                            mythril_results["findings"].append(finding)

                except json.JSONDecodeError:
                    file_result["parse_error"] = "Failed to parse JSON output"

                mythril_results["file_results"][str(sol_file)] = file_result

            except subprocess.TimeoutExpired:
                mythril_results["file_results"][str(sol_file)] = {
                    "status": "timeout",
                    "error": "Analysis timed out"
                }
            except Exception as e:
                mythril_results["file_results"][str(sol_file)] = {
                    "status": "error",
                    "error": str(e)
                }

        return mythril_results

    def run_cppcheck_analysis(self) -> Dict:
        """Run Cppcheck analysis on C++ files."""
        print("🔍 Running Cppcheck analysis...")

        cpp_files = list(self.target_path.glob("**/*.cpp")) + list(self.target_path.glob("**/*.h"))
        if not cpp_files:
            return {"status": "skipped", "reason": "No C++ files found"}

        try:
            cmd = [
                "cppcheck",
                "--enable=all",
                "--xml",
                "--xml-version=2",
                f"--output-file={self.temp_dir}/cppcheck_report.xml",
                "--force",
                "--inconclusive",
                str(self.target_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            cppcheck_results = {
                "status": "completed",
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "findings": []
            }

            # Parse XML report
            xml_report_path = Path(f"{self.temp_dir}/cppcheck_report.xml")
            if xml_report_path.exists():
                cppcheck_results["findings"] = self._parse_cppcheck_xml(xml_report_path)

            return cppcheck_results

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Cppcheck analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_cppcheck_xml(self, xml_path: Path) -> List[Dict]:
        """Parse Cppcheck XML output."""
        findings = []

        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for error in root.findall(".//error"):
                finding = {
                    "tool": "cppcheck",
                    "id": error.get("id", ""),
                    "severity": error.get("severity", "unknown"),
                    "msg": error.get("msg", ""),
                    "verbose": error.get("verbose", ""),
                    "locations": []
                }

                for location in error.findall("location"):
                    finding["locations"].append({
                        "file": location.get("file", ""),
                        "line": location.get("line", ""),
                        "column": location.get("column", "")
                    })

                findings.append(finding)

        except Exception as e:
            print(f"Error parsing Cppcheck XML: {e}")

        return findings

    def create_semgrep_rules(self) -> str:
        """Create custom Semgrep rules for blockchain-specific patterns."""
        blockchain_rules = {
            "rules": [
                {
                    "id": "blockchain-reentrancy-pattern",
                    "pattern": "$X.call(...)",
                    "message": "Potential reentrancy vulnerability - external call detected",
                    "languages": ["solidity"],
                    "severity": "ERROR"
                },
                {
                    "id": "blockchain-tx-origin-auth",
                    "pattern": "require(tx.origin == $ADDR)",
                    "message": "Using tx.origin for authentication is vulnerable to phishing attacks",
                    "languages": ["solidity"],
                    "severity": "ERROR"
                },
                {
                    "id": "blockchain-unsafe-math",
                    "patterns": [
                        {
                            "pattern": "$X + $Y",
                            "pattern-not-inside": "SafeMath.add(...)"
                        },
                        {
                            "pattern": "$X - $Y",
                            "pattern-not-inside": "SafeMath.sub(...)"
                        }
                    ],
                    "message": "Potential integer overflow/underflow - consider using SafeMath",
                    "languages": ["solidity"],
                    "severity": "WARNING"
                },
                {
                    "id": "cpp-buffer-overflow",
                    "pattern": "strcpy($DST, $SRC)",
                    "message": "strcpy is vulnerable to buffer overflow - use strncpy instead",
                    "languages": ["cpp"],
                    "severity": "ERROR"
                },
                {
                    "id": "cpp-format-string",
                    "pattern": "printf($VAR)",
                    "message": "Format string vulnerability - use printf with format specifier",
                    "languages": ["cpp"],
                    "severity": "ERROR"
                }
            ]
        }

        rules_path = f"{self.temp_dir}/blockchain_rules.yaml"
        with open(rules_path, 'w') as f:
            yaml.dump(blockchain_rules, f)

        return rules_path

    def run_semgrep_analysis(self) -> Dict:
        """Run Semgrep analysis with custom blockchain rules."""
        print("🎯 Running Semgrep analysis with blockchain-specific rules...")

        try:
            # Create custom rules
            rules_path = self.create_semgrep_rules()

            cmd = [
                "semgrep",
                "--config", rules_path,
                "--json",
                "--output", f"{self.temp_dir}/semgrep_report.json",
                str(self.target_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            semgrep_results = {
                "status": "completed",
                "return_code": result.returncode,
                "findings": []
            }

            # Parse JSON report
            json_report_path = Path(f"{self.temp_dir}/semgrep_report.json")
            if json_report_path.exists():
                with open(json_report_path, 'r') as f:
                    semgrep_json = json.load(f)
                    semgrep_results["findings"] = self._parse_semgrep_findings(semgrep_json)

            return semgrep_results

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Semgrep analysis timed out"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_semgrep_findings(self, semgrep_json: Dict) -> List[Dict]:
        """Parse Semgrep JSON output."""
        findings = []

        for result in semgrep_json.get("results", []):
            finding = {
                "tool": "semgrep",
                "rule_id": result.get("check_id", ""),
                "message": result.get("extra", {}).get("message", ""),
                "severity": result.get("extra", {}).get("severity", "").lower(),
                "file": result.get("path", ""),
                "line_start": result.get("start", {}).get("line", ""),
                "line_end": result.get("end", {}).get("line", ""),
                "code": result.get("extra", {}).get("lines", "")
            }
            findings.append(finding)

        return findings

    def run_comprehensive_analysis(self) -> Dict:
        """Run all available static analysis tools."""
        start_time = datetime.now()
        print("🚀 Starting comprehensive blockchain static analysis...\n")

        if not self.setup_analysis_environment():
            return self.results

        # Run each available tool
        available_tools = self.results["metadata"]["tools_used"]

        if "slither" in available_tools:
            self.results["tool_results"]["slither"] = self.run_slither_analysis()

        if "mythril" in available_tools:
            self.results["tool_results"]["mythril"] = self.run_mythril_analysis()

        if "cppcheck" in available_tools:
            self.results["tool_results"]["cppcheck"] = self.run_cppcheck_analysis()

        if "semgrep" in available_tools:
            self.results["tool_results"]["semgrep"] = self.run_semgrep_analysis()

        # Calculate analysis duration
        end_time = datetime.now()
        self.results["metadata"]["scan_duration"] = (end_time - start_time).total_seconds()

        # Unify findings across all tools
        self._unify_findings()

        # Generate summary
        self._generate_summary()

        # Clean up temporary directory
        if self.temp_dir and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

        print(f"\n✅ Comprehensive analysis completed in {self.results['metadata']['scan_duration']:.2f} seconds")
        return self.results

    def _unify_findings(self):
        """Unify findings from all tools into a common format."""
        unified = []

        for tool_name, tool_results in self.results["tool_results"].items():
            if "findings" in tool_results:
                for finding in tool_results["findings"]:
                    unified_finding = {
                        "source_tool": tool_name,
                        "severity": finding.get("severity", "unknown"),
                        "title": finding.get("title", finding.get("check", finding.get("rule_id", "Unknown"))),
                        "description": finding.get("description", finding.get("message", finding.get("msg", ""))),
                        "file": finding.get("file", ""),
                        "line": finding.get("line", finding.get("line_start", "")),
                        "confidence": finding.get("confidence", "medium"),
                        "category": self._categorize_finding(finding),
                        "raw_finding": finding
                    }
                    unified.append(unified_finding)

        self.results["unified_findings"] = unified

    def _categorize_finding(self, finding: Dict) -> str:
        """Categorize finding based on content."""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        rule_id = finding.get("rule_id", "").lower()

        content = f"{title} {description} {rule_id}"

        if any(term in content for term in ["reentrancy", "external call", "delegatecall"]):
            return "reentrancy"
        elif any(term in content for term in ["overflow", "underflow", "safemath"]):
            return "integer_overflow"
        elif any(term in content for term in ["tx.origin", "authentication"]):
            return "authentication"
        elif any(term in content for term in ["buffer", "strcpy", "memcpy"]):
            return "buffer_overflow"
        elif any(term in content for term in ["format", "printf", "sprintf"]):
            return "format_string"
        elif any(term in content for term in ["access control", "onlyowner", "modifier"]):
            return "access_control"
        else:
            return "other"

    def _generate_summary(self):
        """Generate analysis summary."""
        findings_by_severity = {}
        findings_by_category = {}
        findings_by_tool = {}

        for finding in self.results["unified_findings"]:
            # By severity
            severity = finding["severity"]
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

            # By category
            category = finding["category"]
            findings_by_category[category] = findings_by_category.get(category, 0) + 1

            # By tool
            tool = finding["source_tool"]
            findings_by_tool[tool] = findings_by_tool.get(tool, 0) + 1

        self.results["summary"] = {
            "total_findings": len(self.results["unified_findings"]),
            "by_severity": findings_by_severity,
            "by_category": findings_by_category,
            "by_tool": findings_by_tool,
            "tools_executed": len(self.results["tool_results"]),
            "analysis_duration": self.results["metadata"]["scan_duration"]
        }

    def _print_installation_instructions(self):
        """Print installation instructions for analysis tools."""
        print("\n📋 Installation Instructions:")
        print("pip install slither-analyzer")
        print("pip install mythril")
        print("pip install semgrep")
        print("apt-get install cppcheck  # Ubuntu/Debian")
        print("brew install cppcheck     # macOS")

    def save_results(self, output_path: Optional[str] = None) -> str:
        """Save analysis results to JSON file."""
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"/Users/ankitthakur/vuln_ml_research/data/results/blockchain_static_analysis_{timestamp}.json"

        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"📄 Analysis results saved to: {output_path}")
        return output_path

def main():
    """Main execution function."""
    if len(sys.argv) != 2:
        print("Usage: python blockchain_static_analyzer.py <target_path>")
        sys.exit(1)

    target_path = sys.argv[1]

    print("🔒 Blockchain Static Analysis Suite")
    print("=" * 50)

    analyzer = BlockchainStaticAnalyzer(target_path)
    results = analyzer.run_comprehensive_analysis()

    if results["unified_findings"]:
        print(f"\n📊 Analysis Summary:")
        print(f"Total Findings: {results['summary']['total_findings']}")
        print(f"Tools Executed: {results['summary']['tools_executed']}")

        severity_counts = results['summary']['by_severity']
        for severity, count in severity_counts.items():
            print(f"  {severity.capitalize()}: {count}")

    # Save results
    analyzer.save_results()

if __name__ == "__main__":
    main()