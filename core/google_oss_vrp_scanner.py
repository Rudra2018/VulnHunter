#!/usr/bin/env python3
"""
Google OSS VRP Scanner
Comprehensive security scanner tailored for Google's Open Source VRP
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Import our scanning components
from core.google_project_detector import GoogleOSSProjectDetector, GoogleProjectInfo
from core.comprehensive_vulnerability_tester import ComprehensiveVulnerabilityTester
from core.supply_chain_analyzer import SupplyChainAnalyzer
from core.secrets_scanner import SecretsScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class GoogleOSSVRPResults:
    """Complete results of Google OSS VRP scan"""
    # Project information
    project_info: GoogleProjectInfo

    # Vulnerability findings
    code_vulnerabilities: List  # From comprehensive tester
    supply_chain_findings: List  # From supply chain analyzer
    secret_findings: List  # From secrets scanner

    # Statistics
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    # Estimated VRP value
    estimated_min_value: int  # USD
    estimated_max_value: int  # USD

    # Scan metadata
    scan_timestamp: str
    scan_duration_seconds: float


class GoogleOSSVRPScanner:
    """
    Comprehensive scanner for Google OSS VRP

    Combines multiple security analysis techniques:
    - Code vulnerability detection (SQL injection, XSS, etc.)
    - Supply chain security analysis
    - Secrets and credential detection
    - Design issue identification
    """

    def __init__(self, project_path: str):
        """
        Initialize Google OSS VRP scanner

        Args:
            project_path: Path to project to scan
        """
        self.project_path = Path(project_path).resolve()
        logger.info(f"Initialized Google OSS VRP Scanner for: {self.project_path}")

    def scan(self, file_extensions: Optional[List[str]] = None) -> GoogleOSSVRPResults:
        """
        Run complete Google OSS VRP scan

        Args:
            file_extensions: List of file extensions to scan (default: common languages)

        Returns:
            GoogleOSSVRPResults with all findings
        """
        start_time = datetime.now()
        logger.info("="*80)
        logger.info("GOOGLE OSS VRP COMPREHENSIVE SCAN")
        logger.info("="*80)

        # Default file extensions
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.ts', '.java', '.go', '.cpp', '.c', '.h', '.php', '.rb']

        # Step 1: Detect if project is eligible for Google OSS VRP
        logger.info("\n[1/4] Detecting Google OSS project eligibility...")
        logger.info("-"*80)
        detector = GoogleOSSProjectDetector(str(self.project_path))
        project_info = detector.detect_project()

        if not project_info.eligible_for_vrp:
            logger.warning("⚠️  This project is NOT eligible for Google OSS VRP")
            logger.info("Continuing scan for informational purposes...\n")
        else:
            logger.info("✅ Project IS eligible for Google OSS VRP")
            logger.info(f"Priority: {project_info.priority_level.upper()}")
            logger.info(f"VRP Tier: {project_info.vrp_tier.upper()}\n")

        # Step 2: Code vulnerability scanning
        logger.info("[2/4] Scanning for code vulnerabilities...")
        logger.info("-"*80)
        vuln_tester = ComprehensiveVulnerabilityTester(str(self.project_path))
        code_vulnerabilities = vuln_tester.comprehensive_scan(file_extensions=file_extensions)
        logger.info(f"✓ Found {len(code_vulnerabilities)} potential code vulnerabilities\n")

        # Step 3: Supply chain analysis
        logger.info("[3/4] Analyzing supply chain security...")
        logger.info("-"*80)
        sc_analyzer = SupplyChainAnalyzer(str(self.project_path))
        supply_chain_findings = sc_analyzer.analyze()
        logger.info(f"✓ Found {len(supply_chain_findings)} supply chain issues\n")

        # Step 4: Secrets scanning
        logger.info("[4/4] Scanning for secrets and credentials...")
        logger.info("-"*80)
        secrets_scanner = SecretsScanner(str(self.project_path))
        secret_findings = secrets_scanner.scan()
        logger.info(f"✓ Found {len(secret_findings)} potential secrets\n")

        # Calculate statistics
        critical_count, high_count, medium_count, low_count = self._calculate_severity_counts(
            code_vulnerabilities, supply_chain_findings, secret_findings
        )

        total_findings = len(code_vulnerabilities) + len(supply_chain_findings) + len(secret_findings)

        # Estimate VRP value
        min_value, max_value = self._estimate_vrp_value(
            project_info,
            critical_count,
            high_count,
            medium_count,
            low_count
        )

        # Calculate scan duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Create results
        results = GoogleOSSVRPResults(
            project_info=project_info,
            code_vulnerabilities=code_vulnerabilities,
            supply_chain_findings=supply_chain_findings,
            secret_findings=secret_findings,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            estimated_min_value=min_value,
            estimated_max_value=max_value,
            scan_timestamp=start_time.isoformat(),
            scan_duration_seconds=duration
        )

        # Print summary
        self._print_summary(results)

        return results

    def _calculate_severity_counts(self, code_vulns, sc_findings, secret_findings) -> tuple:
        """Calculate counts by severity"""
        critical = 0
        high = 0
        medium = 0
        low = 0

        # Code vulnerabilities
        for vuln in code_vulns:
            severity = vuln.severity.value.lower()
            if severity == 'critical':
                critical += 1
            elif severity == 'high':
                high += 1
            elif severity == 'medium':
                medium += 1
            elif severity == 'low':
                low += 1

        # Supply chain findings
        for finding in sc_findings:
            severity = finding.severity.value.lower()
            if severity == 'critical':
                critical += 1
            elif severity == 'high':
                high += 1
            elif severity == 'medium':
                medium += 1
            elif severity == 'low':
                low += 1

        # Secret findings
        for finding in secret_findings:
            severity = finding.severity.value.lower()
            if severity == 'critical':
                critical += 1
            elif severity == 'high':
                high += 1
            elif severity == 'medium':
                medium += 1
            elif severity == 'low':
                low += 1

        return critical, high, medium, low

    def _estimate_vrp_value(self, project_info: GoogleProjectInfo,
                           critical: int, high: int, medium: int, low: int) -> tuple:
        """
        Estimate potential VRP reward value

        Google OSS VRP ranges: $100 - $31,337
        - Tier 1 (High priority): Up to $31,337
        - Tier 2 (Medium priority): Up to $10,000
        - Tier 3 (Lower priority): Up to $5,000
        """
        if not project_info.eligible_for_vrp:
            return 0, 0

        # Base rewards by tier
        tier_max = {
            'tier1': 31337,
            'tier2': 10000,
            'tier3': 5000
        }

        max_reward = tier_max.get(project_info.vrp_tier, 1000)

        # Estimate per finding
        critical_value = (5000, max_reward)  # Critical: $5k - max
        high_value = (1000, 5000)            # High: $1k - $5k
        medium_value = (500, 2000)           # Medium: $500 - $2k
        low_value = (100, 500)               # Low: $100 - $500

        min_total = (
            critical * critical_value[0] +
            high * high_value[0] +
            medium * medium_value[0] +
            low * low_value[0]
        )

        max_total = (
            critical * critical_value[1] +
            high * high_value[1] +
            medium * medium_value[1] +
            low * low_value[1]
        )

        # Cap at tier maximum
        max_total = min(max_total, max_reward * (critical + high + medium + low))

        return min_total, max_total

    def _print_summary(self, results: GoogleOSSVRPResults):
        """Print scan summary"""
        logger.info("\n" + "="*80)
        logger.info("SCAN COMPLETE")
        logger.info("="*80)

        logger.info(f"\nProject: {results.project_info.project_name}")
        logger.info(f"Google OSS VRP Eligible: {'✅ YES' if results.project_info.eligible_for_vrp else '❌ NO'}")

        if results.project_info.eligible_for_vrp:
            logger.info(f"Priority Level: {results.project_info.priority_level.upper()}")
            logger.info(f"VRP Tier: {results.project_info.vrp_tier.upper()}")

        logger.info(f"\nTotal Findings: {results.total_findings}")
        if results.critical_count > 0:
            logger.info(f"  🔴 Critical: {results.critical_count}")
        if results.high_count > 0:
            logger.info(f"  🟠 High: {results.high_count}")
        if results.medium_count > 0:
            logger.info(f"  🟡 Medium: {results.medium_count}")
        if results.low_count > 0:
            logger.info(f"  🟢 Low: {results.low_count}")

        logger.info(f"\nBreakdown:")
        logger.info(f"  Code Vulnerabilities: {len(results.code_vulnerabilities)}")
        logger.info(f"  Supply Chain Issues: {len(results.supply_chain_findings)}")
        logger.info(f"  Secret Exposures: {len(results.secret_findings)}")

        if results.project_info.eligible_for_vrp:
            logger.info(f"\n💰 Estimated VRP Value:")
            logger.info(f"  Minimum: ${results.estimated_min_value:,}")
            logger.info(f"  Maximum: ${results.estimated_max_value:,}")
            logger.info(f"\n📝 Submit to: https://bughunters.google.com/report")

        logger.info(f"\nScan Duration: {results.scan_duration_seconds:.2f} seconds")
        logger.info("="*80 + "\n")


def main():
    """Test the scanner"""
    import sys

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = '.'

    scanner = GoogleOSSVRPScanner(project_path)
    results = scanner.scan()

    # Show top findings
    if results.total_findings > 0:
        print("\n" + "="*80)
        print("TOP FINDINGS")
        print("="*80)

        # Show critical code vulnerabilities
        critical_code = [v for v in results.code_vulnerabilities
                        if v.severity.value.lower() == 'critical']
        if critical_code:
            print(f"\n🔴 Critical Code Vulnerabilities ({len(critical_code)}):")
            for vuln in critical_code[:3]:
                print(f"\n  [{vuln.id}] {vuln.description}")
                print(f"  File: {vuln.evidence.file_path}:{vuln.evidence.line_numbers[0] if vuln.evidence.line_numbers else 'N/A'}")
                print(f"  CWE: {vuln.cwe_id}")

        # Show critical secrets
        critical_secrets = [s for s in results.secret_findings
                           if s.severity.value.lower() == 'critical']
        if critical_secrets:
            print(f"\n🔴 Critical Secrets ({len(critical_secrets)}):")
            for secret in critical_secrets[:3]:
                print(f"\n  [{secret.id}] {secret.description}")
                print(f"  File: {secret.affected_file}:{secret.affected_line}")
                print(f"  Evidence: {secret.evidence}")

        # Show critical supply chain issues
        critical_sc = [f for f in results.supply_chain_findings
                      if f.severity.value.lower() == 'critical']
        if critical_sc:
            print(f"\n🔴 Critical Supply Chain Issues ({len(critical_sc)}):")
            for finding in critical_sc[:3]:
                print(f"\n  [{finding.id}] {finding.title}")
                print(f"  File: {finding.affected_file}")
                print(f"  Category: {finding.category}")


if __name__ == '__main__':
    main()
