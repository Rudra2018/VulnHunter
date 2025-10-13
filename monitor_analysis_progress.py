#!/usr/bin/env python3
"""
Analysis Progress Monitor
Real-time monitoring of enterprise security analysis progress
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime

def monitor_progress():
    """Monitor and display analysis progress"""

    base_dir = Path("enterprise_security_analysis")

    print("🔍 Enterprise Security Analysis - Progress Monitor")
    print("=" * 60)

    # Check if analysis is running
    if not base_dir.exists():
        print("❌ Analysis not started yet")
        return

    # Monitor each organization
    organizations = ["openai", "xai-org", "twitter", "facebook"]

    total_repos_analyzed = 0
    total_findings = 0

    for org in organizations:
        org_dir = base_dir / org

        if not org_dir.exists():
            print(f"⏳ {org.upper()}: Not started")
            continue

        # Check repositories
        repos_dir = org_dir / "repositories"
        reports_dir = org_dir / "reports"
        pocs_dir = org_dir / "pocs"
        evidence_dir = org_dir / "evidence"

        repos_cloned = len(list(repos_dir.glob("*"))) if repos_dir.exists() else 0
        reports_generated = len(list(reports_dir.glob("*_analysis_*.json"))) if reports_dir.exists() else 0
        pocs_created = len(list(pocs_dir.rglob("*.py"))) if pocs_dir.exists() else 0
        evidence_files = len(list(evidence_dir.rglob("*.md"))) if evidence_dir.exists() else 0

        print(f"\n🏢 {org.upper()}")
        print(f"├── Repositories Cloned: {repos_cloned}")
        print(f"├── Analysis Reports: {reports_generated}")
        print(f"├── PoC Scripts Generated: {pocs_created}")
        print(f"└── Evidence Documents: {evidence_files}")

        # Get findings from latest reports
        if reports_dir.exists():
            latest_findings = 0
            for report_file in reports_dir.glob("*_findings_*.json"):
                try:
                    with open(report_file, 'r') as f:
                        findings_data = json.load(f)
                        latest_findings += len(findings_data)
                except:
                    pass

            total_repos_analyzed += reports_generated
            total_findings += latest_findings

            if latest_findings > 0:
                print(f"    └── Security Findings: {latest_findings}")

    # Overall progress
    print(f"\n📊 OVERALL PROGRESS")
    print(f"├── Total Repositories Analyzed: {total_repos_analyzed}")
    print(f"├── Total Security Findings: {total_findings}")

    # Check for completed analysis summaries
    completed_orgs = 0
    for org in organizations:
        summary_files = list((base_dir / org / "reports").glob("*_security_summary_*.md")) if (base_dir / org / "reports").exists() else []
        if summary_files:
            completed_orgs += 1

    print(f"├── Organizations Completed: {completed_orgs}/{len(organizations)}")

    # Check for consolidated report
    consolidated_dir = base_dir / "consolidated_reports"
    if consolidated_dir.exists() and list(consolidated_dir.glob("*.md")):
        print(f"└── ✅ Consolidated Report: Generated")
    else:
        print(f"└── ⏳ Consolidated Report: Pending")

    # Show latest activity
    print(f"\n📋 RECENT ACTIVITY")

    # Find most recent files
    recent_files = []
    for org in organizations:
        org_dir = base_dir / org
        if org_dir.exists():
            for file_path in org_dir.rglob("*"):
                if file_path.is_file() and file_path.stat().st_mtime > time.time() - 300:  # Last 5 minutes
                    recent_files.append((file_path, file_path.stat().st_mtime))

    recent_files.sort(key=lambda x: x[1], reverse=True)

    for file_path, mtime in recent_files[:5]:
        rel_path = file_path.relative_to(base_dir)
        time_str = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
        print(f"├── {time_str}: {rel_path}")

    if not recent_files:
        print("└── No recent activity")

    # Sample findings preview
    print(f"\n🚨 SAMPLE SECURITY FINDINGS")
    sample_findings = []

    for org in organizations:
        findings_dir = base_dir / org / "reports"
        if findings_dir.exists():
            for findings_file in findings_dir.glob("*_findings_*.json"):
                try:
                    with open(findings_file, 'r') as f:
                        findings_data = json.load(f)
                        for finding in findings_data[:2]:  # First 2 findings
                            sample_findings.append({
                                "org": org,
                                "repo": findings_file.name.split("_")[0],
                                "finding": finding
                            })
                except:
                    pass

    for i, sample in enumerate(sample_findings[:5], 1):
        finding = sample["finding"]
        print(f"{i}. {sample['org'].upper()}/{sample['repo']}")
        print(f"   ├── Type: {finding.get('title', 'Unknown')}")
        print(f"   ├── Severity: {finding.get('severity', 'Unknown')}")
        print(f"   └── File: {finding.get('file_path', 'Unknown')}")

    if not sample_findings:
        print("└── No findings available yet")

    print(f"\n⏰ Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    monitor_progress()