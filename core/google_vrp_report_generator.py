#!/usr/bin/env python3
"""
Google VRP Report Generator
Generates professional vulnerability reports formatted for Google Bug Hunters platform
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging

from core.google_oss_vrp_scanner import GoogleOSSVRPResults

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleVRPReportGenerator:
    """
    Generate reports formatted for Google VRP submission
    """

    def __init__(self, results: GoogleOSSVRPResults):
        """
        Initialize report generator

        Args:
            results: GoogleOSSVRPResults from scan
        """
        self.results = results
        self.project_name = results.project_info.project_name

    def generate_markdown_report(self, output_file: str):
        """
        Generate comprehensive Markdown report

        Args:
            output_file: Path to output Markdown file
        """
        logger.info(f"Generating Google VRP report: {output_file}")

        report = []

        # Header
        report.append(self._generate_header())

        # Executive Summary
        report.append(self._generate_executive_summary())

        # Project Information
        report.append(self._generate_project_info())

        # Findings Summary
        report.append(self._generate_findings_summary())

        # Critical Findings (Priority)
        report.append(self._generate_critical_findings())

        # High Findings
        report.append(self._generate_high_findings())

        # Medium/Low Findings
        report.append(self._generate_other_findings())

        # Submission Guidance
        if self.results.project_info.eligible_for_vrp:
            report.append(self._generate_submission_guidance())

        # Methodology
        report.append(self._generate_methodology())

        # Write report
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write('\n\n'.join(report))

        logger.info(f"✓ Report generated: {output_file}")

    def generate_json_report(self, output_file: str):
        """
        Generate JSON report for automation

        Args:
            output_file: Path to output JSON file
        """
        logger.info(f"Generating JSON report: {output_file}")

        report = {
            'scan_metadata': {
                'project_name': self.results.project_info.project_name,
                'scan_timestamp': self.results.scan_timestamp,
                'scan_duration_seconds': self.results.scan_duration_seconds,
                'google_oss_vrp_eligible': self.results.project_info.eligible_for_vrp,
                'vrp_tier': self.results.project_info.vrp_tier if self.results.project_info.eligible_for_vrp else None,
            },
            'summary': {
                'total_findings': self.results.total_findings,
                'critical': self.results.critical_count,
                'high': self.results.high_count,
                'medium': self.results.medium_count,
                'low': self.results.low_count,
                'estimated_value_usd': {
                    'min': self.results.estimated_min_value,
                    'max': self.results.estimated_max_value
                }
            },
            'findings': {
                'code_vulnerabilities': [self._serialize_code_vuln(v) for v in self.results.code_vulnerabilities],
                'supply_chain': [self._serialize_supply_chain(f) for f in self.results.supply_chain_findings],
                'secrets': [self._serialize_secret(s) for s in self.results.secret_findings]
            }
        }

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"✓ JSON report generated: {output_file}")

    def _generate_header(self) -> str:
        """Generate report header"""
        eligible = "✅ ELIGIBLE" if self.results.project_info.eligible_for_vrp else "ℹ️  NOT ELIGIBLE"

        return f"""# Google OSS VRP Security Assessment Report

## {self.results.project_info.project_name}

**Status**: {eligible} for Google Open Source VRP
**Scan Date**: {datetime.fromisoformat(self.results.scan_timestamp).strftime('%B %d, %Y')}
**Report Generated**: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}

---"""

    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        if self.results.total_findings == 0:
            return """## 🎉 Executive Summary

**No security vulnerabilities were detected** in this project. The codebase appears secure based on static analysis."""

        summary = [
            "## 📊 Executive Summary",
            "",
            f"This security assessment identified **{self.results.total_findings} security findings** in the {self.project_name} project:",
            ""
        ]

        # Severity breakdown
        if self.results.critical_count > 0:
            summary.append(f"- 🔴 **{self.results.critical_count} Critical** vulnerabilities requiring immediate attention")
        if self.results.high_count > 0:
            summary.append(f"- 🟠 **{self.results.high_count} High** severity issues")
        if self.results.medium_count > 0:
            summary.append(f"- 🟡 **{self.results.medium_count} Medium** severity issues")
        if self.results.low_count > 0:
            summary.append(f"- 🟢 **{self.results.low_count} Low** severity issues")

        summary.append("")
        summary.append("### Finding Categories")
        summary.append("")
        summary.append(f"- **Code Vulnerabilities**: {len(self.results.code_vulnerabilities)} (SQL injection, XSS, command injection, etc.)")
        summary.append(f"- **Supply Chain Issues**: {len(self.results.supply_chain_findings)} (dependency security, build process)")
        summary.append(f"- **Secret Exposures**: {len(self.results.secret_findings)} (hardcoded credentials, API keys)")

        if self.results.project_info.eligible_for_vrp:
            summary.append("")
            summary.append("### 💰 Estimated VRP Value")
            summary.append("")
            summary.append(f"**${self.results.estimated_min_value:,} - ${self.results.estimated_max_value:,}** USD")
            summary.append("")
            summary.append(f"*Based on {self.results.project_info.vrp_tier.upper()} project classification and severity distribution*")

        return '\n'.join(summary)

    def _generate_project_info(self) -> str:
        """Generate project information section"""
        info = [
            "## 🎯 Project Information",
            "",
            f"**Project Name**: {self.results.project_info.project_name}",
            f"**Google OSS Project**: {'Yes' if self.results.project_info.is_google_oss else 'No'}",
            f"**VRP Eligible**: {'Yes' if self.results.project_info.eligible_for_vrp else 'No'}",
            f"**Priority Level**: {self.results.project_info.priority_level.upper()}",
        ]

        if self.results.project_info.github_org:
            info.append(f"**GitHub**: {self.results.project_info.github_org}/{self.results.project_info.github_repo}")

        if self.results.project_info.eligible_for_vrp:
            info.append(f"**VRP Tier**: {self.results.project_info.vrp_tier.upper()}")

        if self.results.project_info.notes:
            info.append("")
            info.append("**Notes**:")
            for note in self.results.project_info.notes:
                info.append(f"- {note}")

        return '\n'.join(info)

    def _generate_findings_summary(self) -> str:
        """Generate findings summary table"""
        return f"""## 📋 Findings Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Code Vulnerabilities | {self._count_by_severity(self.results.code_vulnerabilities, 'critical')} | {self._count_by_severity(self.results.code_vulnerabilities, 'high')} | {self._count_by_severity(self.results.code_vulnerabilities, 'medium')} | {self._count_by_severity(self.results.code_vulnerabilities, 'low')} | {len(self.results.code_vulnerabilities)} |
| Supply Chain | {self._count_by_severity(self.results.supply_chain_findings, 'critical')} | {self._count_by_severity(self.results.supply_chain_findings, 'high')} | {self._count_by_severity(self.results.supply_chain_findings, 'medium')} | {self._count_by_severity(self.results.supply_chain_findings, 'low')} | {len(self.results.supply_chain_findings)} |
| Secrets & Credentials | {self._count_by_severity(self.results.secret_findings, 'critical')} | {self._count_by_severity(self.results.secret_findings, 'high')} | {self._count_by_severity(self.results.secret_findings, 'medium')} | {self._count_by_severity(self.results.secret_findings, 'low')} | {len(self.results.secret_findings)} |
| **TOTAL** | **{self.results.critical_count}** | **{self.results.high_count}** | **{self.results.medium_count}** | **{self.results.low_count}** | **{self.results.total_findings}** |"""

    def _generate_critical_findings(self) -> str:
        """Generate detailed critical findings section"""
        critical_code = [v for v in self.results.code_vulnerabilities if v.severity.value.lower() == 'critical']
        critical_sc = [f for f in self.results.supply_chain_findings if f.severity.value.lower() == 'critical']
        critical_secrets = [s for s in self.results.secret_findings if s.severity.value.lower() == 'critical']

        if not (critical_code or critical_sc or critical_secrets):
            return "## 🔴 Critical Findings\n\nNo critical vulnerabilities detected."

        sections = ["## 🔴 Critical Findings\n"]

        # Code vulnerabilities
        if critical_code:
            sections.append(f"### Code Vulnerabilities ({len(critical_code)})\n")
            for i, vuln in enumerate(critical_code[:10], 1):  # Limit to top 10
                sections.append(self._format_code_vulnerability(vuln, i))

        # Supply chain
        if critical_sc:
            sections.append(f"### Supply Chain Issues ({len(critical_sc)})\n")
            for i, finding in enumerate(critical_sc[:10], 1):
                sections.append(self._format_supply_chain_finding(finding, i))

        # Secrets
        if critical_secrets:
            sections.append(f"### Secret Exposures ({len(critical_secrets)})\n")
            for i, secret in enumerate(critical_secrets[:10], 1):
                sections.append(self._format_secret_finding(secret, i))

        return '\n\n'.join(sections)

    def _generate_high_findings(self) -> str:
        """Generate high severity findings"""
        high_code = [v for v in self.results.code_vulnerabilities if v.severity.value.lower() == 'high']
        high_sc = [f for f in self.results.supply_chain_findings if f.severity.value.lower() == 'high']
        high_secrets = [s for s in self.results.secret_findings if s.severity.value.lower() == 'high']

        if not (high_code or high_sc or high_secrets):
            return ""

        sections = ["## 🟠 High Severity Findings\n"]

        if high_code:
            sections.append(f"### Code Vulnerabilities ({len(high_code)})\n")
            for i, vuln in enumerate(high_code[:5], 1):  # Top 5
                sections.append(self._format_code_vulnerability(vuln, i))

        if high_sc:
            sections.append(f"### Supply Chain Issues ({len(high_sc)})\n")
            for i, finding in enumerate(high_sc[:5], 1):
                sections.append(self._format_supply_chain_finding(finding, i))

        if high_secrets:
            sections.append(f"### Secret Exposures ({len(high_secrets)})\n")
            for i, secret in enumerate(high_secrets[:5], 1):
                sections.append(self._format_secret_finding(secret, i))

        return '\n\n'.join(sections)

    def _generate_other_findings(self) -> str:
        """Generate medium/low findings summary"""
        medium_total = self.results.medium_count
        low_total = self.results.low_count

        if medium_total == 0 and low_total == 0:
            return ""

        summary = ["## 🟡 Medium & Low Severity Findings\n"]

        if medium_total > 0:
            summary.append(f"**Medium Severity**: {medium_total} findings")
            summary.append("- Review these issues as part of regular security maintenance")
            summary.append("- Address before next major release")

        if low_total > 0:
            summary.append("")
            summary.append(f"**Low Severity**: {low_total} findings")
            summary.append("- Address as part of ongoing security improvements")
            summary.append("- Lower priority but should not be ignored")

        summary.append("")
        summary.append("*Detailed findings available in JSON report*")

        return '\n'.join(summary)

    def _generate_submission_guidance(self) -> str:
        """Generate Google VRP submission guidance"""
        return f"""## 📝 Google VRP Submission Guidance

### Submission Process

1. **Review Findings**: Carefully review all critical and high severity findings
2. **Test Reproduction**: Verify that each vulnerability can be reproduced
3. **Prepare PoC**: Ensure proof-of-concept code is working and safe
4. **Submit Report**: Go to https://bughunters.google.com/report

### Report Template

For each finding, use this structure:

```
Title: [Vulnerability Type] in [Component]

Severity: Critical/High (CVSS X.X)

Summary:
[Brief description of the vulnerability]

Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Proof of Concept:
[Working PoC code]

Impact:
[Description of potential impact]

Remediation:
[Suggested fix]

References:
- CWE-XXX
- OWASP reference
```

### Best Practices

✅ **DO:**
- Submit one finding per report
- Provide clear reproduction steps
- Include working proof of concept
- Be professional and courteous
- Follow responsible disclosure

❌ **DON'T:**
- Test in production without permission
- Access real user data
- Submit duplicates
- Rush submissions without verification

### Expected Timeline

- **Initial Response**: 1-3 business days
- **Triage**: 5-10 business days
- **Resolution**: Varies by severity
- **Reward**: After fix is deployed

### Reward Estimates

Based on {self.results.project_info.vrp_tier.upper()} classification:

- **Critical (CVSS 9-10)**: ${self.results.estimated_max_value//self.results.critical_count if self.results.critical_count > 0 else 5000:,} per finding
- **High (CVSS 7-8.9)**: $1,000 - $5,000 per finding
- **Medium (CVSS 4-6.9)**: $500 - $2,000 per finding

**Total Estimated Value**: ${self.results.estimated_min_value:,} - ${self.results.estimated_max_value:,} USD"""

    def _generate_methodology(self) -> str:
        """Generate methodology section"""
        return f"""## 🔬 Assessment Methodology

### Scanning Approach

This assessment used automated security scanning with multiple techniques:

1. **Static Code Analysis**
   - Pattern-based vulnerability detection
   - AST (Abstract Syntax Tree) analysis
   - Data flow analysis
   - Control flow analysis

2. **Supply Chain Security**
   - Dependency vulnerability scanning
   - Build script security review
   - Installation script analysis
   - Network security assessment

3. **Secrets Detection**
   - Pattern matching for credentials
   - API key detection
   - Private key scanning
   - Database connection string analysis

### Tools & Techniques

- Custom vulnerability scanner
- Google OSS VRP-specific detection rules
- False positive reduction engine
- Automated proof-of-concept generation

### Limitations

- Static analysis only (no dynamic testing)
- May have false positives (manual review recommended)
- Context-specific vulnerabilities may be missed
- Business logic flaws not detected

### Scan Statistics

- **Files Scanned**: {len(list(Path(self.results.project_info.project_name).rglob('*')))} (estimated)
- **Scan Duration**: {self.results.scan_duration_seconds:.2f} seconds
- **Findings**: {self.results.total_findings}
- **Scan Date**: {datetime.fromisoformat(self.results.scan_timestamp).strftime('%Y-%m-%d %H:%M:%S')}

---

**Report Generated By**: Google OSS VRP Security Scanner
**For Questions**: Review documentation or contact security team"""

    def _format_code_vulnerability(self, vuln, index: int) -> str:
        """Format a code vulnerability finding"""
        lines = vuln.evidence.line_numbers if vuln.evidence.line_numbers else ['N/A']
        line_str = f"{lines[0]}-{lines[-1]}" if len(lines) > 1 else str(lines[0])

        return f"""#### Finding #{index}: {vuln.title}

**ID**: `{vuln.id}`
**Type**: {vuln.type.value}
**Severity**: {vuln.severity.value} (CVSS {vuln.cvss_score})
**CWE**: [{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id.split('-')[1]}.html)

**Location**: `{vuln.evidence.file_path}:{line_str}`

**Description**:
{vuln.description}

**Impact**:
{vuln.impact}

**Vulnerable Code**:
```
{vuln.evidence.code_snippet[:500]}
```

**Remediation**:
{vuln.remediation}

**References**:
{chr(10).join('- ' + ref for ref in vuln.references)}

---"""

    def _format_supply_chain_finding(self, finding, index: int) -> str:
        """Format a supply chain finding"""
        return f"""#### Finding #{index}: {finding.title}

**ID**: `{finding.id}`
**Category**: {finding.category.title()}
**Severity**: {finding.severity.value} (CVSS {finding.cvss_score})
**CWE**: [{finding.cwe}](https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[1]}.html)

**Location**: `{finding.affected_file}:{finding.affected_line or 'N/A'}`

**Description**:
{finding.description}

**Evidence**:
```
{finding.evidence[:300]}
```

**Impact**:
{finding.impact}

**Remediation**:
{finding.remediation}

---"""

    def _format_secret_finding(self, secret, index: int) -> str:
        """Format a secret finding"""
        return f"""#### Finding #{index}: {secret.description}

**ID**: `{secret.id}`
**Type**: {secret.secret_type}
**Severity**: {secret.severity.value} (CVSS {secret.cvss_score})
**Confidence**: {secret.confidence:.0%}

**Location**: `{secret.affected_file}:{secret.affected_line}`

**Evidence** (redacted):
```
{secret.evidence}
```

**Impact**:
{secret.impact}

**Remediation**:
{secret.remediation}

⚠️ **IMPORTANT**: This credential should be rotated immediately and removed from version control history.

---"""

    def _count_by_severity(self, findings, severity: str) -> int:
        """Count findings by severity"""
        return sum(1 for f in findings if f.severity.value.lower() == severity.lower())

    def _serialize_code_vuln(self, vuln) -> dict:
        """Serialize code vulnerability to dict"""
        return {
            'id': vuln.id,
            'title': vuln.title,
            'type': vuln.type.value,
            'severity': vuln.severity.value,
            'cvss_score': vuln.cvss_score,
            'cwe': vuln.cwe_id,
            'file': vuln.evidence.file_path,
            'lines': vuln.evidence.line_numbers,
            'description': vuln.description,
            'impact': vuln.impact,
            'remediation': vuln.remediation
        }

    def _serialize_supply_chain(self, finding) -> dict:
        """Serialize supply chain finding to dict"""
        return {
            'id': finding.id,
            'title': finding.title,
            'category': finding.category,
            'severity': finding.severity.value,
            'cvss_score': finding.cvss_score,
            'file': finding.affected_file,
            'line': finding.affected_line,
            'description': finding.description,
            'impact': finding.impact,
            'remediation': finding.remediation
        }

    def _serialize_secret(self, secret) -> dict:
        """Serialize secret finding to dict"""
        return {
            'id': secret.id,
            'type': secret.secret_type,
            'severity': secret.severity.value,
            'cvss_score': secret.cvss_score,
            'confidence': secret.confidence,
            'file': secret.affected_file,
            'line': secret.affected_line,
            'description': secret.description,
            'impact': secret.impact
        }


def main():
    """Test report generator"""
    import sys
    from core.google_oss_vrp_scanner import GoogleOSSVRPScanner

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = '.'

    # Run scan
    scanner = GoogleOSSVRPScanner(project_path)
    results = scanner.scan()

    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_file = f"./reports/google_vrp/GOOGLE_VRP_REPORT_{timestamp}.md"
    json_file = f"./reports/google_vrp/google_vrp_report_{timestamp}.json"

    generator = GoogleVRPReportGenerator(results)
    generator.generate_markdown_report(md_file)
    generator.generate_json_report(json_file)

    print(f"\n✅ Reports generated:")
    print(f"   Markdown: {md_file}")
    print(f"   JSON: {json_file}")


if __name__ == '__main__':
    main()
