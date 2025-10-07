#!/usr/bin/env python3
"""
Professional Vulnerability Report Generator
Creates detailed, bug bounty-ready vulnerability reports
"""

import json
from typing import List, Dict, Tuple
from pathlib import Path
from datetime import datetime
import logging

from core.comprehensive_vulnerability_tester import VulnerabilityFinding, Severity
from core.vulnerability_validator import ValidationResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProfessionalReportGenerator:
    """
    Generate professional vulnerability reports suitable for bug bounty submissions
    """

    def __init__(self, project_name: str, project_version: str = "1.0.0"):
        self.project_name = project_name
        self.project_version = project_version
        self.report_date = datetime.now().strftime("%Y-%m-%d")

    def generate_markdown_report(
        self,
        findings: List[VulnerabilityFinding],
        validation_results: List[ValidationResult],
        output_file: str
    ):
        """Generate comprehensive Markdown report"""

        # Filter for valid findings only
        valid_findings = [
            (f, v) for f, v in zip(findings, validation_results)
            if v.is_valid and v.confidence >= 0.7
        ]

        report = self._generate_header()
        report += self._generate_executive_summary(valid_findings)
        report += self._generate_toc(valid_findings)

        for i, (finding, validation) in enumerate(valid_findings, 1):
            report += self._generate_finding_section(finding, validation, i)

        report += self._generate_conclusion(valid_findings)
        report += self._generate_appendix()

        # Write to file
        Path(output_file).write_text(report)
        logger.info(f"Markdown report generated: {output_file}")

    def _generate_header(self) -> str:
        """Generate report header"""
        return f"""# Vulnerability Assessment Report
## {self.project_name}

**Report Date**: {self.report_date}
**Project Version**: {self.project_version}
**Assessment Type**: Comprehensive Security Analysis
**Methodology**: Static Code Analysis + Manual Validation

---

"""

    def _generate_executive_summary(self, valid_findings: List[Tuple]) -> str:
        """Generate executive summary"""
        total = len(valid_findings)

        # Count by severity
        critical = sum(1 for f, v in valid_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f, v in valid_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f, v in valid_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f, v in valid_findings if f.severity == Severity.LOW)

        # Calculate risk score
        risk_score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
        max_risk = total * 10
        risk_percentage = (risk_score / max_risk * 100) if max_risk > 0 else 0

        summary = f"""## Executive Summary

This report presents the findings of a comprehensive security assessment of **{self.project_name}**. The assessment identified **{total} validated vulnerabilities** requiring immediate attention.

### Risk Overview

| Severity | Count | Risk Weight |
|----------|-------|-------------|
| 🔴 Critical | {critical} | {critical * 10} |
| 🟠 High | {high} | {high * 5} |
| 🟡 Medium | {medium} | {medium * 2} |
| 🟢 Low | {low} | {low * 1} |
| **Total** | **{total}** | **{risk_score}/{max_risk}** |

**Overall Risk Score**: {risk_percentage:.1f}/100

"""

        if critical > 0:
            summary += f"""
⚠️ **CRITICAL**: {critical} critical vulnerability(ies) require **immediate** remediation. These vulnerabilities pose severe security risks and should be addressed within 24-48 hours.
"""

        summary += "\n---\n\n"
        return summary

    def _generate_toc(self, valid_findings: List[Tuple]) -> str:
        """Generate table of contents"""
        toc = "## Table of Contents\n\n"
        toc += "1. [Executive Summary](#executive-summary)\n"
        toc += "2. [Vulnerability Findings](#vulnerability-findings)\n"

        for i, (finding, validation) in enumerate(valid_findings, 1):
            anchor = finding.title.lower().replace(' ', '-').replace('(', '').replace(')', '')
            toc += f"   - [{i}. {finding.title}](#finding-{i}-{anchor})\n"

        toc += "3. [Conclusion and Recommendations](#conclusion-and-recommendations)\n"
        toc += "4. [Appendix](#appendix)\n"
        toc += "\n---\n\n"

        return toc

    def _generate_finding_section(
        self,
        finding: VulnerabilityFinding,
        validation: ValidationResult,
        number: int
    ) -> str:
        """Generate detailed finding section"""

        anchor = finding.title.lower().replace(' ', '-').replace('(', '').replace(')', '')

        section = f"""## Vulnerability Findings

### Finding #{number}: {finding.title} {{#finding-{number}-{anchor}}}

**Vulnerability ID**: `{finding.id}`
**Severity**: {self._severity_badge(finding.severity)} **{finding.severity.value}** (CVSS {finding.cvss_score})
**CWE**: [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html)
**Validation Confidence**: {validation.confidence:.0%}
**Status**: ✅ Verified

---

#### 📋 Description

{finding.description}

**Affected Component**: `{finding.affected_component}`
**Location**: Line(s) {', '.join(map(str, finding.evidence.line_numbers))}

---

#### 💥 Impact

{finding.impact}

**Potential Consequences**:
"""

        # Add impact bullets based on vulnerability type
        section += self._get_impact_bullets(finding)

        section += f"""
---

#### 🔍 Technical Details

**Vulnerable Code Snippet**:

```python
{finding.evidence.code_snippet}
```

**Vulnerability Analysis**:
{finding.evidence.description}

---

#### ✅ Verification

**Validation Method**: {validation.validation_method}

**Verification Steps Completed**:
"""

        for step in validation.verification_steps_completed:
            section += f"- {step}\n"

        if validation.proof_of_concept_result:
            section += f"""
---

#### 🎯 Proof of Concept

```
{validation.proof_of_concept_result}
```

**⚠️ Important**: This proof of concept is provided for validation purposes only. Do not use in production environments or against systems you do not have permission to test.
"""

        section += f"""
---

#### 🛠️ Remediation

**Recommended Fix**:

{finding.remediation}

**Implementation Priority**: {self._get_priority_text(finding.severity)}

**Estimated Remediation Time**: {self._get_remediation_time(finding.severity)}

---

#### 📚 References

"""
        for ref in finding.references:
            section += f"- {ref}\n"

        section += "\n---\n\n"

        return section

    def _generate_conclusion(self, valid_findings: List[Tuple]) -> str:
        """Generate conclusion and recommendations"""

        conclusion = """## Conclusion and Recommendations

### Summary

This security assessment has identified several vulnerabilities that require remediation. The findings range from critical security flaws to lower-severity issues that could potentially be exploited.

### Immediate Actions Required

"""

        critical_findings = [(f, v) for f, v in valid_findings if f.severity == Severity.CRITICAL]
        high_findings = [(f, v) for f, v in valid_findings if f.severity == Severity.HIGH]

        if critical_findings:
            conclusion += f"""
#### 🔴 Critical Priority (24-48 hours)

{len(critical_findings)} critical vulnerability(ies) identified:

"""
            for finding, _ in critical_findings:
                conclusion += f"- **{finding.id}**: {finding.title}\n"

        if high_findings:
            conclusion += f"""
#### 🟠 High Priority (1 week)

{len(high_findings)} high-severity vulnerability(ies) identified:

"""
            for finding, _ in high_findings:
                conclusion += f"- **{finding.id}**: {finding.title}\n"

        conclusion += """
### General Recommendations

1. **Implement Secure Coding Practices**
   - Use parameterized queries for all database operations
   - Sanitize all user input before rendering
   - Implement proper input validation and output encoding

2. **Security Testing Integration**
   - Integrate SAST tools into CI/CD pipeline
   - Conduct regular penetration testing
   - Implement automated security scanning

3. **Security Training**
   - Provide secure coding training for development team
   - Stay updated on OWASP Top 10 and common vulnerabilities
   - Implement security code review process

4. **Monitoring and Response**
   - Implement security monitoring and alerting
   - Establish incident response procedures
   - Regular security audits and assessments

### Next Steps

1. **Immediate**: Address all critical and high-severity findings
2. **Short-term (1-2 weeks)**: Remediate medium-severity issues
3. **Long-term**: Implement security best practices and preventive controls
4. **Continuous**: Monitor for new vulnerabilities and maintain security posture

---

"""
        return conclusion

    def _generate_appendix(self) -> str:
        """Generate appendix with additional information"""

        appendix = """## Appendix

### A. Severity Definitions

| Severity | CVSS Score | Description |
|----------|------------|-------------|
| Critical | 9.0-10.0 | Vulnerabilities that can be easily exploited remotely, leading to complete system compromise |
| High | 7.0-8.9 | Vulnerabilities that could lead to significant data breach or system compromise |
| Medium | 4.0-6.9 | Vulnerabilities with moderate impact or requiring specific conditions to exploit |
| Low | 0.1-3.9 | Vulnerabilities with minimal impact or requiring complex exploit chains |

### B. CWE References

**CWE (Common Weakness Enumeration)** is a community-developed list of software and hardware weakness types. Each finding is mapped to a CWE ID for standardized vulnerability classification.

For more information: https://cwe.mitre.org/

### C. Methodology

This assessment was conducted using:

1. **Static Code Analysis**: Automated scanning of source code for known vulnerability patterns
2. **Manual Code Review**: Expert analysis of security-critical code sections
3. **Validation Testing**: Confirmation of findings through proof-of-concept development
4. **False Positive Reduction**: AI-powered filtering using HackerOne disclosure patterns

### D. Tools Used

- Custom vulnerability scanner (Python-based)
- CodeBERT for code analysis
- HackerOne FP reduction engine
- OWASP guidelines and CWE database

### E. Disclaimer

This report is provided for informational and educational purposes. The findings should be verified in a controlled environment before remediation. The authors assume no liability for any actions taken based on this report.

### F. Contact Information

For questions or clarifications regarding this report, please contact the security assessment team.

---

**Report Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Report Version**: 1.0
**Classification**: Confidential

---

*End of Report*
"""
        return appendix

    def _severity_badge(self, severity: Severity) -> str:
        """Get emoji badge for severity"""
        badges = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "ℹ️"
        }
        return badges.get(severity, "")

    def _get_impact_bullets(self, finding: VulnerabilityFinding) -> str:
        """Get impact bullet points based on vulnerability type"""
        from core.comprehensive_vulnerability_tester import VulnerabilityType

        impacts = {
            VulnerabilityType.SQL_INJECTION: [
                "Unauthorized access to sensitive database records",
                "Data exfiltration and privacy breach",
                "Data manipulation or deletion",
                "Potential complete database compromise"
            ],
            VulnerabilityType.XSS: [
                "Session hijacking and cookie theft",
                "Credential theft through phishing",
                "Malware distribution to users",
                "Defacement or unauthorized actions"
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "Arbitrary command execution on server",
                "Complete system compromise",
                "Data exfiltration",
                "Lateral movement in network"
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                "Access to sensitive configuration files",
                "Exposure of credentials and secrets",
                "Source code disclosure",
                "Potential privilege escalation"
            ]
        }

        bullets = ""
        for impact in impacts.get(finding.type, ["Security compromise"]):
            bullets += f"- {impact}\n"

        return bullets

    def _get_priority_text(self, severity: Severity) -> str:
        """Get priority text for remediation"""
        priorities = {
            Severity.CRITICAL: "🔴 **IMMEDIATE** - Must be fixed within 24-48 hours",
            Severity.HIGH: "🟠 **HIGH** - Should be fixed within 1 week",
            Severity.MEDIUM: "🟡 **MEDIUM** - Should be fixed within 2-4 weeks",
            Severity.LOW: "🟢 **LOW** - Can be scheduled in regular maintenance"
        }
        return priorities.get(severity, "MEDIUM")

    def _get_remediation_time(self, severity: Severity) -> str:
        """Estimate remediation time"""
        times = {
            Severity.CRITICAL: "2-4 hours",
            Severity.HIGH: "4-8 hours",
            Severity.MEDIUM: "2-4 hours",
            Severity.LOW: "1-2 hours"
        }
        return times.get(severity, "2-4 hours")

    def generate_json_report(
        self,
        findings: List[VulnerabilityFinding],
        validation_results: List[ValidationResult],
        output_file: str
    ):
        """Generate JSON report for automated processing"""

        valid_findings = [
            {
                'finding': {
                    'id': f.id,
                    'title': f.title,
                    'type': f.type.value,
                    'severity': f.severity.value,
                    'cvss_score': f.cvss_score,
                    'cwe_id': f.cwe_id,
                    'description': f.description,
                    'impact': f.impact,
                    'affected_component': f.affected_component,
                    'remediation': f.remediation,
                    'references': f.references,
                    'evidence': {
                        'code_snippet': f.evidence.code_snippet,
                        'line_numbers': f.evidence.line_numbers,
                        'file_path': f.evidence.file_path
                    }
                },
                'validation': {
                    'is_valid': v.is_valid,
                    'confidence': v.confidence,
                    'validation_method': v.validation_method,
                    'steps_completed': v.verification_steps_completed
                }
            }
            for f, v in zip(findings, validation_results)
            if v.is_valid and v.confidence >= 0.7
        ]

        report = {
            'metadata': {
                'project_name': self.project_name,
                'project_version': self.project_version,
                'report_date': self.report_date,
                'total_findings': len(valid_findings)
            },
            'findings': valid_findings
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON report generated: {output_file}")


if __name__ == "__main__":
    from core.comprehensive_vulnerability_tester import ComprehensiveVulnerabilityTester
    from core.vulnerability_validator import VulnerabilityValidator

    logger.info("Professional Vulnerability Report Generator\n")

    # Scan and validate
    tester = ComprehensiveVulnerabilityTester(".")
    findings = tester.comprehensive_scan(file_extensions=['.py'])

    if findings:
        validator = VulnerabilityValidator()
        validation_results = validator.validate_all(findings)

        # Generate reports
        generator = ProfessionalReportGenerator(
            project_name="Vulnerability Research Framework",
            project_version="1.0.0"
        )

        generator.generate_markdown_report(
            findings, validation_results,
            "VULNERABILITY_ASSESSMENT_REPORT.md"
        )

        generator.generate_json_report(
            findings, validation_results,
            "vulnerability_report.json"
        )

        logger.info("\n✅ Reports generated successfully!")
    else:
        logger.info("No vulnerabilities found to report")
