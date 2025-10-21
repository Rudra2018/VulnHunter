#!/usr/bin/env python3
"""
Java Framework Vulnerability Hunter
Specialized scanner for Hibernate ORM, Apache Struts, and Spring Framework
"""

import os
import sys
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
import hashlib
import time

class JavaFrameworkVulnHunter:
    def __init__(self):
        # Critical Java vulnerability patterns with CVE references
        self.java_vulnerability_patterns = {
            "hibernate_hql_injection": {
                "patterns": [
                    r"Query\s+.*createQuery\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                    r"createQuery\s*\(\s*.*\+.*[^)]*\)",
                    r"createNativeQuery\s*\(\s*.*\+.*[^)]*\)",
                    r"session\.createQuery\s*\([^)]*\+[^)]*\)",
                    r"entityManager\.createQuery\s*\([^)]*\+[^)]*\)",
                ],
                "severity": 9.5,
                "cwe": "CWE-89",
                "description": "Hibernate HQL/SQL Injection vulnerability",
                "cve_ref": "CVE-2019-14900, CVE-2020-25638"
            },
            "struts_ognl_injection": {
                "patterns": [
                    r"%\{.*\}",
                    r"#.*=.*#.*",
                    r"getText\s*\(\s*[^)]*\+[^)]*\)",
                    r"ActionSupport.*getText.*\+",
                    r"@.*@.*=",
                    r"#application\[.*\]",
                    r"#session\[.*\]",
                    r"#request\[.*\]",
                ],
                "severity": 9.8,
                "cwe": "CWE-94",
                "description": "Struts OGNL Code Injection vulnerability",
                "cve_ref": "CVE-2017-5638, CVE-2018-11776, CVE-2019-0230"
            },
            "spring_spel_injection": {
                "patterns": [
                    r"SpelExpressionParser\(\)\.parseExpression\s*\([^)]*\+[^)]*\)",
                    r"StandardEvaluationContext.*getValue\s*\([^)]*\+[^)]*\)",
                    r"@Value\s*\(\s*[\"'].*#\{.*\}.*[\"']\s*\)",
                    r"parser\.parseExpression\s*\([^)]*user[^)]*\)",
                    r"expressionParser\.parseExpression\s*\([^)]*request[^)]*\)",
                ],
                "severity": 9.0,
                "cwe": "CWE-94",
                "description": "Spring SpEL Code Injection vulnerability",
                "cve_ref": "CVE-2018-1273, CVE-2022-22965"
            },
            "deserialization_vulnerabilities": {
                "patterns": [
                    r"ObjectInputStream.*readObject\s*\(\s*\)",
                    r"XMLDecoder.*readObject\s*\(\s*\)",
                    r"ObjectInput.*readObject\s*\(\s*\)",
                    r"Serializable.*implements.*readObject",
                    r"readUnshared\s*\(\s*\)",
                    r"SerializationUtils\.deserialize",
                    r"XStream.*fromXML",
                    r"ObjectMapper.*readValue.*Object\.class",
                ],
                "severity": 9.2,
                "cwe": "CWE-502",
                "description": "Unsafe Deserialization vulnerability",
                "cve_ref": "CVE-2015-7501, CVE-2016-1000027"
            },
            "xml_external_entity": {
                "patterns": [
                    r"DocumentBuilderFactory\.newInstance\(\).*setFeature.*false",
                    r"SAXParserFactory\.newInstance\(\).*setFeature.*false",
                    r"XMLReaderFactory\.createXMLReader\(\).*setFeature.*false",
                    r"TransformerFactory\.newInstance\(\).*setAttribute.*false",
                    r"DocumentBuilder.*parse\s*\([^)]*user[^)]*\)",
                    r"XMLReader.*parse\s*\([^)]*input[^)]*\)",
                ],
                "severity": 8.5,
                "cwe": "CWE-611",
                "description": "XML External Entity (XXE) vulnerability",
                "cve_ref": "CVE-2018-1000632, CVE-2019-12086"
            },
            "path_traversal": {
                "patterns": [
                    r"new\s+File\s*\([^)]*\+[^)]*\)",
                    r"Paths\.get\s*\([^)]*\+[^)]*\)",
                    r"FileInputStream\s*\([^)]*\+[^)]*\)",
                    r"FileOutputStream\s*\([^)]*\+[^)]*\)",
                    r"Files\.copy\s*\([^)]*\+[^)]*\)",
                    r"\.\.\/",
                    r"\.\.\\\\",
                ],
                "severity": 7.5,
                "cwe": "CWE-22",
                "description": "Path Traversal vulnerability",
                "cve_ref": "CVE-2018-1271, CVE-2019-3799"
            },
            "authentication_bypass": {
                "patterns": [
                    r"return\s+true\s*;.*authenticate",
                    r"isAuthenticated\s*\(\s*\)\s*{\s*return\s+true",
                    r"hasRole\s*\([^)]*\)\s*{\s*return\s+true",
                    r"authorize.*return\s+true",
                    r"checkPermission.*return\s+true",
                    r"SecurityContextHolder\.getContext\(\)\.setAuthentication\(null\)",
                ],
                "severity": 9.0,
                "cwe": "CWE-287",
                "description": "Authentication bypass vulnerability",
                "cve_ref": "CVE-2018-1258, CVE-2020-5398"
            },
            "csrf_vulnerabilities": {
                "patterns": [
                    r"@RequestMapping.*method.*POST.*csrf.*false",
                    r"@PostMapping.*csrf.*disabled",
                    r"csrf\(\)\.disable\(\)",
                    r"CsrfToken.*null",
                    r"requireCsrfProtectionMatcher.*return\s+false",
                ],
                "severity": 6.5,
                "cwe": "CWE-352",
                "description": "Cross-Site Request Forgery vulnerability",
                "cve_ref": "CVE-2020-5421, CVE-2021-22112"
            },
            "reflected_xss": {
                "patterns": [
                    r"response\.getWriter\(\)\.print\s*\([^)]*request\.[^)]*\)",
                    r"out\.print\s*\([^)]*request\.[^)]*\)",
                    r"response\.getWriter\(\)\.println\s*\([^)]*request\.[^)]*\)",
                    r"PrintWriter.*print\s*\([^)]*request\.[^)]*\)",
                    r"ModelAndView.*addObject\s*\([^)]*request\.[^)]*\)",
                ],
                "severity": 7.0,
                "cwe": "CWE-79",
                "description": "Reflected Cross-Site Scripting vulnerability",
                "cve_ref": "CVE-2019-17495, CVE-2020-13935"
            },
            "weak_crypto": {
                "patterns": [
                    r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
                    r"MessageDigest\.getInstance\s*\(\s*[\"']SHA1[\"']\s*\)",
                    r"Cipher\.getInstance\s*\(\s*[\"']DES[\"']\s*\)",
                    r"KeyGenerator\.getInstance\s*\(\s*[\"']DES[\"']\s*\)",
                    r"SecretKeySpec\s*\([^)]*[\"']DES[\"'][^)]*\)",
                    r"new\s+Random\s*\(\s*\)",
                    r"Math\.random\s*\(\s*\)",
                ],
                "severity": 6.0,
                "cwe": "CWE-327",
                "description": "Weak cryptographic implementation",
                "cve_ref": "CVE-2018-1258, CVE-2019-11272"
            }
        }

        # Framework-specific critical files to analyze
        self.critical_java_files = {
            "hibernate": [
                "**/hibernate/**/*.java",
                "**/org/hibernate/**/*.java",
                "**/*Hibernate*.java",
                "**/*Entity*.java",
                "**/*Repository*.java",
                "**/dao/**/*.java",
                "**/model/**/*.java"
            ],
            "struts": [
                "**/struts/**/*.java",
                "**/org/apache/struts/**/*.java",
                "**/*Action*.java",
                "**/*Interceptor*.java",
                "**/struts*.xml",
                "**/*struts*.xml"
            ],
            "spring": [
                "**/spring/**/*.java",
                "**/org/springframework/**/*.java",
                "**/*Controller*.java",
                "**/*Service*.java",
                "**/*Component*.java",
                "**/*Configuration*.java",
                "**/application*.properties",
                "**/application*.yml"
            ]
        }

        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('java_framework_vulnhunter.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def identify_framework(self, repo_path: str) -> List[str]:
        """Identify which Java frameworks are present in the repository"""
        frameworks = []

        # Check for framework indicators
        indicators = {
            "hibernate": ["hibernate", "org.hibernate", "@Entity", "@Table", "SessionFactory"],
            "struts": ["struts", "org.apache.struts", "ActionSupport", "ActionForm", "struts.xml"],
            "spring": ["springframework", "org.springframework", "@Controller", "@Service", "@Component", "@Autowired"]
        }

        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith(('.java', '.xml', '.properties', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()

                        for framework, keywords in indicators.items():
                            if any(keyword.lower() in content for keyword in keywords):
                                if framework not in frameworks:
                                    frameworks.append(framework)
                                    self.logger.info(f"Detected {framework} framework in {file}")
                    except Exception as e:
                        continue

        return frameworks

    def advanced_pattern_analysis(self, file_path: str, frameworks: List[str]) -> List[Dict]:
        """Run advanced pattern analysis on Java framework code"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for vuln_type, vuln_data in self.java_vulnerability_patterns.items():
                # Skip framework-specific patterns if framework not detected
                if vuln_type.startswith('hibernate') and 'hibernate' not in frameworks:
                    continue
                if vuln_type.startswith('struts') and 'struts' not in frameworks:
                    continue
                if vuln_type.startswith('spring') and 'spring' not in frameworks:
                    continue

                for pattern in vuln_data['patterns']:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL | re.IGNORECASE)

                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        context_lines = self.get_context_lines(lines, line_num, 5)

                        # Enhanced analysis for this specific match
                        enhanced_analysis = self.enhance_java_pattern_match(
                            match, content, vuln_type, vuln_data, context_lines, frameworks
                        )

                        if enhanced_analysis['confidence'] > 0.6:  # Medium confidence threshold for Java
                            findings.append({
                                'file': file_path,
                                'line': line_num,
                                'type': vuln_type,
                                'pattern': pattern,
                                'match': match.group()[:200],
                                'context': '\n'.join(context_lines),
                                'severity_score': vuln_data['severity'],
                                'confidence': enhanced_analysis['confidence'],
                                'cwe': vuln_data['cwe'],
                                'description': vuln_data['description'],
                                'cve_references': vuln_data['cve_ref'],
                                'detailed_analysis': enhanced_analysis['analysis'],
                                'exploitation_notes': enhanced_analysis['exploitation'],
                                'framework_detected': frameworks,
                                'bounty_estimate': self.calculate_bounty(vuln_data['severity'], enhanced_analysis['confidence'])
                            })

        except Exception as e:
            self.logger.error(f"Pattern analysis error for {file_path}: {e}")

        return findings

    def enhance_java_pattern_match(self, match, content, vuln_type, vuln_data, context_lines, frameworks) -> Dict:
        """Enhance pattern match with Java-specific analysis"""
        analysis = {
            'confidence': 0.4,
            'analysis': '',
            'exploitation': ''
        }

        context = '\n'.join(context_lines).lower()

        # Framework-specific enhancement
        if vuln_type == "hibernate_hql_injection":
            if any(keyword in context for keyword in ['query', 'hql', 'createquery', 'parameter']):
                analysis['confidence'] += 0.4
                analysis['analysis'] = "HQL query construction with user input concatenation"
                analysis['exploitation'] = "Inject malicious HQL to access unauthorized data or bypass authentication"

        elif vuln_type == "struts_ognl_injection":
            if any(keyword in context for keyword in ['%{', 'ognl', 'textfield', 'action']):
                analysis['confidence'] += 0.5
                analysis['analysis'] = "OGNL expression with potential user-controlled input"
                analysis['exploitation'] = "Execute arbitrary code via OGNL expression injection"

        elif vuln_type == "spring_spel_injection":
            if any(keyword in context for keyword in ['spel', 'expression', 'parseexpression', '@value']):
                analysis['confidence'] += 0.4
                analysis['analysis'] = "Spring SpEL expression with user input"
                analysis['exploitation'] = "Execute arbitrary code via SpEL expression injection"

        elif vuln_type == "deserialization_vulnerabilities":
            if any(keyword in context for keyword in ['readobject', 'deserialize', 'inputstream']):
                analysis['confidence'] += 0.4
                analysis['analysis'] = "Unsafe deserialization of untrusted data"
                analysis['exploitation'] = "Execute arbitrary code via crafted serialized objects"

        elif vuln_type == "xml_external_entity":
            if any(keyword in context for keyword in ['documentbuilder', 'xmlreader', 'parse']):
                analysis['confidence'] += 0.3
                analysis['analysis'] = "XML parsing without XXE protection"
                analysis['exploitation'] = "Read local files or perform SSRF via XXE injection"

        # Check for security annotations (lower confidence if present)
        security_annotations = ['@preauthorize', '@secured', '@rolesallowed', '@validated']
        if any(annotation in context for annotation in security_annotations):
            analysis['confidence'] -= 0.1

        # Check for input validation (lower confidence if present)
        validation_patterns = ['validate', 'sanitize', 'escape', 'whitelist', 'pattern']
        if any(pattern in context for pattern in validation_patterns):
            analysis['confidence'] -= 0.1

        # Check for test files (lower confidence)
        if any(test_indicator in match.string.lower() for test_indicator in ['test', 'mock', 'stub']):
            analysis['confidence'] *= 0.6

        return analysis

    def get_context_lines(self, lines: List[str], line_num: int, context_size: int) -> List[str]:
        """Get context lines around a specific line number"""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        return lines[start:end]

    def calculate_bounty(self, severity_score: float, confidence: float) -> int:
        """Calculate potential bounty based on severity and confidence"""
        base_bounty = int(severity_score * 15000)  # Higher base for Java frameworks
        confidence_multiplier = min(confidence * 1.3, 1.0)
        return int(base_bounty * confidence_multiplier)

    def analyze_framework_specific_files(self, repo_path: str, frameworks: List[str]) -> List[Dict]:
        """Analyze framework-specific critical files"""
        findings = []

        for framework in frameworks:
            if framework in self.critical_java_files:
                self.logger.info(f"Analyzing {framework}-specific files...")

                patterns = self.critical_java_files[framework]
                for pattern in patterns:
                    import glob
                    matching_files = glob.glob(os.path.join(repo_path, pattern), recursive=True)

                    for file_path in matching_files[:50]:  # Limit to prevent overload
                        if os.path.isfile(file_path):
                            file_findings = self.advanced_pattern_analysis(file_path, frameworks)

                            # Add framework-specific metadata
                            for finding in file_findings:
                                finding['framework_specific'] = framework
                                finding['critical_file'] = True

                            findings.extend(file_findings)

        return findings

    def scan_repository(self, repo_path: str) -> Dict:
        """Scan a specific repository for Java framework vulnerabilities"""
        self.logger.info(f"Starting Java framework vulnerability scan on {repo_path}")

        # Identify frameworks present
        frameworks = self.identify_framework(repo_path)
        self.logger.info(f"Detected frameworks: {frameworks}")

        if not frameworks:
            self.logger.warning("No recognized Java frameworks detected")
            return {"error": "No Java frameworks detected"}

        all_findings = []

        try:
            # Phase 1: Framework-specific file analysis
            self.logger.info("Phase 1: Framework-specific file analysis...")
            framework_findings = self.analyze_framework_specific_files(repo_path, frameworks)
            all_findings.extend(framework_findings)

            # Phase 2: General Java vulnerability patterns
            self.logger.info("Phase 2: General vulnerability pattern analysis...")
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)

                        # Skip already analyzed files
                        if not any(f['file'] == file_path for f in framework_findings):
                            pattern_findings = self.advanced_pattern_analysis(file_path, frameworks)
                            all_findings.extend(pattern_findings)

            # Filter and prioritize findings
            critical_findings = [
                f for f in all_findings
                if f.get('confidence', 0) > 0.7 and f.get('severity_score', 0) > 7.0
            ]

            # Generate report
            report = self.generate_java_framework_report(all_findings, critical_findings, frameworks, repo_path)

            return report

        except Exception as e:
            self.logger.error(f"Error during repository scan: {e}")
            return {"error": str(e)}

    def generate_java_framework_report(self, all_findings: List[Dict], critical_findings: List[Dict],
                                     frameworks: List[str], repo_path: str) -> Dict:
        """Generate comprehensive Java framework vulnerability report"""

        # Calculate statistics
        total_findings = len(all_findings)
        critical_count = len(critical_findings)

        severity_distribution = {}
        cwe_distribution = {}
        framework_distribution = {}
        total_bounty = 0

        for finding in critical_findings:
            severity = finding.get('type', 'unknown')
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

            cwe = finding.get('cwe', 'unknown')
            cwe_distribution[cwe] = cwe_distribution.get(cwe, 0) + 1

            framework = finding.get('framework_specific', 'general')
            framework_distribution[framework] = framework_distribution.get(framework, 0) + 1

            total_bounty += finding.get('bounty_estimate', 0)

        # Top findings by severity and confidence
        top_findings = sorted(
            critical_findings,
            key=lambda x: (x.get('severity_score', 0) * x.get('confidence', 0)),
            reverse=True
        )[:15]

        return {
            "scan_summary": {
                "timestamp": datetime.now().isoformat(),
                "repository_path": repo_path,
                "frameworks_detected": frameworks,
                "total_findings": total_findings,
                "critical_findings": critical_count,
                "scan_type": "java_framework_vulnerability_analysis"
            },
            "framework_analysis": {
                "detected_frameworks": frameworks,
                "framework_vulnerability_distribution": framework_distribution,
                "high_risk_frameworks": [f for f in frameworks if framework_distribution.get(f, 0) > 2]
            },
            "vulnerability_statistics": {
                "vulnerability_type_distribution": severity_distribution,
                "cwe_distribution": cwe_distribution,
                "estimated_total_bounty": total_bounty,
                "average_confidence": sum(f.get('confidence', 0) for f in critical_findings) / len(critical_findings) if critical_findings else 0
            },
            "top_critical_findings": [{
                "file": os.path.relpath(f.get('file', ''), repo_path),
                "line": f.get('line', 0),
                "vulnerability_type": f.get('type', ''),
                "framework": f.get('framework_specific', 'general'),
                "severity_score": f.get('severity_score', 0),
                "confidence": f.get('confidence', 0),
                "cwe": f.get('cwe', ''),
                "cve_references": f.get('cve_references', ''),
                "bounty_estimate": f.get('bounty_estimate', 0),
                "description": f.get('description', ''),
                "exploitation_notes": f.get('exploitation_notes', ''),
                "context_preview": f.get('context', '')[:200] + "..." if len(f.get('context', '')) > 200 else f.get('context', '')
            } for f in top_findings],
            "analysis_quality": {
                "pattern_sophistication": "java_framework_specific",
                "framework_coverage": len(frameworks),
                "confidence_threshold": 0.7,
                "severity_threshold": 7.0
            }
        }

def scan_multiple_repositories(repo_paths: List[str]) -> Dict:
    """Scan multiple Java framework repositories"""
    hunter = JavaFrameworkVulnHunter()
    all_reports = {}

    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)
        hunter.logger.info(f"Scanning repository: {repo_name}")

        report = hunter.scan_repository(repo_path)
        all_reports[repo_name] = report

        # Brief summary for each repo
        if 'scan_summary' in report:
            summary = report['scan_summary']
            hunter.logger.info(f"{repo_name}: {summary.get('critical_findings', 0)} critical findings")

    # Generate combined summary
    total_critical = sum(
        report.get('scan_summary', {}).get('critical_findings', 0)
        for report in all_reports.values()
    )

    total_bounty = sum(
        report.get('vulnerability_statistics', {}).get('estimated_total_bounty', 0)
        for report in all_reports.values()
    )

    combined_report = {
        "multi_repository_summary": {
            "timestamp": datetime.now().isoformat(),
            "repositories_scanned": list(all_reports.keys()),
            "total_critical_findings": total_critical,
            "total_estimated_bounty": total_bounty,
            "scan_type": "multi_java_framework_analysis"
        },
        "individual_reports": all_reports
    }

    return combined_report

if __name__ == "__main__":
    # Scan all Java framework repositories
    repo_base = "/Users/ankitthakur/vuln_ml_research/java_framework_analysis"

    repositories = [
        os.path.join(repo_base, "hibernate-orm"),
        os.path.join(repo_base, "struts1-1.3.10"),
        os.path.join(repo_base, "struts1-1.2.9"),
        os.path.join(repo_base, "struts1-1.0"),
        os.path.join(repo_base, "spring-framework-5.3.39"),
        os.path.join(repo_base, "spring-framework-4.3.30")
    ]

    combined_report = scan_multiple_repositories(repositories)

    # Save comprehensive results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"java_framework_vulnerability_analysis_{timestamp}.json"

    with open(results_file, 'w') as f:
        json.dump(combined_report, f, indent=2)

    print("\n=== Java Framework Vulnerability Analysis ===")
    summary = combined_report['multi_repository_summary']
    print(f"Repositories scanned: {len(summary['repositories_scanned'])}")
    print(f"Total critical findings: {summary['total_critical_findings']}")
    print(f"Estimated total bounty: ${summary['total_estimated_bounty']:,}")

    print(f"\nDetailed results saved to: {results_file}")

    # Print top findings from each repository
    for repo_name, report in combined_report['individual_reports'].items():
        if 'top_critical_findings' in report and report['top_critical_findings']:
            print(f"\n{repo_name} - Top Critical Findings:")
            for i, finding in enumerate(report['top_critical_findings'][:3], 1):
                print(f"  {i}. {finding['file']}:{finding['line']}")
                print(f"     Type: {finding['vulnerability_type']}")
                print(f"     Severity: {finding['severity_score']:.1f}, Confidence: {finding['confidence']:.2f}")
                print(f"     CVE Refs: {finding['cve_references']}")
                print(f"     Bounty: ${finding['bounty_estimate']:,}")