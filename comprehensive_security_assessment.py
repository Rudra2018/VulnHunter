#!/usr/bin/env python3
"""
Comprehensive Security Assessment Tool
Complete pipeline: Scan → Validate → Report
"""

import argparse
import sys
from pathlib import Path
import logging
from datetime import datetime

from core.comprehensive_vulnerability_tester import ComprehensiveVulnerabilityTester
from core.vulnerability_validator import VulnerabilityValidator
from core.professional_report_generator import ProfessionalReportGenerator

# Optional PDF support
try:
    from core.pdf_report_generator import PDFReportGenerator
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point for comprehensive security assessment"""

    parser = argparse.ArgumentParser(
        description='Comprehensive Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  python comprehensive_security_assessment.py

  # Scan specific project
  python comprehensive_security_assessment.py --path /path/to/project --name "My Project"

  # Scan with specific file types
  python comprehensive_security_assessment.py --extensions .py .js .java

  # Generate only high-confidence findings
  python comprehensive_security_assessment.py --min-confidence 0.8

  # Output to specific directory
  python comprehensive_security_assessment.py --output ./reports
        """
    )

    parser.add_argument(
        '--path',
        default='.',
        help='Path to project directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--name',
        default='Security Assessment',
        help='Project name for report (default: "Security Assessment")'
    )

    parser.add_argument(
        '--version',
        default='1.0.0',
        help='Project version (default: "1.0.0")'
    )

    parser.add_argument(
        '--extensions',
        nargs='+',
        default=['.py', '.js', '.ts', '.java', '.php', '.rb', '.go'],
        help='File extensions to scan (default: .py .js .ts .java .php .rb .go)'
    )

    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.7,
        help='Minimum validation confidence (0.0-1.0, default: 0.7)'
    )

    parser.add_argument(
        '--output',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )

    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip validation step (faster but less accurate)'
    )

    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Generate only JSON report (no Markdown)'
    )

    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Generate PDF report (requires reportlab or pandoc)'
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    logger.info("=" * 80)
    logger.info("COMPREHENSIVE SECURITY ASSESSMENT")
    logger.info("=" * 80)
    logger.info(f"Project: {args.name}")
    logger.info(f"Path: {args.path}")
    logger.info(f"Extensions: {', '.join(args.extensions)}")
    logger.info(f"Min Confidence: {args.min_confidence:.0%}")
    logger.info(f"Output: {args.output}")
    logger.info("=" * 80)
    logger.info("")

    # Step 1: Vulnerability Scanning
    logger.info("[1/3] Starting vulnerability scan...")
    logger.info("-" * 80)

    tester = ComprehensiveVulnerabilityTester(args.path)
    findings = tester.comprehensive_scan(file_extensions=args.extensions)

    if not findings:
        logger.info("\n✅ No vulnerabilities detected!")
        logger.info("The scanned codebase appears secure based on static analysis.")
        return 0

    logger.info(f"\n✓ Scan complete: Found {len(findings)} potential vulnerabilities")
    logger.info("")

    # Step 2: Validation
    if args.skip_validation:
        logger.info("[2/3] Validation skipped (--skip-validation flag)")
        # Create dummy validation results
        from core.vulnerability_validator import ValidationResult
        validation_results = [
            ValidationResult(
                finding_id=f.id,
                is_valid=True,
                confidence=0.7,
                validation_method="Skipped",
                verification_steps_completed=[],
                proof_of_concept_result=None,
                false_positive_reason=None,
                additional_evidence={},
                validated_at=datetime.now().isoformat()
            )
            for f in findings
        ]
    else:
        logger.info("[2/3] Validating vulnerabilities...")
        logger.info("-" * 80)

        validator = VulnerabilityValidator()
        validation_results = validator.validate_all(findings)

        logger.info("")

    # Filter by confidence
    valid_findings = [
        (f, v) for f, v in zip(findings, validation_results)
        if v.is_valid and v.confidence >= args.min_confidence
    ]

    logger.info(f"✓ Validation complete")
    logger.info(f"  Total findings: {len(findings)}")
    logger.info(f"  Validated: {sum(1 for v in validation_results if v.is_valid)}")
    logger.info(f"  False positives: {sum(1 for v in validation_results if not v.is_valid)}")
    logger.info(f"  High confidence (>= {args.min_confidence:.0%}): {len(valid_findings)}")
    logger.info("")

    if not valid_findings:
        logger.info("\n✅ No high-confidence vulnerabilities found!")
        logger.info("All detected issues appear to be false positives.")
        return 0

    # Step 3: Report Generation
    logger.info("[3/3] Generating reports...")
    logger.info("-" * 80)

    # Choose generator based on PDF requirement
    if args.pdf and PDF_AVAILABLE:
        generator = PDFReportGenerator(
            project_name=args.name,
            project_version=args.version
        )
    else:
        generator = ProfessionalReportGenerator(
            project_name=args.name,
            project_version=args.version
        )

    # Generate JSON report
    json_file = output_dir / f"vulnerability_report_{timestamp}.json"
    generator.generate_json_report(findings, validation_results, str(json_file))

    # Generate Markdown report
    if not args.json_only:
        md_file = output_dir / f"VULNERABILITY_REPORT_{timestamp}.md"
        generator.generate_markdown_report(findings, validation_results, str(md_file))

    # Generate PDF report if requested
    pdf_file = None
    if args.pdf:
        if PDF_AVAILABLE:
            pdf_file = output_dir / f"VULNERABILITY_REPORT_{timestamp}.pdf"
            try:
                generator.generate_pdf_report(findings, validation_results, str(pdf_file))
            except Exception as e:
                logger.warning(f"PDF generation failed: {e}")
                logger.info("Markdown and JSON reports are still available")
        else:
            logger.warning("PDF generation not available. Install: pip install reportlab markdown")
            logger.info("Markdown and JSON reports generated instead")

    logger.info("")
    logger.info("=" * 80)
    logger.info("✅ ASSESSMENT COMPLETE")
    logger.info("=" * 80)
    logger.info(f"\nFound {len(valid_findings)} validated vulnerabilities:")

    # Summary by severity
    from core.comprehensive_vulnerability_tester import Severity

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = sum(1 for f, v in valid_findings if f.severity == severity)
        if count > 0:
            emoji = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🟢"
            }.get(severity, "")
            logger.info(f"  {emoji} {severity.value}: {count}")

    logger.info(f"\n📄 Reports generated:")
    logger.info(f"  JSON: {json_file}")
    if not args.json_only:
        logger.info(f"  Markdown: {md_file}")
    if pdf_file and pdf_file.exists():
        logger.info(f"  PDF: {pdf_file}")

    logger.info("\n💡 Next Steps:")
    logger.info("  1. Review the detailed report")
    logger.info("  2. Prioritize critical and high-severity findings")
    logger.info("  3. Implement recommended remediations")
    logger.info("  4. Re-scan after fixes to verify")

    logger.info("\n" + "=" * 80)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\n\n⚠️  Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n\n❌ Error during assessment: {e}")
        logger.exception("Full traceback:")
        sys.exit(1)
