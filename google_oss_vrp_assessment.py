#!/usr/bin/env python3
"""
Google OSS VRP Security Assessment Tool
Complete security assessment tailored for Google's Open Source Vulnerability Reward Program

Usage:
    python google_oss_vrp_assessment.py [OPTIONS]

Examples:
    # Scan current directory
    python google_oss_vrp_assessment.py

    # Scan specific project
    python google_oss_vrp_assessment.py --path /path/to/google/project

    # Quick scan (skip validation)
    python google_oss_vrp_assessment.py --quick

    # Generate PDF report
    python google_oss_vrp_assessment.py --pdf
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime

# Import core components
from core.google_oss_vrp_scanner import GoogleOSSVRPScanner
from core.google_vrp_report_generator import GoogleVRPReportGenerator

# Optional PDF support
try:
    from core.pdf_report_generator import PDFReportGenerator
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Simplified format for CLI
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Google OSS VRP Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  python google_oss_vrp_assessment.py

  # Scan specific Google OSS project
  python google_oss_vrp_assessment.py --path /path/to/angular

  # Scan with specific file types
  python google_oss_vrp_assessment.py --extensions .go .proto

  # Generate PDF report
  python google_oss_vrp_assessment.py --pdf

  # Output to specific directory
  python google_oss_vrp_assessment.py --output ./my-reports

Supported Google OSS Projects:
  High Priority (Tier 1):
    - Bazel, Angular, Golang, Protocol Buffers, Fuchsia

  Medium Priority (Tier 2):
    - TensorFlow, Kubernetes, Chromium, Android, Firebase, Flutter

Google OSS VRP: https://bughunters.google.com/open-source-security
        """
    )

    parser.add_argument(
        '--path',
        default='.',
        help='Path to project directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--extensions',
        nargs='+',
        default=None,
        help='File extensions to scan (default: .py .js .ts .java .go .cpp .c .h .php .rb)'
    )

    parser.add_argument(
        '--output',
        default='./reports/google_vrp',
        help='Output directory for reports (default: ./reports/google_vrp)'
    )

    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Generate only JSON report (no Markdown)'
    )

    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Generate PDF report (requires pandoc or weasyprint)'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan mode (may have more false positives)'
    )

    parser.add_argument(
        '--check-eligibility',
        action='store_true',
        help='Only check if project is eligible for Google OSS VRP (no scanning)'
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Print header
    print_header()

    # Check eligibility only mode
    if args.check_eligibility:
        from core.google_project_detector import GoogleOSSProjectDetector
        detector = GoogleOSSProjectDetector(args.path)
        project_info = detector.detect_project()
        print(detector.generate_summary(project_info))
        sys.exit(0 if project_info.eligible_for_vrp else 1)

    # Run comprehensive scan
    logger.info(f"Project Path: {args.path}")
    logger.info(f"Output Directory: {args.output}")
    if args.extensions:
        logger.info(f"File Extensions: {', '.join(args.extensions)}")
    logger.info("=" * 80)
    logger.info("")

    # Scan
    scanner = GoogleOSSVRPScanner(args.path)
    results = scanner.scan(file_extensions=args.extensions)

    # Generate reports
    logger.info("\n" + "=" * 80)
    logger.info("GENERATING REPORTS")
    logger.info("=" * 80)

    generator = GoogleVRPReportGenerator(results)

    # JSON report (always generated)
    json_file = output_dir / f"google_vrp_report_{timestamp}.json"
    generator.generate_json_report(str(json_file))

    # Markdown report
    if not args.json_only:
        md_file = output_dir / f"GOOGLE_VRP_REPORT_{timestamp}.md"
        generator.generate_markdown_report(str(md_file))

    # PDF report (if requested)
    if args.pdf:
        if PDF_AVAILABLE:
            # For now, convert markdown to PDF using pandoc
            pdf_file = output_dir / f"GOOGLE_VRP_REPORT_{timestamp}.pdf"
            try:
                import subprocess
                md_file_str = str(md_file) if not args.json_only else str(json_file).replace('.json', '.md')

                # First ensure we have the markdown
                if args.json_only:
                    generator.generate_markdown_report(md_file_str)

                result = subprocess.run(
                    ['pandoc', md_file_str, '-o', str(pdf_file)],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    logger.info(f"  ✓ PDF: {pdf_file}")
                else:
                    logger.warning("  ⚠️  PDF generation failed (pandoc not available or error occurred)")
            except Exception as e:
                logger.warning(f"  ⚠️  PDF generation failed: {e}")
        else:
            logger.warning("  ⚠️  PDF generation not available. Install: pip install reportlab")

    # Print summary
    print_summary(results, json_file, md_file if not args.json_only else None)

    # Exit code based on findings
    if results.critical_count > 0:
        sys.exit(1)  # Critical vulnerabilities found
    elif results.high_count > 0:
        sys.exit(2)  # High severity vulnerabilities found
    else:
        sys.exit(0)  # No critical/high vulnerabilities


def print_header():
    """Print tool header"""
    print("\n" + "=" * 80)
    print("GOOGLE OSS VRP SECURITY ASSESSMENT")
    print("=" * 80)
    print("")
    print("Comprehensive security scanner for Google's Open Source VRP")
    print("https://bughunters.google.com/open-source-security")
    print("")
    print("=" * 80)
    print("")


def print_summary(results, json_file, md_file):
    """Print final summary"""
    print("\n" + "=" * 80)
    print("✅ ASSESSMENT COMPLETE")
    print("=" * 80)
    print("")

    # Project eligibility
    if results.project_info.eligible_for_vrp:
        print(f"🎯 Project: {results.project_info.project_name}")
        print(f"✅ ELIGIBLE for Google OSS VRP ({results.project_info.vrp_tier.upper()})")
        print(f"   Priority: {results.project_info.priority_level.upper()}")
    else:
        print(f"📁 Project: {results.project_info.project_name}")
        print("ℹ️  NOT eligible for Google OSS VRP")
        print("   (This is not a Google-maintained open source project)")

    print("")

    # Findings summary
    print(f"Total Findings: {results.total_findings}")
    if results.critical_count > 0:
        print(f"  🔴 Critical: {results.critical_count}")
    if results.high_count > 0:
        print(f"  🟠 High: {results.high_count}")
    if results.medium_count > 0:
        print(f"  🟡 Medium: {results.medium_count}")
    if results.low_count > 0:
        print(f"  🟢 Low: {results.low_count}")

    print("")
    print("Breakdown:")
    print(f"  • Code Vulnerabilities: {len(results.code_vulnerabilities)}")
    print(f"  • Supply Chain Issues: {len(results.supply_chain_findings)}")
    print(f"  • Secret Exposures: {len(results.secret_findings)}")

    # VRP value estimate
    if results.project_info.eligible_for_vrp and results.total_findings > 0:
        print("")
        print("💰 Estimated VRP Value:")
        print(f"   ${results.estimated_min_value:,} - ${results.estimated_max_value:,} USD")
        print("")
        print("📝 Submit to: https://bughunters.google.com/report")

    # Reports generated
    print("")
    print("📄 Reports Generated:")
    print(f"   JSON: {json_file}")
    if md_file:
        print(f"   Markdown: {md_file}")

    # Next steps
    print("")
    print("💡 Next Steps:")

    if results.critical_count > 0 or results.high_count > 0:
        print("   1. Review critical and high severity findings in the report")
        print("   2. Verify each finding can be reproduced")
        print("   3. Prepare proof-of-concept code")

        if results.project_info.eligible_for_vrp:
            print("   4. Submit findings to Google VRP (one report per finding)")
            print("   5. Follow Google's responsible disclosure guidelines")
        else:
            print("   4. Report to project maintainers via responsible disclosure")
            print("   5. Consider other bug bounty platforms (HackerOne, etc.)")
    else:
        print("   • No critical or high severity issues found")
        print("   • Review medium/low findings for improvements")
        print("   • Consider this a good security baseline")

    # Warnings
    if results.critical_count > 0:
        print("")
        print("⚠️  CRITICAL VULNERABILITIES DETECTED")
        print("   Immediate action required to secure the project")

    print("")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n\n⚠️  Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\n\n❌ Error during assessment: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
