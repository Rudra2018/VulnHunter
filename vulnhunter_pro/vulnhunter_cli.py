#!/usr/bin/env python3
"""
VulnHunter Professional - Command Line Interface
===============================================

Production-ready vulnerability analysis platform with comprehensive coverage.
Mathematical foundation, formal verification, and enterprise features.
"""

import os
import sys
import json
import argparse
import time
from pathlib import Path
from typing import Dict, Any, Optional

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import VulnHunterEngine
from core.config import Config
from core.vulnerability import VulnSeverity


def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="VulnHunter Professional - Advanced Security Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single file
  python vulnhunter_cli.py --target app.py

  # Analyze entire project
  python vulnhunter_cli.py --target /path/to/project --recursive

  # Generate SARIF report
  python vulnhunter_cli.py --target app.py --output-format sarif --output report.sarif

  # High confidence only
  python vulnhunter_cli.py --target app.py --confidence-threshold 0.8

  # Include mathematical proofs
  python vulnhunter_cli.py --target app.py --enable-proofs --verbose

Visit: https://github.com/rudra2018/VulnHunter for documentation
        """
    )

    # Target specification
    parser.add_argument(
        '--target', '-t',
        help='Target file or directory to analyze (not required for --test-mode)'
    )

    # Analysis options
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively analyze directories'
    )

    parser.add_argument(
        '--file-extensions',
        nargs='+',
        help='File extensions to analyze (e.g., .py .js .java)'
    )

    parser.add_argument(
        '--confidence-threshold',
        type=float,
        default=0.5,
        help='Minimum confidence threshold for reporting (0.0-1.0)'
    )

    parser.add_argument(
        '--severity-filter',
        choices=['low', 'medium', 'high', 'critical'],
        help='Only report vulnerabilities of specified severity or higher'
    )

    # Mathematical features
    parser.add_argument(
        '--enable-proofs',
        action='store_true',
        help='Enable mathematical proofs and formal verification'
    )

    parser.add_argument(
        '--enable-topology',
        action='store_true',
        default=True,
        help='Enable topological analysis (default: enabled)'
    )

    parser.add_argument(
        '--enable-symbolic',
        action='store_true',
        help='Enable symbolic execution analysis'
    )

    # Output options
    parser.add_argument(
        '--output-format',
        choices=['json', 'sarif', 'html', 'xml', 'text'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )

    parser.add_argument(
        '--include-source',
        action='store_true',
        help='Include source code snippets in output'
    )

    parser.add_argument(
        '--include-proofs',
        action='store_true',
        help='Include mathematical proofs in output'
    )

    # Configuration
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )

    parser.add_argument(
        '--plugin-dir',
        action='append',
        help='Additional plugin directory (can be specified multiple times)'
    )

    # Logging and verbosity
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except results'
    )

    # Performance options
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Analysis timeout in seconds (default: 300)'
    )

    parser.add_argument(
        '--max-file-size',
        type=int,
        default=50,
        help='Maximum file size to analyze in MB (default: 50)'
    )

    # Special modes
    parser.add_argument(
        '--test-mode',
        action='store_true',
        help='Run in test mode with real vulnerability datasets'
    )

    parser.add_argument(
        '--benchmark',
        action='store_true',
        help='Run performance benchmarks'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='VulnHunter Professional 5.0.0'
    )

    return parser


def load_configuration(args: argparse.Namespace) -> Config:
    """Load configuration from various sources"""
    if args.config:
        config = Config.from_file(args.config)
    else:
        config = Config.from_env()

    # Override with command line arguments
    if args.confidence_threshold:
        config.confidence_threshold = args.confidence_threshold

    if args.timeout:
        config.timeout_seconds = args.timeout

    if args.max_file_size:
        config.max_file_size_mb = args.max_file_size

    if args.output_format:
        config.output_format = args.output_format

    if args.output:
        config.output_file = args.output

    if args.plugin_dir:
        config.plugin_dirs.extend(args.plugin_dir)

    if args.debug:
        config.debug_mode = True
        config.log_level = "DEBUG"
    elif args.verbose:
        config.log_level = "INFO"
    elif args.quiet:
        config.log_level = "ERROR"

    # Mathematical features
    config.enable_mathematical_proofs = args.enable_proofs

    return config


def filter_vulnerabilities(vulnerabilities, args):
    """Filter vulnerabilities based on command line arguments"""
    filtered = []

    severity_order = {
        VulnSeverity.LOW: 1,
        VulnSeverity.MEDIUM: 2,
        VulnSeverity.HIGH: 3,
        VulnSeverity.CRITICAL: 4
    }

    min_severity = 1
    if args.severity_filter:
        severity_mapping = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        min_severity = severity_mapping[args.severity_filter]

    for vuln in vulnerabilities:
        # Apply confidence threshold
        if vuln.confidence < args.confidence_threshold:
            continue

        # Apply severity filter
        vuln_severity_level = severity_order.get(vuln.severity, 0)
        if vuln_severity_level < min_severity:
            continue

        filtered.append(vuln)

    return filtered


def format_output(result, args) -> str:
    """Format analysis result according to specified format"""
    if args.output_format == 'json':
        return result.to_json(indent=2)
    elif args.output_format == 'sarif':
        return json.dumps(result.to_sarif(), indent=2)
    elif args.output_format == 'text':
        return format_text_output(result, args)
    elif args.output_format == 'html':
        return format_html_output(result, args)
    elif args.output_format == 'xml':
        return format_xml_output(result, args)
    else:
        return result.to_json(indent=2)


def format_text_output(result, args) -> str:
    """Format output as human-readable text"""
    lines = []
    lines.append("🛡️  VulnHunter Professional Analysis Report")
    lines.append("=" * 60)

    if result.statistical_summary:
        summary = result.statistical_summary
        lines.append(f"\n📊 Summary:")
        lines.append(f"   Total Vulnerabilities: {summary.total_vulnerabilities}")
        lines.append(f"   Critical: {summary.critical_count}")
        lines.append(f"   High: {summary.high_count}")
        lines.append(f"   Medium: {summary.medium_count}")
        lines.append(f"   Low: {summary.low_count}")
        lines.append(f"   Risk Score: {summary.risk_score:.1f}")
        lines.append(f"   Affected Files: {summary.affected_files}")

    if result.vulnerabilities:
        lines.append(f"\n🚨 Vulnerabilities Found:")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.append(f"\n[{i}] {vuln.title}")
            lines.append(f"    Type: {vuln.vuln_type.value}")
            lines.append(f"    Severity: {vuln.severity.value}")
            lines.append(f"    Location: {vuln.location}")
            lines.append(f"    Confidence: {vuln.confidence:.2f}")

            if vuln.cwe_id:
                lines.append(f"    CWE: {vuln.cwe_id}")

            lines.append(f"    Description: {vuln.description}")

            if vuln.remediation:
                lines.append(f"    Remediation: {vuln.remediation}")

            if args.include_proofs and vuln.mathematical_proof:
                lines.append(f"    Mathematical Proof: {vuln.mathematical_proof.assertion}")

    else:
        lines.append("\n✅ No vulnerabilities found!")

    if result.performance_metrics:
        perf = result.performance_metrics
        lines.append(f"\n⚡ Performance:")
        lines.append(f"   Analysis Time: {perf.analysis_time_ms:.1f}ms")
        lines.append(f"   Files Analyzed: {perf.files_analyzed}")
        lines.append(f"   Lines of Code: {perf.lines_of_code}")

    return "\n".join(lines)


def format_html_output(result, args) -> str:
    """Format output as HTML report"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VulnHunter Professional Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; }}
        .vulnerability {{ border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ VulnHunter Professional Report</h1>
        <p>Target: {result.target_path}</p>
        <p>Analysis Time: {result.completed_at or 'N/A'}</p>
    </div>
"""

    if result.statistical_summary:
        summary = result.statistical_summary
        html += f"""
    <div class="summary">
        <h2>📊 Summary</h2>
        <p>Total Vulnerabilities: <strong>{summary.total_vulnerabilities}</strong></p>
        <p>Critical: {summary.critical_count} | High: {summary.high_count} | Medium: {summary.medium_count} | Low: {summary.low_count}</p>
        <p>Risk Score: <strong>{summary.risk_score:.1f}</strong></p>
        <p>Affected Files: {summary.affected_files}</p>
    </div>
"""

    if result.vulnerabilities:
        html += "<h2>🚨 Vulnerabilities</h2>"
        for vuln in result.vulnerabilities:
            severity_class = vuln.severity.value.lower()
            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.title}</h3>
        <p><strong>Type:</strong> {vuln.vuln_type.value}</p>
        <p><strong>Severity:</strong> {vuln.severity.value}</p>
        <p><strong>Location:</strong> {vuln.location}</p>
        <p><strong>Confidence:</strong> {vuln.confidence:.2f}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        <p><strong>Remediation:</strong> {vuln.remediation}</p>
    </div>
"""

    html += """
</body>
</html>
"""
    return html


def format_xml_output(result, args) -> str:
    """Format output as XML"""
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<VulnHunterReport>\n'
    xml += f'  <target>{result.target_path}</target>\n'
    xml += f'  <analysisTime>{result.completed_at or "N/A"}</analysisTime>\n'

    if result.statistical_summary:
        summary = result.statistical_summary
        xml += '  <summary>\n'
        xml += f'    <totalVulnerabilities>{summary.total_vulnerabilities}</totalVulnerabilities>\n'
        xml += f'    <critical>{summary.critical_count}</critical>\n'
        xml += f'    <high>{summary.high_count}</high>\n'
        xml += f'    <medium>{summary.medium_count}</medium>\n'
        xml += f'    <low>{summary.low_count}</low>\n'
        xml += f'    <riskScore>{summary.risk_score:.1f}</riskScore>\n'
        xml += '  </summary>\n'

    xml += '  <vulnerabilities>\n'
    for vuln in result.vulnerabilities:
        xml += '    <vulnerability>\n'
        xml += f'      <type>{vuln.vuln_type.value}</type>\n'
        xml += f'      <severity>{vuln.severity.value}</severity>\n'
        xml += f'      <title>{vuln.title}</title>\n'
        xml += f'      <description>{vuln.description}</description>\n'
        xml += f'      <location>{vuln.location}</location>\n'
        xml += f'      <confidence>{vuln.confidence:.2f}</confidence>\n'
        xml += '    </vulnerability>\n'

    xml += '  </vulnerabilities>\n'
    xml += '</VulnHunterReport>\n'

    return xml


def run_test_mode() -> int:
    """Run comprehensive test mode"""
    print("🧪 Running VulnHunter Professional Test Suite")
    print("=" * 60)

    try:
        from tests.test_real_vulns import RealVulnerabilityTests

        tester = RealVulnerabilityTests()
        report = tester.run_comprehensive_tests()

        accuracy = report['summary']['overall_accuracy']
        print(f"\n🎯 Overall Test Accuracy: {accuracy:.1%}")

        return 0 if accuracy >= 0.8 else 1

    except ImportError as e:
        print(f"❌ Test module not available: {e}")
        return 1


def main() -> int:
    """Main entry point"""
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Special modes
    if args.test_mode:
        return run_test_mode()

    # Validate target
    if not args.target:
        print("❌ Error: --target is required unless using --test-mode")
        return 1

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"❌ Error: Target path does not exist: {args.target}")
        return 1

    try:
        # Load configuration
        config = load_configuration(args)
        config.validate()

        # Initialize engine
        if not args.quiet:
            print("🚀 VulnHunter Professional v5.0")
            print(f"🎯 Target: {args.target}")

        engine = VulnHunterEngine(config)

        # Run analysis
        start_time = time.time()

        if target_path.is_file():
            result = engine.analyze_file(str(target_path))
        else:
            result = engine.analyze_directory(
                str(target_path),
                recursive=args.recursive,
                file_extensions=args.file_extensions
            )

        analysis_time = time.time() - start_time

        # Filter results
        if result.vulnerabilities:
            result.vulnerabilities = filter_vulnerabilities(result.vulnerabilities, args)
            result.calculate_summary()  # Recalculate after filtering

        # Output results
        output_text = format_output(result, args)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_text)
            if not args.quiet:
                print(f"📄 Report saved to: {args.output}")
        else:
            print(output_text)

        # Print summary to stderr if outputting to stdout
        if not args.output and not args.quiet:
            print(f"\n⚡ Analysis completed in {analysis_time:.2f}s", file=sys.stderr)
            if result.statistical_summary:
                print(f"🔍 Found {result.statistical_summary.total_vulnerabilities} vulnerabilities", file=sys.stderr)

        # Return appropriate exit code
        if result.statistical_summary:
            critical_count = result.statistical_summary.critical_count
            high_count = result.statistical_summary.high_count
            if critical_count > 0:
                return 2  # Critical vulnerabilities found
            elif high_count > 0:
                return 1  # High severity vulnerabilities found

        return 0  # Success

    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        return 130

    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())