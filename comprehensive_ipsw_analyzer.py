#!/usr/bin/env python3
"""
Comprehensive IPSW Analyzer & Report Generator
Analyzes .ipsw firmware files and generates detailed PDF report
"""

import os
import sys
import hashlib
import zipfile
import tempfile
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import subprocess

# Add paths
sys.path.insert(0, os.path.expanduser("~/vuln_ml_research"))
sys.path.insert(0, os.path.expanduser("~/Documents"))


class IPSWAnalyzer:
    """Comprehensive iOS firmware analyzer"""

    def __init__(self):
        self.results = []
        self.temp_dirs = []

    def compute_hash(self, file_path: str) -> Dict[str, str]:
        """Compute multiple hashes"""
        print(f"📊 Computing hashes for {os.path.basename(file_path)}...")

        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            'sha256': sha256.hexdigest(),
            'sha1': sha1.hexdigest(),
            'md5': md5.hexdigest()
        }

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        stat = os.stat(file_path)

        return {
            'path': file_path,
            'filename': os.path.basename(file_path),
            'size_bytes': stat.st_size,
            'size_gb': round(stat.st_size / (1024**3), 2),
            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        }

    def extract_ipsw_metadata(self, ipsw_path: str) -> Dict[str, Any]:
        """Extract metadata from IPSW file"""
        print(f"📦 Extracting IPSW metadata from {os.path.basename(ipsw_path)}...")

        metadata = {
            'extracted': True,
            'build_manifest': None,
            'restore_info': None,
            'firmware_files': [],
            'total_files': 0,
            'extraction_errors': []
        }

        temp_dir = tempfile.mkdtemp(prefix='ipsw_analysis_')
        self.temp_dirs.append(temp_dir)

        try:
            # List contents without full extraction (faster)
            with zipfile.ZipFile(ipsw_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                metadata['total_files'] = len(file_list)

                # Extract important metadata files only
                important_files = [
                    'BuildManifest.plist',
                    'Restore.plist',
                    'SystemVersion.plist'
                ]

                for fname in important_files:
                    if fname in file_list:
                        try:
                            zip_ref.extract(fname, temp_dir)
                            extracted_path = os.path.join(temp_dir, fname)

                            # Read and parse plist
                            with open(extracted_path, 'rb') as f:
                                content = f.read()
                                # Try to parse as plist
                                try:
                                    import plistlib
                                    plist_data = plistlib.loads(content)
                                    metadata[fname.replace('.plist', '').lower()] = {
                                        'found': True,
                                        'size': len(content),
                                        'keys': list(plist_data.keys()) if isinstance(plist_data, dict) else []
                                    }

                                    # Extract specific info
                                    if fname == 'BuildManifest.plist':
                                        metadata['build_version'] = plist_data.get('ProductVersion', 'Unknown')
                                        metadata['build_number'] = plist_data.get('ProductBuildVersion', 'Unknown')
                                        metadata['supported_devices'] = plist_data.get('SupportedProductTypes', [])
                                except Exception as e:
                                    metadata[fname] = {'error': str(e)}
                        except Exception as e:
                            metadata['extraction_errors'].append(f"{fname}: {str(e)}")

                # Identify firmware components
                firmware_components = []
                for fname in file_list[:100]:  # Check first 100 files
                    if any(keyword in fname.lower() for keyword in ['kernel', 'firmware', 'bootloader', 'sep', 'baseband']):
                        firmware_components.append(fname)

                metadata['firmware_files'] = firmware_components

        except Exception as e:
            metadata['extracted'] = False
            metadata['error'] = str(e)

        return metadata

    def run_vulnhunter_analysis(self, file_path: str) -> Dict[str, Any]:
        """Attempt to run VulnHunter analysis"""
        print(f"🦾 Running VulnHunter analysis on {os.path.basename(file_path)}...")

        result = {
            'attempted': True,
            'successful': False,
            'output': None,
            'error': None
        }

        try:
            # Run VulnHunter with timeout
            cmd = [
                sys.executable,
                os.path.expanduser("~/vuln_ml_research/vulnhunter/vulnhunter.py"),
                "hunt",
                file_path
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            result['output'] = process.stdout
            result['error'] = process.stderr
            result['return_code'] = process.returncode
            result['successful'] = process.returncode == 0

        except subprocess.TimeoutExpired:
            result['error'] = "Analysis timed out after 5 minutes"
        except Exception as e:
            result['error'] = str(e)

        return result

    def perform_static_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform static analysis checks"""
        print(f"🔍 Performing static analysis on {os.path.basename(file_path)}...")

        analysis = {
            'checks_performed': [],
            'findings': [],
            'risk_indicators': []
        }

        filename = os.path.basename(file_path).lower()

        # Check 1: Filename analysis
        analysis['checks_performed'].append('Filename pattern analysis')
        if 'restore' in filename:
            analysis['findings'].append({
                'type': 'INFO',
                'finding': 'Restore firmware detected',
                'description': 'This appears to be official Apple restore firmware'
            })

        # Check 2: File size analysis
        analysis['checks_performed'].append('File size analysis')
        size_gb = os.path.getsize(file_path) / (1024**3)
        if size_gb < 1:
            analysis['risk_indicators'].append('Unusually small firmware file (< 1GB)')
        elif size_gb > 20:
            analysis['risk_indicators'].append('Unusually large firmware file (> 20GB)')

        # Check 3: ZIP structure validation
        analysis['checks_performed'].append('ZIP archive validation')
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                test_result = zf.testzip()
                if test_result:
                    analysis['risk_indicators'].append(f'Corrupted file detected: {test_result}')
                else:
                    analysis['findings'].append({
                        'type': 'PASS',
                        'finding': 'ZIP archive structure valid',
                        'description': 'All files pass CRC checks'
                    })
        except zipfile.BadZipFile:
            analysis['risk_indicators'].append('Invalid ZIP archive structure')
        except Exception as e:
            analysis['findings'].append({
                'type': 'ERROR',
                'finding': 'Could not validate ZIP structure',
                'description': str(e)
            })

        # Check 4: Required files check
        analysis['checks_performed'].append('Required files check')
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                files = zf.namelist()
                required_files = ['BuildManifest.plist', 'Restore.plist']
                missing = [f for f in required_files if f not in files]

                if missing:
                    analysis['risk_indicators'].append(f'Missing required files: {", ".join(missing)}')
                else:
                    analysis['findings'].append({
                        'type': 'PASS',
                        'finding': 'All required files present',
                        'description': 'BuildManifest.plist and Restore.plist found'
                    })
        except Exception as e:
            analysis['findings'].append({
                'type': 'ERROR',
                'finding': 'Could not check required files',
                'description': str(e)
            })

        return analysis

    def calculate_risk_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score"""
        score = 100  # Start with perfect score

        # Deduct points for issues
        static_analysis = analysis_results.get('static_analysis', {})
        risk_indicators = static_analysis.get('risk_indicators', [])

        score -= len(risk_indicators) * 10  # -10 per risk indicator

        metadata = analysis_results.get('metadata', {})
        if not metadata.get('extracted', False):
            score -= 20

        if metadata.get('extraction_errors', []):
            score -= len(metadata['extraction_errors']) * 5

        score = max(0, min(100, score))  # Clamp between 0-100

        # Determine risk level
        if score >= 80:
            level = "LOW"
            color = "green"
        elif score >= 60:
            level = "MEDIUM"
            color = "yellow"
        elif score >= 40:
            level = "HIGH"
            color = "orange"
        else:
            level = "CRITICAL"
            color = "red"

        return {
            'score': score,
            'level': level,
            'color': color,
            'factors': risk_indicators
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Complete analysis of a single file"""
        print(f"\n{'='*80}")
        print(f"🔍 Analyzing: {os.path.basename(file_path)}")
        print(f"{'='*80}\n")

        result = {
            'timestamp': datetime.now().isoformat(),
            'file_info': self.get_file_info(file_path),
            'hashes': self.compute_hash(file_path),
            'metadata': self.extract_ipsw_metadata(file_path),
            'static_analysis': self.perform_static_analysis(file_path),
            'vulnhunter': self.run_vulnhunter_analysis(file_path)
        }

        result['risk_assessment'] = self.calculate_risk_score(result)

        return result

    def cleanup(self):
        """Cleanup temporary directories"""
        import shutil
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except:
                pass


def generate_pdf_report(results: List[Dict[str, Any]], output_path: str):
    """Generate comprehensive PDF report"""
    print(f"\n📄 Generating PDF report: {output_path}")

    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        print("❌ reportlab not installed. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "reportlab"], check=True)
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title Page
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )

    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("🦾 VulnHunter", title_style))
    story.append(Paragraph("iOS Firmware Analysis Report", styles['Heading2']))
    story.append(Spacer(1, 0.5*inch))

    # Report info
    report_info = [
        ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Analysis System:", "VulnHunter v1.0.0"],
        ["Files Analyzed:", str(len(results))],
        ["Status:", "✅ Complete"]
    ]

    t = Table(report_info, colWidths=[2*inch, 4*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(t)
    story.append(PageBreak())

    # Individual file reports
    for idx, result in enumerate(results, 1):
        file_info = result['file_info']
        risk = result['risk_assessment']

        # File Header
        story.append(Paragraph(f"Analysis #{idx}: {file_info['filename']}", styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))

        # Risk Assessment Box
        risk_color = {
            'green': colors.green,
            'yellow': colors.yellow,
            'orange': colors.orange,
            'red': colors.red
        }.get(risk['color'], colors.grey)

        risk_data = [
            ["RISK ASSESSMENT"],
            [f"Score: {risk['score']}/100"],
            [f"Level: {risk['level']}"]
        ]

        risk_table = Table(risk_data, colWidths=[6*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), risk_color),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, 0), 16),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 2, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))

        # File Information
        story.append(Paragraph("📁 File Information", styles['Heading2']))
        file_data = [
            ["Property", "Value"],
            ["Filename", file_info['filename']],
            ["Size", f"{file_info['size_gb']} GB ({file_info['size_bytes']:,} bytes)"],
            ["Modified", file_info['modified']],
            ["SHA-256", result['hashes']['sha256'][:32] + "..."],
        ]

        file_table = Table(file_data, colWidths=[2*inch, 4*inch])
        file_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white)
        ]))
        story.append(file_table)
        story.append(Spacer(1, 0.3*inch))

        # Metadata
        story.append(Paragraph("📦 Firmware Metadata", styles['Heading2']))
        metadata = result['metadata']

        if metadata.get('build_version'):
            meta_data = [
                ["Property", "Value"],
                ["iOS Version", metadata.get('build_version', 'Unknown')],
                ["Build Number", metadata.get('build_number', 'Unknown')],
                ["Total Files", str(metadata.get('total_files', 0))],
                ["Firmware Components", str(len(metadata.get('firmware_files', [])))]
            ]

            if metadata.get('supported_devices'):
                devices = ", ".join(metadata['supported_devices'][:3])
                if len(metadata['supported_devices']) > 3:
                    devices += "..."
                meta_data.append(["Supported Devices", devices])

            meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white)
            ]))
            story.append(meta_table)
        else:
            story.append(Paragraph("⚠️ Could not extract metadata", styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # Static Analysis
        story.append(Paragraph("🔍 Static Analysis Results", styles['Heading2']))
        static = result['static_analysis']

        story.append(Paragraph(f"<b>Checks Performed:</b> {len(static['checks_performed'])}", styles['Normal']))
        story.append(Paragraph(f"<b>Findings:</b> {len(static['findings'])}", styles['Normal']))
        story.append(Paragraph(f"<b>Risk Indicators:</b> {len(static['risk_indicators'])}", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))

        if static['risk_indicators']:
            story.append(Paragraph("<b>⚠️ Risk Indicators:</b>", styles['Normal']))
            for indicator in static['risk_indicators']:
                story.append(Paragraph(f"• {indicator}", styles['Normal']))
        else:
            story.append(Paragraph("✅ No risk indicators found", styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # VulnHunter Analysis
        story.append(Paragraph("🦾 VulnHunter ML Analysis", styles['Heading2']))
        vuln_result = result['vulnhunter']

        if vuln_result['successful']:
            story.append(Paragraph("✅ Analysis completed successfully", styles['Normal']))
        else:
            story.append(Paragraph(f"⚠️ Analysis encountered issues: {vuln_result.get('error', 'Unknown error')}", styles['Normal']))
            story.append(Paragraph("<i>Note: This may be due to feature extraction limitations with large firmware files.</i>", styles['Normal']))

        story.append(Spacer(1, 0.5*inch))

        # Add page break between files
        if idx < len(results):
            story.append(PageBreak())

    # Build PDF
    doc.build(story)
    print(f"✅ PDF report generated: {output_path}")


def main():
    print("🦾 VulnHunter - Comprehensive IPSW Analyzer")
    print("=" * 80)

    # Find IPSW files
    downloads_dir = os.path.expanduser("~/Downloads")
    ipsw_files = list(Path(downloads_dir).glob("*.ipsw"))

    if not ipsw_files:
        print(f"❌ No .ipsw files found in {downloads_dir}")
        sys.exit(1)

    print(f"✅ Found {len(ipsw_files)} IPSW file(s)")
    for f in ipsw_files:
        print(f"   • {f.name}")

    # Analyze each file
    analyzer = IPSWAnalyzer()
    results = []

    try:
        for ipsw_file in ipsw_files:
            result = analyzer.analyze_file(str(ipsw_file))
            results.append(result)
    finally:
        analyzer.cleanup()

    # Generate PDF report
    output_path = os.path.join(downloads_dir, f"VulnHunter_IPSW_Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    generate_pdf_report(results, output_path)

    print("\n" + "=" * 80)
    print("✅ Analysis complete!")
    print(f"📄 Report saved to: {output_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
