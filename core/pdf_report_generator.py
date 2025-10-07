#!/usr/bin/env python3
"""
PDF Report Generator for Vulnerability Assessments
Generates professional, bug bounty-ready PDF reports
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List
import logging

from core.comprehensive_vulnerability_tester import VulnerabilityFinding
from core.vulnerability_validator import ValidationResult
from core.professional_report_generator import ProfessionalReportGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PDFReportGenerator(ProfessionalReportGenerator):
    """
    Generate PDF reports from vulnerability findings
    """

    def __init__(self, project_name: str, project_version: str = "1.0.0"):
        super().__init__(project_name, project_version)

    def generate_pdf_report(
        self,
        findings: List[VulnerabilityFinding],
        validation_results: List[ValidationResult],
        output_file: str
    ):
        """
        Generate PDF report using pandoc or weasyprint

        Args:
            findings: List of vulnerability findings
            validation_results: List of validation results
            output_file: Output PDF file path
        """
        logger.info("Generating PDF report...")

        # First generate markdown
        temp_md = tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False)
        temp_md_path = temp_md.name
        temp_md.close()

        # Generate markdown report
        self.generate_markdown_report(findings, validation_results, temp_md_path)

        # Convert to PDF
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Try pandoc first (best quality)
            if self._has_pandoc():
                logger.info("Using pandoc for PDF generation...")
                self._convert_with_pandoc(temp_md_path, output_file)
            # Try weasyprint
            elif self._has_weasyprint():
                logger.info("Using weasyprint for PDF generation...")
                self._convert_with_weasyprint(temp_md_path, output_file)
            # Fallback to markdown2pdf
            else:
                logger.info("Using markdown2pdf fallback...")
                self._convert_with_markdown2pdf(temp_md_path, output_file)

            logger.info(f"✓ PDF report generated: {output_file}")

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            logger.info("Falling back to simple text-based PDF...")
            self._generate_simple_pdf(temp_md_path, output_file)

        finally:
            # Cleanup temp file
            Path(temp_md_path).unlink(missing_ok=True)

    def _has_pandoc(self) -> bool:
        """Check if pandoc is installed"""
        try:
            subprocess.run(['pandoc', '--version'],
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _has_weasyprint(self) -> bool:
        """Check if weasyprint is installed"""
        try:
            import weasyprint
            return True
        except ImportError:
            return False

    def _convert_with_pandoc(self, md_file: str, pdf_file: str):
        """Convert markdown to PDF using pandoc"""
        cmd = [
            'pandoc',
            md_file,
            '-o', pdf_file,
            '--pdf-engine=pdflatex',
            '-V', 'geometry:margin=1in',
            '-V', 'fontsize=11pt',
            '-V', 'colorlinks=true',
            '--toc',
            '--toc-depth=2',
            '--metadata', f'title=Vulnerability Assessment Report',
            '--metadata', f'author=Security Assessment Team',
            '--metadata', f'date={self.report_date}'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            # Try without pdflatex
            logger.warning("pdflatex failed, trying wkhtmltopdf...")
            cmd[cmd.index('--pdf-engine=pdflatex')] = '--pdf-engine=wkhtmltopdf'
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise Exception(f"Pandoc conversion failed: {result.stderr}")

    def _convert_with_weasyprint(self, md_file: str, pdf_file: str):
        """Convert markdown to PDF using weasyprint"""
        import weasyprint
        import markdown

        # Read markdown
        with open(md_file, 'r') as f:
            md_content = f.read()

        # Convert markdown to HTML
        html_content = markdown.markdown(
            md_content,
            extensions=['tables', 'fenced_code', 'toc']
        )

        # Add CSS styling
        html_with_style = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 40px;
                    color: #333;
                }}
                h1 {{
                    color: #2c3e50;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #34495e;
                    border-bottom: 2px solid #95a5a6;
                    padding-bottom: 8px;
                    margin-top: 30px;
                }}
                h3 {{
                    color: #555;
                    margin-top: 20px;
                }}
                code {{
                    background-color: #f4f4f4;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                }}
                pre {{
                    background-color: #f8f8f8;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    overflow-x: auto;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    background-color: #3498db;
                    color: white;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
                .medium {{ color: #f39c12; font-weight: bold; }}
                .low {{ color: #27ae60; font-weight: bold; }}
                hr {{
                    border: none;
                    border-top: 2px solid #bdc3c7;
                    margin: 30px 0;
                }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """

        # Generate PDF
        weasyprint.HTML(string=html_with_style).write_pdf(pdf_file)

    def _convert_with_markdown2pdf(self, md_file: str, pdf_file: str):
        """Fallback: Convert using markdown2pdf"""
        try:
            import markdown2pdf
            markdown2pdf.convert_file(md_file, pdf_file)
        except ImportError:
            raise Exception("No PDF converter available. Install: pip install weasyprint markdown")

    def _generate_simple_pdf(self, md_file: str, pdf_file: str):
        """
        Generate a simple text-based PDF as last resort
        Uses reportlab if available
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
            from reportlab.lib.enums import TA_LEFT, TA_CENTER

            # Read markdown content
            with open(md_file, 'r') as f:
                content = f.read()

            # Create PDF
            doc = SimpleDocTemplate(pdf_file, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Title style
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor='#2c3e50',
                spaceAfter=30,
                alignment=TA_CENTER
            )

            # Add title
            story.append(Paragraph(f"Vulnerability Assessment Report", title_style))
            story.append(Paragraph(f"{self.project_name}", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))

            # Add content (simplified)
            lines = content.split('\n')
            for line in lines[:100]:  # Limit to first 100 lines
                if line.startswith('# '):
                    story.append(Paragraph(line[2:], styles['Heading1']))
                elif line.startswith('## '):
                    story.append(Paragraph(line[3:], styles['Heading2']))
                elif line.startswith('### '):
                    story.append(Paragraph(line[4:], styles['Heading3']))
                elif line.strip():
                    try:
                        story.append(Paragraph(line, styles['Normal']))
                    except:
                        pass  # Skip problematic lines

                story.append(Spacer(1, 0.1*inch))

            # Build PDF
            doc.build(story)
            logger.info("✓ Simple PDF generated using reportlab")

        except ImportError:
            logger.error("reportlab not available. Install with: pip install reportlab")
            logger.info("Copying markdown as text file instead...")
            import shutil
            shutil.copy(md_file, pdf_file.replace('.pdf', '.txt'))
            logger.info(f"✓ Text report saved: {pdf_file.replace('.pdf', '.txt')}")


def install_pdf_dependencies():
    """
    Helper function to install PDF generation dependencies
    """
    print("Installing PDF generation dependencies...")
    print("\nOption 1 (Recommended): Install pandoc")
    print("  macOS: brew install pandoc")
    print("  Ubuntu: sudo apt-get install pandoc texlive-xetex")
    print("  Windows: Download from https://pandoc.org/installing.html")
    print("\nOption 2: Install weasyprint")
    print("  pip install weasyprint markdown")
    print("\nOption 3: Install reportlab")
    print("  pip install reportlab")


if __name__ == "__main__":
    logger.info("PDF Report Generator\n")

    # Check dependencies
    logger.info("Checking PDF generation dependencies...")

    pdf_gen = PDFReportGenerator("Test Project")

    if pdf_gen._has_pandoc():
        logger.info("✓ pandoc available (recommended)")
    else:
        logger.warning("✗ pandoc not available")

    if pdf_gen._has_weasyprint():
        logger.info("✓ weasyprint available")
    else:
        logger.warning("✗ weasyprint not available")

    try:
        from reportlab.lib.pagesizes import letter
        logger.info("✓ reportlab available (fallback)")
    except ImportError:
        logger.warning("✗ reportlab not available")

    print("\n" + "="*60)
    print("To generate PDF reports, install at least one:")
    print("="*60)
    install_pdf_dependencies()
