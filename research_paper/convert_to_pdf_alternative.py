#!/usr/bin/env python3
"""
Alternative PDF Generator for VulnHunter Research
Uses HTML to PDF conversion to handle Unicode characters properly
"""

import os
import subprocess
import weasyprint
from pathlib import Path

def html_to_pdf_weasyprint(html_file, pdf_file):
    """Convert HTML to PDF using WeasyPrint"""
    try:
        import weasyprint
        print(f"🔄 Converting {html_file} to {pdf_file} using WeasyPrint...")

        # Read HTML content
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()

        # Add CSS styling for better PDF output
        css_style = """
        <style>
        body {
            font-family: 'Times New Roman', serif;
            font-size: 11pt;
            line-height: 1.6;
            margin: 1in;
            max-width: 8.5in;
        }
        h1 { font-size: 18pt; margin-top: 24pt; margin-bottom: 12pt; }
        h2 { font-size: 16pt; margin-top: 18pt; margin-bottom: 10pt; }
        h3 { font-size: 14pt; margin-top: 15pt; margin-bottom: 8pt; }
        h4 { font-size: 12pt; margin-top: 12pt; margin-bottom: 6pt; }
        .math { font-family: 'Computer Modern', serif; }
        table { border-collapse: collapse; width: 100%; margin: 12pt 0; }
        th, td { border: 1px solid #ddd; padding: 8pt; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        code { font-family: 'Courier New', monospace; background-color: #f5f5f5; padding: 2pt; }
        pre { background-color: #f5f5f5; padding: 12pt; border-left: 3px solid #ccc; }
        blockquote { margin-left: 24pt; font-style: italic; }
        .toc { margin-bottom: 24pt; }
        .toc ul { list-style-type: none; }
        @page { margin: 1in; size: letter; }
        </style>
        """

        # Insert CSS into HTML
        if '<head>' in html_content:
            html_content = html_content.replace('<head>', f'<head>{css_style}')
        else:
            html_content = f'<html><head>{css_style}</head><body>' + html_content + '</body></html>'

        # Convert to PDF
        weasyprint.HTML(string=html_content).write_pdf(pdf_file)
        print(f"✅ Successfully converted to PDF using WeasyPrint!")
        return True

    except ImportError:
        print("❌ WeasyPrint not available. Installing...")
        try:
            subprocess.run(['pip', 'install', 'weasyprint'], check=True)
            return html_to_pdf_weasyprint(html_file, pdf_file)
        except subprocess.CalledProcessError:
            print("❌ Failed to install WeasyPrint")
            return False
    except Exception as e:
        print(f"❌ WeasyPrint conversion failed: {e}")
        return False

def html_to_pdf_chrome(html_file, pdf_file):
    """Convert HTML to PDF using Chrome/Chromium headless"""
    try:
        # Try different Chrome/Chromium executables
        chrome_paths = [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/usr/bin/google-chrome',
            '/usr/bin/chromium-browser',
            'google-chrome',
            'chromium',
            'chrome'
        ]

        chrome_path = None
        for path in chrome_paths:
            try:
                if os.path.exists(path):
                    chrome_path = path
                    break
                else:
                    subprocess.run([path, '--version'], capture_output=True, check=True)
                    chrome_path = path
                    break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

        if not chrome_path:
            print("❌ Chrome/Chromium not found")
            return False

        print(f"🔄 Converting {html_file} to {pdf_file} using Chrome...")

        # Convert HTML to absolute path
        html_path = Path(html_file).absolute()
        pdf_path = Path(pdf_file).absolute()

        cmd = [
            chrome_path,
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--print-to-pdf=' + str(pdf_path),
            '--print-to-pdf-no-header',
            f'file://{html_path}'
        ]

        subprocess.run(cmd, check=True, capture_output=True)
        print(f"✅ Successfully converted to PDF using Chrome!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Chrome conversion failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Chrome conversion error: {e}")
        return False

def convert_markdown_to_pdf_simple(md_file, pdf_file):
    """Simple markdown to PDF via HTML"""
    try:
        # First convert to HTML
        html_file = md_file.replace('.md', '_temp.html')

        print(f"🔄 Converting {md_file} to HTML...")
        subprocess.run([
            'pandoc', md_file,
            '-o', html_file,
            '--standalone',
            '--toc',
            '--number-sections',
            '--metadata', 'title=VulnHunter Research Paper'
        ], check=True)

        # Then convert HTML to PDF
        success = html_to_pdf_weasyprint(html_file, pdf_file)
        if not success:
            success = html_to_pdf_chrome(html_file, pdf_file)

        # Clean up temp HTML
        if Path(html_file).exists():
            os.remove(html_file)

        return success

    except subprocess.CalledProcessError as e:
        print(f"❌ Markdown conversion failed: {e}")
        return False

def main():
    """Main conversion function"""
    print("🔄 Alternative PDF Generator for VulnHunter Research")
    print("=" * 55)

    # Files to convert
    conversions = [
        ('VulnHunter_Omega_VHS_Research_Paper.md', 'VulnHunter_Omega_VHS_Research_Paper.pdf'),
        ('VulnHunter_Conference_Presentation.md', 'VulnHunter_Conference_Presentation.pdf')
    ]

    success_count = 0

    for md_file, pdf_file in conversions:
        if Path(md_file).exists():
            print(f"\\n📄 Converting {md_file}...")

            # Try HTML conversion if HTML exists
            html_file = md_file.replace('.md', '.html')
            if Path(html_file).exists():
                print(f"Found existing HTML file: {html_file}")
                if html_to_pdf_weasyprint(html_file, pdf_file):
                    success_count += 1
                    continue
                elif html_to_pdf_chrome(html_file, pdf_file):
                    success_count += 1
                    continue

            # Try direct markdown conversion
            if convert_markdown_to_pdf_simple(md_file, pdf_file):
                success_count += 1
            else:
                print(f"❌ Failed to convert {md_file}")
        else:
            print(f"❌ File not found: {md_file}")

    print(f"\\n📊 Conversion Summary:")
    print(f"Successful conversions: {success_count}/{len(conversions)}")

    # List generated PDFs
    pdf_files = list(Path('.').glob('*.pdf'))
    if pdf_files:
        print(f"\\n📄 Generated PDF files:")
        for pdf_file in pdf_files:
            size = pdf_file.stat().st_size / 1024 / 1024
            print(f"  • {pdf_file.name} ({size:.1f} MB)")

    print(f"\\n✅ Alternative PDF generation complete!")

if __name__ == "__main__":
    main()