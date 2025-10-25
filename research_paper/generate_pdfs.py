#!/usr/bin/env python3
"""
PDF Generation Script for VulnHunter Research Paper and Presentation
Converts Markdown files to professional PDF documents suitable for submission
"""

import os
import subprocess
import sys
from pathlib import Path

def check_pandoc():
    """Check if pandoc is installed"""
    try:
        subprocess.run(['pandoc', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_pandoc():
    """Install pandoc via homebrew on macOS"""
    print("Installing pandoc via homebrew...")
    try:
        subprocess.run(['brew', 'install', 'pandoc'], check=True)
        subprocess.run(['brew', 'install', '--cask', 'basictex'], check=True)
        print("✅ Pandoc and BasicTeX installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install pandoc. Please install manually:")
        print("brew install pandoc")
        print("brew install --cask basictex")
        return False

def generate_research_paper_pdf():
    """Generate PDF from research paper markdown"""
    input_file = "VulnHunter_Omega_VHS_Research_Paper.md"
    output_file = "VulnHunter_Omega_VHS_Research_Paper.pdf"

    # LaTeX template for academic paper
    latex_template = """
\\documentclass[11pt,a4paper]{article}
\\usepackage[utf8]{inputenc}
\\usepackage[english]{babel}
\\usepackage{amsmath,amsfonts,amssymb}
\\usepackage{graphicx}
\\usepackage{hyperref}
\\usepackage{geometry}
\\usepackage{fancyhdr}
\\usepackage{setspace}
\\usepackage{booktabs}
\\usepackage{longtable}
\\usepackage{algorithm}
\\usepackage{algpseudocode}

\\geometry{margin=1in}
\\doublespacing
\\pagestyle{fancy}
\\fancyhf{}
\\rhead{\\thepage}
\\lhead{VulnHunter Ωmega + VHS}

\\title{Vulnerability Homotopy Space: Mathematical Topology for Cybersecurity Precision}
\\author{Research Team}
\\date{\\today}

\\begin{document}
\\maketitle
\\tableofcontents
\\newpage
"""

    pandoc_args = [
        'pandoc',
        input_file,
        '-o', output_file,
        '--pdf-engine=pdflatex',
        '--template=eisvogel',
        '--listings',
        '--number-sections',
        '--toc',
        '--bibliography=references.bib',
        '--csl=ieee.csl',
        '-V', 'geometry:margin=1in',
        '-V', 'fontsize=11pt',
        '-V', 'documentclass=article',
        '-V', 'classoption=twocolumn',
        '--highlight-style=github'
    ]

    # Fallback to simpler pandoc if template not available
    simple_args = [
        'pandoc',
        input_file,
        '-o', output_file,
        '--pdf-engine=pdflatex',
        '--number-sections',
        '--toc',
        '-V', 'geometry:margin=1in',
        '-V', 'fontsize=11pt'
    ]

    try:
        print(f"🔄 Generating research paper PDF: {output_file}")
        subprocess.run(pandoc_args, check=True)
        print(f"✅ Research paper PDF generated successfully!")
    except subprocess.CalledProcessError:
        print("⚠️ Advanced template failed, trying simple conversion...")
        try:
            subprocess.run(simple_args, check=True)
            print(f"✅ Research paper PDF generated with simple template!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate research paper PDF: {e}")
            return False

    return True

def generate_presentation_pdf():
    """Generate PDF from presentation markdown"""
    input_file = "VulnHunter_Conference_Presentation.md"
    output_file = "VulnHunter_Conference_Presentation.pdf"

    pandoc_args = [
        'pandoc',
        input_file,
        '-o', output_file,
        '-t', 'beamer',
        '--pdf-engine=pdflatex',
        '--slide-level=2',
        '-V', 'theme=Singapore',
        '-V', 'colortheme=seahorse',
        '-V', 'fonttheme=structurebold',
        '-V', 'navigation=horizontal',
        '--highlight-style=github'
    ]

    # Fallback beamer options
    simple_args = [
        'pandoc',
        input_file,
        '-o', output_file,
        '-t', 'beamer',
        '--pdf-engine=pdflatex',
        '--slide-level=2'
    ]

    try:
        print(f"🔄 Generating presentation PDF: {output_file}")
        subprocess.run(pandoc_args, check=True)
        print(f"✅ Presentation PDF generated successfully!")
    except subprocess.CalledProcessError:
        print("⚠️ Advanced beamer template failed, trying simple conversion...")
        try:
            subprocess.run(simple_args, check=True)
            print(f"✅ Presentation PDF generated with simple template!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate presentation PDF: {e}")
            return False

    return True

def create_references_file():
    """Create a basic references.bib file for citations"""
    references = """
@misc{vulnhunter2024,
  title={Vulnerability Homotopy Space: Mathematical Topology for Cybersecurity Precision},
  author={Research Team},
  year={2024},
  note={Available at: https://github.com/vulnhunter/omega-vhs}
}

@article{carlsson2009topology,
  title={Topology and data},
  author={Carlsson, Gunnar},
  journal={Bulletin of the American Mathematical Society},
  volume={46},
  number={2},
  pages={255--308},
  year={2009}
}

@inproceedings{li2018vuldeepecker,
  title={VulDeePecker: A deep learning-based system for vulnerability detection},
  author={Li, Zhen and Zou, Deqing and Xu, Shouhuai and Ou, Xinyu and Jin, Hai and Wang, Sujuan and Deng, Zhijun and Zhong, Yuyi},
  booktitle={Proceedings of the 25th Annual Network and Distributed System Security Symposium},
  year={2018}
}

@inproceedings{zhou2019devign,
  title={Devign: Effective vulnerability identification by learning comprehensive program semantics via graph neural networks},
  author={Zhou, Yaqin and Liu, Shangqing and Siow, Jingkai and Du, Xiaoning and Liu, Yang},
  booktitle={Advances in Neural Information Processing Systems},
  volume={32},
  year={2019}
}
"""

    with open("references.bib", "w") as f:
        f.write(references)
    print("✅ Created references.bib file")

def main():
    """Main function to generate PDFs"""
    print("🚀 VulnHunter Research Paper PDF Generator")
    print("=" * 50)

    # Check current directory
    current_dir = Path.cwd()
    print(f"Working directory: {current_dir}")

    # Change to research paper directory
    research_dir = Path("research_paper")
    if research_dir.exists():
        os.chdir(research_dir)
        print(f"Changed to: {Path.cwd()}")

    # Check for input files
    paper_file = Path("VulnHunter_Omega_VHS_Research_Paper.md")
    presentation_file = Path("VulnHunter_Conference_Presentation.md")

    if not paper_file.exists():
        print(f"❌ Research paper file not found: {paper_file}")
        return False

    if not presentation_file.exists():
        print(f"❌ Presentation file not found: {presentation_file}")
        return False

    # Check pandoc installation
    if not check_pandoc():
        print("❌ Pandoc not found. Installing...")
        if not install_pandoc():
            return False

    # Create references file
    create_references_file()

    # Generate PDFs
    success = True

    if generate_research_paper_pdf():
        print("✅ Research paper PDF generated successfully!")
    else:
        print("❌ Failed to generate research paper PDF")
        success = False

    if generate_presentation_pdf():
        print("✅ Presentation PDF generated successfully!")
    else:
        print("❌ Failed to generate presentation PDF")
        success = False

    # List generated files
    pdf_files = list(Path.cwd().glob("*.pdf"))
    if pdf_files:
        print("\\n📄 Generated PDF files:")
        for pdf_file in pdf_files:
            size = pdf_file.stat().st_size / 1024 / 1024
            print(f"  • {pdf_file.name} ({size:.1f} MB)")

    if success:
        print("\\n🎉 All PDF files generated successfully!")
        print("Ready for conference and journal submissions!")
    else:
        print("\\n⚠️ Some PDF generation failed. Check error messages above.")

    return success

if __name__ == "__main__":
    main()