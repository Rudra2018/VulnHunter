# IEEE TDSC Manuscript Compilation Instructions

## Manuscript Information
- **Title**: Security Intelligence Framework: A Unified Mathematical Approach for Autonomous Vulnerability Detection
- **Submission ID**: TDSC-2025-10-1683
- **Format**: IEEE Computer Society Double-Column Template
- **File**: `tdsc_manuscript.tex`

## Option 1: Compile Locally (Recommended)

### Install LaTeX (macOS)
```bash
# Install BasicTeX (smaller) or MacTeX (full)
brew install --cask basictex

# Update PATH (restart terminal or run):
eval "$(/usr/libexec/path_helper)"

# Install required packages
sudo tlmgr update --self
sudo tlmgr install IEEEtran cite amsmath algorithmic booktabs multirow
```

### Compile the Manuscript
```bash
cd /Users/ankitthakur/vuln_ml_research/documentation

# First pass
pdflatex tdsc_manuscript.tex

# Run bibtex for references
bibtex tdsc_manuscript

# Two more passes to resolve references
pdflatex tdsc_manuscript.tex
pdflatex tdsc_manuscript.tex
```

### Output
The compiled PDF will be: `tdsc_manuscript.pdf`

## Option 2: Use Overleaf (Online - No Installation Required)

### Steps:
1. Go to [https://www.overleaf.com](https://www.overleaf.com)
2. Create a free account (if you don't have one)
3. Click **New Project** → **Upload Project**
4. Upload `tdsc_manuscript.tex`
5. Click **Recompile** to generate PDF
6. Download the PDF using the **Download** button

### Advantages:
- No local LaTeX installation needed
- Automatic compilation
- Cloud storage and version control
- Collaboration features

## Option 3: Use Docker

```bash
# Pull LaTeX Docker image
docker pull texlive/texlive:latest

# Compile manuscript
cd /Users/ankitthakur/vuln_ml_research/documentation
docker run --rm -v "$PWD":/workspace -w /workspace texlive/texlive:latest \
  sh -c "pdflatex tdsc_manuscript.tex && bibtex tdsc_manuscript && pdflatex tdsc_manuscript.tex && pdflatex tdsc_manuscript.tex"
```

## Option 4: Online LaTeX Compilers

Use any of these free online compilers:
- **Overleaf**: https://www.overleaf.com (Recommended)
- **Papeeria**: https://papeeria.com
- **TeXLive.net**: https://texlive.net

Simply paste the contents of `tdsc_manuscript.tex` and compile.

## Verification Checklist

Before submitting, verify:
- [ ] Double-column format (IEEE Computer Society style)
- [ ] 10pt font size
- [ ] All sections present (Abstract, Introduction, Related Work, etc.)
- [ ] References formatted correctly (IEEE style)
- [ ] Figures and tables properly captioned
- [ ] Author information complete
- [ ] Keywords included
- [ ] Page numbers visible
- [ ] PDF generated successfully

## IEEE TDSC Submission

### Submission Portal
Choose the correct portal based on your original submission:

**Option A: IEEE Author Portal** (NEW system)
- URL: https://ieee.atyponrex.com/journal/tdsc-cs
- Upload: `tdsc_manuscript.pdf`

**Option B: ScholarOne Manuscripts** (OLD system)
- URL: https://mc.manuscriptcentral.com/tdsc-cs
- Upload: `tdsc_manuscript.pdf`

### Required Files
1. **Main Manuscript**: `tdsc_manuscript.pdf` (compiled from .tex)
2. **LaTeX Source**: `tdsc_manuscript.tex` (optional but recommended)
3. **Cover Letter**: Explain the reformatting (see below)

## Sample Cover Letter

```
Dear Dr. Rawat,

Thank you for your feedback regarding manuscript TDSC-2025-10-1683.

I have reformatted the manuscript using the IEEE Computer Society
double-column template as requested. The updated manuscript now
complies with all IEEE TDSC formatting requirements:

- Double-column, single-spaced layout
- IEEE Computer Society template (IEEEtran class)
- 10pt font throughout
- Proper section formatting
- IEEE reference style

The manuscript content remains unchanged from the original submission.

I am uploading the revised manuscript to [IEEE Author Portal /
ScholarOne - specify which one you used originally].

Please let me know if any additional changes are required.

Thank you for your consideration.

Sincerely,
Ankit Thakur
```

## Troubleshooting

### Missing IEEEtran Class
```bash
sudo tlmgr install IEEEtran
```

### Missing Packages
```bash
sudo tlmgr install <package-name>
```

### Compilation Errors
- Check for syntax errors in the .tex file
- Ensure all packages are installed
- Run `pdflatex` multiple times (3x) to resolve references
- Check the `.log` file for detailed error messages

## File Structure

After compilation, you should have:
```
documentation/
├── tdsc_manuscript.tex       # Source file
├── tdsc_manuscript.pdf       # Output PDF (for submission)
├── tdsc_manuscript.aux       # Auxiliary file
├── tdsc_manuscript.log       # Compilation log
├── tdsc_manuscript.bbl       # Bibliography
└── COMPILATION_INSTRUCTIONS.md  # This file
```

## Next Steps

1. **Compile** the manuscript using one of the options above
2. **Review** the generated PDF carefully
3. **Update** author information (email, affiliation) in the .tex file
4. **Recompile** after any changes
5. **Submit** to IEEE TDSC via the appropriate portal

## Additional Resources

- IEEE Author Resources: https://www.computer.org/publications/author-resources
- IEEEtran Documentation: http://mirrors.ctan.org/macros/latex2e/contrib/IEEEtran/IEEEtran_HOWTO.pdf
- LaTeX Help: https://www.latex-project.org/help/

## Questions?

If you encounter issues:
1. Check the compilation log file (`.log`)
2. Search for the error message online
3. Ask on TeX StackExchange: https://tex.stackexchange.com
4. Contact IEEE TDSC support: tdsc@computer.org

---

**Good luck with your submission!**
