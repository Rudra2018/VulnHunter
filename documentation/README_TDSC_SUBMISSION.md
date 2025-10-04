# IEEE TDSC Manuscript - Quick Reference

## 📄 Manuscript Details

**Title**: Security Intelligence Framework: A Unified Mathematical Approach for Autonomous Vulnerability Detection

**Submission ID**: TDSC-2025-10-1683

**Status**: Returned for reformatting

**Required Action**: Reformat using IEEE Computer Society double-column template

## 🎯 What Was Done

✅ Created IEEE TDSC-compliant LaTeX manuscript (`tdsc_manuscript.tex`)
✅ Applied IEEE Computer Society double-column template
✅ Formatted all sections according to IEEE standards
✅ Included proper citations and references
✅ Added mathematical formulations for framework
✅ Documented case studies and experimental results

## 📁 Files in This Directory

| File | Description |
|------|-------------|
| `tdsc_manuscript.tex` | **Main manuscript** in IEEE format (ready to compile) |
| `COMPILATION_INSTRUCTIONS.md` | **Detailed guide** for compiling the manuscript |
| `README_TDSC_SUBMISSION.md` | This quick reference file |

## 🚀 Quick Start

### Fastest Way: Use Overleaf (No Installation)

1. Go to https://www.overleaf.com
2. Sign up/login (free)
3. New Project → Upload Project
4. Upload `tdsc_manuscript.tex`
5. Click "Recompile"
6. Download PDF

**Time: ~5 minutes**

### Alternative: Compile Locally

```bash
# Install LaTeX (one-time setup)
brew install --cask basictex
eval "$(/usr/libexec/path_helper)"

# Compile manuscript
cd /Users/ankitthakur/vuln_ml_research/documentation
pdflatex tdsc_manuscript.tex
bibtex tdsc_manuscript
pdflatex tdsc_manuscript.tex
pdflatex tdsc_manuscript.tex
```

## 📝 What's Inside the Manuscript

### Structure (IEEE TDSC Standard)

1. **Title & Authors** - Properly formatted header
2. **Abstract** (200-250 words) - Comprehensive summary
3. **Keywords** - 7 relevant keywords
4. **Introduction** - Problem motivation and contributions
5. **Related Work** - Comprehensive literature review
6. **Framework Architecture** - Technical approach with equations
7. **Implementation** - System details and configuration
8. **Evaluation** - Experimental results and comparisons
9. **Case Studies** - Real-world vulnerability discoveries
10. **Discussion** - Limitations and future work
11. **Conclusion** - Summary and impact
12. **References** - IEEE-formatted bibliography

### Key Content Highlights

- **Mathematical Framework**: Formal equations for GNN, transformers, and neural-formal verification
- **Novel Contributions**: First neural-formal integration for vulnerability detection
- **Experimental Results**: 100% accuracy, 11+ samples/sec throughput
- **Real-World Impact**: Vulnerabilities found in Transformers, LangChain, vLLM
- **Comprehensive Evaluation**: Comparison with Coverity, VulDeePecker, Devign

## ✏️ Before Submitting - Update These Fields

### In `tdsc_manuscript.tex`, search and replace:

1. **Author Affiliation** (Line ~18):
   ```latex
   \thanks{A. Thakur is with [Your Institution/Affiliation]. E-mail: [your-email@example.com]}
   ```
   Replace with your actual institution and email.

2. **Funding Acknowledgment** (Line ~542):
   ```latex
   This work was supported by [Funding Sources - add if applicable].
   ```
   Add funding sources or remove if none.

3. **Contact Email** (Multiple locations):
   Replace `[your-email@example.com]` with your actual email.

### Quick Find & Replace Commands

```bash
# Open in your favorite editor
code documentation/tdsc_manuscript.tex  # VS Code
vim documentation/tdsc_manuscript.tex   # Vim
nano documentation/tdsc_manuscript.tex  # Nano
```

## 📤 Submission Process

### Step 1: Compile Manuscript
Follow instructions in `COMPILATION_INSTRUCTIONS.md` to generate `tdsc_manuscript.pdf`

### Step 2: Choose Submission Portal

**Check your original submission email** to determine which portal you used:

**Option A**: IEEE Author Portal (NEW)
- URL: https://ieee.atyponrex.com/journal/tdsc-cs
- Look for "IEEE Author Portal" in original confirmation

**Option B**: ScholarOne Manuscripts (OLD)
- URL: https://mc.manuscriptcentral.com/tdsc-cs
- Look for "ScholarOne" or "Manuscript Central" in confirmation

### Step 3: Upload Files

Required:
- `tdsc_manuscript.pdf` (compiled output)

Optional but Recommended:
- `tdsc_manuscript.tex` (source file)
- Cover letter explaining reformatting

### Step 4: Write Cover Letter

Template:
```
Dear Dr. Rawat,

Thank you for the feedback on manuscript TDSC-2025-10-1683.

I have reformatted the manuscript using the IEEE Computer Society
double-column template. The revised version complies with all
formatting requirements while maintaining the original content.

Please let me know if any additional changes are needed.

Best regards,
Ankit Thakur
```

## 📊 Manuscript Statistics

- **Length**: ~12-14 pages (double-column)
- **Sections**: 8 major sections + subsections
- **Equations**: 15+ mathematical formulations
- **Tables**: 3 comparison/results tables
- **References**: 12 key citations (IEEE format)
- **Case Studies**: 3 major vulnerability discoveries

## 🔍 Pre-Submission Checklist

Before uploading, verify:

- [ ] PDF compiles without errors
- [ ] Double-column format throughout
- [ ] Author name and affiliation updated
- [ ] Email address updated
- [ ] Abstract present and properly formatted
- [ ] All sections included
- [ ] Equations rendered correctly
- [ ] Tables formatted properly
- [ ] References in IEEE style
- [ ] Page numbers visible
- [ ] No compilation warnings (or minimal)

## 💡 Tips for Success

### 1. Review the PDF Carefully
Open the compiled PDF and check:
- Formatting looks professional
- No weird line breaks or spacing
- Equations are readable
- Tables fit within columns
- References are complete

### 2. Compare with IEEE Examples
Look at other TDSC papers to ensure similar formatting:
- https://ieeexplore.ieee.org/xpl/RecentIssue.jsp?punumber=8858

### 3. Use Overleaf for Convenience
If local compilation is problematic:
- Overleaf handles all package management
- Real-time PDF preview
- No installation hassles
- Can share with collaborators

### 4. Keep Source Files
After submission, maintain:
- Original `.tex` file
- Compiled `.pdf` file
- Any response letters
- Review correspondence

## 🆘 Common Issues & Solutions

### Issue: "IEEEtran class not found"
**Solution**: Use Overleaf or install: `sudo tlmgr install IEEEtran`

### Issue: "Package XYZ not found"
**Solution**: Install missing package: `sudo tlmgr install <package-name>`

### Issue: "Undefined references"
**Solution**: Run pdflatex 3 times + bibtex once

### Issue: "PDF looks wrong"
**Solution**: Clear auxiliary files and recompile:
```bash
rm *.aux *.log *.out *.bbl *.blg
pdflatex tdsc_manuscript.tex (x3)
```

### Issue: "Can't install LaTeX locally"
**Solution**: Use Overleaf (online, no installation needed)

## 📚 Additional Resources

### IEEE Resources
- TDSC Journal: https://www.computer.org/csdl/journal/tq
- Author Resources: https://www.computer.org/publications/author-resources
- Template Download: https://www.computer.org/publications/author-resources/peer-review/journals#templates

### LaTeX Help
- Overleaf Tutorials: https://www.overleaf.com/learn
- LaTeX StackExchange: https://tex.stackexchange.com
- IEEEtran Guide: http://mirrors.ctan.org/macros/latex2e/contrib/IEEEtran/IEEEtran_HOWTO.pdf

### Compilation Help
- See `COMPILATION_INSTRUCTIONS.md` in this directory
- Docker option available for isolated compilation
- Online compilers listed with links

## 🎓 About the Manuscript

This manuscript presents your **Security Intelligence Framework** combining:
- Graph Neural Networks
- Multi-scale Transformers
- Neural-Formal Verification (first integration for vulnerability detection)
- Adversarial Robustness

**Key Results**:
- 100% accuracy on comprehensive test suite
- 11+ samples/second throughput
- Critical vulnerabilities found in major open-source projects
- 25% better than state-of-the-art approaches

**Novel Contributions**:
1. First neural-formal verification for vulnerability detection
2. Multi-modal architecture (GNN + Transformer + Formal)
3. Production-ready system with enterprise controls
4. Comprehensive real-world evaluation

## 📞 Need Help?

1. **Compilation Issues**: See `COMPILATION_INSTRUCTIONS.md`
2. **LaTeX Errors**: Check StackExchange or use Overleaf
3. **Submission Portal**: Contact tdsc@computer.org
4. **Content Questions**: Review your original research notes

## ✅ Final Steps

1. [ ] Update author information in `.tex` file
2. [ ] Compile manuscript to generate PDF
3. [ ] Review PDF carefully
4. [ ] Prepare cover letter
5. [ ] Upload to correct submission portal
6. [ ] Confirm submission received
7. [ ] Wait for editor response

---

## 🎉 You're Ready!

Everything is prepared for your IEEE TDSC resubmission. The manuscript is properly formatted, comprehensive, and ready for compilation.

**Next Action**: Compile `tdsc_manuscript.tex` using Overleaf or local LaTeX installation.

**Good luck with your submission!** 🚀
