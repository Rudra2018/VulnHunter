# 🚀 Quick Start: Compile & Submit Your TDSC Manuscript

## ⚡ Fastest Method (5 Minutes)

### Using Overleaf (No Installation Required)

1. **Go to Overleaf**
   - Visit: https://www.overleaf.com
   - Sign up (free account)

2. **Upload Manuscript**
   - Click: **New Project** → **Upload Project**
   - Select: `documentation/tdsc_manuscript.tex`
   - Or drag-and-drop the file

3. **Edit Author Info**
   - Find line ~18 in the editor
   - Replace `[Your Institution/Affiliation]` with your university/company
   - Replace `[your-email@example.com]` with your actual email

4. **Compile**
   - Click: **Recompile** button (green button at top)
   - PDF appears on right side

5. **Download PDF**
   - Click: **Download** → **PDF**
   - Save as: `tdsc_manuscript.pdf`

6. **Submit**
   - Go to submission portal (check your email for correct link):
     - IEEE Author Portal: https://ieee.atyponrex.com/journal/tdsc-cs
     - OR ScholarOne: https://mc.manuscriptcentral.com/tdsc-cs
   - Upload your PDF
   - Done! ✅

---

## 💻 Alternative: Local Compilation

### If you prefer compiling on your Mac:

```bash
# Step 1: Install LaTeX (one-time, requires sudo)
brew install --cask basictex
eval "$(/usr/libexec/path_helper)"

# Step 2: Update your info in the manuscript
open -a TextEdit documentation/tdsc_manuscript.tex
# OR use your preferred editor:
# code documentation/tdsc_manuscript.tex
# vim documentation/tdsc_manuscript.tex

# Step 3: Compile (run from project root)
cd /Users/ankitthakur/vuln_ml_research/documentation
pdflatex tdsc_manuscript.tex
bibtex tdsc_manuscript
pdflatex tdsc_manuscript.tex
pdflatex tdsc_manuscript.tex

# Step 4: View PDF
open tdsc_manuscript.pdf

# Step 5: Submit (same as above)
```

---

## ✏️ What to Update Before Submitting

Open `documentation/tdsc_manuscript.tex` and update:

### 1. Email Address (Line 24) - **REQUIRED**
**Find**:
```latex
E-mail: your.email@example.com
```

**Replace with**:
```latex
E-mail: ankit.thakur@yourdomain.com
```

### 2. Affiliation (Line 24) - Optional
**Current**:
```latex
A. Thakur is an Independent Researcher in Security Intelligence and Machine Learning.
```

**Keep as-is or update to**:
```latex
A. Thakur is with Stanford University, Department of Computer Science.
```

### 3. Author Biography (Lines 460-462) - Optional
**Current**: Generic biography

**Customize with**:
- Your actual degree/credentials
- Specific research focus
- Notable achievements

### 4. Funding (Line ~542) - Optional
**Find**:
```latex
This work was supported by [Funding Sources - add if applicable].
```

**Replace or delete** if no funding.

---

## 📤 Submission

### Step 1: Determine Your Portal
Check your **original submission email** from IEEE TDSC. Look for:
- "IEEE Author Portal" → Use Portal A
- "ScholarOne" or "Manuscript Central" → Use Portal B

### Step 2: Upload
**Portal A** (IEEE Author Portal):
- URL: https://ieee.atyponrex.com/journal/tdsc-cs
- Upload: `tdsc_manuscript.pdf`

**Portal B** (ScholarOne):
- URL: https://mc.manuscriptcentral.com/tdsc-cs
- Upload: `tdsc_manuscript.pdf`

### Step 3: Cover Letter (Optional but Recommended)
```
Dear Dr. Rawat,

Thank you for the feedback on TDSC-2025-10-1683.

I have reformatted the manuscript using the IEEE Computer Society
double-column template as requested. All formatting requirements
are now met.

Best regards,
Ankit Thakur
```

---

## ❓ FAQ

**Q: I don't know LaTeX, what do I do?**
A: Use Overleaf! It's designed for non-LaTeX experts. Just upload and click compile.

**Q: The PDF looks weird after compilation**
A: Make sure to compile 3 times with pdflatex (LaTeX needs multiple passes for references)

**Q: I'm getting errors**
A: Use Overleaf instead - it handles all packages automatically

**Q: Which submission portal should I use?**
A: Check your original submission confirmation email - it will mention either "Author Portal" or "ScholarOne"

**Q: How long is the manuscript?**
A: Approximately 12-14 pages in double-column format

**Q: Can I modify the content?**
A: Yes! Edit the .tex file as needed, then recompile

---

## 📋 Pre-Submission Checklist

- [ ] Manuscript compiled successfully
- [ ] PDF opens and looks professional
- [ ] Author name and email updated
- [ ] Institution/affiliation added
- [ ] Funding info added or removed
- [ ] PDF downloaded/saved
- [ ] Correct submission portal identified
- [ ] Cover letter prepared (optional)
- [ ] Ready to upload!

---

## 🎯 Summary

**What you have**: IEEE TDSC-formatted manuscript in LaTeX
**What you need**: Compile to PDF and submit
**Easiest way**: Overleaf (5 minutes)
**Alternative**: Local pdflatex compilation

**Your manuscript ID**: TDSC-2025-10-1683

---

## 📚 More Help

- Detailed compilation guide: `COMPILATION_INSTRUCTIONS.md`
- Complete reference: `README_TDSC_SUBMISSION.md`
- Full summary: `SUBMISSION_SUMMARY.md`

---

## ✅ Ready to Go!

Your manuscript is properly formatted and ready for submission.

**Next action**: Choose Overleaf or local compilation above.

**Estimated time**: 5-15 minutes total.

**Good luck!** 🎉
