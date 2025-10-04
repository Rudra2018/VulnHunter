# IEEE TDSC Pre-Submission Checklist

## 📋 Essential Checks Before Submission

Use this checklist to ensure your manuscript meets all IEEE TDSC requirements.

---

## ✅ Author Information

- [ ] **Email address updated** (Line 24)
  - Current: `your.email@example.com`
  - Update to: Your actual email

- [ ] **Affiliation updated** (Line 24)
  - Current: `Independent Researcher`
  - Options:
    - Keep "Independent Researcher" (if applicable)
    - Or change to: "University Name" / "Company Name"

- [ ] **Author bio updated** (Line 460-462)
  - Review and personalize the biography
  - Add your actual degree/credentials
  - Update research interests if needed

- [ ] **Photo placeholder** (Line 460)
  - Keep `{photo}` as placeholder (LaTeX will handle gracefully)
  - Or add actual photo file: `photo.jpg` or `photo.png`
  - Photo specs: 1 inch wide × 1.25 inches high

---

## ✅ Formatting Requirements

- [ ] **Document class correct**: `\documentclass[10pt,journal,compsoc]{IEEEtran}`
  - ✅ Already set correctly

- [ ] **Double-column format**
  - ✅ IEEEtran handles this automatically

- [ ] **10pt font throughout**
  - ✅ Set in document class

- [ ] **Page limit**: ≤18 pages (including references)
  - ⚠️ Check after compilation
  - If >18 pages, consider:
    - Condensing Introduction/Related Work
    - Moving details to appendix (if TDSC allows)
    - Reducing table sizes
    - Shortening case studies

---

## ✅ Content Structure

- [ ] **Title present and descriptive**
  - ✅ Current: "Security Intelligence Framework: A Unified Mathematical Approach for Autonomous Vulnerability Detection"

- [ ] **Abstract present** (200-250 words recommended)
  - ✅ Current: ~250 words

- [ ] **Keywords included** (5-10 keywords)
  - ✅ Current: 7 keywords

- [ ] **All required sections**:
  - ✅ Introduction with clear contributions
  - ✅ Related Work
  - ✅ Methodology (Framework Architecture)
  - ✅ Implementation
  - ✅ Evaluation/Experiments
  - ✅ Case Studies (optional but strong)
  - ✅ Discussion/Limitations
  - ✅ Conclusion
  - ✅ References

- [ ] **Author biography included**
  - ✅ Added at end (customize it)

---

## ✅ References

- [ ] **IEEE reference style**
  - ✅ Using `\bibliographystyle{IEEEtran}`

- [ ] **All references cited in text**
  - ✅ Current: 12 references, all cited

- [ ] **References complete and formatted**
  - Check each reference has:
    - Author names
    - Title
    - Publication venue
    - Year
    - Page numbers (if applicable)

- [ ] **No broken citations**
  - Compile 3x to verify all `\cite{}` commands resolve

---

## ✅ Figures and Tables (If Added)

- [ ] **All figures have captions**
  - Format: `\caption{Description of figure.}`

- [ ] **All figures referenced in text**
  - Use: `Fig.~\ref{fig:label}` or `Figure~\ref{fig:label}`

- [ ] **All tables have captions**
  - ✅ Current tables (3) have captions

- [ ] **Figure/table quality**
  - Minimum 300 DPI for images
  - Vector graphics (PDF) preferred
  - Readable when printed in grayscale

- [ ] **Figure files included**
  - If using `\includegraphics{file.pdf}`, include the file
  - Or use placeholder text for now

---

## ✅ Mathematical Content

- [ ] **All equations numbered** (if referenced)
  - ✅ Current: 15+ equations, properly numbered

- [ ] **Equations readable**
  - Check subscripts/superscripts not too small
  - Verify special symbols render correctly

- [ ] **Math notation consistent**
  - Same symbols mean same things throughout

---

## ✅ Technical Accuracy

- [ ] **Results match claims**
  - Verify all percentages/numbers in abstract match evaluation section

- [ ] **No placeholder text**
  - Search for: `[TODO]`, `[XXX]`, `[FIXME]`
  - Current status: ✅ None found

- [ ] **Consistent terminology**
  - Same terms used throughout (e.g., "framework" vs "system")

- [ ] **Acronyms defined on first use**
  - Example: "Graph Neural Network (GNN)" then "GNN" after

---

## ✅ Ethical Considerations

- [ ] **Responsible disclosure mentioned**
  - ✅ Included in Discussion section

- [ ] **No active exploits provided**
  - ✅ Only detection methods described

- [ ] **Ethical guidelines followed**
  - ✅ Defensive security focus stated

- [ ] **CVE/vulnerability disclosure proper**
  - ✅ Followed coordinated disclosure

---

## ✅ Compilation

- [ ] **Compiles without errors**
  ```bash
  pdflatex tdsc_manuscript.tex
  bibtex tdsc_manuscript
  pdflatex tdsc_manuscript.tex
  pdflatex tdsc_manuscript.tex
  ```

- [ ] **No compilation warnings** (or minimal/acceptable)
  - Check `.log` file for issues

- [ ] **PDF opens correctly**
  - Test opening in Adobe Reader, Preview, browser

- [ ] **All pages present**
  - Count pages in PDF viewer

- [ ] **No weird spacing/formatting**
  - Review each page visually
  - Check column breaks look reasonable
  - Verify tables fit within columns

---

## ✅ Final Review

- [ ] **Spell check completed**
  - Use editor's spell checker
  - Common typos: "occured" → "occurred", "recieve" → "receive"

- [ ] **Grammar check**
  - Read abstract and conclusion aloud
  - Verify sentence clarity

- [ ] **Consistent verb tense**
  - Usually: present tense for describing framework
  - Past tense for experiments ("we evaluated")

- [ ] **No first-person excessive use**
  - Prefer: "The framework achieves..." vs "We achieve..."
  - Some first-person is OK in Introduction/Conclusion

- [ ] **Professional tone throughout**
  - No informal language
  - No marketing language ("revolutionary", "unprecedented")

---

## ✅ Submission Portal

- [ ] **Correct portal identified**
  - Check original submission email
  - Portal A: https://ieee.atyponrex.com/journal/tdsc-cs
  - Portal B: https://mc.manuscriptcentral.com/tdsc-cs

- [ ] **Manuscript ID ready**
  - TDSC-2025-10-1683

- [ ] **Files prepared**
  - Required: `tdsc_manuscript.pdf`
  - Optional: `tdsc_manuscript.tex` (source)
  - Optional: Cover letter

- [ ] **Cover letter written** (recommended)
  - Acknowledge reformatting request
  - Confirm IEEE template compliance
  - Brief and professional

---

## ✅ Specific TDSC Requirements

- [ ] **Page limit**: ≤18 pages
  - ⚠️ Verify after compilation

- [ ] **Figures**: Color OK but must be readable in grayscale
  - TDSC prints in black & white

- [ ] **Supplementary materials** (if any)
  - Code/data can be submitted separately
  - Not required but can strengthen submission

- [ ] **Competing interests statement**
  - If applicable, declare any conflicts
  - Independent research: typically none

---

## 🔧 Quick Fixes for Common Issues

### Issue: PDF is >18 pages

**Solutions**:
- Reduce Introduction/Related Work by 10-15%
- Condense case study descriptions
- Use more compact table formatting
- Remove redundant paragraphs in Discussion
- Consider moving implementation details to appendix

### Issue: Missing author photo

**Solution**:
- Photo is optional for initial submission
- Can add during revision if accepted
- Keep placeholder `{photo}` for now - LaTeX handles gracefully

### Issue: References not compiling

**Solution**:
```bash
# Clean and rebuild
rm *.aux *.bbl *.blg *.log
pdflatex tdsc_manuscript.tex
bibtex tdsc_manuscript
pdflatex tdsc_manuscript.tex
pdflatex tdsc_manuscript.tex
```

### Issue: Figures not appearing

**Solution**:
- Verify figure files in same directory
- Check file extensions match `\includegraphics{}`
- Use `\usepackage{graphicx}` (already included)
- For now, figures are optional

---

## 📝 Critical Updates Needed

### 1. Email Address (LINE 24)
```latex
% CURRENT:
E-mail: your.email@example.com

% UPDATE TO:
E-mail: ankit.thakur@yourdomain.com  (or your actual email)
```

### 2. Affiliation (LINE 24) - Optional
```latex
% CURRENT:
A. Thakur is an Independent Researcher...

% ALTERNATIVES:
A. Thakur is with Stanford University...
A. Thakur is with Google Research...
(or keep "Independent Researcher" if accurate)
```

### 3. Author Bio (LINES 460-462) - Optional
```latex
% CURRENT:
received his degree in Computer Science and has been working in...

% CUSTOMIZE:
received his M.S. in Computer Science from [University]...
(add your actual credentials)
```

---

## ✅ Final Validation

Before clicking "Submit":

1. [ ] Open PDF and scroll through every page
2. [ ] Verify email address is correct (you'll get correspondence here)
3. [ ] Confirm page count ≤18
4. [ ] Check abstract reads well
5. [ ] Verify all sections present
6. [ ] Confirm references properly formatted
7. [ ] Test PDF opens on different device/viewer

---

## 🎯 Confidence Levels

**HIGH CONFIDENCE** - Already compliant:
- ✅ IEEE double-column format
- ✅ Document structure
- ✅ Section organization
- ✅ Mathematical formulations
- ✅ Reference formatting
- ✅ Professional writing quality

**MEDIUM CONFIDENCE** - Verify after compilation:
- ⚠️ Page count (target: 12-16 pages)
- ⚠️ All equations render correctly
- ⚠️ Tables fit within columns

**REQUIRES UPDATE** - Must change before submission:
- ❌ Email address (currently placeholder)
- ❌ Author affiliation (review if accurate)
- ❌ Author bio (customize if desired)

---

## 📊 Estimated Page Count

Based on content:
- Abstract: 0.25 pages
- Introduction: 1.5 pages
- Related Work: 1.5 pages
- Framework: 2.5 pages
- Implementation: 1.5 pages
- Evaluation: 2 pages
- Case Studies: 2 pages
- Discussion: 1.5 pages
- Conclusion: 0.5 pages
- References: 0.75 pages
- Biography: 0.25 pages

**Estimated Total: ~14 pages** ✅ (well under 18-page limit)

---

## 🚀 Ready to Submit?

### Green Light ✅ if:
- Email updated
- PDF compiles successfully
- Page count ≤18
- All sections present
- References complete

### Yellow Light ⚠️ if:
- Need to verify page count
- Want to add figures/diagrams
- Considering expanding evaluation

### Red Light ❌ if:
- Email still placeholder
- PDF won't compile
- >18 pages

---

## 📞 Support Resources

**LaTeX/Compilation Issues**:
- Use Overleaf: https://www.overleaf.com
- TeX StackExchange: https://tex.stackexchange.com

**TDSC Specific**:
- Journal info: https://www.computer.org/csdl/journal/tq
- Author guide: https://www.computer.org/publications/author-resources
- Contact editor: tdsc@computer.org

**Template Issues**:
- IEEEtran docs: http://mirrors.ctan.org/macros/latex2e/contrib/IEEEtran/

---

## ✅ Final Approval

I confirm that:
- [ ] All required updates completed
- [ ] PDF generated successfully
- [ ] Visual review passed
- [ ] Page limit met
- [ ] Ready for submission

**Date checked**: _______________

**Ready to submit**: YES / NO

---

## 🎉 Next Action

If all boxes checked:
1. Go to appropriate submission portal
2. Upload `tdsc_manuscript.pdf`
3. Submit cover letter (optional but recommended)
4. Confirm submission received
5. Wait for editor response

**Good luck with your submission!**
