#!/bin/bash

# Installation and Compilation Script for TDSC Manuscript
# This script requires sudo access to install LaTeX

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║          TDSC Manuscript Installation & Compilation Script            ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Check if LaTeX is installed
echo "📋 Step 1/4: Checking for LaTeX installation..."
if command -v pdflatex &> /dev/null; then
    echo "✅ pdflatex found: $(which pdflatex)"
    LATEX_VERSION=$(pdflatex --version | head -n 1)
    echo "   Version: $LATEX_VERSION"
else
    echo "❌ pdflatex not found. Installing BasicTeX..."
    echo ""
    echo "   This will require your password (sudo access)"
    echo "   BasicTeX size: ~100MB (vs MacTeX 4GB)"
    echo ""

    # Install BasicTeX via Homebrew
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install from https://brew.sh"
        exit 1
    fi

    echo "   Installing BasicTeX (this may take 2-5 minutes)..."
    brew install --cask basictex

    echo ""
    echo "✅ BasicTeX installed!"
    echo "   Updating PATH..."
    eval "$(/usr/libexec/path_helper)"

    # Verify installation
    if command -v pdflatex &> /dev/null; then
        echo "✅ pdflatex is now available"
    else
        echo "⚠️  pdflatex not found in PATH. You may need to:"
        echo "   1. Close and reopen your terminal"
        echo "   2. Run: eval \"\$(/usr/libexec/path_helper)\""
        echo "   3. Then run this script again"
        exit 1
    fi
fi

echo ""

# Step 2: Install required LaTeX packages
echo "📦 Step 2/4: Installing required LaTeX packages..."
REQUIRED_PACKAGES=(
    "IEEEtran"
    "cite"
    "amsmath"
    "amssymb"
    "amsfonts"
    "algorithmic"
    "graphicx"
    "booktabs"
    "multirow"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    echo "   Checking $package..."
    if ! kpsewhich "$package.sty" &> /dev/null; then
        echo "   Installing $package..."
        sudo tlmgr install "$package" 2>/dev/null || echo "   (may already be installed)"
    fi
done

echo "✅ All packages checked"
echo ""

# Step 3: Navigate to documentation directory
echo "📁 Step 3/4: Navigating to documentation directory..."
cd /Users/ankitthakur/vuln_ml_research/documentation

if [ ! -f "tdsc_manuscript.tex" ]; then
    echo "❌ Error: tdsc_manuscript.tex not found in $(pwd)"
    exit 1
fi

echo "✅ Found tdsc_manuscript.tex"
echo ""

# Step 4: Compile manuscript
echo "🔨 Step 4/4: Compiling manuscript (this may take 1-2 minutes)..."
echo ""

# First pass
echo "   [1/4] First pdflatex pass (generating aux files)..."
pdflatex -interaction=nonstopmode -halt-on-error tdsc_manuscript.tex > compile_log_1.txt 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Error in first compilation. Check compile_log_1.txt"
    tail -n 20 compile_log_1.txt
    exit 1
fi
echo "   ✅ First pass complete"

# BibTeX pass
echo "   [2/4] Running bibtex (processing bibliography)..."
bibtex tdsc_manuscript > compile_log_2.txt 2>&1 || true
echo "   ✅ BibTeX complete"

# Second pass
echo "   [3/4] Second pdflatex pass (resolving references)..."
pdflatex -interaction=nonstopmode -halt-on-error tdsc_manuscript.tex > compile_log_3.txt 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Error in second compilation. Check compile_log_3.txt"
    tail -n 20 compile_log_3.txt
    exit 1
fi
echo "   ✅ Second pass complete"

# Third pass
echo "   [4/4] Third pdflatex pass (finalizing)..."
pdflatex -interaction=nonstopmode -halt-on-error tdsc_manuscript.tex > compile_log_4.txt 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Error in third compilation. Check compile_log_4.txt"
    tail -n 20 compile_log_4.txt
    exit 1
fi
echo "   ✅ Third pass complete"

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ COMPILATION SUCCESSFUL! ✅                        ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📄 Output file: $(pwd)/tdsc_manuscript.pdf"
echo ""

# Check PDF size
if [ -f "tdsc_manuscript.pdf" ]; then
    PDF_SIZE=$(du -h tdsc_manuscript.pdf | cut -f1)
    PDF_PAGES=$(pdfinfo tdsc_manuscript.pdf 2>/dev/null | grep Pages | awk '{print $2}')
    echo "   Size: $PDF_SIZE"
    if [ ! -z "$PDF_PAGES" ]; then
        echo "   Pages: $PDF_PAGES"
    fi
fi

echo ""
echo "📖 To open the PDF:"
echo "   open tdsc_manuscript.pdf"
echo ""
echo "🔍 To check for warnings:"
echo "   grep -i warning tdsc_manuscript.log"
echo ""
echo "📊 Generated files:"
ls -lh tdsc_manuscript.pdf tdsc_manuscript.aux tdsc_manuscript.log 2>/dev/null || true

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  Next: Review the PDF and check for formatting issues                 ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
