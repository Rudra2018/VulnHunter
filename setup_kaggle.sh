#!/bin/bash

# VulnGuard AI - Kaggle Setup Script
# Sets up Kaggle API and downloads vulnerability datasets

set -e

echo "🚀 VulnGuard AI - Kaggle Dataset Setup"
echo "========================================"
echo ""

# Step 1: Install Kaggle API
echo "📦 Step 1: Installing Kaggle API..."
python3 -m pip install --upgrade kaggle

# Step 2: Check for Kaggle credentials
echo ""
echo "🔑 Step 2: Checking Kaggle API credentials..."

if [ ! -f ~/.kaggle/kaggle.json ]; then
    echo "❌ Kaggle credentials not found!"
    echo ""
    echo "📝 To set up Kaggle API credentials:"
    echo "   1. Go to: https://www.kaggle.com/settings"
    echo "   2. Scroll to 'API' section"
    echo "   3. Click 'Create New API Token'"
    echo "   4. This downloads 'kaggle.json'"
    echo "   5. Move it to ~/.kaggle/:"
    echo ""
    echo "      mkdir -p ~/.kaggle"
    echo "      mv ~/Downloads/kaggle.json ~/.kaggle/"
    echo "      chmod 600 ~/.kaggle/kaggle.json"
    echo ""
    echo "Then run this script again!"
    exit 1
else
    echo "✅ Kaggle credentials found!"
    chmod 600 ~/.kaggle/kaggle.json
fi

# Step 3: Create data directory
echo ""
echo "📁 Step 3: Creating data directory..."
mkdir -p ./data/kaggle
echo "✅ Directory created: ./data/kaggle"

# Step 4: Download datasets
echo ""
echo "📥 Step 4: Downloading Kaggle datasets..."
echo "This may take a while depending on your internet connection..."
echo ""

DATASETS=(
    "umer7arooq/public-cve-vulnerabilities-20202024:public-cve-2020-2024"
    "angelcortez/cve-data:cve-data"
    "mayankkumarpoddar/bug-bounty-writeups:bug-bounty-writeups"
    "casimireffect/cve-dataset:cve-dataset"
    "daudthecat/bug-bounty-openai-gpt-oss-20b-by-thecat:bug-bounty-openai"
)

SUCCESS_COUNT=0
TOTAL=${#DATASETS[@]}

for dataset_info in "${DATASETS[@]}"; do
    IFS=':' read -r dataset_path dataset_name <<< "$dataset_info"

    echo ""
    echo "📥 Downloading: $dataset_name"
    echo "   From: $dataset_path"

    if kaggle datasets download -d "$dataset_path" -p "./data/kaggle/$dataset_name" --unzip 2>&1; then
        echo "✅ Downloaded: $dataset_name"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "⚠️  Failed to download: $dataset_name"
        echo "   You can download manually from:"
        echo "   https://www.kaggle.com/datasets/$dataset_path"
    fi
done

# Summary
echo ""
echo "========================================"
echo "📊 Download Summary"
echo "========================================"
echo "Downloaded: $SUCCESS_COUNT / $TOTAL datasets"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "✅ Setup complete!"
    echo ""
    echo "📁 Datasets location: ./data/kaggle/"
    echo ""
    echo "🎯 Next steps:"
    echo "   1. Train the model:"
    echo "      python3 train_with_kaggle.py --data-path ./data/kaggle"
    echo ""
    echo "   2. Or use automatic training:"
    echo "      python3 train_with_kaggle.py --download"
    echo ""
else
    echo "⚠️  No datasets were downloaded successfully"
    echo ""
    echo "💡 You can still train with HuggingFace datasets:"
    echo "   python3 train_with_kaggle.py --huggingface-only"
fi

echo ""
echo "🎉 Setup script completed!"
