#!/bin/bash
# VulnHunter NFV Installation Script
# Installs dependencies for Neural-Formal Verification

echo "🛡️ VulnHunter Neural-Formal Verification Setup"
echo "=============================================="

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install PyTorch (CPU version for compatibility)
echo "🔥 Installing PyTorch..."
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# Install PyTorch Geometric
echo "🧠 Installing PyTorch Geometric..."
pip install torch-geometric

# Install Z3 SMT Solver
echo "🧮 Installing Z3 SMT Solver..."
pip install z3-solver

# Install other requirements
echo "📚 Installing other dependencies..."
pip install -r requirements.txt

# Test installation
echo "🧪 Testing installation..."
python3 -c "import torch; import z3; import torch_geometric; print('✅ All dependencies installed successfully!')"

echo ""
echo "🎉 VulnHunter NFV installation complete!"
echo ""
echo "Usage:"
echo "  source venv/bin/activate"
echo "  python3 test_nfv.py"
echo "  python3 -m src.cli scan contract.sol --prove"
echo ""
echo "Next steps:"
echo "  1. Train the NFV model: python3 src/training/nfv_training.py"
echo "  2. Run benchmarks: python3 test_nfv.py"
echo "  3. Compare with existing tools"