#!/usr/bin/env python3
"""
Simple PyTorch Test for VulnHunter Omega
"""

import torch
import json
import os

def main():
    print("🚀 VulnHunter Ω Simple PyTorch Test")
    print("=" * 50)

    # Test PyTorch
    print(f"✅ PyTorch version: {torch.__version__}")
    print(f"✅ Device: {torch.device('cuda' if torch.cuda.is_available() else 'cpu')}")

    # Test model loading
    model_path = "vulnhunter_omega_optimized_best.pth"
    if os.path.exists(model_path):
        try:
            model_data = torch.load(model_path, map_location='cpu')
            print(f"✅ Model loaded successfully!")

            if isinstance(model_data, dict):
                print(f"   Keys: {list(model_data.keys())}")

                if 'model_state_dict' in model_data:
                    state_dict = model_data['model_state_dict']
                    total_params = sum(p.numel() for p in state_dict.values())
                    print(f"   Total parameters: {total_params:,}")

        except Exception as e:
            print(f"❌ Model loading failed: {e}")
    else:
        print(f"❌ Model file not found: {model_path}")

    # Test basic dependencies
    try:
        import numpy as np
        import networkx as nx
        import scipy
        print(f"✅ Core dependencies working")
    except Exception as e:
        print(f"❌ Dependencies failed: {e}")

    print(f"\n🎉 PyTorch is ready for VulnHunter Omega!")

if __name__ == "__main__":
    main()