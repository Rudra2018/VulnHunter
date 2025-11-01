#!/usr/bin/env python3
"""
Comprehensive Model Training Launcher
Train both VulnHunter Omega v3 and Large models on real-world dataset
"""

import os
import sys
import time
import argparse
import torch
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    parser = argparse.ArgumentParser(description='Train VulnHunter models on comprehensive real-world dataset')
    parser.add_argument('--dataset-size', type=int, default=100000, help='Dataset size to generate')
    parser.add_argument('--skip-data-collection', action='store_true', help='Skip data collection if dataset exists')
    parser.add_argument('--model', choices=['omega_v3', 'large', 'both'], default='both', help='Which model to train')
    parser.add_argument('--epochs', type=int, default=50, help='Number of training epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--learning-rate', type=float, default=2e-5, help='Learning rate')

    args = parser.parse_args()

    print("🚀 VulnHunter Ωmega Comprehensive Training System")
    print("=" * 60)
    print(f"📊 Target dataset size: {args.dataset_size:,} samples")
    print(f"🤖 Models to train: {args.model}")
    print(f"📈 Training epochs: {args.epochs}")
    print(f"🔥 Using device: {'CUDA' if torch.cuda.is_available() else 'CPU'}")
    print("=" * 60)

    # Step 1: Generate comprehensive dataset
    dataset_path = Path("training_data/comprehensive_vulnerability_dataset.json")

    if not args.skip_data_collection or not dataset_path.exists():
        print("\\n🔍 Step 1: Generating Comprehensive Real-World Dataset")
        print("-" * 50)

        from training.comprehensive_dataset_collector import ComprehensiveDatasetCollector

        collector = ComprehensiveDatasetCollector(output_dir="training_data")
        dataset = collector.collect_comprehensive_dataset(target_samples=args.dataset_size)

        print(f"✅ Dataset generated: {len(dataset):,} samples")
    else:
        print("\\n✅ Using existing dataset")
        with open(dataset_path, 'r') as f:
            dataset = json.load(f)
        print(f"📊 Loaded dataset: {len(dataset):,} samples")

    # Step 2: Train Models
    if args.model in ['omega_v3', 'both']:
        print("\\n🤖 Step 2a: Training VulnHunter Omega v3 Model")
        print("-" * 50)
        train_omega_v3_model(args)

    if args.model in ['large', 'both']:
        print("\\n🤖 Step 2b: Training Large 1.5GB Model")
        print("-" * 50)
        train_large_model(args)

    print("\\n🎉 Comprehensive Training Complete!")
    print("📈 Models trained on real-world CVEs, GitHub code, smart contracts, web apps, mobile apps, and binaries")

def train_omega_v3_model(args):
    """Train the Omega v3 model"""
    print("🔥 Initializing VulnHunter Omega v3 training...")

    # Modified training config for Omega v3
    from training.enhanced_training_pipeline import TrainingConfig, main as train_main

    # Patch the config for Omega v3
    original_config_init = TrainingConfig.__init__

    def omega_v3_config_init(self):
        original_config_init(self)
        self.model_type = "omega_v3"
        self.batch_size = args.batch_size
        self.learning_rate = args.learning_rate
        self.num_epochs = args.epochs
        self.embed_dim = 512  # Smaller for v3
        self.num_heads = 8
        self.num_layers = 8

    TrainingConfig.__init__ = omega_v3_config_init

    try:
        # Start training
        start_time = time.time()
        train_main()
        training_time = time.time() - start_time

        print(f"✅ Omega v3 training completed in {training_time/3600:.2f} hours")

        # Update existing model
        import shutil
        best_model_path = Path("models/best_omega_v3_model.pth")
        target_model_path = Path("models/vulnhunter_omega_v3.pth")

        if best_model_path.exists():
            shutil.copy(best_model_path, target_model_path)
            print(f"💾 Updated {target_model_path}")

    except Exception as e:
        print(f"❌ Omega v3 training failed: {e}")
    finally:
        # Restore original config
        TrainingConfig.__init__ = original_config_init

def train_large_model(args):
    """Train the large 1.5GB model"""
    print("🔥 Initializing Large Model training...")

    from training.enhanced_training_pipeline import TrainingConfig, main as train_main

    # Patch the config for Large model
    original_config_init = TrainingConfig.__init__

    def large_model_config_init(self):
        original_config_init(self)
        self.model_type = "large"
        self.batch_size = max(8, args.batch_size // 2)  # Reduce batch size for large model
        self.learning_rate = args.learning_rate / 2  # Lower LR for large model
        self.num_epochs = args.epochs
        self.embed_dim = 1024  # Large embedding
        self.num_heads = 16
        self.num_layers = 24

    TrainingConfig.__init__ = large_model_config_init

    try:
        # Start training
        start_time = time.time()
        train_main()
        training_time = time.time() - start_time

        print(f"✅ Large model training completed in {training_time/3600:.2f} hours")

        # Update existing large model
        import shutil
        best_model_path = Path("models/best_large_model.pth")
        target_model_path = Path("models/vulnhunter_large_model_1.5gb.pth")

        if best_model_path.exists():
            shutil.copy(best_model_path, target_model_path)
            print(f"💾 Updated {target_model_path}")

    except Exception as e:
        print(f"❌ Large model training failed: {e}")
    finally:
        # Restore original config
        TrainingConfig.__init__ = original_config_init

if __name__ == "__main__":
    main()