#!/usr/bin/env python3
"""
Train VulnGuard AI with Kaggle Datasets

This script helps you download and train with the comprehensive Kaggle datasets:
1. Public CVE Vulnerabilities 2020-2024
2. CVE Data
3. Bug Bounty Writeups
4. CVE Dataset
5. Bug Bounty OpenAI GPT OSS

Usage:
    # Option 1: Auto-download with Kaggle API
    python train_with_kaggle.py --download

    # Option 2: Train with manually downloaded datasets
    python train_with_kaggle.py --data-path /path/to/kaggle/data

    # Option 3: Train with only HuggingFace datasets (no Kaggle)
    python train_with_kaggle.py --huggingface-only
"""

import argparse
import logging
import sys
import os
from core.ultimate_trainer import UltimateVulnGuardTrainer
from core.kaggle_dataset_integrator import KaggleDatasetIntegrator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def download_kaggle_datasets(output_path: str = "./data/kaggle"):
    """Download all Kaggle datasets"""
    logger.info("🚀 Downloading Kaggle datasets...")

    integrator = KaggleDatasetIntegrator()

    # Check if Kaggle API is available
    if not integrator.check_kaggle_api():
        logger.error("❌ Kaggle API not available")
        logger.info("\n📝 To use Kaggle API:")
        logger.info("   1. Install: pip install kaggle")
        logger.info("   2. Get API credentials from: https://www.kaggle.com/settings")
        logger.info("   3. Save to: ~/.kaggle/kaggle.json")
        logger.info("   4. Set permissions: chmod 600 ~/.kaggle/kaggle.json")
        logger.info("\n💡 OR download datasets manually:")
        for key, config in integrator.kaggle_datasets.items():
            logger.info(f"   {config['url']}")
        return False

    # Download each dataset
    datasets_to_download = [
        'public-cve-2020-2024',
        'cve-data',
        'bug-bounty-writeups',
        'cve-dataset',
        'bug-bounty-openai'
    ]

    success_count = 0
    for dataset_name in datasets_to_download:
        logger.info(f"\n📥 Downloading {dataset_name}...")
        if integrator.download_kaggle_dataset(dataset_name, output_path):
            success_count += 1
            logger.info(f"✅ {dataset_name} downloaded")
        else:
            logger.warning(f"⚠️  Failed to download {dataset_name}")

    logger.info(f"\n📊 Downloaded {success_count}/{len(datasets_to_download)} datasets")

    if success_count > 0:
        logger.info(f"💾 Datasets saved to: {output_path}")
        return True
    else:
        return False


def train_models(kaggle_data_path: str = None, huggingface_only: bool = False):
    """Train models with all available datasets"""
    logger.info("🚀 Starting Ultimate VulnGuard AI Training")
    logger.info("=" * 80)

    # Initialize trainer
    trainer = UltimateVulnGuardTrainer()

    # Load datasets
    if huggingface_only:
        logger.info("📂 Training with HuggingFace datasets only")
        kaggle_data_path = None
    elif kaggle_data_path:
        logger.info(f"📂 Training with HuggingFace + Kaggle datasets from: {kaggle_data_path}")
    else:
        logger.info("📂 Training with HuggingFace datasets (no Kaggle data provided)")

    if not trainer.load_all_datasets(kaggle_data_path=kaggle_data_path):
        logger.error("❌ Failed to load datasets")
        return None

    # Prepare training data
    logger.info("\n🔄 Preparing training data...")
    X, y = trainer.prepare_training_data()

    if X is None or y is None:
        logger.error("❌ Failed to prepare training data")
        return None

    # Train models
    logger.info("\n🤖 Training models...")
    trainer.train_ultimate_models(X, y)

    # Save models
    logger.info("\n💾 Saving models...")
    model_file = trainer.save_models()

    logger.info("\n" + "=" * 80)
    logger.info("🎉 TRAINING COMPLETE!")
    logger.info(f"📁 Model saved: {model_file}")
    logger.info("=" * 80)

    # Show usage instructions
    logger.info("\n📖 To use the trained model:")
    logger.info(f"   from core.ultimate_trainer import UltimateVulnGuardTrainer")
    logger.info(f"   trainer = UltimateVulnGuardTrainer()")
    logger.info(f"   # Load saved models")
    logger.info(f"   model_data = pickle.load(open('{model_file}', 'rb'))")
    logger.info(f"   trainer.models = model_data['models']")
    logger.info(f"   # Predict")
    logger.info(f"   result = trainer.predict(code_text)")

    return trainer


def main():
    parser = argparse.ArgumentParser(
        description='Train VulnGuard AI with Kaggle Datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download datasets and train
  python train_with_kaggle.py --download --data-path ./data/kaggle

  # Train with existing Kaggle datasets
  python train_with_kaggle.py --data-path ./data/kaggle

  # Train with only HuggingFace datasets
  python train_with_kaggle.py --huggingface-only

Kaggle Datasets:
  1. Public CVE Vulnerabilities 2020-2024
     https://www.kaggle.com/datasets/umer7arooq/public-cve-vulnerabilities-20202024

  2. CVE Data
     https://www.kaggle.com/datasets/angelcortez/cve-data

  3. Bug Bounty Writeups
     https://www.kaggle.com/datasets/mayankkumarpoddar/bug-bounty-writeups

  4. CVE Dataset
     https://www.kaggle.com/datasets/casimireffect/cve-dataset

  5. Bug Bounty OpenAI GPT OSS
     https://www.kaggle.com/datasets/daudthecat/bug-bounty-openai-gpt-oss-20b-by-thecat
        """
    )

    parser.add_argument(
        '--download',
        action='store_true',
        help='Download Kaggle datasets using Kaggle API'
    )

    parser.add_argument(
        '--data-path',
        type=str,
        default=None,
        help='Path to Kaggle datasets directory'
    )

    parser.add_argument(
        '--huggingface-only',
        action='store_true',
        help='Train with only HuggingFace datasets (skip Kaggle)'
    )

    parser.add_argument(
        '--output-path',
        type=str,
        default='./data/kaggle',
        help='Output path for downloaded datasets (default: ./data/kaggle)'
    )

    args = parser.parse_args()

    # Handle download
    if args.download:
        logger.info("📥 Download mode enabled")
        if download_kaggle_datasets(args.output_path):
            logger.info("✅ Download complete")
            # Update data path to downloaded location
            if not args.data_path:
                args.data_path = args.output_path
        else:
            logger.error("❌ Download failed")
            logger.info("\n💡 You can still train with HuggingFace datasets only:")
            logger.info("   python train_with_kaggle.py --huggingface-only")
            sys.exit(1)

    # Train models
    logger.info("\n" + "=" * 80)
    logger.info("TRAINING PHASE")
    logger.info("=" * 80)

    trainer = train_models(
        kaggle_data_path=args.data_path,
        huggingface_only=args.huggingface_only
    )

    if trainer:
        logger.info("\n✅ Success!")
        return 0
    else:
        logger.error("\n❌ Training failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
