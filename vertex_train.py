#!/usr/bin/env python3
"""
VulnHunter Training Script for Vertex AI
Handles GCS data loading, GPU training, and model export
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
import torch
from google.cloud import storage
from datetime import datetime

# Import VulnHunter modules
from train_enhanced_vulnhunter import VulnHunterPipeline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VertexAITrainer:
    """Handles VulnHunter training on Vertex AI with GCS integration"""

    def __init__(self, args):
        self.args = args
        self.bucket_name = args.bucket_name
        self.project_id = args.project_id

        # Initialize GCS client
        self.storage_client = storage.Client(project=self.project_id)

        # Local paths
        self.local_data_dir = Path('/tmp/data')
        self.local_model_dir = Path('/tmp/models')
        self.local_data_dir.mkdir(parents=True, exist_ok=True)
        self.local_model_dir.mkdir(parents=True, exist_ok=True)

        # Check GPU availability
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'

        logger.info("=" * 80)
        logger.info("VulnHunter Vertex AI Trainer Initialized")
        logger.info("=" * 80)
        logger.info(f"Project ID: {self.project_id}")
        logger.info(f"Bucket: {self.bucket_name}")
        logger.info(f"Device: {self.device}")

        if torch.cuda.is_available():
            logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
            logger.info(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.2f} GB")
        else:
            logger.warning("⚠️  No GPU detected. Training will be slow!")

    def download_data_from_gcs(self):
        """Download training data from Google Cloud Storage"""
        logger.info("\n" + "=" * 80)
        logger.info("Downloading Data from GCS")
        logger.info("=" * 80)

        bucket = self.storage_client.bucket(self.bucket_name)

        # Files to download
        files_to_download = [
            f'data/{self.args.data_prefix}_graphs.pt',
            f'data/{self.args.data_prefix}_codes.json',
            f'data/{self.args.data_prefix}_labels.json'
        ]

        for gcs_path in files_to_download:
            local_path = self.local_data_dir / Path(gcs_path).name
            blob = bucket.blob(gcs_path)

            if not blob.exists():
                logger.error(f"❌ File not found in GCS: gs://{self.bucket_name}/{gcs_path}")
                raise FileNotFoundError(f"Missing data file: {gcs_path}")

            logger.info(f"Downloading: gs://{self.bucket_name}/{gcs_path}")
            logger.info(f"  -> {local_path}")

            # Download with progress
            blob.download_to_filename(str(local_path))

            # Verify download
            size_mb = local_path.stat().st_size / 1024 / 1024
            logger.info(f"  ✅ Downloaded ({size_mb:.2f} MB)")

        logger.info("✅ All data downloaded successfully")

    def load_data(self):
        """Load data from local files"""
        logger.info("\n" + "=" * 80)
        logger.info("Loading Data")
        logger.info("=" * 80)

        # Load graphs
        graphs_path = self.local_data_dir / f'{self.args.data_prefix}_graphs.pt'
        logger.info(f"Loading graphs from {graphs_path}...")
        graph_data = torch.load(graphs_path, map_location='cpu')
        logger.info(f"  ✅ Loaded {len(graph_data)} graphs")

        # Load code texts
        codes_path = self.local_data_dir / f'{self.args.data_prefix}_codes.json'
        logger.info(f"Loading code texts from {codes_path}...")
        with open(codes_path, 'r') as f:
            code_texts = json.load(f)
        logger.info(f"  ✅ Loaded {len(code_texts)} code samples")

        # Load labels
        labels_path = self.local_data_dir / f'{self.args.data_prefix}_labels.json'
        logger.info(f"Loading labels from {labels_path}...")
        with open(labels_path, 'r') as f:
            labels = json.load(f)
        logger.info(f"  ✅ Loaded {len(labels)} labels")

        # Dataset statistics
        vulnerable_count = sum(labels)
        safe_count = len(labels) - vulnerable_count

        logger.info(f"\nDataset Statistics:")
        logger.info(f"  Total samples: {len(labels)}")
        logger.info(f"  Vulnerable: {vulnerable_count} ({vulnerable_count/len(labels)*100:.1f}%)")
        logger.info(f"  Safe: {safe_count} ({safe_count/len(labels)*100:.1f}%)")

        return graph_data, code_texts, labels

    def train(self):
        """Execute complete training pipeline"""
        logger.info("\n" + "=" * 80)
        logger.info("STARTING VULNHUNTER TRAINING ON VERTEX AI")
        logger.info("=" * 80)
        logger.info(f"Run name: {self.args.run_name}")
        logger.info(f"Training start time: {datetime.now().isoformat()}")

        # Step 1: Download data
        self.download_data_from_gcs()

        # Step 2: Load data
        graph_data, code_texts, labels = self.load_data()

        # Step 3: Configure training
        config = {
            'device': self.device,
            'hidden_dim': self.args.hidden_dim,
            'num_heads': self.args.num_heads,
            'dropout': self.args.dropout,
            'gradient_accumulation_steps': self.args.gradient_accumulation,
            'gnn_epochs': self.args.gnn_epochs,
            'codebert_epochs': self.args.codebert_epochs,
            'batch_size': self.args.batch_size,
            'learning_rate': self.args.learning_rate
        }

        logger.info("\n" + "=" * 80)
        logger.info("Training Configuration")
        logger.info("=" * 80)
        for key, value in config.items():
            logger.info(f"  {key}: {value}")

        # Step 4: Initialize pipeline
        logger.info("\nInitializing VulnHunter Pipeline...")
        pipeline = VulnHunterPipeline(config)

        # Step 5: Prepare data
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 0: Data Preparation")
        logger.info("=" * 80)

        train_graphs, train_codes, train_labels, \
        val_graphs, val_codes, val_labels, \
        test_graphs, test_codes, test_labels = pipeline.prepare_data(
            graph_data, code_texts, labels,
            use_resampling=False  # Use class weights for graphs
        )

        # Step 6: Train GNN-Transformer
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 1: GNN-Transformer Training")
        logger.info("=" * 80)

        gnn_history = pipeline.train_gnn_model(
            train_graphs, val_graphs,
            epochs=self.args.gnn_epochs,
            batch_size=self.args.batch_size,
            learning_rate=self.args.learning_rate
        )

        # Step 7: Train CodeBERT
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 2: CodeBERT Fine-tuning")
        logger.info("=" * 80)

        codebert_trainer = pipeline.train_codebert_model(
            train_codes, train_labels,
            val_codes, val_labels,
            epochs=self.args.codebert_epochs,
            batch_size=max(8, self.args.batch_size // 4)  # Smaller batch for BERT
        )

        # Step 8: Create ensemble
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 3: Ensemble Creation")
        logger.info("=" * 80)

        optimal_weights = pipeline.create_ensemble(
            val_graphs, val_codes, val_labels
        )

        # Step 9: Optimize threshold
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 4: Threshold Optimization")
        logger.info("=" * 80)

        optimal_threshold, threshold_metrics = pipeline.optimize_threshold(
            val_graphs, val_codes, val_labels
        )

        # Step 10: Add Z3 verification
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 5: Z3 Verification Layer")
        logger.info("=" * 80)

        pipeline.add_verification_layer()

        # Step 11: Final evaluation
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 6: Final Evaluation")
        logger.info("=" * 80)

        results = pipeline.evaluate(
            test_graphs, test_codes, test_labels,
            use_verification=True
        )

        # Step 12: Save results
        self.save_results(results, optimal_threshold, optimal_weights)

        # Step 13: Upload models to GCS
        self.upload_models_to_gcs()

        logger.info("\n" + "=" * 80)
        logger.info("🎉 TRAINING COMPLETE!")
        logger.info("=" * 80)
        logger.info(f"Accuracy: {results['accuracy']:.4f}")
        logger.info(f"F1 (weighted): {results['f1_weighted']:.4f}")
        logger.info(f"F1 (macro): {results['f1_macro']:.4f}")
        logger.info(f"Training end time: {datetime.now().isoformat()}")

        return results

    def save_results(self, results, optimal_threshold, optimal_weights):
        """Save training results to JSON"""
        logger.info("\nSaving results...")

        results_dict = {
            'accuracy': float(results['accuracy']),
            'f1_weighted': float(results['f1_weighted']),
            'f1_macro': float(results['f1_macro']),
            'confusion_matrix': results['confusion_matrix'].tolist(),
            'optimal_threshold': float(optimal_threshold),
            'ensemble_weights': {
                'gnn_weight': float(optimal_weights[0]),
                'codebert_weight': float(optimal_weights[1])
            },
            'training_config': {
                'hidden_dim': self.args.hidden_dim,
                'num_heads': self.args.num_heads,
                'dropout': self.args.dropout,
                'gnn_epochs': self.args.gnn_epochs,
                'codebert_epochs': self.args.codebert_epochs,
                'batch_size': self.args.batch_size,
                'learning_rate': self.args.learning_rate
            },
            'run_name': self.args.run_name,
            'timestamp': datetime.now().isoformat()
        }

        results_path = self.local_model_dir / 'results.json'
        with open(results_path, 'w') as f:
            json.dump(results_dict, f, indent=2)

        logger.info(f"  ✅ Results saved to {results_path}")

    def upload_models_to_gcs(self):
        """Upload trained models and results to GCS"""
        logger.info("\n" + "=" * 80)
        logger.info("Uploading Models to GCS")
        logger.info("=" * 80)

        bucket = self.storage_client.bucket(self.bucket_name)

        # Model files to upload
        model_files = {
            'models/best_gnn_model.pth': 'GNN model',
            'models/codebert_vuln/pytorch_model.bin': 'CodeBERT model',
            'models/codebert_vuln/config.json': 'CodeBERT config',
            'models/codebert_vuln/tokenizer_config.json': 'Tokenizer config',
            'models/codebert_vuln/vocab.json': 'Vocabulary',
            'models/codebert_vuln/merges.txt': 'BPE merges',
            'models/ensemble_config.pkl': 'Ensemble config',
            'models/threshold_analysis.png': 'Threshold plot'
        }

        # Add results
        results_file = self.local_model_dir / 'results.json'
        if results_file.exists():
            gcs_results_path = f'models/{self.args.run_name}/results.json'
            blob = bucket.blob(gcs_results_path)
            blob.upload_from_filename(str(results_file))
            logger.info(f"  ✅ Uploaded: gs://{self.bucket_name}/{gcs_results_path}")

        # Upload model files
        uploaded_count = 0
        for local_file, description in model_files.items():
            local_path = Path(local_file)

            # Check multiple possible locations
            possible_paths = [
                local_path,
                self.local_model_dir / local_path.name,
                Path('/app') / local_path
            ]

            for path in possible_paths:
                if path.exists():
                    gcs_path = f'models/{self.args.run_name}/{path.name}'
                    blob = bucket.blob(gcs_path)

                    logger.info(f"Uploading {description}...")
                    logger.info(f"  {path} -> gs://{self.bucket_name}/{gcs_path}")

                    blob.upload_from_filename(str(path))

                    # Verify upload
                    blob.reload()
                    size_mb = blob.size / 1024 / 1024
                    logger.info(f"  ✅ Uploaded ({size_mb:.2f} MB)")

                    uploaded_count += 1
                    break

        logger.info(f"\n✅ Uploaded {uploaded_count} files")
        logger.info(f"Models location: gs://{self.bucket_name}/models/{self.args.run_name}/")


def main():
    parser = argparse.ArgumentParser(description='VulnHunter Training on Vertex AI')

    # GCS arguments
    parser.add_argument('--project-id', type=str, required=True,
                       help='GCP Project ID')
    parser.add_argument('--bucket-name', type=str, required=True,
                       help='GCS bucket name (without gs:// prefix)')
    parser.add_argument('--data-prefix', type=str, default='vulnhunter',
                       help='Data file prefix in GCS')
    parser.add_argument('--run-name', type=str, default='run-001',
                       help='Training run name for organizing outputs')

    # Model architecture arguments
    parser.add_argument('--hidden-dim', type=int, default=256,
                       help='Hidden dimension for GNN')
    parser.add_argument('--num-heads', type=int, default=8,
                       help='Number of attention heads')
    parser.add_argument('--dropout', type=float, default=0.3,
                       help='Dropout rate')

    # Training arguments
    parser.add_argument('--gnn-epochs', type=int, default=100,
                       help='Number of epochs for GNN training')
    parser.add_argument('--codebert-epochs', type=int, default=10,
                       help='Number of epochs for CodeBERT fine-tuning')
    parser.add_argument('--batch-size', type=int, default=32,
                       help='Batch size for training')
    parser.add_argument('--learning-rate', type=float, default=1e-3,
                       help='Learning rate')
    parser.add_argument('--gradient-accumulation', type=int, default=4,
                       help='Gradient accumulation steps (for memory efficiency)')

    args = parser.parse_args()

    # Log all arguments
    logger.info("Training Arguments:")
    for arg, value in vars(args).items():
        logger.info(f"  {arg}: {value}")

    try:
        # Create trainer
        trainer = VertexAITrainer(args)

        # Run training
        results = trainer.train()

        logger.info("\n✅ Training job completed successfully!")
        sys.exit(0)

    except Exception as e:
        logger.error(f"\n❌ Training failed with error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
