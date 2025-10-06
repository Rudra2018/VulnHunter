#!/usr/bin/env python3
"""
Complete Multi-Task VulnHunter Training Script
Integrates: Enhanced GitHub Data + Multi-Task Model + VD-Score + FP Reduction
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List

import torch
from torch.utils.data import DataLoader
from transformers import RobertaTokenizer
from sklearn.model_selection import train_test_split

# Import custom modules
from core.enhanced_github_integrator import EnhancedGitHubIntegrator
from core.multitask_gnn_model import MultiTaskGNNTransformer, MultiTaskLoss
from core.multitask_training_pipeline import (
    MultiModalVulnerabilityDataset,
    ASTGraphConstructor,
    MultiTaskTrainer,
    VDScoreMetric,
    collate_multimodal_batch
)
from core.false_positive_reduction import IntegratedFalsePositiveReduction

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Train Multi-Task VulnHunter with GitHub datasets"
    )

    # Data arguments
    parser.add_argument(
        '--data_path',
        type=str,
        default='data/primevul_train.jsonl',
        help='Path to PrimeVul/DiverseVul dataset'
    )
    parser.add_argument(
        '--github_token',
        type=str,
        default=None,
        help='GitHub API token for commit/issue extraction'
    )
    parser.add_argument(
        '--max_samples',
        type=int,
        default=None,
        help='Maximum samples to process (for testing)'
    )
    parser.add_argument(
        '--use_github_api',
        action='store_true',
        help='Fetch commit/issue metadata from GitHub API'
    )

    # Model arguments
    parser.add_argument(
        '--input_dim',
        type=int,
        default=128,
        help='Input dimension for node features'
    )
    parser.add_argument(
        '--hidden_dim',
        type=int,
        default=256,
        help='Hidden dimension for model'
    )
    parser.add_argument(
        '--num_heads',
        type=int,
        default=8,
        help='Number of attention heads'
    )
    parser.add_argument(
        '--dropout',
        type=float,
        default=0.3,
        help='Dropout rate'
    )
    parser.add_argument(
        '--num_transformer_layers',
        type=int,
        default=6,
        help='Number of transformer layers'
    )

    # Training arguments
    parser.add_argument(
        '--batch_size',
        type=int,
        default=32,
        help='Batch size for training'
    )
    parser.add_argument(
        '--learning_rate',
        type=float,
        default=1e-3,
        help='Learning rate'
    )
    parser.add_argument(
        '--num_epochs',
        type=int,
        default=100,
        help='Number of training epochs'
    )
    parser.add_argument(
        '--early_stopping_patience',
        type=int,
        default=15,
        help='Early stopping patience'
    )
    parser.add_argument(
        '--mixed_precision',
        action='store_true',
        default=True,
        help='Use mixed precision training'
    )

    # Task arguments
    parser.add_argument(
        '--use_validation_head',
        action='store_true',
        default=True,
        help='Enable validation status prediction'
    )
    parser.add_argument(
        '--use_fp_head',
        action='store_true',
        default=True,
        help='Enable false positive prediction'
    )

    # Output arguments
    parser.add_argument(
        '--output_dir',
        type=str,
        default='models/multitask',
        help='Output directory for models and results'
    )

    return parser.parse_args()


def main():
    """Main training pipeline"""
    args = parse_args()

    logger.info("="*80)
    logger.info("VulnHunter Multi-Task Training Pipeline")
    logger.info("="*80)
    logger.info(f"Configuration:")
    for arg, value in vars(args).items():
        logger.info(f"  {arg}: {value}")
    logger.info("="*80 + "\n")

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save configuration
    with open(output_dir / 'config.json', 'w') as f:
        json.dump(vars(args), f, indent=2)

    # ========================================================================
    # STEP 1: Load and Process GitHub Dataset
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 1: Loading and Processing GitHub Dataset")
    logger.info("="*80)

    integrator = EnhancedGitHubIntegrator(
        github_token=args.github_token or os.getenv('GITHUB_TOKEN')
    )

    # Process dataset with enhanced metadata
    processed_samples = integrator.process_primevul_dataset(
        data_path=args.data_path,
        max_samples=args.max_samples,
        use_github_api=args.use_github_api
    )

    logger.info(f"✅ Processed {len(processed_samples)} samples")

    # Save processed data
    processed_path = output_dir / 'processed_samples.json'
    with open(processed_path, 'w') as f:
        json.dump(processed_samples, f, indent=2)
    logger.info(f"💾 Saved processed data to {processed_path}")

    # ========================================================================
    # STEP 2: Split Data
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 2: Splitting Data (80/20 train/val)")
    logger.info("="*80)

    # Extract labels for stratification
    labels = [s['label'] for s in processed_samples]

    train_samples, val_samples = train_test_split(
        processed_samples,
        test_size=0.2,
        random_state=42,
        stratify=labels
    )

    logger.info(f"Train: {len(train_samples)} samples")
    logger.info(f"Val: {len(val_samples)} samples")

    # Class distribution
    train_vuln = sum(s['label'] for s in train_samples)
    val_vuln = sum(s['label'] for s in val_samples)
    logger.info(f"Train: {train_vuln} vulnerable ({train_vuln/len(train_samples)*100:.1f}%)")
    logger.info(f"Val: {val_vuln} vulnerable ({val_vuln/len(val_samples)*100:.1f}%)")

    # ========================================================================
    # STEP 3: Create Datasets and Dataloaders
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 3: Creating Datasets and Dataloaders")
    logger.info("="*80)

    # Initialize tokenizer
    logger.info("Loading CodeBERT tokenizer...")
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')

    # Initialize graph constructor
    logger.info("Initializing AST graph constructor...")
    graph_constructor = ASTGraphConstructor(language='c')

    # Create datasets
    logger.info("Creating train dataset...")
    train_dataset = MultiModalVulnerabilityDataset(
        samples=train_samples,
        tokenizer=tokenizer,
        max_text_length=256,
        graph_constructor=graph_constructor
    )

    logger.info("Creating validation dataset...")
    val_dataset = MultiModalVulnerabilityDataset(
        samples=val_samples,
        tokenizer=tokenizer,
        max_text_length=256,
        graph_constructor=graph_constructor
    )

    # Create dataloaders
    logger.info(f"Creating dataloaders (batch_size={args.batch_size})...")
    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=collate_multimodal_batch,
        num_workers=0  # Set to 0 for debugging
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=collate_multimodal_batch,
        num_workers=0
    )

    logger.info(f"✅ Train batches: {len(train_loader)}")
    logger.info(f"✅ Val batches: {len(val_loader)}")

    # ========================================================================
    # STEP 4: Initialize Model and Loss
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 4: Initializing Multi-Task Model")
    logger.info("="*80)

    # Initialize model
    model = MultiTaskGNNTransformer(
        input_dim=args.input_dim,
        hidden_dim=args.hidden_dim,
        num_heads=args.num_heads,
        dropout=args.dropout,
        num_transformer_layers=args.num_transformer_layers,
        use_validation_head=args.use_validation_head,
        use_fp_head=args.use_fp_head
    )

    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(f"Total parameters: {total_params:,}")
    logger.info(f"Trainable parameters: {trainable_params:,}")

    # Initialize loss
    loss_fn = MultiTaskLoss(
        use_validation=args.use_validation_head,
        use_fp=args.use_fp_head
    )

    logger.info("✅ Model and loss initialized")

    # ========================================================================
    # STEP 5: Train Model
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 5: Training Multi-Task Model")
    logger.info("="*80)

    # Initialize trainer
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    logger.info(f"Using device: {device}")

    trainer = MultiTaskTrainer(
        model=model,
        loss_fn=loss_fn,
        device=device,
        learning_rate=args.learning_rate,
        use_mixed_precision=args.mixed_precision and device == 'cuda'
    )

    # Train
    history = trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        num_epochs=args.num_epochs,
        early_stopping_patience=args.early_stopping_patience,
        save_dir=str(output_dir)
    )

    logger.info("✅ Training complete!")

    # ========================================================================
    # STEP 6: Evaluate with False Positive Reduction
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("STEP 6: Evaluating with False Positive Reduction")
    logger.info("="*80)

    # Load best model
    checkpoint = torch.load(output_dir / 'best_multitask_model.pth')
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    model.to(device)

    # Initialize FP reducer
    fp_reducer = IntegratedFalsePositiveReduction()

    # Evaluate on validation set with FP reduction
    fp_reduced_results = []
    original_predictions = []
    reduced_predictions = []

    logger.info("Running FP reduction on validation set...")
    for sample in val_samples[:100]:  # Sample 100 for demonstration
        # Get model prediction
        graph = graph_constructor.construct_graph_from_code(sample['code'])
        graph = graph.to(device)

        with torch.no_grad():
            # Create batch
            commit_tokens = tokenizer(
                sample.get('commit_message', ''),
                max_length=256,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            diff_tokens = tokenizer(
                sample.get('commit_diff', ''),
                max_length=256,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )

            outputs = model(
                x=graph.x.unsqueeze(0),
                edge_index=graph.edge_index,
                batch=torch.zeros(graph.x.size(0), dtype=torch.long).to(device),
                commit_msg_input_ids=commit_tokens['input_ids'].to(device),
                commit_msg_attention_mask=commit_tokens['attention_mask'].to(device),
                diff_input_ids=diff_tokens['input_ids'].to(device),
                diff_attention_mask=diff_tokens['attention_mask'].to(device)
            )

            vuln_probs = torch.softmax(outputs['vulnerability'], dim=1)
            vuln_pred = torch.argmax(vuln_probs, dim=1).item()
            vuln_conf = vuln_probs[0, vuln_pred].item()

        # Apply FP reduction
        issue_texts = []
        for discussion in sample.get('issue_discussions', []):
            issue_texts.append(f"{discussion['title']} {discussion['body']}")

        reduction_result = fp_reducer.reduce_false_positives(
            code=sample['code'],
            model_prediction=vuln_pred,
            model_confidence=vuln_conf,
            issue_texts=issue_texts if issue_texts else None,
            vuln_type=None  # Auto-detect
        )

        fp_reduced_results.append(reduction_result)
        original_predictions.append(vuln_pred)
        reduced_predictions.append(reduction_result['final_prediction'])

    # Compare results
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score, classification_report

    y_true = [s['label'] for s in val_samples[:100]]
    original_acc = accuracy_score(y_true, original_predictions)
    reduced_acc = accuracy_score(y_true, reduced_predictions)

    original_f1 = f1_score(y_true, original_predictions, average='weighted')
    reduced_f1 = f1_score(y_true, reduced_predictions, average='weighted')

    fp_count = sum(r['is_false_positive'] for r in fp_reduced_results)

    logger.info("\nFalse Positive Reduction Results:")
    logger.info(f"  Samples evaluated: 100")
    logger.info(f"  False positives detected: {fp_count}")
    logger.info(f"  Original accuracy: {original_acc:.4f}")
    logger.info(f"  Reduced accuracy: {reduced_acc:.4f} ({(reduced_acc-original_acc)*100:+.2f}%)")
    logger.info(f"  Original F1: {original_f1:.4f}")
    logger.info(f"  Reduced F1: {reduced_f1:.4f} ({(reduced_f1-original_f1)*100:+.2f}%)")

    # Save FP reduction results
    fp_results_path = output_dir / 'fp_reduction_results.json'
    with open(fp_results_path, 'w') as f:
        json.dump({
            'fp_count': fp_count,
            'original_accuracy': original_acc,
            'reduced_accuracy': reduced_acc,
            'original_f1': original_f1,
            'reduced_f1': reduced_f1,
            'sample_results': fp_reduced_results[:10]  # Save first 10 examples
        }, f, indent=2)

    logger.info(f"💾 FP reduction results saved to {fp_results_path}")

    # ========================================================================
    # STEP 7: Summary
    # ========================================================================
    logger.info("\n" + "="*80)
    logger.info("TRAINING SUMMARY")
    logger.info("="*80)

    best_metrics = checkpoint['metrics']
    logger.info(f"\nBest Model Metrics:")
    logger.info(f"  VD-Score (FNR@1%FPR): {best_metrics['vd_score']:.4f} ⭐")
    logger.info(f"  Accuracy: {best_metrics['accuracy']:.4f}")
    logger.info(f"  F1 Macro: {best_metrics['f1_macro']:.4f}")
    logger.info(f"  F1 Safe: {best_metrics['f1_safe']:.4f}")
    logger.info(f"  F1 Vulnerable: {best_metrics['f1_vulnerable']:.4f}")
    logger.info(f"  AUC-ROC: {best_metrics['auc_roc']:.4f}")
    logger.info(f"  Validation Task F1: {best_metrics['validation_f1']:.4f}")
    logger.info(f"  FP Detection F1: {best_metrics['fp_f1']:.4f}")

    logger.info(f"\nWith False Positive Reduction:")
    logger.info(f"  FP Detections: {fp_count}/100 samples")
    logger.info(f"  Accuracy Improvement: {(reduced_acc-original_acc)*100:+.2f}%")
    logger.info(f"  F1 Improvement: {(reduced_f1-original_f1)*100:+.2f}%")

    logger.info(f"\nModels saved to: {output_dir}")
    logger.info(f"  - best_multitask_model.pth")
    logger.info(f"  - training_history.json")
    logger.info(f"  - fp_reduction_results.json")
    logger.info(f"  - config.json")

    logger.info("\n" + "="*80)
    logger.info("✅ Multi-Task VulnHunter Training Complete!")
    logger.info("="*80 + "\n")


if __name__ == "__main__":
    main()
