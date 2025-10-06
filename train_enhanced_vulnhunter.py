#!/usr/bin/env python3
"""
VulnHunter Enhanced Training Pipeline
Complete integration: GNN-Transformer + CodeBERT + Z3 Verification
Target: 96-98% accuracy on imbalanced vulnerability detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from pathlib import Path
import logging
from typing import List, Dict, Tuple
import json

# Import enhanced modules
from core.enhanced_gnn_trainer import EnhancedGNNTrainer, FocalLoss
from core.advanced_imbalance_handler import AdvancedImbalanceHandler
from core.codebert_ensemble import CodeBERTVulnerabilityDetector, VulnHunterEnsemble, train_complete_ensemble
from core.z3_verification_module import Z3VerificationModule, VerifiedEnsemblePredictor
from core.gpu_optimization_utils import (
    GPUMemoryOptimizer,
    GradientAccumulationTrainer,
    ThresholdOptimizer,
    diagnose_gpu_oom_error
)

# PyG imports
from torch_geometric.nn import GATConv, GCNConv, global_mean_pool, global_max_pool
from torch_geometric.loader import DataLoader
from torch_geometric.data import Data

# Sklearn
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedGNNTransformer(nn.Module):
    """
    Enhanced GNN-Transformer architecture with improvements
    """
    def __init__(self, input_dim, hidden_dim=256, num_heads=8, dropout=0.3):
        super().__init__()

        # Graph layers with attention
        self.gnn1 = GATConv(input_dim, hidden_dim, heads=num_heads, dropout=dropout)
        self.gnn2 = GATConv(hidden_dim * num_heads, hidden_dim, heads=4, dropout=dropout)
        self.gnn3 = GCNConv(hidden_dim * 4, hidden_dim)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            activation='gelu',
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=6)

        # Regularization
        self.dropout = nn.Dropout(dropout)
        self.dropout_gnn = nn.Dropout(dropout * 0.6)

        # Classification head with batch norm
        self.bn1 = nn.BatchNorm1d(hidden_dim * 2)
        self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim // 2)
        self.bn2 = nn.BatchNorm1d(hidden_dim // 2)
        self.fc2 = nn.Linear(hidden_dim // 2, 2)

    def forward(self, x, edge_index, batch):
        # GNN processing
        h1 = F.elu(self.gnn1(x, edge_index))
        h1 = self.dropout_gnn(h1)

        h2 = F.elu(self.gnn2(h1, edge_index))
        h2 = self.dropout_gnn(h2)

        h3 = F.elu(self.gnn3(h2, edge_index))

        # Transformer
        h_transformed = self.transformer(h3.unsqueeze(1)).squeeze(1)

        # Global pooling
        h_mean = global_mean_pool(h_transformed, batch)
        h_max = global_max_pool(h_transformed, batch)
        h = torch.cat([h_mean, h_max], dim=1)

        # Classification
        h = self.bn1(h)
        h = F.elu(self.fc1(h))
        h = self.dropout(h)
        h = self.bn2(h)
        out = self.fc2(h)

        return out


class VulnHunterPipeline:
    """
    Complete VulnHunter training and inference pipeline
    """

    def __init__(self, config: Dict):
        self.config = config
        self.device = config.get('device', 'cuda' if torch.cuda.is_available() else 'cpu')

        # Models
        self.gnn_model = None
        self.codebert_model = None
        self.ensemble = None
        self.verifier = None

        # Data handlers
        self.imbalance_handler = None
        self.threshold_optimizer = None

        logger.info("VulnHunter Pipeline initialized")
        logger.info(f"  Device: {self.device}")

    def prepare_data(
        self,
        graph_data: List[Data],
        code_texts: List[str],
        labels: List[int],
        use_resampling: bool = True
    ) -> Tuple:
        """
        Prepare and balance training data

        Args:
            graph_data: List of PyG Data objects
            code_texts: List of source code strings
            labels: List of labels (0=safe, 1=vulnerable)
            use_resampling: Apply SMOTE resampling

        Returns:
            (train_graphs, train_codes, train_labels, val_graphs, val_codes, val_labels, test_graphs, test_codes, test_labels)
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 1: Data Preparation")
        logger.info("=" * 80)

        # Split data first
        indices = np.arange(len(labels))
        train_idx, temp_idx, _, temp_labels = train_test_split(
            indices, labels, test_size=0.3, random_state=42, stratify=labels
        )
        val_idx, test_idx, _, _ = train_test_split(
            temp_idx, temp_labels, test_size=0.5, random_state=42, stratify=temp_labels
        )

        # Extract train/val/test splits
        train_graphs = [graph_data[i] for i in train_idx]
        train_codes = [code_texts[i] for i in train_idx]
        train_labels = [labels[i] for i in train_idx]

        val_graphs = [graph_data[i] for i in val_idx]
        val_codes = [code_texts[i] for i in val_idx]
        val_labels = [labels[i] for i in val_idx]

        test_graphs = [graph_data[i] for i in test_idx]
        test_codes = [code_texts[i] for i in test_idx]
        test_labels = [labels[i] for i in test_idx]

        logger.info(f"Original splits:")
        logger.info(f"  Train: {len(train_labels)} samples")
        logger.info(f"  Val: {len(val_labels)} samples")
        logger.info(f"  Test: {len(test_labels)} samples")

        # Handle imbalance on training set
        if use_resampling:
            logger.info("\nApplying SMOTE-Tomek resampling to training set...")

            # For graph data, we need to create feature matrix
            # This is a simplified approach - you may need to adapt based on your graph structure
            train_features = np.array([g.x.numpy().flatten()[:1000] for g in train_graphs])  # Take first 1000 features

            self.imbalance_handler = AdvancedImbalanceHandler(
                strategy='smote_tomek',
                target_ratio=0.5,
                random_state=42
            )

            train_features_balanced, train_labels_balanced = self.imbalance_handler.balance_data(
                train_features,
                np.array(train_labels)
            )

            # Note: After SMOTE, you'd need to reconstruct graph objects
            # This is complex and depends on your graph construction pipeline
            # For now, we'll use class weights instead (more practical for graphs)
            logger.info("⚠️  SMOTE on graph data requires reconstruction. Using class weights instead.")
            use_resampling = False

        if not use_resampling:
            # Use class weights
            self.imbalance_handler = AdvancedImbalanceHandler(strategy='class_weights')
            class_weights = self.imbalance_handler.get_pytorch_weights(np.array(train_labels))
            logger.info(f"Using class weights: {class_weights}")

        return (
            train_graphs, train_codes, train_labels,
            val_graphs, val_codes, val_labels,
            test_graphs, test_codes, test_labels
        )

    def train_gnn_model(
        self,
        train_graphs: List[Data],
        val_graphs: List[Data],
        epochs: int = 100,
        batch_size: int = 32,
        learning_rate: float = 1e-3
    ):
        """
        Train GNN-Transformer model
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 2: Training GNN-Transformer")
        logger.info("=" * 80)

        # Create data loaders
        train_loader = DataLoader(train_graphs, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_graphs, batch_size=batch_size * 2, shuffle=False)

        # Initialize model
        input_dim = train_graphs[0].x.shape[1]
        self.gnn_model = EnhancedGNNTransformer(
            input_dim=input_dim,
            hidden_dim=self.config.get('hidden_dim', 256),
            num_heads=self.config.get('num_heads', 8),
            dropout=self.config.get('dropout', 0.3)
        )

        # Create trainer with focal loss
        trainer = EnhancedGNNTrainer(
            model=self.gnn_model,
            device=self.device,
            loss_type='focal',
            focal_alpha=0.25,  # Weight for safe class
            focal_gamma=2.0,
            use_mixed_precision=True,
            gradient_accumulation_steps=self.config.get('gradient_accumulation_steps', 1)
        )

        # Setup optimizer and scheduler
        trainer.setup_optimizer_scheduler(
            learning_rate=learning_rate,
            weight_decay=0.01,
            max_epochs=epochs
        )

        # Train
        history = trainer.train(
            train_loader=train_loader,
            val_loader=val_loader,
            epochs=epochs,
            early_stopping_patience=20,
            save_path='models/best_gnn_model.pth'
        )

        logger.info("✅ GNN-Transformer training complete")

        return history

    def train_codebert_model(
        self,
        train_codes: List[str],
        train_labels: List[int],
        val_codes: List[str],
        val_labels: List[int],
        epochs: int = 10,
        batch_size: int = 16
    ):
        """
        Fine-tune CodeBERT model
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 3: Fine-tuning CodeBERT")
        logger.info("=" * 80)

        self.codebert_model = CodeBERTVulnerabilityDetector(
            model_name="microsoft/codebert-base",
            max_length=512,
            device=self.device
        )

        # Get class weights
        class_weights = self.imbalance_handler.get_pytorch_weights(np.array(train_labels))

        # Train
        trainer = self.codebert_model.train(
            train_texts=train_codes,
            train_labels=train_labels,
            val_texts=val_codes,
            val_labels=val_labels,
            output_dir='models/codebert_vuln',
            epochs=epochs,
            batch_size=batch_size,
            learning_rate=2e-5,
            weight_decay=0.01,
            class_weights=class_weights
        )

        logger.info("✅ CodeBERT fine-tuning complete")

        return trainer

    def create_ensemble(
        self,
        val_graphs: List[Data],
        val_codes: List[str],
        val_labels: List[int]
    ):
        """
        Create and optimize ensemble
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 4: Creating Ensemble")
        logger.info("=" * 80)

        self.ensemble = VulnHunterEnsemble(
            gnn_model=self.gnn_model,
            codebert_model=self.codebert_model,
            gnn_weight=0.6,
            codebert_weight=0.4,
            device=self.device
        )

        # Optimize weights on validation set
        optimal_weights = self.ensemble.optimize_weights(
            val_graphs,
            val_codes,
            np.array(val_labels),
            metric='f1'
        )

        # Save ensemble config
        self.ensemble.save('models/ensemble_config.pkl')

        logger.info("✅ Ensemble created and optimized")

        return optimal_weights

    def optimize_threshold(
        self,
        val_graphs: List[Data],
        val_codes: List[str],
        val_labels: List[int]
    ):
        """
        Optimize classification threshold
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 5: Threshold Optimization")
        logger.info("=" * 80)

        # Get ensemble predictions
        results = self.ensemble.predict_ensemble(val_graphs, val_codes)
        val_proba = results['ensemble_probabilities']

        # Optimize threshold
        self.threshold_optimizer = ThresholdOptimizer(target_metric='f1_macro')
        optimal_threshold, metrics = self.threshold_optimizer.find_optimal_threshold(
            np.array(val_labels),
            val_proba,
            plot_path='models/threshold_analysis.png'
        )

        logger.info("✅ Threshold optimization complete")

        return optimal_threshold, metrics

    def add_verification_layer(self):
        """
        Add Z3 verification layer
        """
        logger.info("\n" + "=" * 80)
        logger.info("STEP 6: Adding Z3 Verification")
        logger.info("=" * 80)

        self.verifier = VerifiedEnsemblePredictor(
            ensemble=self.ensemble,
            verification_module=Z3VerificationModule(timeout_ms=5000),
            verification_threshold=0.6
        )

        logger.info("✅ Z3 verification layer added")

    def evaluate(
        self,
        test_graphs: List[Data],
        test_codes: List[str],
        test_labels: List[int],
        use_verification: bool = True
    ) -> Dict:
        """
        Comprehensive evaluation
        """
        logger.info("\n" + "=" * 80)
        logger.info("FINAL EVALUATION")
        logger.info("=" * 80)

        if use_verification and self.verifier:
            # Predict with verification
            results = self.verifier.predict_with_verification(
                test_graphs,
                test_codes,
                verify_all=False  # Only verify uncertain predictions
            )
            predictions = results['predictions']
            confidences = results['confidences']

            logger.info(f"\nVerification Summary:")
            logger.info(f"  Verified: {results['verified_count']}/{len(test_labels)}")
            logger.info(f"  Corrections: {results['corrections']}")
        else:
            # Standard ensemble prediction
            results = self.ensemble.predict_ensemble(test_graphs, test_codes)
            proba = results['ensemble_probabilities']

            # Apply optimal threshold
            if self.threshold_optimizer:
                predictions = self.threshold_optimizer.predict_with_optimal_threshold(proba)
            else:
                predictions = (proba >= 0.5).astype(int)

            confidences = proba

        # Compute metrics
        accuracy = accuracy_score(test_labels, predictions)
        f1_weighted = f1_score(test_labels, predictions, average='weighted')
        f1_macro = f1_score(test_labels, predictions, average='macro')

        logger.info("\n" + "=" * 80)
        logger.info("RESULTS")
        logger.info("=" * 80)
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"F1 (weighted): {f1_weighted:.4f}")
        logger.info(f"F1 (macro): {f1_macro:.4f}")

        logger.info("\nClassification Report:")
        print(classification_report(
            test_labels,
            predictions,
            target_names=['Safe', 'Vulnerable']
        ))

        logger.info("\nConfusion Matrix:")
        cm = confusion_matrix(test_labels, predictions)
        print(cm)

        return {
            'accuracy': accuracy,
            'f1_weighted': f1_weighted,
            'f1_macro': f1_macro,
            'predictions': predictions,
            'confidences': confidences,
            'confusion_matrix': cm
        }


def main():
    """
    Main training pipeline
    """
    logger.info("=" * 80)
    logger.info("VulnHunter Enhanced Training Pipeline")
    logger.info("Target: 96-98% Accuracy")
    logger.info("=" * 80)

    # Configuration
    config = {
        'device': 'cuda' if torch.cuda.is_available() else 'cpu',
        'hidden_dim': 256,
        'num_heads': 8,
        'dropout': 0.3,
        'gradient_accumulation_steps': 4,
        'gnn_epochs': 100,
        'codebert_epochs': 10,
        'batch_size': 32,
        'learning_rate': 1e-3
    }

    # Initialize pipeline
    pipeline = VulnHunterPipeline(config)

    # TODO: Load your actual data here
    # graph_data = load_graph_data()
    # code_texts = load_code_texts()
    # labels = load_labels()

    logger.info("\n⚠️  This is a template. Please integrate with your data loading:")
    logger.info("  1. Load graph representations (PyG Data objects)")
    logger.info("  2. Load source code strings")
    logger.info("  3. Load labels (0=safe, 1=vulnerable)")
    logger.info("\nTo run the complete pipeline:")
    logger.info("  1. Prepare data: pipeline.prepare_data(graphs, codes, labels)")
    logger.info("  2. Train GNN: pipeline.train_gnn_model(train_graphs, val_graphs)")
    logger.info("  3. Train CodeBERT: pipeline.train_codebert_model(train_codes, train_labels, val_codes, val_labels)")
    logger.info("  4. Create ensemble: pipeline.create_ensemble(val_graphs, val_codes, val_labels)")
    logger.info("  5. Optimize threshold: pipeline.optimize_threshold(val_graphs, val_codes, val_labels)")
    logger.info("  6. Add verification: pipeline.add_verification_layer()")
    logger.info("  7. Evaluate: pipeline.evaluate(test_graphs, test_codes, test_labels)")

    logger.info("\n✅ Pipeline ready. Integrate with your data and run!")


if __name__ == "__main__":
    main()
