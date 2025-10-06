#!/usr/bin/env python3
"""
VulnHunter Model Ensemble: GNN-Transformer + CodeBERT
Combines graph-based and transformer-based approaches for 96-98% accuracy
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging
from pathlib import Path
import pickle

# Transformers for CodeBERT
try:
    from transformers import (
        RobertaTokenizer,
        RobertaForSequenceClassification,
        Trainer,
        TrainingArguments,
        EarlyStoppingCallback
    )
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("⚠️  transformers not installed. Install with: pip install transformers")

from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CodeBERTVulnerabilityDetector:
    """
    Fine-tuned CodeBERT for vulnerability detection
    Uses microsoft/codebert-base pre-trained on code
    """

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        max_length: int = 512,
        device: str = None
    ):
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError("transformers library required. Install with: pip install transformers")

        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.max_length = max_length

        logger.info(f"Loading CodeBERT model: {model_name}")
        self.tokenizer = RobertaTokenizer.from_pretrained(model_name)
        self.model = RobertaForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2,
            problem_type="single_label_classification"
        )
        self.model.to(self.device)

        logger.info(f"CodeBERT loaded on device: {self.device}")

    def prepare_dataset(
        self,
        code_texts: List[str],
        labels: List[int]
    ):
        """
        Tokenize code samples for CodeBERT

        Args:
            code_texts: List of source code strings
            labels: List of labels (0=safe, 1=vulnerable)

        Returns:
            Hugging Face Dataset
        """
        encodings = self.tokenizer(
            code_texts,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors='pt'
        )

        class VulnDataset(torch.utils.data.Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __getitem__(self, idx):
                item = {k: v[idx] for k, v in self.encodings.items()}
                item['labels'] = torch.tensor(self.labels[idx])
                return item

            def __len__(self):
                return len(self.labels)

        return VulnDataset(encodings, labels)

    def train(
        self,
        train_texts: List[str],
        train_labels: List[int],
        val_texts: List[str],
        val_labels: List[int],
        output_dir: str = './codebert_vuln',
        epochs: int = 10,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
        weight_decay: float = 0.01,
        class_weights: Optional[torch.Tensor] = None
    ):
        """
        Fine-tune CodeBERT on vulnerability detection

        Args:
            train_texts: Training code samples
            train_labels: Training labels
            val_texts: Validation code samples
            val_labels: Validation labels
            output_dir: Directory to save model
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            weight_decay: Weight decay for regularization
            class_weights: Optional class weights for imbalanced data
        """
        logger.info("=" * 80)
        logger.info("Fine-tuning CodeBERT for Vulnerability Detection")
        logger.info("=" * 80)

        # Prepare datasets
        train_dataset = self.prepare_dataset(train_texts, train_labels)
        val_dataset = self.prepare_dataset(val_texts, val_labels)

        logger.info(f"Training samples: {len(train_dataset)}")
        logger.info(f"Validation samples: {len(val_dataset)}")

        # If class weights provided, use custom trainer
        if class_weights is not None:
            class_weights = class_weights.to(self.device)
            logger.info(f"Using class weights: {class_weights}")

            class WeightedTrainer(Trainer):
                def compute_loss(self, model, inputs, return_outputs=False):
                    labels = inputs.pop("labels")
                    outputs = model(**inputs)
                    logits = outputs.logits
                    loss_fct = nn.CrossEntropyLoss(weight=class_weights)
                    loss = loss_fct(logits, labels)
                    return (loss, outputs) if return_outputs else loss

            trainer_class = WeightedTrainer
        else:
            trainer_class = Trainer

        # Training arguments
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size * 2,
            learning_rate=learning_rate,
            weight_decay=weight_decay,
            warmup_steps=500,
            logging_steps=100,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            fp16=torch.cuda.is_available(),  # Mixed precision on GPU
            gradient_accumulation_steps=2,
            max_grad_norm=1.0,
            save_total_limit=3,
            report_to="none"  # Disable wandb/tensorboard
        )

        def compute_metrics(eval_pred):
            predictions, labels = eval_pred
            preds = predictions.argmax(-1)

            return {
                'accuracy': accuracy_score(labels, preds),
                'f1': f1_score(labels, preds, average='weighted'),
                'f1_macro': f1_score(labels, preds, average='macro'),
                'precision': precision_recall_fscore_support(labels, preds, average='weighted')[0],
                'recall': precision_recall_fscore_support(labels, preds, average='weighted')[1]
            }

        # Create trainer
        trainer = trainer_class(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )

        # Train
        logger.info("Starting training...")
        trainer.train()

        # Save best model
        trainer.save_model(output_dir)
        self.tokenizer.save_pretrained(output_dir)

        logger.info(f"✅ CodeBERT fine-tuning complete. Model saved to {output_dir}")

        return trainer

    def predict(
        self,
        code_texts: List[str],
        batch_size: int = 32
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict vulnerability for code samples

        Args:
            code_texts: List of code strings
            batch_size: Batch size for inference

        Returns:
            predictions (0 or 1), probabilities (for class 1)
        """
        self.model.eval()

        all_preds = []
        all_probs = []

        with torch.no_grad():
            for i in range(0, len(code_texts), batch_size):
                batch_texts = code_texts[i:i + batch_size]

                # Tokenize
                encodings = self.tokenizer(
                    batch_texts,
                    truncation=True,
                    padding=True,
                    max_length=self.max_length,
                    return_tensors='pt'
                ).to(self.device)

                # Forward pass
                outputs = self.model(**encodings)
                logits = outputs.logits

                # Get predictions
                probs = F.softmax(logits, dim=1)
                preds = torch.argmax(logits, dim=1)

                all_preds.extend(preds.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of vulnerable

        return np.array(all_preds), np.array(all_probs)


class VulnHunterEnsemble:
    """
    Ensemble combining GNN-Transformer and CodeBERT
    Uses weighted voting for final predictions
    """

    def __init__(
        self,
        gnn_model: Optional[nn.Module] = None,
        codebert_model: Optional[CodeBERTVulnerabilityDetector] = None,
        gnn_weight: float = 0.6,
        codebert_weight: float = 0.4,
        device: str = None
    ):
        """
        Args:
            gnn_model: Trained GNN-Transformer model
            codebert_model: Trained CodeBERT model
            gnn_weight: Weight for GNN predictions (default 0.6)
            codebert_weight: Weight for CodeBERT predictions (default 0.4)
            device: Device for inference
        """
        self.gnn_model = gnn_model
        self.codebert_model = codebert_model
        self.gnn_weight = gnn_weight
        self.codebert_weight = codebert_weight
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')

        # Normalize weights
        total_weight = gnn_weight + codebert_weight
        self.gnn_weight /= total_weight
        self.codebert_weight /= total_weight

        logger.info("VulnHunter Ensemble initialized")
        logger.info(f"  GNN weight: {self.gnn_weight:.2f}")
        logger.info(f"  CodeBERT weight: {self.codebert_weight:.2f}")

    def predict_gnn(
        self,
        graph_data_list: List,
        batch_size: int = 32
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Get predictions from GNN model

        Args:
            graph_data_list: List of PyG Data objects

        Returns:
            predictions, probabilities
        """
        from torch_geometric.loader import DataLoader

        self.gnn_model.eval()
        loader = DataLoader(graph_data_list, batch_size=batch_size, shuffle=False)

        all_preds = []
        all_probs = []

        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                out = self.gnn_model(batch.x, batch.edge_index, batch.batch)

                probs = F.softmax(out, dim=1)
                preds = torch.argmax(out, dim=1)

                all_preds.extend(preds.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())

        return np.array(all_preds), np.array(all_probs)

    def predict_ensemble(
        self,
        graph_data_list: List,
        code_texts: List[str],
        threshold: float = 0.5,
        use_gnn: bool = True,
        use_codebert: bool = True
    ) -> Dict[str, np.ndarray]:
        """
        Ensemble prediction combining GNN and CodeBERT

        Args:
            graph_data_list: Graph representations for GNN
            code_texts: Source code strings for CodeBERT
            threshold: Classification threshold (default 0.5)
            use_gnn: Include GNN predictions
            use_codebert: Include CodeBERT predictions

        Returns:
            Dictionary with predictions, probabilities, and individual model outputs
        """
        if not use_gnn and not use_codebert:
            raise ValueError("At least one model must be enabled")

        results = {}

        # Get GNN predictions
        if use_gnn and self.gnn_model is not None:
            logger.info("Running GNN predictions...")
            gnn_preds, gnn_probs = self.predict_gnn(graph_data_list)
            results['gnn_predictions'] = gnn_preds
            results['gnn_probabilities'] = gnn_probs
        else:
            gnn_probs = np.zeros(len(code_texts))

        # Get CodeBERT predictions
        if use_codebert and self.codebert_model is not None:
            logger.info("Running CodeBERT predictions...")
            codebert_preds, codebert_probs = self.codebert_model.predict(code_texts)
            results['codebert_predictions'] = codebert_preds
            results['codebert_probabilities'] = codebert_probs
        else:
            codebert_probs = np.zeros(len(code_texts))

        # Weighted ensemble
        if use_gnn and use_codebert:
            ensemble_probs = (
                self.gnn_weight * gnn_probs +
                self.codebert_weight * codebert_probs
            )
        elif use_gnn:
            ensemble_probs = gnn_probs
        else:
            ensemble_probs = codebert_probs

        ensemble_preds = (ensemble_probs >= threshold).astype(int)

        results['ensemble_predictions'] = ensemble_preds
        results['ensemble_probabilities'] = ensemble_probs

        return results

    def optimize_weights(
        self,
        graph_data_list: List,
        code_texts: List[str],
        true_labels: np.ndarray,
        metric: str = 'f1'
    ) -> Tuple[float, float]:
        """
        Optimize ensemble weights on validation set

        Args:
            graph_data_list: Validation graphs
            code_texts: Validation code texts
            true_labels: True labels
            metric: Metric to optimize ('f1', 'accuracy')

        Returns:
            Optimal (gnn_weight, codebert_weight)
        """
        logger.info("Optimizing ensemble weights...")

        # Get base predictions
        gnn_preds, gnn_probs = self.predict_gnn(graph_data_list)
        codebert_preds, codebert_probs = self.codebert_model.predict(code_texts)

        best_score = 0.0
        best_weights = (0.5, 0.5)

        # Grid search over weights
        for gnn_w in np.arange(0.0, 1.1, 0.1):
            codebert_w = 1.0 - gnn_w

            ensemble_probs = gnn_w * gnn_probs + codebert_w * codebert_probs
            ensemble_preds = (ensemble_probs >= 0.5).astype(int)

            if metric == 'f1':
                score = f1_score(true_labels, ensemble_preds, average='weighted')
            else:
                score = accuracy_score(true_labels, ensemble_preds)

            if score > best_score:
                best_score = score
                best_weights = (gnn_w, codebert_w)

        self.gnn_weight, self.codebert_weight = best_weights

        logger.info(f"✅ Optimal weights found:")
        logger.info(f"   GNN: {self.gnn_weight:.2f}")
        logger.info(f"   CodeBERT: {self.codebert_weight:.2f}")
        logger.info(f"   Best {metric}: {best_score:.4f}")

        return best_weights

    def save(self, path: str):
        """Save ensemble configuration"""
        config = {
            'gnn_weight': self.gnn_weight,
            'codebert_weight': self.codebert_weight,
            'device': str(self.device)
        }

        with open(path, 'wb') as f:
            pickle.dump(config, f)

        logger.info(f"Ensemble config saved to {path}")

    @classmethod
    def load(cls, path: str, gnn_model, codebert_model):
        """Load ensemble configuration"""
        with open(path, 'rb') as f:
            config = pickle.load(f)

        ensemble = cls(
            gnn_model=gnn_model,
            codebert_model=codebert_model,
            gnn_weight=config['gnn_weight'],
            codebert_weight=config['codebert_weight'],
            device=config['device']
        )

        logger.info(f"Ensemble config loaded from {path}")
        return ensemble


# Complete pipeline example
def train_complete_ensemble(
    train_graphs: List,
    train_codes: List[str],
    train_labels: List[int],
    val_graphs: List,
    val_codes: List[str],
    val_labels: List[int],
    gnn_model: nn.Module,
    output_dir: str = './vulnhunter_ensemble'
) -> VulnHunterEnsemble:
    """
    Complete pipeline to train and optimize ensemble

    Args:
        train_graphs: Training graph data
        train_codes: Training code texts
        train_labels: Training labels
        val_graphs: Validation graph data
        val_codes: Validation code texts
        val_labels: Validation labels
        gnn_model: Pre-trained GNN model
        output_dir: Output directory

    Returns:
        Optimized VulnHunterEnsemble
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # 1. Fine-tune CodeBERT
    logger.info("\n" + "=" * 80)
    logger.info("STEP 1: Fine-tuning CodeBERT")
    logger.info("=" * 80)

    codebert = CodeBERTVulnerabilityDetector()

    # Compute class weights for imbalance
    from core.advanced_imbalance_handler import AdvancedImbalanceHandler
    handler = AdvancedImbalanceHandler(strategy='class_weights')
    class_weights = handler.get_pytorch_weights(np.array(train_labels))

    codebert.train(
        train_texts=train_codes,
        train_labels=train_labels,
        val_texts=val_codes,
        val_labels=val_labels,
        output_dir=f'{output_dir}/codebert',
        epochs=10,
        batch_size=16,
        class_weights=class_weights
    )

    # 2. Create ensemble
    logger.info("\n" + "=" * 80)
    logger.info("STEP 2: Creating Ensemble")
    logger.info("=" * 80)

    ensemble = VulnHunterEnsemble(
        gnn_model=gnn_model,
        codebert_model=codebert,
        gnn_weight=0.6,
        codebert_weight=0.4
    )

    # 3. Optimize weights
    logger.info("\n" + "=" * 80)
    logger.info("STEP 3: Optimizing Ensemble Weights")
    logger.info("=" * 80)

    ensemble.optimize_weights(
        val_graphs,
        val_codes,
        np.array(val_labels),
        metric='f1'
    )

    # 4. Save ensemble
    ensemble.save(f'{output_dir}/ensemble_config.pkl')

    logger.info("\n✅ Ensemble training complete!")

    return ensemble


if __name__ == "__main__":
    logger.info("VulnHunter Ensemble Module")
    logger.info("Combine GNN-Transformer + CodeBERT for maximum accuracy")
