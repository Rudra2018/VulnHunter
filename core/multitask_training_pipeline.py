#!/usr/bin/env python3
"""
Multi-Task Training Pipeline for VulnHunter
Combines: Code Graphs (AST) + Text Embeddings (CodeBERT) + Multi-Task Learning
Evaluation: VD-Score (FNR at 1% FPR)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch_geometric.data import Data, Batch
from torch.cuda.amp import autocast, GradScaler
from transformers import RobertaTokenizer, RobertaModel
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_curve, auc, confusion_matrix, classification_report
)
from typing import Dict, List, Tuple, Optional
import numpy as np
import logging
from tqdm import tqdm
from pathlib import Path
import json
import tree_sitter
from tree_sitter import Language, Parser
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VDScoreMetric:
    """
    VD-Score: False Negative Rate (FNR) at 1% False Positive Rate (FPR)
    Lower is better - measures how many vulnerabilities we miss at strict threshold
    """

    @staticmethod
    def compute_vd_score(y_true: np.ndarray, y_proba: np.ndarray, target_fpr: float = 0.01) -> Dict:
        """
        Compute VD-Score: FNR at target FPR

        Args:
            y_true: Ground truth labels (0=safe, 1=vulnerable)
            y_proba: Predicted probabilities for vulnerable class
            target_fpr: Target false positive rate (default 1%)

        Returns:
            {
                'vd_score': FNR at target FPR,
                'threshold': Threshold achieving target FPR,
                'fnr': False negative rate,
                'fpr': False positive rate,
                'tpr': True positive rate
            }
        """
        # Get all FPR, TPR, thresholds
        fpr, tpr, thresholds = roc_curve(y_true, y_proba)

        # Find threshold that achieves target FPR
        idx = np.where(fpr <= target_fpr)[0]

        if len(idx) == 0:
            # No threshold achieves target FPR
            logger.warning(f"No threshold achieves FPR <= {target_fpr}")
            return {
                'vd_score': 1.0,  # Worst case
                'threshold': 1.0,
                'fnr': 1.0,
                'fpr': 0.0,
                'tpr': 0.0,
                'auc_roc': auc(fpr, tpr)
            }

        # Get highest TPR (lowest FNR) at target FPR
        best_idx = idx[-1]
        best_threshold = thresholds[best_idx]
        best_tpr = tpr[best_idx]
        best_fpr = fpr[best_idx]
        best_fnr = 1.0 - best_tpr

        return {
            'vd_score': best_fnr,  # This is what we want to minimize
            'threshold': best_threshold,
            'fnr': best_fnr,
            'fpr': best_fpr,
            'tpr': best_tpr,
            'auc_roc': auc(fpr, tpr)
        }


class ASTGraphConstructor:
    """
    Construct code graphs from Abstract Syntax Tree (AST)
    Uses tree-sitter for robust parsing
    """

    def __init__(self, language: str = 'c'):
        """
        Args:
            language: Programming language ('c', 'cpp', 'python', 'java')
        """
        self.language = language
        self.parser = None
        self.init_parser()

    def init_parser(self):
        """Initialize tree-sitter parser"""
        try:
            # Build tree-sitter languages if not exists
            lib_path = Path(__file__).parent / 'build' / 'languages.so'

            if not lib_path.exists():
                logger.info("Building tree-sitter languages...")
                lib_path.parent.mkdir(parents=True, exist_ok=True)

                # Clone tree-sitter language repos
                repos = {
                    'c': 'https://github.com/tree-sitter/tree-sitter-c',
                    'cpp': 'https://github.com/tree-sitter/tree-sitter-cpp',
                    'python': 'https://github.com/tree-sitter/tree-sitter-python',
                    'java': 'https://github.com/tree-sitter/tree-sitter-java'
                }

                # For now, use simplified approach
                logger.warning("Tree-sitter not fully configured. Using fallback AST construction.")
                self.parser = None
                return

            # Load language
            LANGUAGE = Language(str(lib_path), self.language)
            self.parser = Parser()
            self.parser.set_language(LANGUAGE)

        except Exception as e:
            logger.warning(f"Failed to initialize tree-sitter: {e}. Using fallback.")
            self.parser = None

    def construct_graph_from_code(self, code: str, node_feature_dim: int = 128) -> Data:
        """
        Construct PyTorch Geometric graph from code

        Args:
            code: Source code string
            node_feature_dim: Dimension of node features

        Returns:
            PyTorch Geometric Data object
        """
        if self.parser:
            return self._construct_from_tree_sitter(code, node_feature_dim)
        else:
            return self._construct_from_simple_ast(code, node_feature_dim)

    def _construct_from_simple_ast(self, code: str, node_feature_dim: int) -> Data:
        """
        Simplified AST construction (fallback)
        Creates graph based on code structure
        """
        import ast as py_ast

        try:
            # Try to parse as Python (for demonstration)
            tree = py_ast.parse(code)
        except:
            # If parsing fails, create simple graph
            return self._create_simple_graph(code, node_feature_dim)

        # Extract nodes and edges
        nodes = []
        edges = []
        node_map = {}

        def visit_node(node, parent_idx=None):
            idx = len(nodes)
            node_map[id(node)] = idx

            # Create node feature (one-hot encoding of node type)
            node_type = type(node).__name__
            node_hash = hash(node_type) % node_feature_dim
            feature = torch.zeros(node_feature_dim)
            feature[node_hash] = 1.0
            nodes.append(feature)

            # Add edge from parent
            if parent_idx is not None:
                edges.append([parent_idx, idx])
                edges.append([idx, parent_idx])  # Bidirectional

            # Visit children
            for child in py_ast.iter_child_nodes(node):
                visit_node(child, idx)

        visit_node(tree)

        # Convert to tensors
        if len(nodes) == 0:
            return self._create_simple_graph(code, node_feature_dim)

        x = torch.stack(nodes)
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.empty((2, 0), dtype=torch.long)

        return Data(x=x, edge_index=edge_index)

    def _create_simple_graph(self, code: str, node_feature_dim: int) -> Data:
        """
        Create simple graph when AST parsing fails
        Uses code tokens and sequential connections
        """
        # Tokenize code
        tokens = code.split()

        if len(tokens) == 0:
            # Empty code - single node
            x = torch.randn(1, node_feature_dim)
            edge_index = torch.empty((2, 0), dtype=torch.long)
            return Data(x=x, edge_index=edge_index)

        # Create nodes (max 100 tokens)
        tokens = tokens[:100]
        nodes = []
        for token in tokens:
            token_hash = hash(token) % node_feature_dim
            feature = torch.zeros(node_feature_dim)
            feature[token_hash] = 1.0
            nodes.append(feature)

        x = torch.stack(nodes)

        # Create sequential edges
        edges = []
        for i in range(len(tokens) - 1):
            edges.append([i, i + 1])
            edges.append([i + 1, i])

        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.empty((2, 0), dtype=torch.long)

        return Data(x=x, edge_index=edge_index)


class MultiModalVulnerabilityDataset(Dataset):
    """
    Dataset combining code graphs and text embeddings
    """

    def __init__(
        self,
        samples: List[Dict],
        tokenizer: RobertaTokenizer,
        max_text_length: int = 256,
        graph_constructor: Optional[ASTGraphConstructor] = None
    ):
        """
        Args:
            samples: List of samples from enhanced_github_integrator
            tokenizer: CodeBERT tokenizer
            max_text_length: Max length for text tokenization
            graph_constructor: AST graph constructor
        """
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_text_length = max_text_length
        self.graph_constructor = graph_constructor or ASTGraphConstructor()

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]

        # 1. Construct code graph from AST
        code = sample.get('code', '')
        graph = self.graph_constructor.construct_graph_from_code(code)

        # 2. Tokenize commit message
        commit_msg = sample.get('commit_message', '')
        commit_tokens = self.tokenizer(
            commit_msg,
            max_length=self.max_text_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )

        # 3. Tokenize commit diff
        commit_diff = sample.get('commit_diff', '')
        diff_tokens = self.tokenizer(
            commit_diff,
            max_length=self.max_text_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )

        # 4. Labels
        labels = {
            'vulnerability': sample.get('label', 0),  # 0=safe, 1=vulnerable
            'validation': self._encode_validation_status(sample.get('validation_status', 'unknown')),
            'false_positive': 1 if sample.get('is_false_positive', False) else 0
        }

        return {
            'graph': graph,
            'commit_msg_input_ids': commit_tokens['input_ids'].squeeze(0),
            'commit_msg_attention_mask': commit_tokens['attention_mask'].squeeze(0),
            'diff_input_ids': diff_tokens['input_ids'].squeeze(0),
            'diff_attention_mask': diff_tokens['attention_mask'].squeeze(0),
            'labels': labels
        }

    def _encode_validation_status(self, status: str) -> int:
        """Encode validation status to integer"""
        mapping = {'unknown': 0, 'unconfirmed': 1, 'validated': 2}
        return mapping.get(status, 0)


def collate_multimodal_batch(batch):
    """
    Custom collate function for multi-modal data
    """
    # Separate graphs and text
    graphs = [item['graph'] for item in batch]
    batched_graph = Batch.from_data_list(graphs)

    # Stack text tensors
    commit_msg_input_ids = torch.stack([item['commit_msg_input_ids'] for item in batch])
    commit_msg_attention_mask = torch.stack([item['commit_msg_attention_mask'] for item in batch])
    diff_input_ids = torch.stack([item['diff_input_ids'] for item in batch])
    diff_attention_mask = torch.stack([item['diff_attention_mask'] for item in batch])

    # Stack labels
    labels = {
        'vulnerability': torch.tensor([item['labels']['vulnerability'] for item in batch], dtype=torch.long),
        'validation': torch.tensor([item['labels']['validation'] for item in batch], dtype=torch.long),
        'false_positive': torch.tensor([item['labels']['false_positive'] for item in batch], dtype=torch.long)
    }

    return {
        'graph': batched_graph,
        'commit_msg_input_ids': commit_msg_input_ids,
        'commit_msg_attention_mask': commit_msg_attention_mask,
        'diff_input_ids': diff_input_ids,
        'diff_attention_mask': diff_attention_mask,
        'labels': labels
    }


class MultiTaskTrainer:
    """
    Multi-task training pipeline with VD-Score evaluation
    """

    def __init__(
        self,
        model: nn.Module,
        loss_fn: nn.Module,
        device: str = 'cuda',
        learning_rate: float = 1e-3,
        use_mixed_precision: bool = True
    ):
        self.model = model.to(device)
        self.loss_fn = loss_fn.to(device)
        self.device = device
        self.use_mixed_precision = use_mixed_precision

        # Optimizer
        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )

        # Scheduler
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self.optimizer,
            T_0=10,
            T_mult=2
        )

        # Mixed precision scaler
        self.scaler = GradScaler() if use_mixed_precision else None

        # Metrics
        self.vd_score_metric = VDScoreMetric()

    def train_epoch(self, train_loader: DataLoader) -> Dict:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        task_losses = {'vulnerability': 0.0, 'validation': 0.0, 'false_positive': 0.0}

        pbar = tqdm(train_loader, desc="Training")
        for batch_idx, batch in enumerate(pbar):
            # Move to device
            graph = batch['graph'].to(self.device)
            commit_msg_input_ids = batch['commit_msg_input_ids'].to(self.device)
            commit_msg_attention_mask = batch['commit_msg_attention_mask'].to(self.device)
            diff_input_ids = batch['diff_input_ids'].to(self.device)
            diff_attention_mask = batch['diff_attention_mask'].to(self.device)

            labels = {
                k: v.to(self.device) for k, v in batch['labels'].items()
            }

            # Forward pass
            self.optimizer.zero_grad()

            if self.use_mixed_precision:
                with autocast():
                    # Model forward (assumes model supports text inputs)
                    outputs = self.model(
                        x=graph.x,
                        edge_index=graph.edge_index,
                        batch=graph.batch,
                        commit_msg_input_ids=commit_msg_input_ids,
                        commit_msg_attention_mask=commit_msg_attention_mask,
                        diff_input_ids=diff_input_ids,
                        diff_attention_mask=diff_attention_mask
                    )

                    # Compute loss
                    loss, individual_losses = self.loss_fn(outputs, labels)

                # Backward pass
                self.scaler.scale(loss).backward()
                self.scaler.step(self.optimizer)
                self.scaler.update()
            else:
                outputs = self.model(
                    x=graph.x,
                    edge_index=graph.edge_index,
                    batch=graph.batch,
                    commit_msg_input_ids=commit_msg_input_ids,
                    commit_msg_attention_mask=commit_msg_attention_mask,
                    diff_input_ids=diff_input_ids,
                    diff_attention_mask=diff_attention_mask
                )

                loss, individual_losses = self.loss_fn(outputs, labels)
                loss.backward()
                self.optimizer.step()

            # Update metrics
            total_loss += loss.item()
            for task, task_loss in individual_losses.items():
                if task != 'total':
                    task_losses[task] += task_loss.item()

            pbar.set_postfix({'loss': loss.item()})

        # Average losses
        avg_loss = total_loss / len(train_loader)
        avg_task_losses = {k: v / len(train_loader) for k, v in task_losses.items()}

        return {'total_loss': avg_loss, **avg_task_losses}

    @torch.no_grad()
    def evaluate(self, val_loader: DataLoader) -> Dict:
        """Evaluate with VD-Score"""
        self.model.eval()

        all_predictions = {
            'vulnerability': [],
            'validation': [],
            'false_positive': []
        }
        all_labels = {
            'vulnerability': [],
            'validation': [],
            'false_positive': []
        }
        all_proba = []

        for batch in tqdm(val_loader, desc="Evaluating"):
            # Move to device
            graph = batch['graph'].to(self.device)
            commit_msg_input_ids = batch['commit_msg_input_ids'].to(self.device)
            commit_msg_attention_mask = batch['commit_msg_attention_mask'].to(self.device)
            diff_input_ids = batch['diff_input_ids'].to(self.device)
            diff_attention_mask = batch['diff_attention_mask'].to(self.device)

            labels = {
                k: v.to(self.device) for k, v in batch['labels'].items()
            }

            # Forward pass
            outputs = self.model(
                x=graph.x,
                edge_index=graph.edge_index,
                batch=graph.batch,
                commit_msg_input_ids=commit_msg_input_ids,
                commit_msg_attention_mask=commit_msg_attention_mask,
                diff_input_ids=diff_input_ids,
                diff_attention_mask=diff_attention_mask
            )

            # Get predictions
            vuln_proba = F.softmax(outputs['vulnerability'], dim=1)[:, 1]  # P(vulnerable)
            vuln_pred = torch.argmax(outputs['vulnerability'], dim=1)

            validation_pred = torch.argmax(outputs['validation'], dim=1)
            fp_pred = torch.argmax(outputs['false_positive'], dim=1)

            # Store
            all_proba.extend(vuln_proba.cpu().numpy())
            all_predictions['vulnerability'].extend(vuln_pred.cpu().numpy())
            all_predictions['validation'].extend(validation_pred.cpu().numpy())
            all_predictions['false_positive'].extend(fp_pred.cpu().numpy())

            all_labels['vulnerability'].extend(labels['vulnerability'].cpu().numpy())
            all_labels['validation'].extend(labels['validation'].cpu().numpy())
            all_labels['false_positive'].extend(labels['false_positive'].cpu().numpy())

        # Convert to numpy
        y_true = np.array(all_labels['vulnerability'])
        y_pred = np.array(all_predictions['vulnerability'])
        y_proba = np.array(all_proba)

        # Compute VD-Score
        vd_metrics = self.vd_score_metric.compute_vd_score(y_true, y_proba, target_fpr=0.01)

        # Standard metrics
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'f1_macro': f1_score(y_true, y_pred, average='macro'),
            'f1_weighted': f1_score(y_true, y_pred, average='weighted'),
            'f1_safe': f1_score(y_true, y_pred, pos_label=0),
            'f1_vulnerable': f1_score(y_true, y_pred, pos_label=1),
            'precision': precision_score(y_true, y_pred, average='weighted'),
            'recall': recall_score(y_true, y_pred, average='weighted'),
            **vd_metrics  # Add VD-Score metrics
        }

        # Validation task metrics
        val_y_true = np.array(all_labels['validation'])
        val_y_pred = np.array(all_predictions['validation'])
        metrics['validation_accuracy'] = accuracy_score(val_y_true, val_y_pred)
        metrics['validation_f1'] = f1_score(val_y_true, val_y_pred, average='weighted')

        # False positive task metrics
        fp_y_true = np.array(all_labels['false_positive'])
        fp_y_pred = np.array(all_predictions['false_positive'])
        metrics['fp_accuracy'] = accuracy_score(fp_y_true, fp_y_pred)
        metrics['fp_f1'] = f1_score(fp_y_true, fp_y_pred, average='weighted')

        return metrics

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        num_epochs: int = 100,
        early_stopping_patience: int = 15,
        save_dir: str = 'models'
    ):
        """
        Complete training pipeline
        """
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)

        best_vd_score = float('inf')
        patience_counter = 0
        history = []

        logger.info("🚀 Starting Multi-Task Training")
        logger.info(f"Device: {self.device}")
        logger.info(f"Mixed Precision: {self.use_mixed_precision}")

        for epoch in range(num_epochs):
            logger.info(f"\n{'='*60}")
            logger.info(f"Epoch {epoch + 1}/{num_epochs}")
            logger.info(f"{'='*60}")

            # Train
            train_metrics = self.train_epoch(train_loader)
            logger.info(f"Train Loss: {train_metrics['total_loss']:.4f}")
            logger.info(f"  Vulnerability: {train_metrics['vulnerability']:.4f}")
            logger.info(f"  Validation: {train_metrics['validation']:.4f}")
            logger.info(f"  False Positive: {train_metrics['false_positive']:.4f}")

            # Evaluate
            val_metrics = self.evaluate(val_loader)
            logger.info(f"\nValidation Metrics:")
            logger.info(f"  Accuracy: {val_metrics['accuracy']:.4f}")
            logger.info(f"  F1 Macro: {val_metrics['f1_macro']:.4f}")
            logger.info(f"  F1 Safe: {val_metrics['f1_safe']:.4f}")
            logger.info(f"  F1 Vulnerable: {val_metrics['f1_vulnerable']:.4f}")
            logger.info(f"  VD-Score (FNR@1%FPR): {val_metrics['vd_score']:.4f} ⭐")
            logger.info(f"  AUC-ROC: {val_metrics['auc_roc']:.4f}")
            logger.info(f"  Validation Task F1: {val_metrics['validation_f1']:.4f}")
            logger.info(f"  FP Detection F1: {val_metrics['fp_f1']:.4f}")

            # Save history
            history.append({
                'epoch': epoch + 1,
                'train': train_metrics,
                'val': val_metrics
            })

            # Check for improvement (lower VD-Score is better)
            if val_metrics['vd_score'] < best_vd_score:
                best_vd_score = val_metrics['vd_score']
                patience_counter = 0

                # Save best model
                torch.save({
                    'epoch': epoch + 1,
                    'model_state_dict': self.model.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'best_vd_score': best_vd_score,
                    'metrics': val_metrics
                }, save_dir / 'best_multitask_model.pth')

                logger.info(f"✅ New best VD-Score: {best_vd_score:.4f} (model saved)")
            else:
                patience_counter += 1
                logger.info(f"No improvement ({patience_counter}/{early_stopping_patience})")

            # Early stopping
            if patience_counter >= early_stopping_patience:
                logger.info(f"\n⏹️  Early stopping triggered after {epoch + 1} epochs")
                break

            # Step scheduler
            self.scheduler.step()

        # Save training history
        with open(save_dir / 'training_history.json', 'w') as f:
            json.dump(history, f, indent=2)

        logger.info(f"\n{'='*60}")
        logger.info(f"✅ Training Complete!")
        logger.info(f"Best VD-Score: {best_vd_score:.4f}")
        logger.info(f"Models saved to: {save_dir}")
        logger.info(f"{'='*60}\n")

        return history


# Example usage
if __name__ == "__main__":
    from core.multitask_gnn_model import MultiTaskGNNTransformer, MultiTaskLoss
    from core.enhanced_github_integrator import EnhancedGitHubIntegrator

    logger.info("Multi-Task Training Pipeline Test")

    # 1. Load data (mock for testing)
    samples = [
        {
            'code': 'void unsafe_copy(char *dst, char *src) { strcpy(dst, src); }',
            'label': 1,
            'commit_message': 'Fix buffer overflow vulnerability validated via fuzzing',
            'commit_diff': '- strcpy(dst, src);\n+ strncpy(dst, src, MAX_LEN);',
            'validation_status': 'validated',
            'is_false_positive': False
        },
        {
            'code': 'int safe_add(int a, int b) { return a + b; }',
            'label': 0,
            'commit_message': 'Add safe arithmetic function',
            'commit_diff': '+ int safe_add(int a, int b) { return a + b; }',
            'validation_status': 'unknown',
            'is_false_positive': False
        }
    ] * 100  # Replicate for testing

    # Split
    train_samples = samples[:160]
    val_samples = samples[160:]

    # 2. Create datasets
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
    graph_constructor = ASTGraphConstructor()

    train_dataset = MultiModalVulnerabilityDataset(
        train_samples,
        tokenizer,
        graph_constructor=graph_constructor
    )

    val_dataset = MultiModalVulnerabilityDataset(
        val_samples,
        tokenizer,
        graph_constructor=graph_constructor
    )

    # 3. Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=8,
        shuffle=True,
        collate_fn=collate_multimodal_batch
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=8,
        shuffle=False,
        collate_fn=collate_multimodal_batch
    )

    # 4. Initialize model
    model = MultiTaskGNNTransformer(
        input_dim=128,
        hidden_dim=256,
        num_heads=8,
        dropout=0.3,
        use_validation_head=True,
        use_fp_head=True
    )

    # 5. Initialize loss
    loss_fn = MultiTaskLoss(
        use_validation=True,
        use_fp=True
    )

    # 6. Initialize trainer
    trainer = MultiTaskTrainer(
        model=model,
        loss_fn=loss_fn,
        device='cuda' if torch.cuda.is_available() else 'cpu',
        learning_rate=1e-3,
        use_mixed_precision=True
    )

    # 7. Train
    history = trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        num_epochs=5,  # Short test
        early_stopping_patience=3,
        save_dir='models/test'
    )

    logger.info("✅ Pipeline test complete!")
