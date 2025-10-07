#!/usr/bin/env python3
"""
Train False Positive Reduction Model on HackerOne Data
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from pathlib import Path
import logging
from tqdm import tqdm
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns

from core.hackerone_dataset_builder import HackerOneDatasetBuilder
from core.enhanced_fp_engine import EnhancedFPReductionModel, HackerOneFPEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HackerOneDataset(Dataset):
    """PyTorch Dataset for HackerOne vulnerability data"""

    def __init__(self, df: pd.DataFrame, tokenizer, device="cpu"):
        self.df = df
        self.tokenizer = tokenizer
        self.device = device

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]

        # Tokenize code
        code = str(row['code'])
        inputs = self.tokenizer(
            code,
            max_length=512,
            truncation=True,
            padding='max_length',
            return_tensors='pt'
        )

        # Labels: 0=safe/FP, 1=vulnerable/TP
        label = int(row['label'])

        # For FP detection, invert if it's a false positive
        fp_label = 1 if row['is_false_positive'] else 0

        return {
            'input_ids': inputs['input_ids'].squeeze(0),
            'attention_mask': inputs['attention_mask'].squeeze(0),
            'label': torch.tensor(label, dtype=torch.long),
            'fp_label': torch.tensor(fp_label, dtype=torch.long),
            'code': code
        }


class HackerOneFPTrainer:
    """Trainer for False Positive Reduction Model"""

    def __init__(
        self,
        model: nn.Module,
        code_model,
        device: str = "cpu",
        learning_rate: float = 1e-4,
        output_dir: str = "models/fp_reduction"
    ):
        self.model = model.to(device)
        self.code_model = code_model.to(device)
        self.device = device
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.optimizer = optim.AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )

        self.criterion = nn.CrossEntropyLoss()
        self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode='min',
            factor=0.5,
            patience=3
        )

        self.best_val_loss = float('inf')
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }

    def get_code_embeddings(self, input_ids, attention_mask):
        """Get embeddings from CodeBERT"""
        with torch.no_grad():
            outputs = self.code_model(
                input_ids=input_ids,
                attention_mask=attention_mask
            )
            # Use [CLS] token embedding
            embeddings = outputs.last_hidden_state[:, 0, :]
        return embeddings

    def train_epoch(self, dataloader):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        predictions = []
        labels = []

        for batch in tqdm(dataloader, desc="Training"):
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            fp_labels = batch['fp_label'].to(self.device)

            # Get code embeddings
            embeddings = self.get_code_embeddings(input_ids, attention_mask)

            # Forward pass
            logits, _ = self.model(embeddings)
            loss = self.criterion(logits, fp_labels)

            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()

            total_loss += loss.item()

            # Track predictions
            preds = torch.argmax(logits, dim=-1)
            predictions.extend(preds.cpu().numpy())
            labels.extend(fp_labels.cpu().numpy())

        avg_loss = total_loss / len(dataloader)
        accuracy = accuracy_score(labels, predictions)

        return avg_loss, accuracy

    def validate(self, dataloader):
        """Validate model"""
        self.model.eval()
        total_loss = 0
        predictions = []
        labels = []
        all_probs = []

        with torch.no_grad():
            for batch in tqdm(dataloader, desc="Validating"):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                fp_labels = batch['fp_label'].to(self.device)

                # Get code embeddings
                embeddings = self.get_code_embeddings(input_ids, attention_mask)

                # Forward pass
                logits, _ = self.model(embeddings)
                loss = self.criterion(logits, fp_labels)

                total_loss += loss.item()

                # Track predictions
                probs = torch.softmax(logits, dim=-1)
                preds = torch.argmax(logits, dim=-1)

                predictions.extend(preds.cpu().numpy())
                labels.extend(fp_labels.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of FP class

        avg_loss = total_loss / len(dataloader)
        accuracy = accuracy_score(labels, predictions)
        precision = precision_score(labels, predictions, zero_division=0)
        recall = recall_score(labels, predictions, zero_division=0)
        f1 = f1_score(labels, predictions, zero_division=0)

        try:
            auc = roc_auc_score(labels, all_probs)
        except:
            auc = 0.0

        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc': auc,
            'predictions': predictions,
            'labels': labels
        }

    def train(
        self,
        train_loader,
        val_loader,
        num_epochs: int = 20,
        early_stopping_patience: int = 5
    ):
        """Full training loop"""
        logger.info(f"Starting training for {num_epochs} epochs...")

        patience_counter = 0

        for epoch in range(num_epochs):
            logger.info(f"\nEpoch {epoch + 1}/{num_epochs}")
            logger.info("=" * 60)

            # Train
            train_loss, train_acc = self.train_epoch(train_loader)
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)

            # Validate
            val_metrics = self.validate(val_loader)
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['val_acc'].append(val_metrics['accuracy'])

            logger.info(f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f}")
            logger.info(f"Val Loss: {val_metrics['loss']:.4f} | Val Acc: {val_metrics['accuracy']:.4f}")
            logger.info(f"Val Precision: {val_metrics['precision']:.4f} | Val Recall: {val_metrics['recall']:.4f}")
            logger.info(f"Val F1: {val_metrics['f1']:.4f} | Val AUC: {val_metrics['auc']:.4f}")

            # Learning rate scheduling
            self.scheduler.step(val_metrics['loss'])

            # Save best model
            if val_metrics['loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['loss']
                self.save_model('best_model.pt')
                logger.info(f"✓ Saved best model (val_loss: {val_metrics['loss']:.4f})")
                patience_counter = 0
            else:
                patience_counter += 1

            # Early stopping
            if patience_counter >= early_stopping_patience:
                logger.info(f"\nEarly stopping triggered after {epoch + 1} epochs")
                break

        logger.info("\n" + "=" * 60)
        logger.info("Training complete!")
        logger.info(f"Best validation loss: {self.best_val_loss:.4f}")

        return self.history

    def save_model(self, filename: str):
        """Save model checkpoint"""
        path = self.output_dir / filename
        torch.save(self.model.state_dict(), path)
        logger.info(f"Model saved to {path}")

    def plot_training_history(self):
        """Plot training curves"""
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))

        # Loss
        axes[0].plot(self.history['train_loss'], label='Train Loss')
        axes[0].plot(self.history['val_loss'], label='Val Loss')
        axes[0].set_xlabel('Epoch')
        axes[0].set_ylabel('Loss')
        axes[0].set_title('Training and Validation Loss')
        axes[0].legend()
        axes[0].grid(True)

        # Accuracy
        axes[1].plot(self.history['train_acc'], label='Train Accuracy')
        axes[1].plot(self.history['val_acc'], label='Val Accuracy')
        axes[1].set_xlabel('Epoch')
        axes[1].set_ylabel('Accuracy')
        axes[1].set_title('Training and Validation Accuracy')
        axes[1].legend()
        axes[1].grid(True)

        plt.tight_layout()
        plot_path = self.output_dir / 'training_history.png'
        plt.savefig(plot_path, dpi=300)
        logger.info(f"Training plot saved to {plot_path}")


def evaluate_on_test_set(model, code_model, test_loader, device):
    """Evaluate model on test set"""
    logger.info("\nEvaluating on test set...")

    model.eval()
    predictions = []
    labels = []
    all_probs = []

    with torch.no_grad():
        for batch in tqdm(test_loader, desc="Testing"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            fp_labels = batch['fp_label'].to(device)

            # Get embeddings
            outputs = code_model(input_ids=input_ids, attention_mask=attention_mask)
            embeddings = outputs.last_hidden_state[:, 0, :]

            # Predict
            logits, _ = model(embeddings)
            probs = torch.softmax(logits, dim=-1)
            preds = torch.argmax(logits, dim=-1)

            predictions.extend(preds.cpu().numpy())
            labels.extend(fp_labels.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())

    # Compute metrics
    logger.info("\n" + "=" * 60)
    logger.info("TEST SET RESULTS")
    logger.info("=" * 60)

    logger.info(f"\nAccuracy: {accuracy_score(labels, predictions):.4f}")
    logger.info(f"Precision: {precision_score(labels, predictions, zero_division=0):.4f}")
    logger.info(f"Recall: {recall_score(labels, predictions, zero_division=0):.4f}")
    logger.info(f"F1 Score: {f1_score(labels, predictions, zero_division=0):.4f}")

    try:
        auc = roc_auc_score(labels, all_probs)
        logger.info(f"AUC-ROC: {auc:.4f}")
    except:
        pass

    logger.info("\nClassification Report:")
    logger.info("\n" + classification_report(
        labels, predictions,
        target_names=['Not FP', 'False Positive']
    ))

    # Confusion matrix
    cm = confusion_matrix(labels, predictions)
    logger.info("\nConfusion Matrix:")
    logger.info(f"TN: {cm[0,0]}, FP: {cm[0,1]}")
    logger.info(f"FN: {cm[1,0]}, TP: {cm[1,1]}")

    return predictions, labels


def main():
    """Main training pipeline"""
    logger.info("=" * 60)
    logger.info("HackerOne False Positive Reduction - Training")
    logger.info("=" * 60)

    # Configuration
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"\nDevice: {device}")

    # Step 1: Build dataset
    logger.info("\n[1/4] Building HackerOne dataset...")
    builder = HackerOneDatasetBuilder()
    df = builder.build_dataset(num_samples=10000, balance_ratio=0.5)
    df = builder.add_contextual_features(df)
    builder.save_dataset(df, name="hackerone_fp_training")

    # Step 2: Prepare data loaders
    logger.info("\n[2/4] Preparing data loaders...")

    # Load engine to get tokenizer and code model
    engine = HackerOneFPEngine(device=device)

    # Create datasets
    train_df = pd.read_csv("data/hackerone_synthetic/hackerone_fp_training_train.csv")
    val_df = pd.read_csv("data/hackerone_synthetic/hackerone_fp_training_val.csv")
    test_df = pd.read_csv("data/hackerone_synthetic/hackerone_fp_training_test.csv")

    train_dataset = HackerOneDataset(train_df, engine.tokenizer, device)
    val_dataset = HackerOneDataset(val_df, engine.tokenizer, device)
    test_dataset = HackerOneDataset(test_df, engine.tokenizer, device)

    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=16, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=16, shuffle=False)

    logger.info(f"Train samples: {len(train_dataset)}")
    logger.info(f"Val samples: {len(val_dataset)}")
    logger.info(f"Test samples: {len(test_dataset)}")

    # Step 3: Train model
    logger.info("\n[3/4] Training FP reduction model...")

    model = EnhancedFPReductionModel(input_dim=768, hidden_dim=256)
    trainer = HackerOneFPTrainer(
        model=model,
        code_model=engine.code_model,
        device=device,
        learning_rate=1e-4
    )

    history = trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        num_epochs=20,
        early_stopping_patience=5
    )

    # Plot training history
    trainer.plot_training_history()

    # Step 4: Evaluate on test set
    logger.info("\n[4/4] Final evaluation...")

    # Load best model
    best_model_path = Path("models/fp_reduction/best_model.pt")
    model.load_state_dict(torch.load(best_model_path, map_location=device))

    predictions, labels = evaluate_on_test_set(
        model=model,
        code_model=engine.code_model,
        test_loader=test_loader,
        device=device
    )

    # Save final model for inference
    final_model_path = Path("models/fp_reduction/hackerone_fp_model_final.pt")
    torch.save(model.state_dict(), final_model_path)
    logger.info(f"\n✅ Final model saved to: {final_model_path}")

    logger.info("\n" + "=" * 60)
    logger.info("Training pipeline complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
