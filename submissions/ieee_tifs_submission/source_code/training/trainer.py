import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
import matplotlib.pyplot as plt
import pandas as pd
import os
import json
from tqdm import tqdm
import numpy as np

class VulnTrainer:
    def __init__(self, model, train_loader, val_loader, config):
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.config = config
        
        # Ensure learning_rate is float
        lr = float(config.get('learning_rate', 2e-5))
        
        self.optimizer = optim.AdamW(
            model.parameters(),
            lr=lr,
            weight_decay=0.01
        )
        
        self.scheduler = optim.lr_scheduler.StepLR(self.optimizer, step_size=3, gamma=0.1)
        
        # Loss functions
        self.criterion_vuln = nn.BCEWithLogitsLoss()
        self.criterion_type = nn.CrossEntropyLoss()
        self.criterion_severity = nn.MSELoss()
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
            'train_precision': [],
            'val_precision': [],
            'train_recall': [],
            'val_recall': [],
            'train_f1': [],
            'val_f1': []
        }
        
        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
        print(f"Using device: {self.device}")
    
    def train(self, epochs: int):
        print("Starting training...")
        
        best_val_loss = float('inf')
        patience_counter = 0
        patience = self.config.get('early_stopping_patience', 5)
        
        for epoch in range(epochs):
            # Training phase
            self.model.train()
            train_loss = 0.0
            train_metrics = {
                'correct': 0,
                'total': 0,
                'true_positives': 0,
                'false_positives': 0,
                'false_negatives': 0
            }
            
            train_bar = tqdm(self.train_loader, desc=f'Epoch {epoch+1}/{epochs} [Train]')
            
            for batch in train_bar:
                # Move data to device
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                vuln_labels = batch['vulnerability_labels'].to(self.device)
                type_labels = batch['vuln_type_labels'].to(self.device)
                severity_labels = batch['severity_labels'].to(self.device)
                
                # Zero gradients
                self.optimizer.zero_grad()
                
                # Forward pass
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                
                # Calculate losses
                loss_vuln = self.criterion_vuln(
                    outputs['vulnerability'].squeeze(), 
                    vuln_labels
                )
                loss_type = self.criterion_type(
                    outputs['vuln_type'],
                    type_labels
                )
                loss_severity = self.criterion_severity(
                    outputs['severity'].squeeze(),
                    severity_labels
                )
                
                # Combined loss
                total_loss = loss_vuln + 0.7 * loss_type + 0.3 * loss_severity
                
                # Backward pass
                total_loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
                # Statistics
                train_loss += total_loss.item()
                
                # Calculate metrics
                preds = torch.sigmoid(outputs['vulnerability'].squeeze()) > 0.5
                train_metrics['correct'] += (preds == vuln_labels).sum().item()
                train_metrics['total'] += vuln_labels.size(0)
                
                # Calculate TP, FP, FN for precision/recall
                train_metrics['true_positives'] += ((preds == 1) & (vuln_labels == 1)).sum().item()
                train_metrics['false_positives'] += ((preds == 1) & (vuln_labels == 0)).sum().item()
                train_metrics['false_negatives'] += ((preds == 0) & (vuln_labels == 1)).sum().item()
                
                train_bar.set_postfix({
                    'loss': f'{total_loss.item():.4f}',
                    'acc': f'{train_metrics["correct"]/train_metrics["total"]:.4f}'
                })
            
            # Validation phase
            val_loss, val_metrics = self.validate()
            
            # Update scheduler
            self.scheduler.step()
            
            # Calculate metrics
            train_acc = train_metrics['correct'] / train_metrics['total']
            train_precision = self._calculate_precision(train_metrics)
            train_recall = self._calculate_recall(train_metrics)
            train_f1 = self._calculate_f1(train_precision, train_recall)
            
            val_acc = val_metrics['correct'] / val_metrics['total']
            val_precision = self._calculate_precision(val_metrics)
            val_recall = self._calculate_recall(val_metrics)
            val_f1 = self._calculate_f1(val_precision, val_recall)
            
            # Record history
            epoch_train_loss = train_loss / len(self.train_loader)
            
            self.history['train_loss'].append(epoch_train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_acc'].append(val_acc)
            self.history['train_precision'].append(train_precision)
            self.history['val_precision'].append(val_precision)
            self.history['train_recall'].append(train_recall)
            self.history['val_recall'].append(val_recall)
            self.history['train_f1'].append(train_f1)
            self.history['val_f1'].append(val_f1)
            
            print(f'Epoch {epoch+1}/{epochs}:')
            print(f'  Train Loss: {epoch_train_loss:.4f}, Train Acc: {train_acc:.4f}')
            print(f'  Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}')
            print(f'  Train Precision: {train_precision:.4f}, Recall: {train_recall:.4f}, F1: {train_f1:.4f}')
            print(f'  Val Precision: {val_precision:.4f}, Recall: {val_recall:.4f}, F1: {val_f1:.4f}')
            print(f'  LR: {self.optimizer.param_groups[0]["lr"]:.2e}')
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                self.save_model('models/saved_models/best_model.pth')
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"Early stopping after {epoch+1} epochs")
                    break
    
    def validate(self):
        self.model.eval()
        val_loss = 0.0
        val_metrics = {
            'correct': 0,
            'total': 0,
            'true_positives': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        with torch.no_grad():
            val_bar = tqdm(self.val_loader, desc='Validating')
            for batch in val_bar:
                # Move data to device
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                vuln_labels = batch['vulnerability_labels'].to(self.device)
                type_labels = batch['vuln_type_labels'].to(self.device)
                severity_labels = batch['severity_labels'].to(self.device)
                
                # Forward pass
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                
                # Calculate losses
                loss_vuln = self.criterion_vuln(
                    outputs['vulnerability'].squeeze(), 
                    vuln_labels
                )
                loss_type = self.criterion_type(
                    outputs['vuln_type'],
                    type_labels
                )
                loss_severity = self.criterion_severity(
                    outputs['severity'].squeeze(),
                    severity_labels
                )
                
                total_loss = loss_vuln + 0.7 * loss_type + 0.3 * loss_severity
                val_loss += total_loss.item()
                
                # Calculate metrics
                preds = torch.sigmoid(outputs['vulnerability'].squeeze()) > 0.5
                val_metrics['correct'] += (preds == vuln_labels).sum().item()
                val_metrics['total'] += vuln_labels.size(0)
                
                # Calculate TP, FP, FN for precision/recall
                val_metrics['true_positives'] += ((preds == 1) & (vuln_labels == 1)).sum().item()
                val_metrics['false_positives'] += ((preds == 1) & (vuln_labels == 0)).sum().item()
                val_metrics['false_negatives'] += ((preds == 0) & (vuln_labels == 1)).sum().item()
                
                val_bar.set_postfix({
                    'loss': f'{total_loss.item():.4f}',
                    'acc': f'{val_metrics["correct"]/val_metrics["total"]:.4f}'
                })
        
        return val_loss / len(self.val_loader), val_metrics
    
    def _calculate_precision(self, metrics):
        tp = metrics['true_positives']
        fp = metrics['false_positives']
        if tp + fp == 0:
            return 0.0
        return tp / (tp + fp)
    
    def _calculate_recall(self, metrics):
        tp = metrics['true_positives']
        fn = metrics['false_negatives']
        if tp + fn == 0:
            return 0.0
        return tp / (tp + fn)
    
    def _calculate_f1(self, precision, recall):
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)
    
    def save_model(self, path: str):
        """Save model and training history"""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save model
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'config': self.config,
            'history': self.history
        }, path)
        
        # Save history as CSV
        history_df = pd.DataFrame(self.history)
        history_path = path.replace('.pth', '_history.csv')
        history_df.to_csv(history_path, index=False)
        
        print(f"Model saved to {path}")
        print(f"Training history saved to {history_path}")
    
    def plot_training_history(self, save_path: str = None):
        """Plot training history"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Loss plot
        ax1.plot(self.history['train_loss'], label='Train Loss')
        ax1.plot(self.history['val_loss'], label='Val Loss')
        ax1.set_title('Model Loss')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Loss')
        ax1.legend()
        ax1.grid(True)
        
        # Accuracy plot
        ax2.plot(self.history['train_acc'], label='Train Accuracy')
        ax2.plot(self.history['val_acc'], label='Val Accuracy')
        ax2.set_title('Model Accuracy')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Accuracy')
        ax2.legend()
        ax2.grid(True)
        
        # Precision/Recall plot
        ax3.plot(self.history['train_precision'], label='Train Precision', linestyle='--')
        ax3.plot(self.history['val_precision'], label='Val Precision', linestyle='--')
        ax3.plot(self.history['train_recall'], label='Train Recall')
        ax3.plot(self.history['val_recall'], label='Val Recall')
        ax3.set_title('Precision and Recall')
        ax3.set_xlabel('Epoch')
        ax3.set_ylabel('Score')
        ax3.legend()
        ax3.grid(True)
        
        # F1-Score plot
        ax4.plot(self.history['train_f1'], label='Train F1-Score')
        ax4.plot(self.history['val_f1'], label='Val F1-Score')
        ax4.set_title('F1-Score')
        ax4.set_xlabel('Epoch')
        ax4.set_ylabel('F1-Score')
        ax4.legend()
        ax4.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Training plot saved to {save_path}")
        
        plt.show()

def evaluate_model(model, test_loader, device):
    """Evaluate model performance"""
    model.eval()
    all_predictions = []
    all_labels = []
    all_probabilities = []
    
    with torch.no_grad():
        for batch in tqdm(test_loader, desc='Evaluating'):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['vulnerability_labels'].to(device)
            
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            
            probabilities = torch.sigmoid(outputs['vulnerability'].squeeze())
            predictions = probabilities > 0.5
            
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probabilities.extend(probabilities.cpu().numpy())
    
    # Calculate metrics
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
    
    accuracy = accuracy_score(all_labels, all_predictions)
    precision = precision_score(all_labels, all_predictions, zero_division=0)
    recall = recall_score(all_labels, all_predictions, zero_division=0)
    f1 = f1_score(all_labels, all_predictions, zero_division=0)
    
    # Calculate AUC if we have probabilities
    try:
        auc = roc_auc_score(all_labels, all_probabilities)
    except:
        auc = 0.0
    
    # Confusion matrix
    cm = confusion_matrix(all_labels, all_predictions)
    
    print(f"Evaluation Results:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  AUC:       {auc:.4f}")
    print(f"  Confusion Matrix:")
    print(f"    TN: {cm[0,0]}, FP: {cm[0,1]}")
    print(f"    FN: {cm[1,0]}, TP: {cm[1,1]}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'auc': auc,
        'confusion_matrix': cm.tolist(),
        'predictions': all_predictions,
        'labels': all_labels,
        'probabilities': all_probabilities
    }

def train_simple_model():
    """Simple training function for testing"""
    print("Testing simple training pipeline...")
    
    # Create a simple model
    from src.models.vuln_detector import SimpleVulnDetector
    config = {
        'vocab_size': 1000,
        'embedding_dim': 128,
        'num_classes': 16,
        'learning_rate': 0.001,
        'batch_size': 4
    }
    
    model = SimpleVulnDetector(config)
    
    # Create simple synthetic data
    from torch.utils.data import TensorDataset, DataLoader
    input_data = torch.randint(0, 1000, (32, 50))  # 32 samples, sequence length 50
    labels = torch.cat([torch.ones(16), torch.zeros(16)]).float()  # 16 vulnerable, 16 safe
    
    dataset = TensorDataset(input_data, labels, torch.zeros(32).long(), torch.zeros(32).float())
    train_loader = DataLoader(dataset, batch_size=4, shuffle=True)
    val_loader = DataLoader(dataset, batch_size=4, shuffle=False)
    
    # Train for a few epochs
    trainer = VulnTrainer(model, train_loader, val_loader, config)
    trainer.train(epochs=2)
    
    print("Simple training test completed!")
    return trainer

if __name__ == "__main__":
    train_simple_model()
