#!/usr/bin/env python3
"""
Azure ML training script for VulnHunter V5
"""

import os
import argparse
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np
import logging
import json
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleVulnDataset(Dataset):
    """Simple dataset for vulnerability detection"""

    def __init__(self, dataframe):
        self.data = dataframe.reset_index(drop=True)

        # Extract features from code (simplified feature extraction)
        self.features = []
        self.labels = []

        for _, row in self.data.iterrows():
            code = row['code']
            # Simple feature extraction
            features = [
                len(code),  # Code length
                code.count('('),  # Function calls
                code.count('if'),  # Conditionals
                code.count('for') + code.count('while'),  # Loops
                code.count('=') - code.count('=='),  # Assignments
                1.0 if 'strcpy' in code else 0.0,  # Dangerous functions
                1.0 if 'malloc' in code else 0.0,  # Memory allocation
                1.0 if 'require' in code else 0.0,  # Solidity requires
                code.count('\n'),  # Line count
                1.0 if row['language'] == 'solidity' else 0.0  # Language indicator
            ]

            # Pad to 20 features
            while len(features) < 20:
                features.append(0.0)

            self.features.append(features[:20])
            self.labels.append(row['is_vulnerable'])

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return {
            'features': torch.tensor(self.features[idx], dtype=torch.float32),
            'label': torch.tensor(self.labels[idx], dtype=torch.long)
        }


class SimpleVulnModel(nn.Module):
    """Simple neural network for vulnerability detection"""

    def __init__(self, input_dim=20, hidden_dim=64, num_classes=2):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim//2, num_classes)
        )

    def forward(self, x):
        return self.network(x)


def train_model(data_path, output_dir):
    """Train the vulnerability detection model"""
    logger.info(f"Starting training with data from {data_path}")

    # Load data
    df = pd.read_csv(data_path)
    logger.info(f"Loaded dataset with {len(df)} samples")

    # Split data
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42,
                                        stratify=df['is_vulnerable'])

    # Create datasets
    train_dataset = SimpleVulnDataset(train_df)
    test_dataset = SimpleVulnDataset(test_df)

    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=2, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=2, shuffle=False)

    # Initialize model
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = SimpleVulnModel().to(device)

    logger.info(f"Using device: {device}")
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters())}")

    # Loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    # Training loop
    num_epochs = 50
    best_f1 = 0.0

    for epoch in range(num_epochs):
        model.train()
        train_loss = 0.0

        for batch in train_loader:
            features = batch['features'].to(device)
            labels = batch['label'].to(device)

            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()

        # Validation
        model.eval()
        test_predictions = []
        test_labels = []

        with torch.no_grad():
            for batch in test_loader:
                features = batch['features'].to(device)
                labels = batch['label'].to(device)

                outputs = model(features)
                predictions = torch.argmax(outputs, dim=1)

                test_predictions.extend(predictions.cpu().numpy())
                test_labels.extend(labels.cpu().numpy())

        # Calculate metrics
        accuracy = accuracy_score(test_labels, test_predictions)
        precision = precision_score(test_labels, test_predictions, zero_division=0)
        recall = recall_score(test_labels, test_predictions, zero_division=0)
        f1 = f1_score(test_labels, test_predictions, zero_division=0)

        logger.info(f"Epoch {epoch+1}/{num_epochs}: "
                   f"Loss={train_loss/len(train_loader):.4f}, "
                   f"Acc={accuracy:.4f}, F1={f1:.4f}")

        # Save best model
        if f1 > best_f1:
            best_f1 = f1
            torch.save(model.state_dict(), os.path.join(output_dir, 'best_model.pt'))

    # Save final metrics
    final_metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'best_f1': best_f1
    }

    with open(os.path.join(output_dir, 'metrics.json'), 'w') as f:
        json.dump(final_metrics, f, indent=2)

    logger.info(f"Training completed. Best F1: {best_f1:.4f}")
    logger.info(f"Final metrics: {final_metrics}")

    return final_metrics


def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description='VulnHunter V5 Training')
    parser.add_argument('--data-path', type=str, required=True,
                       help='Path to training dataset')
    parser.add_argument('--output-dir', type=str, default='./outputs',
                       help='Output directory for model and metrics')

    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Train model
    metrics = train_model(args.data_path, args.output_dir)

    logger.info("Training completed successfully!")


if __name__ == "__main__":
    main()