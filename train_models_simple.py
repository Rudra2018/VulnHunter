#!/usr/bin/env python3
"""
Simple Model Training Script
Train VulnHunter models on comprehensive real-world dataset
"""

import os
import sys
import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score
from tqdm import tqdm
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.vulnhunter_omega_math3_engine import VulnHunterOmegaMath3Engine

class SimpleVulnDataset(Dataset):
    def __init__(self, samples, tokenizer, math3_engine=None, max_length=512):
        self.samples = samples
        self.tokenizer = tokenizer
        self.math3_engine = math3_engine
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]

        # Tokenize
        encoding = self.tokenizer(
            sample['code'],
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        # Math3 features
        math3_features = torch.zeros(8)
        if self.math3_engine:
            try:
                scores = self.math3_engine.analyze(sample['code'])
                if isinstance(scores, dict):
                    math3_features = torch.tensor(list(scores.values())[:8], dtype=torch.float32)
            except:
                pass

        return {
            'input_ids': encoding['input_ids'].squeeze(0),
            'attention_mask': encoding['attention_mask'].squeeze(0),
            'math3_features': math3_features,
            'label': torch.tensor(1 if sample['is_vulnerable'] else 0, dtype=torch.long)
        }

class SimpleVulnModel(nn.Module):
    def __init__(self, vocab_size, embed_dim=512, num_heads=8, num_layers=6):
        super().__init__()

        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.position_embedding = nn.Embedding(512, embed_dim)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=0.1,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.math3_projection = nn.Linear(8, embed_dim // 4)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim + embed_dim // 4, embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(embed_dim // 2, 2)
        )

    def forward(self, input_ids, attention_mask, math3_features):
        batch_size, seq_len = input_ids.shape

        # Embeddings
        token_embeds = self.embedding(input_ids)
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)
        pos_embeds = self.position_embedding(positions)
        embeddings = token_embeds + pos_embeds

        # Transformer
        attention_mask_float = attention_mask.float()
        attention_mask_float = attention_mask_float.masked_fill(attention_mask == 0, float('-inf'))
        attention_mask_float = attention_mask_float.masked_fill(attention_mask == 1, 0.0)

        transformer_out = self.transformer(embeddings, src_key_padding_mask=attention_mask_float)
        pooled = transformer_out.mean(dim=1)

        # Math3 integration
        math3_proj = self.math3_projection(math3_features)
        combined = torch.cat([pooled, math3_proj], dim=1)

        # Classification
        logits = self.classifier(combined)
        return logits

def train_model(model, train_loader, val_loader, device, epochs=10):
    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss()

    num_training_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=num_training_steps // 10,
        num_training_steps=num_training_steps
    )

    best_f1 = 0.0

    for epoch in range(epochs):
        # Training
        model.train()
        total_loss = 0

        print(f"\\nEpoch {epoch+1}/{epochs}")
        train_bar = tqdm(train_loader, desc="Training")

        for batch in train_bar:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            math3_features = batch['math3_features'].to(device)
            labels = batch['label'].to(device)

            optimizer.zero_grad()
            logits = model(input_ids, attention_mask, math3_features)
            loss = criterion(logits, labels)
            loss.backward()

            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            total_loss += loss.item()
            train_bar.set_postfix({'Loss': f'{loss.item():.4f}'})

        # Validation
        model.eval()
        val_preds = []
        val_labels = []
        val_loss = 0

        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Validating"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                math3_features = batch['math3_features'].to(device)
                labels = batch['label'].to(device)

                logits = model(input_ids, attention_mask, math3_features)
                loss = criterion(logits, labels)
                val_loss += loss.item()

                preds = torch.argmax(logits, dim=-1)
                val_preds.extend(preds.cpu().numpy())
                val_labels.extend(labels.cpu().numpy())

        # Metrics
        f1 = f1_score(val_labels, val_preds, average='weighted')
        precision = precision_score(val_labels, val_preds, average='weighted')
        recall = recall_score(val_labels, val_preds, average='weighted')

        print(f"Epoch {epoch+1} - Train Loss: {total_loss/len(train_loader):.4f}")
        print(f"Val Loss: {val_loss/len(val_loader):.4f}, F1: {f1:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}")

        # Save best model
        if f1 > best_f1:
            best_f1 = f1
            torch.save({
                'model_state_dict': model.state_dict(),
                'f1_score': f1,
                'epoch': epoch
            }, 'models/vulnhunter_simple_best.pth')
            print(f"💾 New best model saved! F1: {f1:.4f}")

    return best_f1

def main():
    print("🚀 Simple VulnHunter Training on Comprehensive Dataset")
    print("=" * 60)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🔥 Device: {device}")

    # Load dataset
    print("📚 Loading comprehensive dataset...")
    with open('training_data/comprehensive_vulnerability_dataset.json', 'r') as f:
        dataset = json.load(f)

    print(f"📊 Loaded {len(dataset):,} samples")

    # Split data
    train_samples, temp_samples = train_test_split(
        dataset, test_size=0.3, random_state=42,
        stratify=[s['is_vulnerable'] for s in dataset]
    )
    val_samples, test_samples = train_test_split(
        temp_samples, test_size=0.5, random_state=42,
        stratify=[s['is_vulnerable'] for s in temp_samples]
    )

    print(f"🔀 Split - Train: {len(train_samples):,}, Val: {len(val_samples):,}, Test: {len(test_samples):,}")

    # Setup tokenizer and Math3 engine
    tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    math3_engine = VulnHunterOmegaMath3Engine()

    # Create datasets and loaders
    train_dataset = SimpleVulnDataset(train_samples, tokenizer, math3_engine)
    val_dataset = SimpleVulnDataset(val_samples, tokenizer, math3_engine)

    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True, num_workers=2)
    val_loader = DataLoader(val_dataset, batch_size=8, shuffle=False, num_workers=2)

    # Initialize and train model
    print("🏗️ Initializing model...")
    model = SimpleVulnModel(
        vocab_size=tokenizer.vocab_size,
        embed_dim=512,
        num_heads=8,
        num_layers=6
    )

    param_count = sum(p.numel() for p in model.parameters())
    print(f"🔢 Model parameters: {param_count:,}")

    # Train
    print("\\n🎯 Starting training...")
    start_time = time.time()
    best_f1 = train_model(model, train_loader, val_loader, device, epochs=15)
    training_time = time.time() - start_time

    print(f"\\n✅ Training completed in {training_time/60:.1f} minutes")
    print(f"🏆 Best F1 Score: {best_f1:.4f}")

    # Update existing model
    import shutil
    best_model_path = 'models/vulnhunter_simple_best.pth'
    target_path = 'models/vulnhunter_omega_v3.pth'

    if os.path.exists(best_model_path):
        shutil.copy(best_model_path, target_path)
        print(f"💾 Updated {target_path}")

    print("\\n🎉 Training Complete!")
    print("📈 Model trained on comprehensive real-world vulnerability dataset")

if __name__ == "__main__":
    main()