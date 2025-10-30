#!/usr/bin/env python3
"""
VulnHunter Ω Transformer Lite Engine
Lightweight transformer-based code analysis without external model dependencies

Features:
- Custom transformer architecture for vulnerability detection
- No external model downloads required
- Fast inference and training
- Mathematical feature integration
- Attention-based explainability
"""

import os
import sys
import json
import time
import logging
import warnings
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import re

# Core ML libraries
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

# Scientific computing
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)

@dataclass
class TransformerLiteConfig:
    """Configuration for lightweight transformer"""
    vocab_size: int = 5000
    max_sequence_length: int = 512
    hidden_size: int = 256
    num_attention_heads: int = 8
    num_hidden_layers: int = 6
    intermediate_size: int = 1024
    dropout_rate: float = 0.1
    learning_rate: float = 1e-4
    batch_size: int = 16
    num_epochs: int = 10

class SimpleTokenizer:
    """Simple tokenizer for code analysis"""

    def __init__(self, vocab_size: int = 5000):
        self.vocab_size = vocab_size
        self.word_to_id = {}
        self.id_to_word = {}
        self.special_tokens = {
            '[PAD]': 0,
            '[UNK]': 1,
            '[CLS]': 2,
            '[SEP]': 3,
            '[MASK]': 4
        }
        self.vocab_built = False

    def build_vocab(self, texts: List[str]):
        """Build vocabulary from training texts"""
        word_freq = {}

        # Add special tokens first
        for token, idx in self.special_tokens.items():
            self.word_to_id[token] = idx
            self.id_to_word[idx] = token

        # Count word frequencies
        for text in texts:
            tokens = self._tokenize_text(text)
            for token in tokens:
                word_freq[token] = word_freq.get(token, 0) + 1

        # Sort by frequency and take top vocab_size - len(special_tokens)
        sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
        max_words = self.vocab_size - len(self.special_tokens)

        current_id = len(self.special_tokens)
        for word, freq in sorted_words[:max_words]:
            if word not in self.word_to_id:
                self.word_to_id[word] = current_id
                self.id_to_word[current_id] = word
                current_id += 1

        self.vocab_built = True

    def _tokenize_text(self, text: str) -> List[str]:
        """Simple tokenization for code"""
        # Basic tokenization: split on common delimiters
        text = re.sub(r'[^\w\s\(\)\[\]\{\};:,\.\-\+\*\/\=\<\>\!\&\|\^]', ' ', text)
        tokens = []

        # Split on whitespace and common operators
        parts = re.split(r'(\s+|\(|\)|\[|\]|\{|\}|;|:|,|\.|\+|\-|\*|\/|\=|\<|\>|\!|\&|\||\^)', text)

        for part in parts:
            part = part.strip()
            if part:
                # Further split camelCase and snake_case
                subparts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)|[0-9]+|\w+', part)
                if subparts:
                    tokens.extend(subparts)
                else:
                    tokens.append(part)

        return [token.lower() for token in tokens if token]

    def encode(self, text: str, max_length: int = 512) -> Dict[str, torch.Tensor]:
        """Encode text to token IDs"""
        if not self.vocab_built:
            raise ValueError("Vocabulary not built. Call build_vocab() first.")

        tokens = self._tokenize_text(text)

        # Add CLS token at beginning
        token_ids = [self.special_tokens['[CLS]']]

        # Convert tokens to IDs
        for token in tokens[:max_length - 2]:  # Leave space for CLS and SEP
            token_ids.append(self.word_to_id.get(token, self.special_tokens['[UNK]']))

        # Add SEP token
        token_ids.append(self.special_tokens['[SEP]'])

        # Pad to max_length
        attention_mask = [1] * len(token_ids)
        while len(token_ids) < max_length:
            token_ids.append(self.special_tokens['[PAD]'])
            attention_mask.append(0)

        return {
            'input_ids': torch.tensor(token_ids, dtype=torch.long),
            'attention_mask': torch.tensor(attention_mask, dtype=torch.long)
        }

class CodeVulnerabilityDatasetLite(Dataset):
    """Lightweight dataset for code vulnerability detection"""

    def __init__(self, codes: List[str], labels: List[int], tokenizer: SimpleTokenizer, max_length: int = 512):
        self.codes = codes
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        code = str(self.codes[idx])
        label = self.labels[idx]

        # Encode code
        encoding = self.tokenizer.encode(code, max_length=self.max_length)

        return {
            'input_ids': encoding['input_ids'],
            'attention_mask': encoding['attention_mask'],
            'labels': torch.tensor(label, dtype=torch.long)
        }

class MultiHeadAttention(nn.Module):
    """Multi-head attention mechanism"""

    def __init__(self, hidden_size: int, num_heads: int, dropout: float = 0.1):
        super().__init__()
        assert hidden_size % num_heads == 0

        self.hidden_size = hidden_size
        self.num_heads = num_heads
        self.head_size = hidden_size // num_heads

        self.query = nn.Linear(hidden_size, hidden_size)
        self.key = nn.Linear(hidden_size, hidden_size)
        self.value = nn.Linear(hidden_size, hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.output = nn.Linear(hidden_size, hidden_size)

    def forward(self, hidden_states, attention_mask=None):
        batch_size, seq_len, _ = hidden_states.shape

        # Linear transformations and reshape
        q = self.query(hidden_states).view(batch_size, seq_len, self.num_heads, self.head_size).transpose(1, 2)
        k = self.key(hidden_states).view(batch_size, seq_len, self.num_heads, self.head_size).transpose(1, 2)
        v = self.value(hidden_states).view(batch_size, seq_len, self.num_heads, self.head_size).transpose(1, 2)

        # Attention scores
        scores = torch.matmul(q, k.transpose(-2, -1)) / np.sqrt(self.head_size)

        # Apply attention mask
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(1).unsqueeze(2)
            scores = scores.masked_fill(mask == 0, -1e9)

        # Attention weights
        attention_weights = F.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)

        # Apply attention to values
        context = torch.matmul(attention_weights, v)
        context = context.transpose(1, 2).contiguous().view(batch_size, seq_len, self.hidden_size)

        # Output projection
        output = self.output(context)

        return output, attention_weights

class TransformerBlock(nn.Module):
    """Transformer encoder block"""

    def __init__(self, hidden_size: int, num_heads: int, intermediate_size: int, dropout: float = 0.1):
        super().__init__()
        self.attention = MultiHeadAttention(hidden_size, num_heads, dropout)
        self.attention_norm = nn.LayerNorm(hidden_size)
        self.feedforward = nn.Sequential(
            nn.Linear(hidden_size, intermediate_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(intermediate_size, hidden_size),
            nn.Dropout(dropout)
        )
        self.feedforward_norm = nn.LayerNorm(hidden_size)

    def forward(self, hidden_states, attention_mask=None):
        # Multi-head attention with residual connection
        attention_output, attention_weights = self.attention(hidden_states, attention_mask)
        hidden_states = self.attention_norm(hidden_states + attention_output)

        # Feedforward with residual connection
        ff_output = self.feedforward(hidden_states)
        hidden_states = self.feedforward_norm(hidden_states + ff_output)

        return hidden_states, attention_weights

class VulnHunterTransformerLite(nn.Module):
    """Lightweight transformer for vulnerability detection"""

    def __init__(self, config: TransformerLiteConfig, mathematical_features_dim: int = 512):
        super().__init__()
        self.config = config

        # Embedding layers
        self.embeddings = nn.Embedding(config.vocab_size, config.hidden_size)
        self.position_embeddings = nn.Embedding(config.max_sequence_length, config.hidden_size)
        self.embedding_dropout = nn.Dropout(config.dropout_rate)

        # Transformer blocks
        self.transformer_blocks = nn.ModuleList([
            TransformerBlock(
                hidden_size=config.hidden_size,
                num_heads=config.num_attention_heads,
                intermediate_size=config.intermediate_size,
                dropout=config.dropout_rate
            ) for _ in range(config.num_hidden_layers)
        ])

        # Mathematical feature integration
        self.math_feature_projection = nn.Linear(mathematical_features_dim, config.hidden_size)

        # Feature fusion
        self.fusion_layer = nn.Linear(config.hidden_size * 2, config.hidden_size)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(config.hidden_size, config.intermediate_size),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.intermediate_size, config.hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.hidden_size // 2, 2)  # Binary classification
        )

        # Vulnerability type classifier
        self.vuln_type_classifier = nn.Sequential(
            nn.Linear(config.hidden_size, config.intermediate_size),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.intermediate_size, 15)  # 15 vulnerability types
        )

        self._init_weights()

    def _init_weights(self):
        """Initialize weights"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Embedding):
                nn.init.normal_(module.weight, mean=0.0, std=0.02)

    def forward(self, input_ids, attention_mask, mathematical_features=None):
        batch_size, seq_len = input_ids.shape

        # Get embeddings
        token_embeddings = self.embeddings(input_ids)
        position_ids = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)
        position_embeddings = self.position_embeddings(position_ids)

        hidden_states = token_embeddings + position_embeddings
        hidden_states = self.embedding_dropout(hidden_states)

        # Pass through transformer blocks
        all_attention_weights = []
        for transformer_block in self.transformer_blocks:
            hidden_states, attention_weights = transformer_block(hidden_states, attention_mask)
            all_attention_weights.append(attention_weights)

        # Global average pooling
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            hidden_states = hidden_states * mask
            pooled_output = hidden_states.sum(dim=1) / mask.sum(dim=1)
        else:
            pooled_output = hidden_states.mean(dim=1)

        # Integrate mathematical features if provided
        if mathematical_features is not None:
            math_projected = self.math_feature_projection(mathematical_features)
            fused_features = torch.cat([pooled_output, math_projected], dim=-1)
            final_features = self.fusion_layer(fused_features)
        else:
            final_features = pooled_output

        # Classification
        vulnerability_logits = self.classifier(final_features)
        vuln_type_logits = self.vuln_type_classifier(final_features)

        return {
            'vulnerability_logits': vulnerability_logits,
            'vuln_type_logits': vuln_type_logits,
            'attention_weights': all_attention_weights,
            'final_features': final_features
        }

class VulnHunterTransformerLiteEngine:
    """Main engine for lightweight transformer-based analysis"""

    def __init__(self, config: Optional[TransformerLiteConfig] = None):
        self.config = config or TransformerLiteConfig()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # Initialize tokenizer
        self.tokenizer = SimpleTokenizer(vocab_size=self.config.vocab_size)

        # Initialize model
        self.model = None

        # Vulnerability type mapping
        self.vulnerability_types = [
            'buffer_overflow', 'injection', 'xss', 'csrf', 'reentrancy',
            'access_control', 'dos_attack', 'memory_corruption', 'integer_overflow',
            'race_condition', 'weak_crypto', 'insecure_storage', 'data_leakage',
            'authentication_bypass', 'permission_bypass'
        ]

        logging.info(f"VulnHunter Transformer Lite Engine initialized on {self.device}")

    def generate_synthetic_training_data(self, num_samples: int = 1000) -> Tuple[List[str], List[int]]:
        """Generate synthetic training data"""

        # Vulnerable code patterns
        vulnerable_patterns = [
            # Buffer overflow patterns
            '''
            void vulnerable_function(char* input) {
                char buffer[256];
                strcpy(buffer, input);
                printf("Buffer: %s\\n", buffer);
            }
            ''',

            # SQL injection patterns
            '''
            def login(username, password):
                query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                cursor.execute(query)
                return cursor.fetchone()
            ''',

            # Reentrancy patterns
            '''
            contract VulnerableContract {
                mapping(address => uint) balances;

                function withdraw(uint amount) public {
                    require(balances[msg.sender] >= amount);
                    msg.sender.call{value: amount}("");
                    balances[msg.sender] -= amount;
                }
            }
            ''',

            # XSS patterns
            '''
            function displayMessage(message) {
                document.getElementById('output').innerHTML = message;
            }
            ''',

            # Access control patterns
            '''
            function deleteUser(userId) {
                db.users.remove({_id: userId});
            }
            '''
        ]

        # Safe code patterns
        safe_patterns = [
            # Safe buffer handling
            '''
            void safe_function(const char* input) {
                char buffer[256];
                strncpy(buffer, input, sizeof(buffer) - 1);
                buffer[sizeof(buffer) - 1] = '\\0';
                printf("Buffer: %s\\n", buffer);
            }
            ''',

            # Parameterized queries
            '''
            def login(username, password):
                query = "SELECT * FROM users WHERE username=? AND password=?"
                cursor.execute(query, (username, password))
                return cursor.fetchone()
            ''',

            # Safe contract pattern
            '''
            contract SafeContract {
                mapping(address => uint) balances;

                function withdraw(uint amount) public {
                    require(balances[msg.sender] >= amount);
                    balances[msg.sender] -= amount;
                    msg.sender.transfer(amount);
                }
            }
            ''',

            # Safe HTML output
            '''
            function displayMessage(message) {
                document.getElementById('output').textContent = message;
            }
            ''',

            # Proper access control
            '''
            function deleteUser(userId) {
                require(msg.sender == admin, "Only admin can delete users");
                db.users.remove({_id: userId});
            }
            '''
        ]

        codes = []
        labels = []

        # Generate equal numbers of vulnerable and safe samples
        samples_per_type = num_samples // 2

        # Add vulnerable samples
        for i in range(samples_per_type):
            pattern = vulnerable_patterns[i % len(vulnerable_patterns)]
            modified_pattern = self._add_code_variation(pattern, i)
            codes.append(modified_pattern)
            labels.append(1)  # Vulnerable

        # Add safe samples
        for i in range(samples_per_type):
            pattern = safe_patterns[i % len(safe_patterns)]
            modified_pattern = self._add_code_variation(pattern, i)
            codes.append(modified_pattern)
            labels.append(0)  # Safe

        return codes, labels

    def _add_code_variation(self, code: str, seed: int) -> str:
        """Add variations to code patterns"""
        variations = [
            (r'buffer', f'buf_{seed}'),
            (r'input', f'data_{seed}'),
            (r'username', f'user_{seed}'),
            (r'password', f'pass_{seed}'),
            (r'amount', f'value_{seed}')
        ]

        modified = code
        for old, new in variations:
            modified = re.sub(old, new, modified)

        if seed % 3 == 0:
            modified = f"// Generated variation {seed}\n{modified}"

        return modified

    def train_model(self, codes: List[str], labels: List[int], mathematical_features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Train the lightweight transformer model"""

        # Build vocabulary
        logging.info("Building vocabulary...")
        self.tokenizer.build_vocab(codes)

        # Create dataset
        dataset = CodeVulnerabilityDatasetLite(codes, labels, self.tokenizer, self.config.max_sequence_length)

        # Split into train/validation
        split_idx = int(0.8 * len(dataset))
        train_dataset = torch.utils.data.Subset(dataset, range(split_idx))
        val_dataset = torch.utils.data.Subset(dataset, range(split_idx, len(dataset)))

        # Create data loaders
        train_loader = DataLoader(train_dataset, batch_size=self.config.batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=self.config.batch_size, shuffle=False)

        # Initialize model
        self.model = VulnHunterTransformerLite(
            config=self.config,
            mathematical_features_dim=512 if mathematical_features is not None else 0
        ).to(self.device)

        # Optimizer
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=0.01
        )

        # Loss function
        criterion = nn.CrossEntropyLoss()

        # Training loop
        training_stats = []
        best_val_accuracy = 0.0

        for epoch in range(self.config.num_epochs):
            self.model.train()
            total_train_loss = 0
            train_predictions = []
            train_true_labels = []

            for batch_idx, batch in enumerate(train_loader):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels_batch = batch['labels'].to(self.device)

                # Get mathematical features if available
                math_feats = None
                if mathematical_features is not None:
                    indices = [i + batch_idx * self.config.batch_size for i in range(len(labels_batch))]
                    indices = [i for i in indices if i < len(mathematical_features)]
                    if indices:
                        math_feats = torch.tensor([mathematical_features[i] for i in indices], dtype=torch.float).to(self.device)

                # Forward pass
                optimizer.zero_grad()
                outputs = self.model(input_ids, attention_mask, math_feats)

                loss = criterion(outputs['vulnerability_logits'], labels_batch)

                # Backward pass
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()

                total_train_loss += loss.item()

                # Collect predictions
                predictions = torch.argmax(outputs['vulnerability_logits'], dim=-1)
                train_predictions.extend(predictions.cpu().numpy())
                train_true_labels.extend(labels_batch.cpu().numpy())

            # Validation
            val_accuracy, val_loss = self._validate(val_loader, mathematical_features)

            # Calculate training accuracy
            train_accuracy = accuracy_score(train_true_labels, train_predictions)
            avg_train_loss = total_train_loss / len(train_loader)

            # Save best model
            if val_accuracy > best_val_accuracy:
                best_val_accuracy = val_accuracy
                self._save_model(f"best_transformer_lite_epoch_{epoch+1}")

            # Track statistics
            epoch_stats = {
                'epoch': epoch + 1,
                'train_loss': avg_train_loss,
                'train_accuracy': train_accuracy,
                'val_loss': val_loss,
                'val_accuracy': val_accuracy
            }
            training_stats.append(epoch_stats)

            logging.info(f"Epoch {epoch+1}/{self.config.num_epochs} - Train Acc: {train_accuracy:.4f}, Val Acc: {val_accuracy:.4f}")

        return {
            'training_stats': training_stats,
            'best_val_accuracy': best_val_accuracy,
            'vocab_size': len(self.tokenizer.word_to_id),
            'final_model': self.model
        }

    def _validate(self, val_loader: DataLoader, mathematical_features: Optional[np.ndarray] = None) -> Tuple[float, float]:
        """Validate the model"""
        self.model.eval()
        total_val_loss = 0
        val_predictions = []
        val_true_labels = []

        with torch.no_grad():
            for batch_idx, batch in enumerate(val_loader):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels_batch = batch['labels'].to(self.device)

                # Get mathematical features if available
                math_feats = None
                if mathematical_features is not None:
                    indices = [i + batch_idx * self.config.batch_size for i in range(len(labels_batch))]
                    indices = [i for i in indices if i < len(mathematical_features)]
                    if indices:
                        math_feats = torch.tensor([mathematical_features[i] for i in indices], dtype=torch.float).to(self.device)

                outputs = self.model(input_ids, attention_mask, math_feats)

                loss = F.cross_entropy(outputs['vulnerability_logits'], labels_batch)
                total_val_loss += loss.item()

                predictions = torch.argmax(outputs['vulnerability_logits'], dim=-1)
                val_predictions.extend(predictions.cpu().numpy())
                val_true_labels.extend(labels_batch.cpu().numpy())

        val_accuracy = accuracy_score(val_true_labels, val_predictions)
        avg_val_loss = total_val_loss / len(val_loader)

        return val_accuracy, avg_val_loss

    def analyze_code_transformer(self, code: str, mathematical_features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Analyze code using the lightweight transformer"""

        if self.model is None or not self.tokenizer.vocab_built:
            logging.warning("Model not trained. Using fallback analysis.")
            return self._fallback_analysis(code)

        self.model.eval()

        # Encode input
        encoding = self.tokenizer.encode(code, max_length=self.config.max_sequence_length)
        input_ids = encoding['input_ids'].unsqueeze(0).to(self.device)
        attention_mask = encoding['attention_mask'].unsqueeze(0).to(self.device)

        # Convert mathematical features if provided
        math_feats = None
        if mathematical_features is not None:
            math_feats = torch.tensor(mathematical_features, dtype=torch.float).unsqueeze(0).to(self.device)

        with torch.no_grad():
            outputs = self.model(input_ids, attention_mask, math_feats)

            # Get predictions
            vulnerability_probs = F.softmax(outputs['vulnerability_logits'], dim=-1)
            vulnerability_pred = torch.argmax(vulnerability_probs, dim=-1)

            vuln_type_probs = F.softmax(outputs['vuln_type_logits'], dim=-1)
            vuln_type_pred = torch.argmax(vuln_type_probs, dim=-1)

            return {
                'vulnerability_detected': bool(vulnerability_pred.item()),
                'vulnerability_confidence': float(vulnerability_probs[0, 1].item()),
                'vulnerability_type': self.vulnerability_types[vuln_type_pred.item()],
                'vulnerability_type_confidence': float(vuln_type_probs[0, vuln_type_pred].item()),
                'attention_weights': [att.cpu().numpy() for att in outputs['attention_weights']],
                'transformer_features': outputs['final_features'].cpu().numpy(),
                'analysis_method': 'transformer_lite',
                'model_type': 'VulnHunter_Transformer_Lite_v1.0'
            }

    def _fallback_analysis(self, code: str) -> Dict[str, Any]:
        """Fallback analysis using pattern matching"""
        vulnerability_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'injection': [r'execute\s*\(\s*["\'].*\+.*["\']', r'eval\s*\('],
            'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
            'reentrancy': [r'\.call\s*\{.*value.*\}', r'\.send\s*\('],
            'access_control': [r'require\s*\(\s*msg\.sender\s*==', r'onlyOwner']
        }

        detected_vulnerabilities = []
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detected_vulnerabilities.append(vuln_type)
                    break

        vulnerability_detected = len(detected_vulnerabilities) > 0
        primary_vuln = detected_vulnerabilities[0] if detected_vulnerabilities else 'buffer_overflow'

        return {
            'vulnerability_detected': vulnerability_detected,
            'vulnerability_confidence': 0.8 if vulnerability_detected else 0.2,
            'vulnerability_type': primary_vuln,
            'vulnerability_type_confidence': 0.75,
            'detected_patterns': detected_vulnerabilities,
            'analysis_method': 'pattern_matching_fallback',
            'model_type': 'VulnHunter_Transformer_Lite_Fallback'
        }

    def _save_model(self, model_name: str):
        """Save the trained model"""
        if self.model is not None:
            model_path = Path(f"models/{model_name}.pth")
            model_path.parent.mkdir(exist_ok=True)

            # Save model state and tokenizer
            save_data = {
                'model_state_dict': self.model.state_dict(),
                'config': self.config,
                'tokenizer_vocab': self.tokenizer.word_to_id,
                'tokenizer_reverse': self.tokenizer.id_to_word
            }

            torch.save(save_data, model_path)
            logging.info(f"Model saved to {model_path}")

    def demonstrate_transformer_lite_analysis(self):
        """Demonstrate lightweight transformer analysis"""

        logging.info("🚀 VulnHunter Ω Transformer Lite Demonstration")
        logging.info("=" * 70)

        # Generate training data
        logging.info("📊 Generating training data...")
        codes, labels = self.generate_synthetic_training_data(num_samples=200)

        # Train model
        logging.info("🤖 Training lightweight transformer...")
        training_results = self.train_model(codes, labels)

        logging.info(f"✅ Training completed! Best validation accuracy: {training_results['best_val_accuracy']:.3f}")
        logging.info(f"📚 Vocabulary size: {training_results['vocab_size']}")

        # Test cases
        test_cases = [
            {
                'name': 'Buffer Overflow Vulnerability',
                'code': '''
                void process_data(char* user_input) {
                    char buffer[100];
                    strcpy(buffer, user_input);
                    printf("Processed: %s", buffer);
                }
                ''',
                'expected_vulnerable': True
            },
            {
                'name': 'Safe String Handling',
                'code': '''
                void process_data_safe(const char* user_input) {
                    char buffer[100];
                    strncpy(buffer, user_input, sizeof(buffer) - 1);
                    buffer[sizeof(buffer) - 1] = '\\0';
                    printf("Processed: %s", buffer);
                }
                ''',
                'expected_vulnerable': False
            },
            {
                'name': 'Smart Contract Reentrancy',
                'code': '''
                contract VulnerableWithdraw {
                    mapping(address => uint) public balances;

                    function withdraw() public {
                        uint amount = balances[msg.sender];
                        require(amount > 0);
                        msg.sender.call{value: amount}("");
                        balances[msg.sender] = 0;
                    }
                }
                ''',
                'expected_vulnerable': True
            }
        ]

        results = []

        for test_case in test_cases:
            logging.info(f"\n📋 Analyzing: {test_case['name']}")
            logging.info("-" * 50)

            start_time = time.time()
            analysis_result = self.analyze_code_transformer(test_case['code'])
            analysis_time = time.time() - start_time

            vulnerability_detected = analysis_result['vulnerability_detected']
            confidence = analysis_result['vulnerability_confidence']
            vuln_type = analysis_result['vulnerability_type']

            logging.info(f"🎯 Vulnerability Detected: {vulnerability_detected}")
            logging.info(f"🔍 Confidence Score: {confidence:.3f}")
            logging.info(f"🏷️  Vulnerability Type: {vuln_type}")
            logging.info(f"⏱️  Analysis Time: {analysis_time:.3f} seconds")
            logging.info(f"🤖 Model Type: {analysis_result['model_type']}")

            correct_prediction = vulnerability_detected == test_case['expected_vulnerable']
            status = "✅ CORRECT" if correct_prediction else "❌ INCORRECT"
            logging.info(f"📊 Prediction Status: {status}")

            results.append({
                'test_case': test_case['name'],
                'vulnerability_detected': vulnerability_detected,
                'confidence': confidence,
                'vulnerability_type': vuln_type,
                'analysis_time': analysis_time,
                'correct_prediction': correct_prediction,
                'expected': test_case['expected_vulnerable']
            })

        # Summary
        logging.info("\n" + "=" * 70)
        logging.info("🚀 TRANSFORMER LITE ANALYSIS SUMMARY")
        logging.info("=" * 70)

        total_tests = len(results)
        correct_predictions = sum(1 for r in results if r['correct_prediction'])
        accuracy = correct_predictions / total_tests
        avg_confidence = np.mean([r['confidence'] for r in results])
        avg_analysis_time = np.mean([r['analysis_time'] for r in results])

        logging.info(f"📊 Total Test Cases: {total_tests}")
        logging.info(f"✅ Correct Predictions: {correct_predictions}")
        logging.info(f"🎯 Accuracy: {accuracy:.1%}")
        logging.info(f"🔍 Average Confidence: {avg_confidence:.3f}")
        logging.info(f"⏱️ Average Analysis Time: {avg_analysis_time:.3f} seconds")

        summary_stats = {
            'total_tests': total_tests,
            'correct_predictions': correct_predictions,
            'accuracy': accuracy,
            'average_confidence': avg_confidence,
            'average_analysis_time': avg_analysis_time,
            'training_stats': training_results['training_stats'],
            'best_val_accuracy': training_results['best_val_accuracy'],
            'vocab_size': training_results['vocab_size'],
            'results': results
        }

        # Save results
        results_path = Path("results/transformer_lite_analysis_results.json")
        results_path.parent.mkdir(exist_ok=True)

        with open(results_path, 'w') as f:
            json.dump(summary_stats, f, indent=2)

        logging.info(f"📁 Results saved to: {results_path}")
        logging.info("🚀 VulnHunter Ω Transformer Lite Engine - Ready for Production!")

        return summary_stats

def main():
    """Main function for running transformer lite engine"""

    print("🚀 Initializing VulnHunter Ω Transformer Lite Engine...")

    # Initialize configuration
    config = TransformerLiteConfig(
        vocab_size=2000,
        max_sequence_length=256,
        hidden_size=128,
        num_attention_heads=4,
        num_hidden_layers=3,
        batch_size=8,
        num_epochs=5,
        learning_rate=1e-4
    )

    # Initialize engine
    transformer_engine = VulnHunterTransformerLiteEngine(config)

    # Run demonstration
    demo_results = transformer_engine.demonstrate_transformer_lite_analysis()

    print(f"\n🚀 Transformer Lite Engine Analysis Complete!")
    print(f"🎯 Achieved {demo_results['accuracy']:.1%} accuracy on test cases")
    print(f"🔍 Average confidence: {demo_results['average_confidence']:.3f}")
    print(f"⏱️ Average analysis time: {demo_results['average_analysis_time']:.3f}s")
    print(f"🤖 Best validation accuracy: {demo_results['best_val_accuracy']:.3f}")

if __name__ == "__main__":
    main()