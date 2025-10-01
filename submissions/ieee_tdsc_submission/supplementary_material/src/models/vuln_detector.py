import torch
import torch.nn as nn
import torch.nn.functional as F
import warnings

# Suppress specific warnings
warnings.filterwarnings("ignore", message=".*torch.load.*")

class SimpleVulnDetector(nn.Module):
    """Simplified model for testing without external dependencies"""
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        
        # Simple embedding layer
        vocab_size = config.get('vocab_size', 10000)
        embedding_dim = config.get('embedding_dim', 256)
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        
        # CNN for code pattern detection
        self.conv1d = nn.Sequential(
            nn.Conv1d(embedding_dim, 128, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(128, 64, 3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1)
        )
        
        # Classifier for vulnerability detection (binary)
        self.classifier = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, 1)  # Binary classification
        )
        
        # Classifier for vulnerability type
        self.type_classifier = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, config.get('num_classes', 16))
        )
        
        # Severity regressor
        self.severity_regressor = nn.Sequential(
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, input_ids, attention_mask=None):
        """
        Forward pass for the simple vulnerability detector
        
        Args:
            input_ids: Tokenized input sequences [batch_size, seq_len]
            attention_mask: Attention mask [batch_size, seq_len]
        
        Returns:
            Dictionary with vulnerability, type, and severity predictions
        """
        # Embedding layer
        embeddings = self.embedding(input_ids)  # [batch_size, seq_len, embedding_dim]
        
        # Apply attention mask if provided
        if attention_mask is not None:
            # Expand mask to match embedding dimensions
            mask = attention_mask.unsqueeze(-1).expand_as(embeddings).float()
            embeddings = embeddings * mask
        
        # Transpose for CNN: [batch_size, embedding_dim, seq_len]
        embeddings = embeddings.transpose(1, 2)
        
        # CNN feature extraction
        features = self.conv1d(embeddings)  # [batch_size, 64, 1]
        features = features.squeeze(-1)     # [batch_size, 64]
        
        # Multiple outputs
        vulnerability = self.classifier(features)      # [batch_size, 1]
        vuln_type = self.type_classifier(features)     # [batch_size, num_classes]
        severity = self.severity_regressor(features)   # [batch_size, 1]
        
        return {
            'vulnerability': vulnerability.squeeze(-1),  # [batch_size]
            'vuln_type': vuln_type,                      # [batch_size, num_classes]
            'severity': severity.squeeze(-1)             # [batch_size]
        }

class MultiModalVulnDetector(nn.Module):
    """Advanced multi-modal vulnerability detector using transformer architecture"""
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        
        # Text/Code encoder - use a smaller model for testing
        model_name = config.get('code_bert_model', 'microsoft/codebert-base')
        try:
            from transformers import AutoModel, AutoTokenizer
            self.code_encoder = AutoModel.from_pretrained(model_name)
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            print(f"Successfully loaded {model_name}")
        except Exception as e:
            print(f"Warning: Could not load {model_name}: {e}")
            # Fallback to a simpler approach
            self.code_encoder = None
            self.tokenizer = None
        
        # Add padding token if it doesn't exist
        if self.tokenizer and self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Binary features encoder
        self.binary_encoder = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64)
        )
        
        # Combined classifier dimensions
        if self.code_encoder:
            hidden_size = self.code_encoder.config.hidden_size
        else:
            hidden_size = 768  # Default BERT hidden size
        
        combined_dim = hidden_size + 64
        
        # Main classifier
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 1)  # Binary classification
        )
        
        # Vulnerability type classifier
        self.vuln_type_classifier = nn.Sequential(
            nn.Linear(combined_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, config['num_classes'])
        )
        
        # Severity regressor (for CVSS score prediction)
        self.severity_regressor = nn.Sequential(
            nn.Linear(combined_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()  # Output between 0-1 (normalized CVSS)
        )
    
    def forward(self, code_inputs=None, binary_features=None, attention_mask=None):
        """
        Forward pass for multi-modal vulnerability detector
        
        Args:
            code_inputs: Tokenized code inputs
            binary_features: Binary analysis features
            attention_mask: Attention mask for code inputs
        
        Returns:
            Dictionary with vulnerability predictions
        """
        # Encode code/text
        if code_inputs is not None and self.code_encoder is not None:
            code_outputs = self.code_encoder(code_inputs, attention_mask=attention_mask)
            code_embeddings = code_outputs.last_hidden_state[:, 0, :]  # [CLS] token
        else:
            # Create dummy embeddings if no code encoder
            batch_size = binary_features.size(0) if binary_features is not None else 1
            hidden_size = self.code_encoder.config.hidden_size if self.code_encoder else 768
            code_embeddings = torch.zeros(batch_size, hidden_size, device=next(self.parameters()).device)
        
        # Encode binary features
        if binary_features is not None:
            binary_embeddings = self.binary_encoder(binary_features)
        else:
            # Create dummy binary embeddings
            binary_embeddings = torch.zeros(code_embeddings.size(0), 64, device=code_embeddings.device)
        
        # Combine embeddings
        combined = torch.cat([code_embeddings, binary_embeddings], dim=-1)
        
        # Multiple outputs
        vulnerability_logits = self.classifier(combined)           # [batch_size, 1]
        vuln_type_logits = self.vuln_type_classifier(combined)     # [batch_size, num_classes]
        severity_score = self.severity_regressor(combined)         # [batch_size, 1]
        
        return {
            'vulnerability': vulnerability_logits.squeeze(-1),     # [batch_size]
            'vuln_type': vuln_type_logits,                         # [batch_size, num_classes]
            'severity': severity_score.squeeze(-1)                 # [batch_size]
        }
    
    def prepare_code_input(self, code_snippets: list):
        """Prepare code inputs for the model"""
        if self.tokenizer is None:
            # Return dummy inputs if tokenizer is not available
            batch_size = len(code_snippets)
            seq_len = self.config.get('max_sequence_length', 512)
            return {
                'input_ids': torch.zeros(batch_size, seq_len).long(),
                'attention_mask': torch.ones(batch_size, seq_len).long()
            }
        
        return self.tokenizer(
            code_snippets,
            padding=True,
            truncation=True,
            max_length=self.config.get('max_sequence_length', 512),
            return_tensors="pt"
        )

class EnhancedVulnDetector(nn.Module):
    """Enhanced model with attention mechanism and better architecture"""
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        
        # Embedding layer
        self.embedding = nn.Embedding(
            config.get('vocab_size', 10000),
            config.get('embedding_dim', 256)
        )
        
        # Positional encoding
        self.pos_encoder = nn.Parameter(
            torch.zeros(1, config.get('max_sequence_length', 512), config.get('embedding_dim', 256))
        )
        
        # Transformer encoder
        encoder_layers = nn.TransformerEncoderLayer(
            d_model=config.get('embedding_dim', 256),
            nhead=8,
            dim_feedforward=512,
            dropout=0.1
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers=3)
        
        # Self-attention pooling
        self.attention_pool = nn.Sequential(
            nn.Linear(config.get('embedding_dim', 256), 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )
        
        # Classification heads
        self.vulnerability_head = nn.Sequential(
            nn.Linear(config.get('embedding_dim', 256), 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 1)
        )
        
        self.type_head = nn.Sequential(
            nn.Linear(config.get('embedding_dim', 256), 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, config.get('num_classes', 16))
        )
        
        self.severity_head = nn.Sequential(
            nn.Linear(config.get('embedding_dim', 256), 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, input_ids, attention_mask=None):
        # Embedding
        x = self.embedding(input_ids)  # [batch_size, seq_len, embedding_dim]
        
        # Add positional encoding
        x = x + self.pos_encoder[:, :x.size(1), :]
        
        # Transformer expects [seq_len, batch_size, embedding_dim]
        x = x.transpose(0, 1)
        
        # Transformer encoder
        x = self.transformer_encoder(x)  # [seq_len, batch_size, embedding_dim]
        
        # Transpose back to [batch_size, seq_len, embedding_dim]
        x = x.transpose(0, 1)
        
        # Attention pooling
        attention_weights = F.softmax(self.attention_pool(x), dim=1)
        context_vector = torch.sum(attention_weights * x, dim=1)  # [batch_size, embedding_dim]
        
        # Multiple outputs
        vulnerability = self.vulnerability_head(context_vector).squeeze(-1)
        vuln_type = self.type_head(context_vector)
        severity = self.severity_head(context_vector).squeeze(-1)
        
        return {
            'vulnerability': vulnerability,
            'vuln_type': vuln_type,
            'severity': severity,
            'attention_weights': attention_weights
        }

class VulnerabilityTrainer:
    def __init__(self, model, train_loader, val_loader, config):
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.config = config
        
        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=config.get('learning_rate', 2e-5),
            weight_decay=0.01
        )
        
        # Multi-task loss weights
        self.weights = {
            'vulnerability': 1.0,
            'vuln_type': 0.7,
            'severity': 0.3
        }
    
    def train_epoch(self):
        self.model.train()
        total_loss = 0
        
        for batch in self.train_loader:
            self.optimizer.zero_grad()
            
            # Forward pass
            outputs = self.model(**batch)
            
            # Calculate multi-task loss
            loss = self.calculate_multi_task_loss(outputs, batch)
            
            # Backward pass
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
        
        return total_loss / len(self.train_loader)
    
    def calculate_multi_task_loss(self, outputs, batch):
        loss = 0
        
        # Vulnerability detection loss (binary cross-entropy)
        if 'vulnerability_labels' in batch:
            vuln_loss = F.binary_cross_entropy_with_logits(
                outputs['vulnerability'],
                batch['vulnerability_labels']
            )
            loss += self.weights['vulnerability'] * vuln_loss
        
        # Vulnerability type classification loss
        if 'vuln_type_labels' in batch:
            type_loss = F.cross_entropy(
                outputs['vuln_type'],
                batch['vuln_type_labels']
            )
            loss += self.weights['vuln_type'] * type_loss
        
        # Severity regression loss
        if 'severity_labels' in batch:
            severity_loss = F.mse_loss(
                outputs['severity'].squeeze(),
                batch['severity_labels']
            )
            loss += self.weights['severity'] * severity_loss
        
        return loss

def test_model():
    """Test the model with sample data"""
    print("Testing model architecture...")
    
    # Test SimpleVulnDetector
    config = {
        'vocab_size': 10000,
        'embedding_dim': 256,
        'num_classes': 16,
        'max_sequence_length': 256,
        'learning_rate': 2e-5
    }
    
    print("Testing SimpleVulnDetector...")
    model = SimpleVulnDetector(config)
    
    # Test with sample input
    sample_input = torch.randint(0, 10000, (2, 100))  # batch_size=2, seq_len=100
    sample_mask = torch.ones(2, 100)  # attention mask
    
    with torch.no_grad():
        outputs = model(input_ids=sample_input, attention_mask=sample_mask)
    
    print("SimpleVulnDetector test completed successfully!")
    print(f"Input shape: {sample_input.shape}")
    print(f"Vulnerability output: {outputs['vulnerability'].shape}")
    print(f"Type output: {outputs['vuln_type'].shape}")
    print(f"Severity output: {outputs['severity'].shape}")
    
    # Test EnhancedVulnDetector
    print("\nTesting EnhancedVulnDetector...")
    enhanced_model = EnhancedVulnDetector(config)
    
    with torch.no_grad():
        enhanced_outputs = enhanced_model(input_ids=sample_input, attention_mask=sample_mask)
    
    print("EnhancedVulnDetector test completed successfully!")
    print(f"Vulnerability output: {enhanced_outputs['vulnerability'].shape}")
    print(f"Type output: {enhanced_outputs['vuln_type'].shape}")
    print(f"Severity output: {enhanced_outputs['severity'].shape}")
    print(f"Attention weights: {enhanced_outputs['attention_weights'].shape}")

def count_parameters(model):
    """Count the number of trainable parameters in a model"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)

def model_summary():
    """Print summary of all available models"""
    config = {
        'vocab_size': 10000,
        'embedding_dim': 256,
        'num_classes': 16,
        'max_sequence_length': 256
    }
    
    print("Model Summary:")
    print("=" * 50)
    
    # SimpleVulnDetector
    simple_model = SimpleVulnDetector(config)
    simple_params = count_parameters(simple_model)
    print(f"SimpleVulnDetector: {simple_params:,} parameters")
    
    # EnhancedVulnDetector
    enhanced_model = EnhancedVulnDetector(config)
    enhanced_params = count_parameters(enhanced_model)
    print(f"EnhancedVulnDetector: {enhanced_params:,} parameters")
    
    # MultiModalVulnDetector
    try:
        multimodal_config = config.copy()
        multimodal_config['code_bert_model'] = 'microsoft/codebert-base'
        multimodal_model = MultiModalVulnDetector(multimodal_config)
        multimodal_params = count_parameters(multimodal_model)
        print(f"MultiModalVulnDetector: {multimodal_params:,} parameters")
    except Exception as e:
        print(f"MultiModalVulnDetector: Could not load - {e}")
    
    print("=" * 50)

if __name__ == "__main__":
    test_model()
    print("\n")
    model_summary()
