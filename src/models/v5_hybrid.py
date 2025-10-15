"""
VulnHunter V5 Hybrid Model: GNN-MultiScaleTransformer with Dynamic Features
Combines static analysis, control flow graphs, and dynamic execution features
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
import networkx as nx
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from transformers import AutoTokenizer, AutoModel
import shap
import structlog

logger = structlog.get_logger(__name__)


class MultiScaleTransformer(nn.Module):
    """
    Multi-scale transformer for code representation
    """

    def __init__(self,
                 d_model: int = 512,
                 nhead: int = 8,
                 num_layers: int = 6,
                 dropout: float = 0.1):
        super().__init__()

        self.d_model = d_model
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        self.code_encoder = AutoModel.from_pretrained("microsoft/codebert-base")

        # Multi-scale attention layers
        self.local_attention = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model, nhead//2, dropout=dropout),
            num_layers=num_layers//2
        )

        self.global_attention = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model, nhead, dropout=dropout),
            num_layers=num_layers//2
        )

        # Scale fusion
        self.scale_fusion = nn.MultiheadAttention(d_model, nhead, dropout=dropout)
        self.layer_norm = nn.LayerNorm(d_model)

    def forward(self, code_text: List[str]) -> torch.Tensor:
        """
        Forward pass through multi-scale transformer
        """
        batch_size = len(code_text)

        # Tokenize and encode code
        encoded = self.tokenizer(
            code_text,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )

        # Get CodeBERT embeddings
        with torch.no_grad():
            code_embeddings = self.code_encoder(**encoded).last_hidden_state

        # Local attention (focusing on nearby tokens)
        local_features = self.local_attention(code_embeddings.transpose(0, 1))

        # Global attention (full sequence)
        global_features = self.global_attention(code_embeddings.transpose(0, 1))

        # Fuse multi-scale features
        fused_features, _ = self.scale_fusion(
            local_features,
            global_features,
            global_features
        )

        # Pool to get fixed-size representation
        pooled = torch.mean(fused_features, dim=0)  # [batch_size, d_model]

        return self.layer_norm(pooled)


class GraphNeuralNetwork(nn.Module):
    """
    Graph Neural Network for control flow graph representation
    """

    def __init__(self,
                 input_dim: int = 64,
                 hidden_dim: int = 128,
                 output_dim: int = 256,
                 num_layers: int = 3,
                 dropout: float = 0.1):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim

        # Graph convolution layers
        self.convs = nn.ModuleList([
            GATConv(input_dim if i == 0 else hidden_dim,
                   hidden_dim,
                   heads=4,
                   dropout=dropout,
                   concat=True if i < num_layers - 1 else False)
            for i in range(num_layers)
        ])

        # Graph-level readout
        self.readout = nn.Sequential(
            nn.Linear(hidden_dim * 4, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_dim)
        )

    def forward(self, data: Data) -> torch.Tensor:
        """
        Forward pass through GNN
        """
        x, edge_index, batch = data.x, data.edge_index, data.batch

        # Apply graph convolutions
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, training=self.training)

        # Global pooling
        graph_embedding = global_mean_pool(x, batch)

        # Readout
        return self.readout(graph_embedding)


class DynamicFeatureFusion(nn.Module):
    """
    Fusion module for static and dynamic features
    """

    def __init__(self,
                 static_dim: int = 768,
                 dynamic_dim: int = 10,
                 fusion_dim: int = 512,
                 dropout: float = 0.1):
        super().__init__()

        self.static_projection = nn.Sequential(
            nn.Linear(static_dim, fusion_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        self.dynamic_projection = nn.Sequential(
            nn.Linear(dynamic_dim, fusion_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        # Cross-attention for feature fusion
        self.cross_attention = nn.MultiheadAttention(
            fusion_dim, num_heads=8, dropout=dropout
        )

        # Feature interaction layers
        self.interaction = nn.Sequential(
            nn.Linear(fusion_dim * 2, fusion_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(fusion_dim, fusion_dim)
        )

        self.layer_norm = nn.LayerNorm(fusion_dim)

    def forward(self,
                static_features: torch.Tensor,
                dynamic_features: torch.Tensor) -> torch.Tensor:
        """
        Fuse static and dynamic features
        """
        # Project to common dimension
        static_proj = self.static_projection(static_features)
        dynamic_proj = self.dynamic_projection(dynamic_features)

        # Add sequence dimension for attention
        static_seq = static_proj.unsqueeze(1)  # [batch, 1, dim]
        dynamic_seq = dynamic_proj.unsqueeze(1)  # [batch, 1, dim]

        # Cross-attention between static and dynamic
        attended_static, _ = self.cross_attention(
            static_seq.transpose(0, 1),
            dynamic_seq.transpose(0, 1),
            dynamic_seq.transpose(0, 1)
        )

        attended_dynamic, _ = self.cross_attention(
            dynamic_seq.transpose(0, 1),
            static_seq.transpose(0, 1),
            static_seq.transpose(0, 1)
        )

        # Remove sequence dimension
        attended_static = attended_static.squeeze(0)
        attended_dynamic = attended_dynamic.squeeze(0)

        # Concatenate and interact
        combined = torch.cat([attended_static, attended_dynamic], dim=-1)
        fused = self.interaction(combined)

        return self.layer_norm(fused + static_proj)  # Residual connection


class VulnHunterV5Model(nn.Module):
    """
    VulnHunter V5: Hybrid Static-Dynamic Vulnerability Detection Model
    """

    def __init__(self,
                 static_feature_dim: int = 38,
                 dynamic_feature_dim: int = 10,
                 graph_input_dim: int = 64,
                 hidden_dim: int = 512,
                 num_classes: int = 2,
                 dropout: float = 0.1):
        super().__init__()

        self.static_feature_dim = static_feature_dim
        self.dynamic_feature_dim = dynamic_feature_dim
        self.num_classes = num_classes

        # Components
        self.transformer = MultiScaleTransformer()
        self.gnn = GraphNeuralNetwork(graph_input_dim, hidden_dim//2, hidden_dim)

        # Static feature processing
        self.static_encoder = nn.Sequential(
            nn.Linear(static_feature_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim//2, hidden_dim)
        )

        # Feature fusion
        self.fusion = DynamicFeatureFusion(
            static_dim=self.transformer.d_model + hidden_dim + hidden_dim,
            dynamic_dim=dynamic_feature_dim,
            fusion_dim=hidden_dim,
            dropout=dropout
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim//2, hidden_dim//4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim//4, num_classes)
        )

        # Initialize explainer
        self.explainer = None

    def create_cfg_data(self, code: str) -> Data:
        """
        Create control flow graph data from code
        """
        # Simple CFG construction (in practice, use proper AST parsing)
        lines = code.split('\n')
        lines = [line.strip() for line in lines if line.strip()]

        if not lines:
            # Empty graph
            return Data(
                x=torch.zeros(1, self.gnn.input_dim),
                edge_index=torch.empty(2, 0, dtype=torch.long)
            )

        # Create nodes (one per line)
        num_nodes = len(lines)
        node_features = []

        for line in lines:
            # Simple feature extraction per line
            features = [
                len(line),  # Line length
                line.count('if'),  # Conditionals
                line.count('for') + line.count('while'),  # Loops
                line.count('=') - line.count('=='),  # Assignments
                line.count('('),  # Function calls
                1.0 if any(keyword in line for keyword in ['malloc', 'free', 'strcpy']) else 0.0,
                # Add more features up to input_dim
            ]

            # Pad or truncate to input_dim
            while len(features) < self.gnn.input_dim:
                features.append(0.0)
            features = features[:self.gnn.input_dim]

            node_features.append(features)

        x = torch.tensor(node_features, dtype=torch.float)

        # Create edges (simple sequential flow + conditional jumps)
        edge_list = []

        # Sequential edges
        for i in range(num_nodes - 1):
            edge_list.append([i, i + 1])

        # Conditional edges (if statements)
        for i, line in enumerate(lines):
            if 'if' in line:
                # Add jump edges to simulate branches
                for j in range(i + 1, min(i + 5, num_nodes)):
                    edge_list.append([i, j])

        if edge_list:
            edge_index = torch.tensor(edge_list, dtype=torch.long).t()
        else:
            edge_index = torch.empty(2, 0, dtype=torch.long)

        return Data(x=x, edge_index=edge_index)

    def forward(self,
                code_text: List[str],
                static_features: torch.Tensor,
                dynamic_features: torch.Tensor,
                cfg_data: Optional[List[Data]] = None) -> torch.Tensor:
        """
        Forward pass through the hybrid model
        """
        batch_size = len(code_text)

        # 1. Transformer encoding
        transformer_features = self.transformer(code_text)

        # 2. Static feature encoding
        static_encoded = self.static_encoder(static_features)

        # 3. Graph neural network encoding
        if cfg_data is None:
            # Create CFG data from code
            cfg_data = [self.create_cfg_data(code) for code in code_text]

        # Batch the graph data
        batch_cfg = Batch.from_data_list(cfg_data)
        graph_features = self.gnn(batch_cfg)

        # 4. Combine static representations
        combined_static = torch.cat([
            transformer_features,
            static_encoded,
            graph_features
        ], dim=-1)

        # 5. Fusion with dynamic features
        fused_features = self.fusion(combined_static, dynamic_features)

        # 6. Classification
        logits = self.classifier(fused_features)

        return logits

    def predict_proba(self,
                     code_text: List[str],
                     static_features: torch.Tensor,
                     dynamic_features: torch.Tensor) -> torch.Tensor:
        """
        Get prediction probabilities
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(code_text, static_features, dynamic_features)
            probabilities = F.softmax(logits, dim=-1)
        return probabilities

    def explain_prediction(self,
                          code_text: List[str],
                          static_features: torch.Tensor,
                          dynamic_features: torch.Tensor) -> Dict[str, Any]:
        """
        Generate SHAP explanations for predictions
        """
        logger.info("Generating SHAP explanations")

        try:
            if self.explainer is None:
                # Create a wrapper function for SHAP
                def model_wrapper(combined_input):
                    # Split combined input back into components
                    batch_size = combined_input.shape[0]
                    feature_dim = self.static_feature_dim + self.dynamic_feature_dim

                    static_part = combined_input[:, :self.static_feature_dim]
                    dynamic_part = combined_input[:, self.static_feature_dim:feature_dim]

                    # Use dummy code for SHAP (since it can't handle text directly)
                    dummy_code = ["dummy code"] * batch_size

                    logits = self.forward(dummy_code, static_part, dynamic_part)
                    return F.softmax(logits, dim=-1).cpu().numpy()

                # Combine features for SHAP
                combined_features = torch.cat([static_features, dynamic_features], dim=-1)

                # Initialize SHAP explainer
                self.explainer = shap.DeepExplainer(
                    model_wrapper,
                    combined_features[:1]  # Use first sample as background
                )

            # Generate explanations
            combined_input = torch.cat([static_features, dynamic_features], dim=-1)
            shap_values = self.explainer.shap_values(combined_input.cpu().numpy())

            explanation = {
                "shap_values": shap_values,
                "feature_names": [f"static_{i}" for i in range(self.static_feature_dim)] +
                               [f"dynamic_{i}" for i in range(self.dynamic_feature_dim)],
                "feature_importance": np.abs(shap_values[1]).mean(axis=0).tolist()  # For vulnerable class
            }

            return explanation

        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")
            return {
                "error": str(e),
                "feature_importance": [0.0] * (self.static_feature_dim + self.dynamic_feature_dim)
            }

    def get_attention_weights(self) -> Dict[str, torch.Tensor]:
        """
        Get attention weights from transformer and fusion modules
        """
        weights = {}

        # Transformer attention weights (if available)
        if hasattr(self.transformer, 'attention_weights'):
            weights['transformer'] = self.transformer.attention_weights

        # Fusion attention weights
        if hasattr(self.fusion, 'attention_weights'):
            weights['fusion'] = self.fusion.attention_weights

        return weights


class VulnHunterV5Loss(nn.Module):
    """
    Custom loss function for VulnHunter V5
    """

    def __init__(self,
                 class_weights: Optional[torch.Tensor] = None,
                 focal_alpha: float = 1.0,
                 focal_gamma: float = 2.0):
        super().__init__()

        self.class_weights = class_weights
        self.focal_alpha = focal_alpha
        self.focal_gamma = focal_gamma

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Compute focal loss with class weighting
        """
        # Cross entropy loss
        ce_loss = F.cross_entropy(logits, targets, weight=self.class_weights, reduction='none')

        # Focal loss components
        pt = torch.exp(-ce_loss)
        focal_loss = self.focal_alpha * (1 - pt) ** self.focal_gamma * ce_loss

        return focal_loss.mean()


# Example usage and testing
if __name__ == "__main__":
    # Test the model
    model = VulnHunterV5Model(
        static_feature_dim=38,
        dynamic_feature_dim=10,
        num_classes=2
    )

    # Sample data
    batch_size = 2
    code_samples = [
        "function transfer(address to, uint amount) { balances[to] += amount; }",
        "void safe_function(char* input) { if(input != NULL) process(input); }"
    ]

    static_features = torch.randn(batch_size, 38)
    dynamic_features = torch.randn(batch_size, 10)

    # Forward pass
    logits = model(code_samples, static_features, dynamic_features)
    print(f"Output shape: {logits.shape}")

    # Predictions
    probabilities = model.predict_proba(code_samples, static_features, dynamic_features)
    print(f"Probabilities: {probabilities}")

    # Explanations
    explanations = model.explain_prediction(code_samples, static_features, dynamic_features)
    print(f"Feature importance shape: {len(explanations.get('feature_importance', []))}")

    logger.info("VulnHunter V5 model test completed successfully")