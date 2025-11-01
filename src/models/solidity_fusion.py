"""
VulnHunter Blockchain: Solidity Fusion Model
Advanced GNN + Transformer fusion specifically adapted for smart contract security
Target: 95%+ F1 score on real-world vulnerability detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import re

# Import our blockchain-specific components
from .blockchain_gnn import BlockchainGNN
from .transformer_encoder import TransformerEncoder
from ..parser.languages.solidity_parser import SolidityParser

class SolidityTransformerEncoder(nn.Module):
    """
    Specialized Transformer encoder for Solidity code
    Enhanced with blockchain-specific vocabulary and attention patterns
    """

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        max_length: int = 512,
        hidden_dim: int = 768,
        output_dim: int = 256,
        dropout: float = 0.1
    ):
        super(SolidityTransformerEncoder, self).__init__()

        # Base transformer setup
        from transformers import AutoTokenizer, AutoModel, AutoConfig

        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.transformer = AutoModel.from_pretrained(model_name)
        self.config = AutoConfig.from_pretrained(model_name)

        self.max_length = max_length
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim

        # Add Solidity-specific tokens
        solidity_tokens = {
            "additional_special_tokens": [
                # Vulnerability markers
                "[REENTRANCY]", "[OVERFLOW]", "[ACCESS_CONTROL]", "[UNCHECKED_CALL]",
                "[TIMESTAMP_DEP]", "[TX_ORIGIN]", "[DOS_GAS]", "[UNINIT_STORAGE]",
                "[FRONT_RUNNING]", "[GAS_GRIEFING]",

                # Solidity keywords
                "[CONTRACT]", "[FUNCTION]", "[MODIFIER]", "[EVENT]", "[STRUCT]",
                "[MAPPING]", "[PAYABLE]", "[EXTERNAL]", "[INTERNAL]", "[PRIVATE]",
                "[PUBLIC]", "[VIEW]", "[PURE]", "[REQUIRE]", "[ASSERT]",

                # Security patterns
                "[SAFE_CALL]", "[UNSAFE_CALL]", "[STATE_CHANGE]", "[EXTERNAL_CALL]",
                "[OWNER_CHECK]", "[REENTRANCY_GUARD]", "[SAFEMATH]", "[OVERFLOW_CHECK]"
            ]
        }

        self.tokenizer.add_special_tokens(solidity_tokens)
        self.transformer.resize_token_embeddings(len(self.tokenizer))

        # Vulnerability pattern detection
        self.vulnerability_patterns = {
            'reentrancy': [
                (r'(.call\{[^}]*\}|\.call|\.send|\.transfer)\s*\([^)]*\)\s*;?\s*\n[^}]*\w+\s*[\-\+\*\/]?=', '[REENTRANCY]'),
                (r'external.*function[^{]*{[^}]*\.call[^}]*\w+\s*=', '[REENTRANCY]'),
                (r'payable.*function[^{]*{[^}]*\.call[^}]*balances\[', '[REENTRANCY]')
            ],
            'integer_overflow': [
                (r'uint\d*\s+\w+\s*[\+\-\*\/]?=.*(?!SafeMath)', '[OVERFLOW]'),
                (r'(\+\+|\-\-).*uint.*(?!SafeMath)', '[OVERFLOW]'),
                (r'uint.*[\+\-\*\/].*uint.*(?!SafeMath)', '[OVERFLOW]')
            ],
            'access_control': [
                (r'function\s+\w+\s*\([^)]*\)\s*(?:external|public)(?![^{]*(?:onlyOwner|require\s*\(\s*msg\.sender))', '[ACCESS_CONTROL]'),
                (r'msg\.sender\s*==.*(?!onlyOwner|modifier)', '[ACCESS_CONTROL]')
            ],
            'unchecked_call': [
                (r'\.call\s*\([^)]*\)\s*;(?!\s*require)', '[UNCHECKED_CALL]'),
                (r'\.send\s*\([^)]*\)\s*;(?!\s*require)', '[UNCHECKED_CALL]')
            ]
        }

        # Blockchain-specific attention
        self.solidity_attention = SolidityAttention(hidden_dim, num_heads=12)

        # Output projection
        self.output_projection = nn.Sequential(
            nn.Linear(hidden_dim, output_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(output_dim * 2, output_dim),
            nn.LayerNorm(output_dim)
        )

        # Vulnerability-specific embeddings
        self.vulnerability_embeddings = nn.Embedding(10, hidden_dim)  # 10 vuln types

    def preprocess_solidity_code(self, code: str) -> str:
        """Enhanced preprocessing for Solidity code with vulnerability marking"""
        processed_code = code

        # Add vulnerability markers
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern, marker in patterns:
                processed_code = re.sub(pattern, rf'{marker}\1', processed_code, flags=re.MULTILINE | re.IGNORECASE)

        # Mark important Solidity constructs
        solidity_markers = [
            (r'\bcontract\s+(\w+)', r'[CONTRACT] contract \1'),
            (r'\bfunction\s+(\w+)', r'[FUNCTION] function \1'),
            (r'\bmodifier\s+(\w+)', r'[MODIFIER] modifier \1'),
            (r'\bmapping\s*\([^)]*\)', r'[MAPPING]\g<0>'),
            (r'\brequire\s*\(', r'[REQUIRE] require('),
            (r'\bassert\s*\(', r'[ASSERT] assert('),
            (r'\bpayable\b', r'[PAYABLE] payable'),
            (r'\bexternal\b', r'[EXTERNAL] external'),
            (r'msg\.sender', r'[MSG_SENDER] msg.sender'),
            (r'msg\.value', r'[MSG_VALUE] msg.value'),
            (r'block\.timestamp', r'[BLOCK_TIMESTAMP] block.timestamp'),
            (r'tx\.origin', r'[TX_ORIGIN] tx.origin')
        ]

        for pattern, replacement in solidity_markers:
            processed_code = re.sub(pattern, replacement, processed_code)

        # Clean up excessive whitespace
        processed_code = re.sub(r'\n\s*\n\s*\n', '\n\n', processed_code)
        processed_code = re.sub(r'[ \t]+', ' ', processed_code)

        return processed_code

    def forward(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Forward pass through Solidity transformer encoder

        Args:
            code: Solidity source code

        Returns:
            Dictionary with encoded representations and vulnerability predictions
        """
        # Preprocess code
        processed_code = self.preprocess_solidity_code(code)

        # Tokenize
        inputs = self.tokenizer(
            processed_code,
            return_tensors="pt",
            max_length=self.max_length,
            truncation=True,
            padding=True,
            return_attention_mask=True
        )

        # Move to device
        device = next(self.transformer.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        # Get transformer outputs
        outputs = self.transformer(**inputs)
        sequence_output = outputs.last_hidden_state  # [batch_size, seq_len, hidden_dim]

        # Apply Solidity-specific attention
        attended_output = self.solidity_attention(sequence_output, inputs['attention_mask'])

        # Create multiple representations
        representations = {
            'sequence': sequence_output,
            'attended': attended_output,
            'cls_token': sequence_output[:, 0, :],
            'mean_pooled': self._mean_pool(sequence_output, inputs['attention_mask']),
            'max_pooled': self._max_pool(sequence_output, inputs['attention_mask'])
        }

        # Combine representations
        combined_repr = torch.cat([
            representations['cls_token'],
            representations['mean_pooled'],
            representations['attended']
        ], dim=-1)

        # Project to output dimension
        final_embedding = self.output_projection(combined_repr)

        return {
            'embedding': final_embedding,
            'representations': representations,
            'attention_weights': self.solidity_attention.last_attention_weights
        }

    def _mean_pool(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Mean pooling with attention mask"""
        mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
        sum_embeddings = torch.sum(hidden_states * mask_expanded, dim=1)
        sum_mask = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
        return sum_embeddings / sum_mask

    def _max_pool(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Max pooling with attention mask"""
        mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
        hidden_states = hidden_states.clone()
        hidden_states[mask_expanded == 0] = -1e9
        return torch.max(hidden_states, dim=1)[0]

class SolidityAttention(nn.Module):
    """Solidity-specific attention mechanism for vulnerability patterns"""

    def __init__(self, hidden_dim: int, num_heads: int = 12):
        super(SolidityAttention, self).__init__()

        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads

        self.query = nn.Linear(hidden_dim, hidden_dim)
        self.key = nn.Linear(hidden_dim, hidden_dim)
        self.value = nn.Linear(hidden_dim, hidden_dim)
        self.output = nn.Linear(hidden_dim, hidden_dim)

        self.dropout = nn.Dropout(0.1)
        self.scale = self.head_dim ** -0.5

        # Store attention weights for visualization
        self.last_attention_weights = None

    def forward(self, hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        batch_size, seq_len, _ = hidden_states.size()

        # Project to Q, K, V
        queries = self.query(hidden_states)
        keys = self.key(hidden_states)
        values = self.value(hidden_states)

        # Reshape for multi-head attention
        queries = queries.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        keys = keys.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        values = values.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        # Compute attention scores
        attention_scores = torch.matmul(queries, keys.transpose(-2, -1)) * self.scale

        # Apply attention mask
        if attention_mask is not None:
            mask_expanded = attention_mask.unsqueeze(1).unsqueeze(1).expand(
                batch_size, self.num_heads, seq_len, seq_len
            )
            attention_scores = attention_scores.masked_fill(mask_expanded == 0, -1e9)

        # Apply softmax
        attention_weights = F.softmax(attention_scores, dim=-1)
        attention_weights = self.dropout(attention_weights)

        # Store for visualization
        self.last_attention_weights = attention_weights.detach()

        # Apply attention to values
        attended_values = torch.matmul(attention_weights, values)

        # Reshape and project
        attended_values = attended_values.transpose(1, 2).contiguous().view(
            batch_size, seq_len, self.hidden_dim
        )

        output = self.output(attended_values)

        # Global pooling for sequence representation
        if attention_mask is not None:
            mask_expanded = attention_mask.unsqueeze(-1).expand(output.size()).float()
            pooled_output = torch.sum(output * mask_expanded, dim=1) / torch.clamp(
                mask_expanded.sum(dim=1), min=1e-9
            )
        else:
            pooled_output = output.mean(dim=1)

        return pooled_output

class SolidityFusionModel(nn.Module):
    """
    Complete fusion model for Solidity vulnerability detection
    Combines blockchain-specific GNN with Solidity-aware Transformer
    """

    def __init__(
        self,
        gnn_input_dim: int = 30,
        gnn_hidden_dim: int = 128,
        transformer_output_dim: int = 256,
        fusion_dim: int = 512,
        num_vulnerability_types: int = 10,
        dropout: float = 0.1
    ):
        super(SolidityFusionModel, self).__init__()

        self.parser = SolidityParser()
        self.gnn = BlockchainGNN(
            input_dim=gnn_input_dim,
            hidden_dim=gnn_hidden_dim,
            output_dim=transformer_output_dim,
            num_vulnerability_types=num_vulnerability_types
        )
        self.transformer = SolidityTransformerEncoder(
            output_dim=transformer_output_dim
        )

        # Cross-modal fusion
        self.fusion_attention = CrossModalFusion(
            gnn_dim=transformer_output_dim,
            transformer_dim=transformer_output_dim,
            fusion_dim=fusion_dim
        )

        # Multi-task prediction heads
        self.binary_classifier = nn.Sequential(
            nn.Linear(fusion_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 2)  # vulnerable/safe
        )

        self.vulnerability_type_classifier = nn.Sequential(
            nn.Linear(fusion_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_vulnerability_types)
        )

        self.severity_predictor = nn.Sequential(
            nn.Linear(fusion_dim, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 5),  # 0=critical, 1=high, 2=medium, 3=low, 4=safe
            nn.Softmax(dim=-1)
        )

        self.confidence_estimator = nn.Sequential(
            nn.Linear(fusion_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

        # Gas complexity predictor
        self.gas_predictor = nn.Sequential(
            nn.Linear(fusion_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )

        # Vulnerability type mapping
        self.vulnerability_types = [
            'reentrancy', 'integer_overflow', 'access_control', 'unchecked_call',
            'timestamp_dependence', 'tx_origin', 'dos_gas_limit', 'uninitialized_storage',
            'front_running', 'insufficient_gas_griefing'
        ]

    def forward(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Complete forward pass through fusion model

        Args:
            code: Solidity source code

        Returns:
            Comprehensive vulnerability analysis results
        """
        # Parse code to graph
        graph = self.parser.parse_solidity_code(code)
        graph_data = self._solidity_graph_to_pyg(graph)

        # Get GNN embeddings
        gnn_results = self.gnn(graph_data)
        gnn_embedding = gnn_results['graph_embedding']

        # Get Transformer embeddings
        transformer_results = self.transformer(code)
        transformer_embedding = transformer_results['embedding']

        # Cross-modal fusion
        fused_embedding = self.fusion_attention(gnn_embedding, transformer_embedding)

        # Multi-task predictions
        binary_logits = self.binary_classifier(fused_embedding)
        vulnerability_type_logits = self.vulnerability_type_classifier(fused_embedding)
        severity_scores = self.severity_predictor(fused_embedding)
        confidence_score = self.confidence_estimator(fused_embedding)
        gas_complexity = self.gas_predictor(fused_embedding)

        # Combine results
        results = {
            # Main predictions
            'binary_prediction': torch.softmax(binary_logits, dim=-1),
            'vulnerability_type_predictions': torch.sigmoid(vulnerability_type_logits),
            'severity_prediction': severity_scores,
            'confidence_score': confidence_score,
            'gas_complexity': gas_complexity,

            # Component results
            'gnn_results': gnn_results,
            'transformer_results': transformer_results,
            'fused_embedding': fused_embedding,

            # Graph analysis
            'graph_stats': self._extract_graph_stats(graph),
            'contract_features': graph.contract_features
        }

        return results

    def analyze_solidity_contract(self, code: str) -> Dict[str, Any]:
        """
        High-level contract analysis with interpretable results

        Args:
            code: Solidity source code

        Returns:
            Human-readable analysis results
        """
        with torch.no_grad():
            results = self.forward(code)

        # Extract key predictions
        is_vulnerable = results['binary_prediction'][0, 1].item() > 0.5
        vulnerability_prob = results['binary_prediction'][0, 1].item()

        # Get top vulnerability types
        vuln_type_scores = results['vulnerability_type_predictions'][0]
        top_vulnerabilities = []

        for i, score in enumerate(vuln_type_scores):
            if score.item() > 0.3:  # Threshold for reporting
                top_vulnerabilities.append({
                    'type': self.vulnerability_types[i],
                    'score': score.item(),
                    'severity': self._get_vulnerability_severity(self.vulnerability_types[i], score.item())
                })

        # Sort by score
        top_vulnerabilities.sort(key=lambda x: x['score'], reverse=True)

        # Severity analysis
        severity_dist = results['severity_prediction'][0]
        predicted_severity = torch.argmax(severity_dist).item()
        severity_labels = ['Critical', 'High', 'Medium', 'Low', 'Safe']

        # Confidence and complexity
        confidence = results['confidence_score'][0].item()
        gas_complexity = results['gas_complexity'][0].item()

        # Graph statistics
        graph_stats = results['graph_stats']
        contract_features = results['contract_features']

        analysis = {
            'overall_assessment': {
                'is_vulnerable': is_vulnerable,
                'vulnerability_probability': vulnerability_prob,
                'predicted_severity': severity_labels[predicted_severity],
                'confidence_score': confidence,
                'risk_level': self._calculate_risk_level(vulnerability_prob, predicted_severity, confidence)
            },
            'vulnerability_details': {
                'detected_vulnerabilities': top_vulnerabilities,
                'gnn_specific_detections': self._extract_gnn_detections(results['gnn_results']),
                'total_vulnerability_types': len(top_vulnerabilities)
            },
            'contract_analysis': {
                'complexity_metrics': {
                    'gas_complexity': gas_complexity,
                    'cyclomatic_complexity': contract_features.get('complexity_score', 0),
                    'function_count': contract_features.get('function_count', 0),
                    'state_variable_count': contract_features.get('state_var_count', 0)
                },
                'security_features': {
                    'has_constructor': contract_features.get('has_constructor', False),
                    'has_fallback': contract_features.get('has_fallback', False),
                    'uses_inheritance': contract_features.get('uses_inheritance', False),
                    'solidity_version': contract_features.get('solidity_version', 'unknown')
                },
                'graph_statistics': graph_stats
            },
            'recommendations': self._generate_recommendations(top_vulnerabilities, contract_features),
            'technical_details': {
                'model_confidence': confidence,
                'processing_time': 0.0,  # Would be filled in real implementation
                'model_version': '0.3.0-blockchain'
            }
        }

        return analysis

    def _solidity_graph_to_pyg(self, graph) -> Data:
        """Convert Solidity graph to PyTorch Geometric format"""
        if len(graph.nodes) == 0:
            return Data(
                x=torch.zeros(1, 30),
                edge_index=torch.empty((2, 0), dtype=torch.long),
                batch=torch.zeros(1, dtype=torch.long)
            )

        x = graph.node_features
        edge_index = graph.edge_index
        batch = torch.zeros(x.size(0), dtype=torch.long)

        return Data(x=x, edge_index=edge_index, batch=batch)

    def _extract_graph_stats(self, graph) -> Dict[str, Any]:
        """Extract interpretable graph statistics"""
        return {
            'node_count': len(graph.nodes),
            'edge_count': len(graph.edges),
            'vulnerability_nodes': sum(1 for node in graph.nodes if node.vulnerability_markers),
            'function_nodes': sum(1 for node in graph.nodes if node.node_type == 'function_definition'),
            'average_security_level': np.mean([node.security_level for node in graph.nodes]) if graph.nodes else 4,
            'total_gas_estimate': sum(node.gas_estimate for node in graph.nodes),
            'max_complexity': max((node.features.get('complexity_score', 0) for node in graph.nodes), default=0)
        }

    def _extract_gnn_detections(self, gnn_results: Dict) -> List[Dict]:
        """Extract GNN-specific vulnerability detections"""
        detections = []
        vuln_predictions = gnn_results['vulnerability_predictions']

        for vuln_type, score_tensor in vuln_predictions.items():
            score = score_tensor.item() if hasattr(score_tensor, 'item') else float(score_tensor)
            if score > 0.5:
                detections.append({
                    'type': vuln_type,
                    'score': score,
                    'detection_method': 'Graph Neural Network',
                    'pattern_based': True
                })

        return detections

    def _get_vulnerability_severity(self, vuln_type: str, score: float) -> str:
        """Get severity level for vulnerability type"""
        critical_vulns = {'reentrancy', 'integer_overflow', 'unchecked_call'}
        high_vulns = {'access_control', 'tx_origin', 'timestamp_dependence'}

        if vuln_type in critical_vulns and score > 0.7:
            return 'Critical'
        elif vuln_type in critical_vulns or (vuln_type in high_vulns and score > 0.6):
            return 'High'
        elif score > 0.5:
            return 'Medium'
        else:
            return 'Low'

    def _calculate_risk_level(self, vuln_prob: float, severity: int, confidence: float) -> str:
        """Calculate overall risk level"""
        risk_score = vuln_prob * confidence * (5 - severity) / 5

        if risk_score > 0.8:
            return "CRITICAL"
        elif risk_score > 0.6:
            return "HIGH"
        elif risk_score > 0.4:
            return "MEDIUM"
        elif risk_score > 0.2:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_recommendations(self, vulnerabilities: List[Dict], contract_features: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Vulnerability-specific recommendations
        vuln_types = {v['type'] for v in vulnerabilities}

        if 'reentrancy' in vuln_types:
            recommendations.append("Implement reentrancy guards or use checks-effects-interactions pattern")
        if 'integer_overflow' in vuln_types:
            recommendations.append("Use SafeMath library or upgrade to Solidity ^0.8.0 for automatic overflow checks")
        if 'access_control' in vuln_types:
            recommendations.append("Add proper access control modifiers (onlyOwner, require statements)")
        if 'unchecked_call' in vuln_types:
            recommendations.append("Always check return values of external calls with require statements")
        if 'timestamp_dependence' in vuln_types:
            recommendations.append("Avoid using block.timestamp for critical logic; consider block.number instead")
        if 'tx_origin' in vuln_types:
            recommendations.append("Replace tx.origin with msg.sender for authentication")

        # General recommendations
        if not contract_features.get('has_constructor', False):
            recommendations.append("Consider adding a constructor for proper initialization")

        if contract_features.get('function_count', 0) > 20:
            recommendations.append("Consider breaking large contracts into smaller, modular contracts")

        return recommendations

class CrossModalFusion(nn.Module):
    """Enhanced cross-modal fusion for Solidity analysis"""

    def __init__(self, gnn_dim: int, transformer_dim: int, fusion_dim: int):
        super(CrossModalFusion, self).__init__()

        self.gnn_projector = nn.Linear(gnn_dim, fusion_dim)
        self.transformer_projector = nn.Linear(transformer_dim, fusion_dim)

        self.cross_attention = nn.MultiheadAttention(
            embed_dim=fusion_dim,
            num_heads=8,
            dropout=0.1,
            batch_first=True
        )

        self.fusion_layers = nn.Sequential(
            nn.Linear(fusion_dim * 2, fusion_dim),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(fusion_dim, fusion_dim),
            nn.LayerNorm(fusion_dim)
        )

    def forward(self, gnn_features: torch.Tensor, transformer_features: torch.Tensor) -> torch.Tensor:
        # Project to common dimension
        gnn_proj = self.gnn_projector(gnn_features)
        transformer_proj = self.transformer_projector(transformer_features)

        # Add sequence dimension for attention
        gnn_seq = gnn_proj.unsqueeze(1)
        transformer_seq = transformer_proj.unsqueeze(1)

        # Cross attention
        gnn_attended, _ = self.cross_attention(gnn_seq, transformer_seq, transformer_seq)
        transformer_attended, _ = self.cross_attention(transformer_seq, gnn_seq, gnn_seq)

        # Remove sequence dimension
        gnn_attended = gnn_attended.squeeze(1)
        transformer_attended = transformer_attended.squeeze(1)

        # Combine and fuse
        combined = torch.cat([gnn_attended, transformer_attended], dim=-1)
        fused = self.fusion_layers(combined)

        # Residual connection
        fused = fused + gnn_proj + transformer_proj

        return fused

def test_solidity_fusion():
    """Test the complete Solidity fusion model"""
    print("=== Testing Solidity Fusion Model ===")

    # Create model
    model = SolidityFusionModel()

    # Test contract with reentrancy vulnerability
    test_contract = '''
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // State change after external call
    }
}
'''

    # Analyze contract
    try:
        analysis = model.analyze_solidity_contract(test_contract)

        print(f"Vulnerable: {analysis['overall_assessment']['is_vulnerable']}")
        print(f"Risk Level: {analysis['overall_assessment']['risk_level']}")
        print(f"Confidence: {analysis['overall_assessment']['confidence_score']:.3f}")

        print("\nDetected Vulnerabilities:")
        for vuln in analysis['vulnerability_details']['detected_vulnerabilities']:
            print(f"  - {vuln['type']}: {vuln['score']:.3f} ({vuln['severity']})")

        print(f"\nContract Complexity: {analysis['contract_analysis']['complexity_metrics']}")
        print(f"Recommendations: {len(analysis['recommendations'])} items")

    except Exception as e:
        print(f"Error during analysis: {e}")

    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

if __name__ == "__main__":
    test_solidity_fusion()