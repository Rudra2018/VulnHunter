"""
VulnHunter PoC: Advanced Fusion Model
Combines GNN structural analysis with Transformer semantic understanding
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

from .gnn_encoder import GNNEncoder, VulnerabilityGNN
from .transformer_encoder import TransformerEncoder, CodeSecurityAnalyzer
from ..parser.code_to_graph import CodeToGraphParser, CodeGraph

class VulnHunterFusion(nn.Module):
    """
    Advanced fusion model combining Graph Neural Networks and Transformers
    for comprehensive vulnerability detection
    """

    def __init__(
        self,
        gnn_config: Dict[str, Any] = None,
        transformer_config: Dict[str, Any] = None,
        fusion_dim: int = 512,
        num_vulnerability_types: int = 8,
        dropout: float = 0.1
    ):
        super(VulnHunterFusion, self).__init__()

        # Default configurations
        self.gnn_config = gnn_config or {
            'input_dim': 20,
            'hidden_dim': 128,
            'output_dim': 256,
            'model_type': 'hybrid'
        }

        self.transformer_config = transformer_config or {
            'model_name': 'microsoft/codebert-base',
            'output_dim': 256
        }

        self.fusion_dim = fusion_dim
        self.num_vulnerability_types = num_vulnerability_types

        # Initialize components
        self.code_parser = CodeToGraphParser()
        self.gnn_encoder = GNNEncoder(**self.gnn_config)
        self.transformer_encoder = TransformerEncoder(**self.transformer_config)

        # Fusion layers
        self.fusion_attention = CrossModalAttention(
            gnn_dim=self.gnn_config['output_dim'] * 3,  # 3 pooling strategies
            transformer_dim=self.transformer_config['output_dim'],
            fusion_dim=fusion_dim
        )

        self.fusion_projector = nn.Sequential(
            nn.Linear(fusion_dim, fusion_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(fusion_dim // 2, fusion_dim),
            nn.LayerNorm(fusion_dim)
        )

        # Multi-task prediction heads
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(fusion_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(128, 2)  # Binary classification
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
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

        self.confidence_estimator = nn.Sequential(
            nn.Linear(fusion_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

        # Vulnerability type mapping
        self.vulnerability_types = [
            'sql_injection', 'command_injection', 'path_traversal', 'xss',
            'buffer_overflow', 'code_injection', 'file_inclusion', 'authentication_bypass'
        ]

    def forward(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the fusion model

        Args:
            code: Python source code string

        Returns:
            Dictionary containing all predictions and intermediate results
        """
        # Parse code to graph
        graph = self.code_parser.parse_code_to_graph(code)

        # Convert to PyTorch Geometric format
        graph_data = self._graph_to_pyg(graph)

        # Get GNN encoding
        gnn_embedding = self.gnn_encoder(graph_data)

        # Get Transformer encoding
        transformer_embedding, transformer_vuln_preds, transformer_confidence = \
            self.transformer_encoder(code)

        # Apply cross-modal attention fusion
        fused_embedding = self.fusion_attention(gnn_embedding, transformer_embedding)

        # Project fused embedding
        final_embedding = self.fusion_projector(fused_embedding)

        # Multi-task predictions
        vuln_logits = self.vulnerability_classifier(final_embedding)
        vuln_type_logits = self.vulnerability_type_classifier(final_embedding)
        severity_score = self.severity_predictor(final_embedding)
        confidence_score = self.confidence_estimator(final_embedding)

        # Combine results
        results = {
            'vulnerability_prediction': torch.softmax(vuln_logits, dim=-1),
            'vulnerability_type_predictions': torch.sigmoid(vuln_type_logits),
            'severity_score': severity_score,
            'confidence_score': confidence_score,
            'transformer_predictions': transformer_vuln_preds,
            'transformer_confidence': transformer_confidence,
            'fused_embedding': final_embedding,
            'gnn_embedding': gnn_embedding,
            'transformer_embedding': transformer_embedding,
            'graph_stats': self._get_graph_stats(graph)
        }

        return results

    def _graph_to_pyg(self, graph: CodeGraph) -> Data:
        """Convert CodeGraph to PyTorch Geometric Data object"""
        # Handle empty graphs
        if len(graph.nodes) == 0:
            return Data(
                x=torch.zeros(1, 20),
                edge_index=torch.empty((2, 0), dtype=torch.long),
                batch=torch.zeros(1, dtype=torch.long)
            )

        # Use pre-computed features from graph
        x = graph.node_features
        edge_index = graph.edge_index

        # Create batch (single graph)
        batch = torch.zeros(x.size(0), dtype=torch.long)

        return Data(x=x, edge_index=edge_index, batch=batch)

    def _get_graph_stats(self, graph: CodeGraph) -> Dict[str, float]:
        """Extract statistical features from graph"""
        stats = {
            'num_nodes': len(graph.nodes),
            'num_edges': len(graph.edges),
            'avg_degree': len(graph.edges) * 2 / max(len(graph.nodes), 1),
            'vulnerability_nodes': sum(1 for node in graph.nodes
                                     if node.features.get('is_vulnerable', 0)),
            'function_nodes': sum(1 for node in graph.nodes
                                if node.features.get('is_function', 0)),
            'call_nodes': sum(1 for node in graph.nodes
                            if node.features.get('is_call', 0)),
            'max_depth': max((node.features.get('depth', 0) for node in graph.nodes), default=0),
            'avg_complexity': np.mean([node.features.get('complexity_score', 1.0)
                                     for node in graph.nodes]) if graph.nodes else 1.0
        }
        return stats

    def analyze_vulnerability(self, code: str) -> Dict[str, Any]:
        """
        Comprehensive vulnerability analysis

        Args:
            code: Python source code

        Returns:
            Detailed analysis results
        """
        with torch.no_grad():
            results = self.forward(code)

        # Extract predictions
        is_vulnerable = results['vulnerability_prediction'][0, 1].item() > 0.5
        vuln_probability = results['vulnerability_prediction'][0, 1].item()
        severity = results['severity_score'][0].item()
        confidence = results['confidence_score'][0].item()

        # Get top vulnerability types
        vuln_type_scores = results['vulnerability_type_predictions'][0]
        top_vuln_types = []
        for i, score in enumerate(vuln_type_scores):
            if score.item() > 0.3:  # Threshold for reporting
                top_vuln_types.append({
                    'type': self.vulnerability_types[i],
                    'score': score.item()
                })

        # Sort by score
        top_vuln_types.sort(key=lambda x: x['score'], reverse=True)

        # Graph statistics
        graph_stats = results['graph_stats']

        analysis = {
            'is_vulnerable': is_vulnerable,
            'vulnerability_probability': vuln_probability,
            'severity_score': severity,
            'confidence_score': confidence,
            'vulnerability_types': top_vuln_types,
            'graph_statistics': graph_stats,
            'risk_level': self._calculate_risk_level(vuln_probability, severity, confidence),
            'recommendations': self._generate_recommendations(top_vuln_types, graph_stats),
            'transformer_specific': {
                vuln_type: score[0].item()
                for vuln_type, score in results['transformer_predictions'].items()
            }
        }

        return analysis

    def _calculate_risk_level(self, probability: float, severity: float, confidence: float) -> str:
        """Calculate overall risk level"""
        risk_score = probability * severity * confidence

        if risk_score > 0.7:
            return "CRITICAL"
        elif risk_score > 0.5:
            return "HIGH"
        elif risk_score > 0.3:
            return "MEDIUM"
        elif risk_score > 0.1:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_recommendations(self, vuln_types: List[Dict], graph_stats: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Type-specific recommendations
        for vuln_type in vuln_types:
            vuln_name = vuln_type['type']
            if vuln_name == 'sql_injection':
                recommendations.append("Use parameterized queries instead of string concatenation")
            elif vuln_name == 'command_injection':
                recommendations.append("Sanitize input and use subprocess with shell=False")
            elif vuln_name == 'path_traversal':
                recommendations.append("Validate file paths and use os.path.join()")
            elif vuln_name == 'xss':
                recommendations.append("Escape output and validate user input")

        # Graph-based recommendations
        if graph_stats['call_nodes'] > graph_stats['num_nodes'] * 0.3:
            recommendations.append("Review function calls for security implications")

        if graph_stats['max_depth'] > 10:
            recommendations.append("Consider refactoring complex nested code")

        return recommendations

class CrossModalAttention(nn.Module):
    """
    Cross-modal attention mechanism for fusing GNN and Transformer representations
    """

    def __init__(self, gnn_dim: int, transformer_dim: int, fusion_dim: int):
        super(CrossModalAttention, self).__init__()

        self.gnn_dim = gnn_dim
        self.transformer_dim = transformer_dim
        self.fusion_dim = fusion_dim

        # Projection layers
        self.gnn_projector = nn.Linear(gnn_dim, fusion_dim)
        self.transformer_projector = nn.Linear(transformer_dim, fusion_dim)

        # Attention layers
        self.attention = nn.MultiheadAttention(
            embed_dim=fusion_dim,
            num_heads=8,
            dropout=0.1,
            batch_first=True
        )

        # Fusion layers
        self.fusion_layers = nn.Sequential(
            nn.Linear(fusion_dim * 2, fusion_dim),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(fusion_dim, fusion_dim)
        )

    def forward(self, gnn_features: torch.Tensor, transformer_features: torch.Tensor) -> torch.Tensor:
        """
        Apply cross-modal attention fusion

        Args:
            gnn_features: GNN embeddings [batch_size, gnn_dim]
            transformer_features: Transformer embeddings [batch_size, transformer_dim]

        Returns:
            Fused representation [batch_size, fusion_dim]
        """
        batch_size = gnn_features.size(0)

        # Project to common dimension
        gnn_proj = self.gnn_projector(gnn_features)  # [batch_size, fusion_dim]
        transformer_proj = self.transformer_projector(transformer_features)  # [batch_size, fusion_dim]

        # Add sequence dimension for attention
        gnn_seq = gnn_proj.unsqueeze(1)  # [batch_size, 1, fusion_dim]
        transformer_seq = transformer_proj.unsqueeze(1)  # [batch_size, 1, fusion_dim]

        # Cross attention: GNN attends to Transformer
        gnn_attended, _ = self.attention(gnn_seq, transformer_seq, transformer_seq)
        gnn_attended = gnn_attended.squeeze(1)  # [batch_size, fusion_dim]

        # Cross attention: Transformer attends to GNN
        transformer_attended, _ = self.attention(transformer_seq, gnn_seq, gnn_seq)
        transformer_attended = transformer_attended.squeeze(1)  # [batch_size, fusion_dim]

        # Combine attended representations
        combined = torch.cat([gnn_attended, transformer_attended], dim=-1)

        # Final fusion
        fused = self.fusion_layers(combined)

        # Residual connection
        fused = fused + gnn_proj + transformer_proj

        return fused

class VulnHunterComplete(nn.Module):
    """
    Complete VulnHunter system with all components
    """

    def __init__(self):
        super(VulnHunterComplete, self).__init__()

        self.fusion_model = VulnHunterFusion()

        # Additional analysis components
        self.pattern_matcher = SecurityPatternMatcher()
        self.risk_calculator = RiskCalculator()

    def scan_code(self, code: str, include_details: bool = True) -> Dict[str, Any]:
        """
        Complete code security scan

        Args:
            code: Source code to analyze
            include_details: Whether to include detailed analysis

        Returns:
            Comprehensive scan results
        """
        # Main fusion analysis
        main_results = self.fusion_model.analyze_vulnerability(code)

        # Pattern matching
        pattern_results = self.pattern_matcher.analyze(code)

        # Risk calculation
        risk_assessment = self.risk_calculator.calculate(main_results, pattern_results)

        # Combine all results
        complete_results = {
            **main_results,
            'pattern_analysis': pattern_results,
            'risk_assessment': risk_assessment,
            'scan_metadata': {
                'model_version': '1.0.0-poc',
                'scan_timestamp': torch.tensor([0.0]),  # Placeholder
                'code_length': len(code),
                'lines_of_code': len(code.split('\n'))
            }
        }

        if not include_details:
            # Simplified output for CLI
            complete_results = {
                'is_vulnerable': complete_results['is_vulnerable'],
                'risk_level': complete_results['risk_level'],
                'vulnerability_probability': complete_results['vulnerability_probability'],
                'top_issues': complete_results['vulnerability_types'][:3]
            }

        return complete_results

class SecurityPatternMatcher:
    """Basic pattern matcher for known security issues"""

    def __init__(self):
        self.patterns = {
            'hardcoded_secrets': [r'password\s*=\s*["\'][^"\']+["\']', r'api_key\s*=\s*["\'][^"\']+["\']'],
            'weak_crypto': [r'md5\(', r'sha1\(', r'DES\('],
            'unsafe_eval': [r'eval\s*\(', r'exec\s*\('],
            'debug_code': [r'print\s*\(.*password', r'console\.log\(.*secret']
        }

    def analyze(self, code: str) -> Dict[str, List[str]]:
        """Find pattern matches in code"""
        import re
        matches = {}
        for pattern_type, patterns in self.patterns.items():
            matches[pattern_type] = []
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    matches[pattern_type].append(pattern)
        return matches

class RiskCalculator:
    """Calculate overall risk based on multiple factors"""

    def calculate(self, main_results: Dict, pattern_results: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        base_risk = main_results['vulnerability_probability']
        pattern_risk = len([v for v in pattern_results.values() if v]) * 0.1

        total_risk = min(base_risk + pattern_risk, 1.0)

        return {
            'total_risk_score': total_risk,
            'contributing_factors': {
                'ml_prediction': base_risk,
                'pattern_matches': pattern_risk
            },
            'risk_factors': list(pattern_results.keys())
        }

def test_vulnhunter_fusion():
    """Test the complete VulnHunter fusion model"""
    print("=== Testing VulnHunter Fusion Model ===")

    # Create complete model
    vulnhunter = VulnHunterComplete()

    # Test codes
    test_codes = [
        # SQL Injection
        '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
''',
        # Safe version
        '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
''',
        # Command injection
        '''
import os
def process_file(filename):
    command = "convert " + filename + " output.pdf"
    os.system(command)
'''
    ]

    for i, code in enumerate(test_codes):
        print(f"\n--- Analysis {i+1} ---")
        print(f"Code: {code[:100]}...")

        try:
            results = vulnhunter.scan_code(code, include_details=False)

            print(f"Vulnerable: {results['is_vulnerable']}")
            print(f"Risk Level: {results['risk_level']}")
            print(f"Probability: {results['vulnerability_probability']:.3f}")

            if results['top_issues']:
                print("Top Issues:")
                for issue in results['top_issues']:
                    print(f"  - {issue['type']}: {issue['score']:.3f}")

        except Exception as e:
            print(f"Error during analysis: {e}")

    print(f"\nTotal model parameters: {sum(p.numel() for p in vulnhunter.parameters()):,}")

if __name__ == "__main__":
    test_vulnhunter_fusion()