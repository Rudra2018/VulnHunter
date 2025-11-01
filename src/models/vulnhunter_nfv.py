"""
VulnHunter Neural-Formal Verification (NFV) Integration Model
Combines neural prediction with formal mathematical proofs for vulnerability detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple, Any
import logging
import z3
import numpy as np

from src.models.vulnhunter_fusion import VulnHunterFusion
from src.nfv.nfv_layer import NFVLayer
from src.parser.languages.solidity_parser import SolidityParser

logger = logging.getLogger(__name__)

class VulnHunterNFV(nn.Module):
    """
    Neural-Formal Verification model that combines:
    1. Neural vulnerability prediction (GNN + Transformer fusion)
    2. Formal mathematical proof via SMT solving
    3. Proof-guided training for enhanced accuracy
    """

    def __init__(
        self,
        d_model: int = 256,
        num_heads: int = 8,
        num_layers: int = 6,
        vocab_size: int = 50000,
        max_seq_len: int = 512,
        num_vuln_types: int = 10,
        k_paths: int = 3,
        proof_weight: float = 0.3,
        neural_weight: float = 0.5,
        path_weight: float = 0.2
    ):
        super(VulnHunterNFV, self).__init__()

        # Core neural fusion model
        self.fusion = VulnHunterFusion(
            d_model=d_model,
            num_heads=num_heads,
            num_layers=num_layers,
            vocab_size=vocab_size,
            max_seq_len=max_seq_len,
            num_vuln_types=num_vuln_types
        )

        # Neural-Formal Verification layer
        self.nfv = NFVLayer(
            d_model=d_model,
            k_paths=k_paths
        )

        # Loss weights
        self.proof_weight = proof_weight
        self.neural_weight = neural_weight
        self.path_weight = path_weight

        # Solidity parser for code analysis
        self.parser = SolidityParser()

        # Confidence calibration layer
        self.confidence_layer = nn.Sequential(
            nn.Linear(d_model + 1, 128),  # +1 for proof result
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

        logger.info(f"Initialized VulnHunterNFV with {sum(p.numel() for p in self.parameters())} parameters")

    def forward(
        self,
        graph_data,
        code_tokens: torch.Tensor,
        attention_mask: torch.Tensor,
        code_str: str,
        true_label: Optional[torch.Tensor] = None,
        vulnerability_types: Optional[torch.Tensor] = None
    ) -> Dict[str, Any]:
        """
        Forward pass combining neural prediction with formal verification

        Args:
            graph_data: PyTorch Geometric graph data
            code_tokens: Tokenized code sequence [batch_size, seq_len]
            attention_mask: Attention mask for tokens [batch_size, seq_len]
            code_str: Original code string for SMT analysis
            true_label: Ground truth labels for training
            vulnerability_types: Multi-label vulnerability types

        Returns:
            Dictionary containing neural predictions, formal proofs, and combined results
        """
        batch_size = code_tokens.size(0)

        # 1. Neural vulnerability prediction
        neural_output = self.fusion(
            graph_data=graph_data,
            code_tokens=code_tokens,
            attention_mask=attention_mask,
            vulnerability_types=vulnerability_types
        )

        neural_pred = neural_output['vulnerability_prob']
        vuln_type_logits = neural_output['vulnerability_types']
        graph_embedding = neural_output['graph_embedding']

        # 2. Formal verification via NFV layer
        try:
            nfv_output = self.nfv(
                graph_data=graph_data,
                code_str=code_str,
                true_label=true_label
            )

            proven_vuln = nfv_output['proven_vulnerable']
            proof_results = nfv_output['proof_results']
            witnesses = nfv_output['witnesses']
            constraints = nfv_output['constraints']
            proof_loss = nfv_output.get('proof_loss', None)

        except Exception as e:
            logger.warning(f"NFV layer failed: {e}. Falling back to neural-only prediction.")
            proven_vuln = False
            proof_results = []
            witnesses = []
            constraints = []
            proof_loss = torch.tensor(0.0, device=code_tokens.device)

        # 3. Confidence calibration
        proof_indicator = torch.tensor([1.0 if proven_vuln else 0.0],
                                     device=code_tokens.device, dtype=torch.float32)

        confidence_input = torch.cat([
            graph_embedding.mean(dim=0).unsqueeze(0),  # Global graph representation
            proof_indicator.unsqueeze(0)
        ], dim=-1)

        confidence_score = self.confidence_layer(confidence_input).squeeze()

        # 4. Final vulnerability decision
        # If formally proven vulnerable -> HIGH confidence
        # If formally proven safe -> LOW confidence (unless neural strongly disagrees)
        # If unproven -> rely on neural prediction with moderate confidence

        if proven_vuln:
            final_prediction = 1.0
            final_confidence = 0.95
            decision_reason = "PROVEN_VULNERABLE"
        elif any(proof_results):  # Some paths analyzed but not proven vulnerable
            # Combine neural and proof evidence
            neural_prob = torch.sigmoid(neural_pred).item()
            if neural_prob > 0.8:  # Neural strongly predicts vulnerable
                final_prediction = neural_prob
                final_confidence = 0.7
                decision_reason = "NEURAL_HIGH_UNPROVEN"
            else:  # Likely safe
                final_prediction = neural_prob * 0.5  # Reduce confidence
                final_confidence = 0.6
                decision_reason = "LIKELY_SAFE"
        else:  # No formal analysis possible
            final_prediction = torch.sigmoid(neural_pred).item()
            final_confidence = confidence_score.item()
            decision_reason = "NEURAL_ONLY"

        # 5. Compute combined loss (training only)
        total_loss = None
        if self.training and true_label is not None:
            # Neural prediction loss
            neural_loss = F.binary_cross_entropy_with_logits(
                neural_pred, true_label.float()
            )

            # Vulnerability type loss
            vuln_type_loss = torch.tensor(0.0, device=code_tokens.device)
            if vulnerability_types is not None:
                vuln_type_loss = F.binary_cross_entropy_with_logits(
                    vuln_type_logits, vulnerability_types.float()
                )

            # Proof loss (if available)
            if proof_loss is not None and torch.is_tensor(proof_loss):
                total_proof_loss = proof_loss
            else:
                total_proof_loss = torch.tensor(0.0, device=code_tokens.device)

            # Path alignment loss (encourage attention on proven vulnerable paths)
            path_loss = torch.tensor(0.0, device=code_tokens.device)

            # Combined loss
            total_loss = (
                self.neural_weight * neural_loss +
                self.neural_weight * vuln_type_loss +
                self.proof_weight * total_proof_loss +
                self.path_weight * path_loss
            )

        return {
            # Neural outputs
            'neural_prediction': torch.sigmoid(neural_pred).item(),
            'neural_logits': neural_pred,
            'vulnerability_types': torch.sigmoid(vuln_type_logits),
            'graph_embedding': graph_embedding,

            # Formal verification outputs
            'proven_vulnerable': proven_vuln,
            'proof_results': proof_results,
            'witnesses': witnesses,
            'constraints': constraints,

            # Combined decision
            'final_prediction': final_prediction,
            'confidence_score': final_confidence,
            'decision_reason': decision_reason,

            # Training
            'loss': total_loss,
            'neural_loss': neural_loss if total_loss is not None else None,
            'proof_loss': proof_loss,

            # Metadata
            'analysis_successful': len(constraints) > 0,
            'num_paths_analyzed': len(proof_results)
        }

    def predict_vulnerability(
        self,
        code_str: str,
        return_explanation: bool = True
    ) -> Dict[str, Any]:
        """
        High-level prediction interface for single code sample

        Args:
            code_str: Source code to analyze
            return_explanation: Whether to include detailed explanation

        Returns:
            Prediction results with confidence and explanation
        """
        self.eval()

        try:
            # Parse code
            parsed_data = self.parser.parse_code(code_str)

            # Convert to tensors
            graph_data = parsed_data['graph']
            code_tokens = torch.tensor(parsed_data['tokens']).unsqueeze(0)
            attention_mask = torch.ones_like(code_tokens)

            with torch.no_grad():
                output = self.forward(
                    graph_data=graph_data,
                    code_tokens=code_tokens,
                    attention_mask=attention_mask,
                    code_str=code_str
                )

            result = {
                'vulnerable': output['final_prediction'] > 0.5,
                'confidence': output['confidence_score'],
                'probability': output['final_prediction'],
                'decision_reason': output['decision_reason'],
                'proven_vulnerable': output['proven_vulnerable']
            }

            if return_explanation:
                result.update({
                    'neural_prediction': output['neural_prediction'],
                    'vulnerability_types': output['vulnerability_types'].tolist() if torch.is_tensor(output['vulnerability_types']) else [],
                    'proof_witnesses': output['witnesses'],
                    'analysis_successful': output['analysis_successful'],
                    'num_paths_analyzed': output['num_paths_analyzed']
                })

            return result

        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                'vulnerable': False,
                'confidence': 0.0,
                'probability': 0.0,
                'decision_reason': 'ANALYSIS_FAILED',
                'proven_vulnerable': False,
                'error': str(e)
            }

    def get_model_info(self) -> Dict[str, Any]:
        """Get model architecture and parameter information"""
        total_params = sum(p.numel() for p in self.parameters())
        trainable_params = sum(p.numel() for p in self.parameters() if p.requires_grad)

        return {
            'model_name': 'VulnHunterNFV',
            'version': '0.4.0',
            'total_parameters': total_params,
            'trainable_parameters': trainable_params,
            'architecture': 'Neural-Formal Verification',
            'components': {
                'fusion_model': 'GNN + Transformer',
                'formal_verification': 'Z3 SMT Solver',
                'proof_system': 'Differentiable Constraints'
            },
            'capabilities': [
                'Vulnerability Detection',
                'Formal Proof Generation',
                'Exploit Witness Generation',
                'Multi-type Classification',
                'Confidence Calibration'
            ]
        }