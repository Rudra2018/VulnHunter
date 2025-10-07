#!/usr/bin/env python3
"""
Enhanced False Positive Reduction Engine
Trained on HackerOne disclosure patterns
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
import re
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HackerOnePatternExtractor:
    """
    Extract patterns from HackerOne-style vulnerability reports
    """

    def __init__(self):
        # HackerOne-specific false positive indicators
        self.hackerone_fp_patterns = {
            'policy_exclusion': [
                r'out\s+of\s+scope',
                r'not\s+covered\s+by\s+(?:our\s+)?policy',
                r'excluded\s+per\s+program\s+rules',
                r'known\s+issue',
                r'won\'?t\s+fix'
            ],
            'insufficient_impact': [
                r'low\s+severity',
                r'minimal\s+impact',
                r'no\s+real\s+world\s+impact',
                r'theoretical\s+(?:vulnerability|issue)',
                r'requires\s+(?:physical\s+access|local\s+access)',
                r'self(?:-|\s+)(?:xss|stored\s+xss)',  # Self-XSS is typically not valid
            ],
            'incomplete_report': [
                r'need\s+more\s+information',
                r'cannot\s+reproduce',
                r'unclear\s+(?:report|description)',
                r'missing\s+(?:steps|poc|reproduction)',
                r'insufficient\s+details'
            ],
            'already_known': [
                r'duplicate\s+of\s+#?\d+',
                r'already\s+reported',
                r'known\s+and\s+tracked',
                r'existing\s+issue',
                r'previously\s+disclosed'
            ],
            'not_a_vulnerability': [
                r'not\s+a\s+(?:security\s+)?(?:vulnerability|issue|bug)',
                r'expected\s+behavior',
                r'by\s+design',
                r'intentional\s+functionality',
                r'false\s+alarm'
            ],
            'mitigated': [
                r'already\s+(?:protected|mitigated|fixed)',
                r'defense\s+in\s+depth',
                r'additional\s+(?:protection|validation)\s+(?:in\s+place|exists)',
                r'waf\s+(?:blocks|prevents)\s+this',
                r'rate\s+limiting\s+prevents'
            ]
        }

        # True positive indicators from HackerOne
        self.hackerone_tp_patterns = {
            'confirmed': [
                r'bounty\s+awarded',
                r'(?:thank\s+you|thanks)\s+for\s+(?:the\s+)?(?:report|submission)',
                r'confirmed\s+and\s+(?:fixed|patched)',
                r'resolved\s+and\s+deployed',
                r'valid\s+(?:security\s+)?(?:issue|vulnerability)',
                r'triaged\s+as\s+(?:critical|high|medium)'
            ],
            'impact_confirmed': [
                r'impact\s+(?:is\s+)?(?:confirmed|validated|verified)',
                r'successfully\s+(?:reproduced|exploited)',
                r'poc\s+(?:works|validated|confirmed)',
                r'demonstrates\s+(?:clear\s+)?(?:security\s+)?risk'
            ],
            'severity': [
                r'critical\s+(?:severity|impact|vulnerability)',
                r'high\s+severity',
                r'(?:cvss|severity)\s+score:?\s*(?:9|10|\d\.\d)',
                r'immediate\s+(?:fix|patch)\s+required'
            ],
            'bounty_paid': [
                r'\$\d+(?:,\d{3})*(?:\.\d{2})?\s+(?:bounty|reward)',
                r'bounty:\s*\$\d+',
                r'rewarded\s+with'
            ]
        }

        # Severity indicators
        self.severity_keywords = {
            'critical': ['rce', 'remote code execution', 'authentication bypass',
                        'full account takeover', 'database exposure'],
            'high': ['sql injection', 'xss', 'csrf', 'idor', 'privilege escalation',
                    'sensitive data exposure'],
            'medium': ['information disclosure', 'open redirect', 'rate limiting',
                      'missing security headers'],
            'low': ['verbose error', 'self-xss', 'clickjacking']
        }

    def extract_features(self, report_text: str, code: str = "") -> Dict:
        """
        Extract features from HackerOne report

        Args:
            report_text: Report title + description + comments
            code: Associated code snippet

        Returns:
            Feature dictionary
        """
        text_lower = report_text.lower()

        # Count FP indicators
        fp_scores = {}
        for category, patterns in self.hackerone_fp_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text_lower))
            fp_scores[category] = score

        total_fp_score = sum(fp_scores.values())

        # Count TP indicators
        tp_scores = {}
        for category, patterns in self.hackerone_tp_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text_lower))
            tp_scores[category] = score

        total_tp_score = sum(tp_scores.values())

        # Detect severity
        detected_severity = 'medium'
        for severity, keywords in self.severity_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                detected_severity = severity
                break

        # Check for bounty amount
        bounty_match = re.search(r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)', report_text)
        bounty_amount = float(bounty_match.group(1).replace(',', '')) if bounty_match else 0.0

        # Code-level features
        code_features = self._analyze_code(code) if code else {}

        return {
            'fp_total': total_fp_score,
            'tp_total': total_tp_score,
            'fp_categories': fp_scores,
            'tp_categories': tp_scores,
            'severity': detected_severity,
            'bounty_amount': bounty_amount,
            'has_bounty': bounty_amount > 0,
            'code_features': code_features,
            'text_length': len(report_text),
            'confidence_score': self._calculate_confidence(total_tp_score, total_fp_score)
        }

    def _analyze_code(self, code: str) -> Dict:
        """Analyze code snippet for vulnerability patterns"""
        return {
            'has_input_validation': bool(re.search(r'validate|sanitize|escape|filter', code, re.I)),
            'has_parameterized_query': bool(re.search(r'\?|prepare|bind_param|\$\d+', code)),
            'has_unsafe_function': bool(re.search(r'eval|exec|system|strcpy|gets', code, re.I)),
            'has_concatenation': bool(re.search(r'["\'][^"\']*["\'][\s]*\+|\+[\s]*["\']', code)),
            'code_length': len(code)
        }

    def _calculate_confidence(self, tp_score: int, fp_score: int) -> float:
        """Calculate confidence in classification"""
        if tp_score == 0 and fp_score == 0:
            return 0.5

        total = tp_score + fp_score
        return tp_score / total


class EnhancedFPReductionModel(nn.Module):
    """
    Neural network for false positive reduction
    Trained on HackerOne patterns
    """

    def __init__(
        self,
        input_dim: int = 768,
        hidden_dim: int = 256,
        num_classes: int = 2,
        dropout: float = 0.3
    ):
        super().__init__()

        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.BatchNorm1d(hidden_dim // 4),
            nn.ReLU(),
        )

        self.classifier = nn.Linear(hidden_dim // 4, num_classes)

        # Attention mechanism for interpretability
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim // 4, hidden_dim // 8),
            nn.Tanh(),
            nn.Linear(hidden_dim // 8, 1)
        )

    def forward(self, x):
        features = self.feature_extractor(x)

        # Apply attention
        attention_weights = F.softmax(self.attention(features), dim=0)
        attended_features = features * attention_weights

        logits = self.classifier(attended_features)
        return logits, attention_weights


class HackerOneFPEngine:
    """
    Complete False Positive Reduction Engine
    Combines pattern matching, feature extraction, and neural classification
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: str = "cpu"
    ):
        self.device = device
        self.pattern_extractor = HackerOnePatternExtractor()

        # Load CodeBERT for code embedding
        logger.info("Loading CodeBERT...")
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        self.code_model = AutoModel.from_pretrained("microsoft/codebert-base").to(device)

        # Load FP reduction model
        self.fp_model = EnhancedFPReductionModel().to(device)

        if model_path and Path(model_path).exists():
            logger.info(f"Loading trained model from {model_path}")
            self.fp_model.load_state_dict(torch.load(model_path, map_location=device))

        self.fp_model.eval()

    def embed_code(self, code: str) -> torch.Tensor:
        """Generate code embedding using CodeBERT"""
        inputs = self.tokenizer(
            code,
            return_tensors="pt",
            max_length=512,
            truncation=True,
            padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.code_model(**inputs)
            # Use [CLS] token embedding
            embedding = outputs.last_hidden_state[:, 0, :]

        return embedding

    def predict(
        self,
        code: str,
        report_text: str = "",
        model_prediction: int = 1,
        model_confidence: float = 0.5
    ) -> Dict:
        """
        Predict if detection is a false positive

        Args:
            code: Source code snippet
            report_text: HackerOne report text (if available)
            model_prediction: Original model prediction (0=safe, 1=vulnerable)
            model_confidence: Original model confidence

        Returns:
            {
                'is_false_positive': bool,
                'confidence': float,
                'final_prediction': int,
                'reasoning': str,
                'features': Dict
            }
        """
        # Extract HackerOne-style features
        features = self.pattern_extractor.extract_features(report_text, code)

        # Quick rule-based filtering
        if features['fp_total'] > 3 and features['tp_total'] == 0:
            return {
                'is_false_positive': True,
                'confidence': 0.9,
                'final_prediction': 0,
                'reasoning': 'Strong FP indicators in report',
                'features': features
            }

        if features['tp_total'] > 3 and features['bounty_amount'] > 500:
            return {
                'is_false_positive': False,
                'confidence': 0.95,
                'final_prediction': 1,
                'reasoning': 'Confirmed with bounty payment',
                'features': features
            }

        # Neural network prediction
        code_embedding = self.embed_code(code)

        with torch.no_grad():
            logits, attention = self.fp_model(code_embedding)
            probs = F.softmax(logits, dim=-1)
            nn_prediction = torch.argmax(probs, dim=-1).item()
            nn_confidence = probs[0][nn_prediction].item()

        # Ensemble: combine rule-based + neural network
        ensemble_confidence = (
            features['confidence_score'] * 0.3 +
            nn_confidence * 0.4 +
            model_confidence * 0.3
        )

        is_fp = (nn_prediction == 0 and model_prediction == 1)

        # Adjust based on severity
        if features['severity'] == 'critical' and features['tp_total'] > 0:
            is_fp = False
            ensemble_confidence = max(ensemble_confidence, 0.7)

        return {
            'is_false_positive': is_fp,
            'confidence': ensemble_confidence,
            'final_prediction': 0 if is_fp else model_prediction,
            'reasoning': self._generate_reasoning(features, is_fp),
            'features': features,
            'nn_confidence': nn_confidence,
            'attention_weights': attention.cpu().numpy() if attention.dim() > 0 else None
        }

    def _generate_reasoning(self, features: Dict, is_fp: bool) -> str:
        """Generate human-readable reasoning"""
        if is_fp:
            reasons = []
            for category, score in features['fp_categories'].items():
                if score > 0:
                    reasons.append(f"{category} ({score} indicators)")

            return f"Classified as FP due to: {', '.join(reasons) if reasons else 'low confidence'}"
        else:
            reasons = []
            for category, score in features['tp_categories'].items():
                if score > 0:
                    reasons.append(f"{category} ({score} indicators)")

            severity = features['severity']
            return f"Valid vulnerability ({severity} severity). Evidence: {', '.join(reasons) if reasons else 'code patterns'}"

    def batch_filter(self, samples: List[Dict]) -> List[Dict]:
        """Filter a batch of vulnerability detections"""
        results = []

        logger.info(f"Filtering {len(samples)} detections...")

        for i, sample in enumerate(samples):
            result = self.predict(
                code=sample.get('code', ''),
                report_text=sample.get('report_text', ''),
                model_prediction=sample.get('prediction', 1),
                model_confidence=sample.get('confidence', 0.5)
            )

            results.append({
                **sample,
                'fp_analysis': result
            })

            if (i + 1) % 100 == 0:
                logger.info(f"Processed {i + 1}/{len(samples)}")

        fp_count = sum(1 for r in results if r['fp_analysis']['is_false_positive'])
        logger.info(f"Filtered out {fp_count} false positives ({fp_count/len(results):.1%})")

        return results


if __name__ == "__main__":
    logger.info("Enhanced False Positive Engine - Testing\n")

    engine = HackerOneFPEngine()

    # Test Case 1: False Positive - Out of scope
    logger.info("="*60)
    logger.info("Test 1: Out of scope vulnerability")
    logger.info("="*60)

    code1 = """
    def upload_file(request):
        file = request.files['upload']
        file.save('/tmp/' + file.filename)
    """

    report1 = """
    Path traversal vulnerability in file upload.
    Status: Out of scope per program policy.
    Reason: /tmp directory is isolated container filesystem.
    """

    result1 = engine.predict(code1, report1, model_prediction=1, model_confidence=0.75)
    logger.info(f"FP: {result1['is_false_positive']}")
    logger.info(f"Confidence: {result1['confidence']:.2f}")
    logger.info(f"Reasoning: {result1['reasoning']}\n")

    # Test Case 2: True Positive - Confirmed with bounty
    logger.info("="*60)
    logger.info("Test 2: Confirmed SQL injection with bounty")
    logger.info("="*60)

    code2 = """
    def get_user(username):
        query = "SELECT * FROM users WHERE name = '" + username + "'"
        return db.execute(query)
    """

    report2 = """
    SQL Injection in user lookup endpoint.
    Status: Resolved
    Severity: High
    Bounty awarded: $2,500
    Successfully exploited in staging environment.
    CVE-2024-12345 assigned.
    """

    result2 = engine.predict(code2, report2, model_prediction=1, model_confidence=0.92)
    logger.info(f"FP: {result2['is_false_positive']}")
    logger.info(f"Confidence: {result2['confidence']:.2f}")
    logger.info(f"Reasoning: {result2['reasoning']}\n")

    # Test Case 3: False Positive - Duplicate
    logger.info("="*60)
    logger.info("Test 3: Duplicate report")
    logger.info("="*60)

    code3 = """
    app.get('/redirect', (req, res) => {
        res.redirect(req.query.url);
    });
    """

    report3 = """
    Open redirect vulnerability.
    Status: Duplicate of #12345
    Already reported and fixed in v2.3.1
    """

    result3 = engine.predict(code3, report3, model_prediction=1, model_confidence=0.65)
    logger.info(f"FP: {result3['is_false_positive']}")
    logger.info(f"Confidence: {result3['confidence']:.2f}")
    logger.info(f"Reasoning: {result3['reasoning']}\n")

    logger.info("✅ All tests complete!")
