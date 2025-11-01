#!/usr/bin/env python3
"""
🎯 VulnHunter Ψ Anomaly Detector - Phase 5 Q1 Component
========================================================
Advanced anomaly detection for zero-day discovery

Implementation from 1.txt requirements:
- Isolation Forest on embedding drift
- Flag semantic changes not in training data
- Detect novel vulnerability patterns
- Integration with differential analysis

Key Techniques:
- Embedding-based anomaly detection
- Multi-dimensional feature extraction
- ML-based outlier detection
- Semantic drift analysis
"""

import numpy as np
import json
import time
import pickle
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

# Machine Learning libraries
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN

# Integration with differential analysis
from differential_analysis import DiffAnalysisResult, CodeChange

@dataclass
class EmbeddingFeatures:
    """Features extracted for embedding analysis"""
    code_complexity: float
    ast_node_density: float
    security_keyword_density: float
    change_pattern_diversity: float
    function_call_anomaly: float
    data_flow_complexity: float
    control_flow_anomaly: float
    semantic_similarity: float

@dataclass
class AnomalyDetection:
    """Single anomaly detection result"""
    repository_name: str
    file_path: str
    anomaly_score: float
    isolation_score: float
    outlier_probability: float
    novelty_indicators: List[str]
    embedding_features: EmbeddingFeatures
    semantic_drift_score: float
    risk_classification: str  # 'low', 'medium', 'high', 'critical'

@dataclass
class AnomalyReport:
    """Complete anomaly analysis report"""
    analysis_timestamp: str
    total_samples_analyzed: int
    anomalies_detected: int
    high_risk_anomalies: List[AnomalyDetection]
    embedding_drift_detected: bool
    model_performance: Dict[str, float]
    novel_patterns_discovered: List[str]

class SemanticEmbeddingExtractor:
    """Extracts semantic embeddings from code changes"""

    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            stop_words='english'
        )
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=50)

        # Security-relevant keywords for feature extraction
        self.security_keywords = [
            'auth', 'password', 'token', 'secret', 'key', 'crypto', 'encrypt',
            'decrypt', 'hash', 'sign', 'verify', 'admin', 'root', 'privilege',
            'access', 'permission', 'bypass', 'exploit', 'vulnerability',
            'injection', 'xss', 'csrf', 'sql', 'command', 'execute', 'eval',
            'deserialize', 'pickle', 'marshal', 'unsafe', 'buffer', 'overflow'
        ]

    def extract_features(self, code_change: CodeChange) -> EmbeddingFeatures:
        """Extract comprehensive features from code change"""

        # Calculate code complexity metrics
        complexity = self._calculate_complexity(code_change)
        ast_density = self._calculate_ast_density(code_change)
        security_density = self._calculate_security_keyword_density(code_change)
        pattern_diversity = self._calculate_pattern_diversity(code_change)
        function_anomaly = self._calculate_function_call_anomaly(code_change)
        data_flow = self._calculate_data_flow_complexity(code_change)
        control_flow = self._calculate_control_flow_anomaly(code_change)
        semantic_sim = self._calculate_semantic_similarity(code_change)

        return EmbeddingFeatures(
            code_complexity=complexity,
            ast_node_density=ast_density,
            security_keyword_density=security_density,
            change_pattern_diversity=pattern_diversity,
            function_call_anomaly=function_anomaly,
            data_flow_complexity=data_flow,
            control_flow_anomaly=control_flow,
            semantic_similarity=semantic_sim
        )

    def _calculate_complexity(self, code_change: CodeChange) -> float:
        """Calculate code complexity based on AST changes"""
        ast_changes = code_change.ast_changes

        complexity_score = 0.0

        # Count different types of AST nodes
        nodes_added = len(ast_changes.get('nodes_added', []))
        nodes_modified = len(ast_changes.get('nodes_modified', []))
        nodes_removed = len(ast_changes.get('nodes_removed', []))

        # Weighted complexity
        complexity_score += nodes_added * 0.5
        complexity_score += nodes_modified * 0.3
        complexity_score += nodes_removed * 0.2

        # Normalize by change size
        total_lines = code_change.lines_added + code_change.lines_removed
        if total_lines > 0:
            complexity_score = complexity_score / total_lines

        return min(complexity_score, 1.0)

    def _calculate_ast_density(self, code_change: CodeChange) -> float:
        """Calculate AST node density"""
        ast_changes = code_change.ast_changes

        total_nodes = (len(ast_changes.get('nodes_added', [])) +
                      len(ast_changes.get('nodes_modified', [])) +
                      len(ast_changes.get('nodes_removed', [])))

        total_lines = code_change.lines_added + code_change.lines_removed
        if total_lines == 0:
            return 0.0

        return min(total_nodes / total_lines, 1.0)

    def _calculate_security_keyword_density(self, code_change: CodeChange) -> float:
        """Calculate density of security-relevant keywords"""

        # Count security keywords in change patterns
        security_count = 0
        for pattern in code_change.change_patterns:
            for keyword in self.security_keywords:
                if keyword in pattern.lower():
                    security_count += 1

        # Also check AST security patterns
        ast_changes = code_change.ast_changes
        security_patterns = ast_changes.get('security_patterns_added', [])
        security_count += len(security_patterns)

        # Normalize
        total_patterns = len(code_change.change_patterns) + 1
        return min(security_count / total_patterns, 1.0)

    def _calculate_pattern_diversity(self, code_change: CodeChange) -> float:
        """Calculate diversity of change patterns"""
        patterns = code_change.change_patterns

        if not patterns:
            return 0.0

        # Unique patterns ratio
        unique_patterns = len(set(patterns))
        total_patterns = len(patterns)

        return unique_patterns / total_patterns

    def _calculate_function_call_anomaly(self, code_change: CodeChange) -> float:
        """Calculate function call anomaly score"""
        ast_changes = code_change.ast_changes

        # Look for unusual function calls in AST changes
        anomaly_score = 0.0

        nodes_added = ast_changes.get('nodes_added', [])
        for node in nodes_added:
            if 'Call:' in node:
                # Extract function name
                func_name = node.split(':')[1] if ':' in node else ''

                # Check for suspicious function names
                suspicious_funcs = ['eval', 'exec', 'system', 'loads', 'compile']
                if any(func in func_name.lower() for func in suspicious_funcs):
                    anomaly_score += 0.3

        return min(anomaly_score, 1.0)

    def _calculate_data_flow_complexity(self, code_change: CodeChange) -> float:
        """Calculate data flow complexity"""

        # Simplified heuristic based on change patterns
        data_flow_indicators = [
            'assignment', 'return', 'parameter', 'variable',
            'input', 'output', 'data', 'stream'
        ]

        complexity = 0.0
        for pattern in code_change.change_patterns:
            for indicator in data_flow_indicators:
                if indicator in pattern.lower():
                    complexity += 0.1

        return min(complexity, 1.0)

    def _calculate_control_flow_anomaly(self, code_change: CodeChange) -> float:
        """Calculate control flow anomaly"""

        # Look for unusual control flow patterns
        control_patterns = [
            'if', 'else', 'while', 'for', 'try', 'except',
            'break', 'continue', 'return', 'goto'
        ]

        anomaly_score = 0.0
        ast_changes = code_change.ast_changes

        # Check for unusual control structures in AST
        nodes_added = ast_changes.get('nodes_added', [])
        for node in nodes_added:
            for pattern in control_patterns:
                if pattern in node.lower():
                    anomaly_score += 0.1

        return min(anomaly_score, 1.0)

    def _calculate_semantic_similarity(self, code_change: CodeChange) -> float:
        """Calculate semantic similarity to known patterns"""

        # Compare change patterns to known vulnerability patterns
        known_vuln_patterns = [
            'sql_injection', 'xss', 'csrf', 'path_traversal',
            'command_injection', 'buffer_overflow', 'use_after_free',
            'integer_overflow', 'null_pointer_dereference'
        ]

        similarity_score = 0.0
        for pattern in code_change.change_patterns:
            for known_pattern in known_vuln_patterns:
                # Simple similarity check (could use more sophisticated methods)
                if any(word in pattern.lower() for word in known_pattern.split('_')):
                    similarity_score += 0.2

        return min(similarity_score, 1.0)

class IsolationForestDetector:
    """Isolation Forest-based anomaly detector"""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.is_fitted = False
        self.feature_scaler = StandardScaler()

    def fit(self, features_list: List[EmbeddingFeatures]):
        """Train the isolation forest on normal code patterns"""

        if not features_list:
            raise ValueError("No features provided for training")

        # Convert features to numpy array
        feature_matrix = self._features_to_matrix(features_list)

        # Scale features
        scaled_features = self.feature_scaler.fit_transform(feature_matrix)

        # Fit isolation forest
        self.isolation_forest.fit(scaled_features)
        self.is_fitted = True

        print(f"✅ Isolation Forest trained on {len(features_list)} samples")

    def detect_anomalies(self, features_list: List[EmbeddingFeatures]) -> List[float]:
        """Detect anomalies in new features"""

        if not self.is_fitted:
            raise ValueError("Model must be fitted before detecting anomalies")

        if not features_list:
            return []

        # Convert features to numpy array
        feature_matrix = self._features_to_matrix(features_list)

        # Scale features
        scaled_features = self.feature_scaler.transform(feature_matrix)

        # Get anomaly scores
        anomaly_scores = self.isolation_forest.decision_function(scaled_features)

        # Convert to probability-like scores (0-1 range)
        # More negative = more anomalous
        normalized_scores = [(1 - score) / 2 for score in anomaly_scores]

        return normalized_scores

    def _features_to_matrix(self, features_list: List[EmbeddingFeatures]) -> np.ndarray:
        """Convert features to numpy matrix"""

        matrix = []
        for features in features_list:
            row = [
                features.code_complexity,
                features.ast_node_density,
                features.security_keyword_density,
                features.change_pattern_diversity,
                features.function_call_anomaly,
                features.data_flow_complexity,
                features.control_flow_anomaly,
                features.semantic_similarity
            ]
            matrix.append(row)

        return np.array(matrix)

class AnomalyDetectionEngine:
    """
    Main anomaly detection engine for VulnHunter Ψ
    Implements 1.txt specification: Isolation Forest on embedding drift
    """

    def __init__(self):
        self.embedding_extractor = SemanticEmbeddingExtractor()
        self.isolation_detector = IsolationForestDetector()
        self.baseline_features: List[EmbeddingFeatures] = []
        self.anomaly_threshold = 0.7

        print("🎯 VulnHunter Ψ Anomaly Detector Initialized")
        print("   - Isolation Forest for outlier detection")
        print("   - Semantic embedding analysis")
        print("   - Drift detection capabilities")

    async def train_baseline_model(self, training_data: List[DiffAnalysisResult]):
        """Train baseline model on known good/normal code changes"""

        print(f"🔬 Training baseline model on {len(training_data)} repositories")

        all_features = []

        for diff_result in training_data:
            # Extract features from all code changes
            for change in diff_result.high_risk_changes:
                if change.security_relevance_score < 0.3:  # Normal changes only
                    features = self.embedding_extractor.extract_features(change)
                    all_features.append(features)

        if not all_features:
            print("⚠️ No normal features found for training. Using synthetic baseline.")
            all_features = self._generate_synthetic_baseline()

        # Train isolation forest
        self.isolation_detector.fit(all_features)
        self.baseline_features = all_features

        print(f"✅ Baseline model trained on {len(all_features)} feature samples")

    def _generate_synthetic_baseline(self) -> List[EmbeddingFeatures]:
        """Generate synthetic baseline features for training"""

        synthetic_features = []

        # Generate normal-looking features
        for _ in range(100):
            features = EmbeddingFeatures(
                code_complexity=np.random.normal(0.3, 0.1),
                ast_node_density=np.random.normal(0.4, 0.1),
                security_keyword_density=np.random.normal(0.1, 0.05),
                change_pattern_diversity=np.random.normal(0.5, 0.1),
                function_call_anomaly=np.random.normal(0.2, 0.1),
                data_flow_complexity=np.random.normal(0.3, 0.1),
                control_flow_anomaly=np.random.normal(0.2, 0.1),
                semantic_similarity=np.random.normal(0.4, 0.1)
            )

            # Ensure values are in valid range [0, 1]
            features = EmbeddingFeatures(
                code_complexity=max(0, min(1, features.code_complexity)),
                ast_node_density=max(0, min(1, features.ast_node_density)),
                security_keyword_density=max(0, min(1, features.security_keyword_density)),
                change_pattern_diversity=max(0, min(1, features.change_pattern_diversity)),
                function_call_anomaly=max(0, min(1, features.function_call_anomaly)),
                data_flow_complexity=max(0, min(1, features.data_flow_complexity)),
                control_flow_anomaly=max(0, min(1, features.control_flow_anomaly)),
                semantic_similarity=max(0, min(1, features.semantic_similarity))
            )

            synthetic_features.append(features)

        return synthetic_features

    async def detect_anomalies(self, diff_results: List[DiffAnalysisResult]) -> AnomalyReport:
        """Detect anomalies in differential analysis results"""

        print(f"🔍 Running anomaly detection on {len(diff_results)} repositories")

        all_detections = []
        novel_patterns = set()

        for diff_result in diff_results:
            # Extract features for all high-risk changes
            for change in diff_result.high_risk_changes:
                features = self.embedding_extractor.extract_features(change)

                # Run anomaly detection
                anomaly_scores = self.isolation_detector.detect_anomalies([features])
                isolation_score = anomaly_scores[0] if anomaly_scores else 0.0

                # Calculate semantic drift
                drift_score = self._calculate_semantic_drift(features)

                # Determine risk classification
                risk_class = self._classify_risk(isolation_score, drift_score, change)

                # Identify novelty indicators
                novelty_indicators = self._identify_novelty_indicators(change, features)

                detection = AnomalyDetection(
                    repository_name=diff_result.repo_name,
                    file_path=change.file_path,
                    anomaly_score=change.security_relevance_score,
                    isolation_score=isolation_score,
                    outlier_probability=isolation_score,
                    novelty_indicators=novelty_indicators,
                    embedding_features=features,
                    semantic_drift_score=drift_score,
                    risk_classification=risk_class
                )

                all_detections.append(detection)

                # Collect novel patterns
                novel_patterns.update(change.change_patterns)

        # Filter high-risk anomalies
        high_risk_anomalies = [
            d for d in all_detections
            if d.isolation_score > self.anomaly_threshold or
               d.risk_classification in ['high', 'critical']
        ]

        # Check for embedding drift
        embedding_drift = self._detect_embedding_drift(all_detections)

        # Calculate model performance metrics
        performance = self._calculate_model_performance(all_detections)

        report = AnomalyReport(
            analysis_timestamp=datetime.now().isoformat(),
            total_samples_analyzed=len(all_detections),
            anomalies_detected=len([d for d in all_detections if d.isolation_score > self.anomaly_threshold]),
            high_risk_anomalies=high_risk_anomalies,
            embedding_drift_detected=embedding_drift,
            model_performance=performance,
            novel_patterns_discovered=list(novel_patterns)
        )

        print(f"✅ Anomaly detection complete:")
        print(f"   Total samples: {report.total_samples_analyzed}")
        print(f"   Anomalies detected: {report.anomalies_detected}")
        print(f"   High-risk anomalies: {len(report.high_risk_anomalies)}")
        print(f"   Embedding drift: {report.embedding_drift_detected}")

        return report

    def _calculate_semantic_drift(self, features: EmbeddingFeatures) -> float:
        """Calculate semantic drift from baseline"""

        if not self.baseline_features:
            return 0.0

        # Compare features to baseline mean
        baseline_means = self._calculate_baseline_means()

        drift_score = 0.0
        feature_values = [
            features.code_complexity, features.ast_node_density,
            features.security_keyword_density, features.change_pattern_diversity,
            features.function_call_anomaly, features.data_flow_complexity,
            features.control_flow_anomaly, features.semantic_similarity
        ]

        for i, value in enumerate(feature_values):
            baseline_mean = baseline_means[i]
            drift = abs(value - baseline_mean)
            drift_score += drift

        return min(drift_score / len(feature_values), 1.0)

    def _calculate_baseline_means(self) -> List[float]:
        """Calculate mean values from baseline features"""

        if not self.baseline_features:
            return [0.5] * 8  # Default neutral values

        means = []
        for i in range(8):  # Number of features
            values = []
            for features in self.baseline_features:
                feature_values = [
                    features.code_complexity, features.ast_node_density,
                    features.security_keyword_density, features.change_pattern_diversity,
                    features.function_call_anomaly, features.data_flow_complexity,
                    features.control_flow_anomaly, features.semantic_similarity
                ]
                values.append(feature_values[i])

            means.append(np.mean(values))

        return means

    def _classify_risk(self, isolation_score: float, drift_score: float,
                      change: CodeChange) -> str:
        """Classify risk level based on scores"""

        # High isolation score or drift = higher risk
        combined_score = (isolation_score + drift_score + change.security_relevance_score) / 3

        if combined_score > 0.8:
            return 'critical'
        elif combined_score > 0.6:
            return 'high'
        elif combined_score > 0.4:
            return 'medium'
        else:
            return 'low'

    def _identify_novelty_indicators(self, change: CodeChange,
                                   features: EmbeddingFeatures) -> List[str]:
        """Identify what makes this change novel"""

        indicators = []

        # High semantic drift
        if features.semantic_similarity < 0.3:
            indicators.append('low_similarity_to_known_patterns')

        # Unusual function calls
        if features.function_call_anomaly > 0.7:
            indicators.append('unusual_function_calls')

        # High security keyword density
        if features.security_keyword_density > 0.6:
            indicators.append('high_security_keyword_density')

        # Complex change patterns
        if features.change_pattern_diversity > 0.8:
            indicators.append('complex_change_patterns')

        # Novel AST patterns
        ast_changes = change.ast_changes
        if ast_changes.get('security_patterns_added'):
            indicators.append('novel_security_ast_patterns')

        return indicators

    def _detect_embedding_drift(self, detections: List[AnomalyDetection]) -> bool:
        """Detect if there's systematic embedding drift"""

        if len(detections) < 10:
            return False

        # Check if many samples have high drift scores
        high_drift_count = len([d for d in detections if d.semantic_drift_score > 0.6])
        drift_ratio = high_drift_count / len(detections)

        return drift_ratio > 0.3  # 30% threshold

    def _calculate_model_performance(self, detections: List[AnomalyDetection]) -> Dict[str, float]:
        """Calculate model performance metrics"""

        if not detections:
            return {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0}

        # Basic performance metrics
        total_samples = len(detections)
        anomalies = len([d for d in detections if d.isolation_score > self.anomaly_threshold])

        return {
            'total_samples': total_samples,
            'anomaly_rate': anomalies / total_samples if total_samples > 0 else 0.0,
            'avg_isolation_score': np.mean([d.isolation_score for d in detections]),
            'avg_drift_score': np.mean([d.semantic_drift_score for d in detections])
        }

    def save_model(self, model_path: str):
        """Save trained model for reuse"""

        model_data = {
            'isolation_forest': self.isolation_detector,
            'baseline_features': self.baseline_features,
            'embedding_extractor': self.embedding_extractor,
            'anomaly_threshold': self.anomaly_threshold
        }

        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"💾 Anomaly detection model saved: {model_path}")

    def load_model(self, model_path: str):
        """Load pre-trained model"""

        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        self.isolation_detector = model_data['isolation_forest']
        self.baseline_features = model_data['baseline_features']
        self.embedding_extractor = model_data['embedding_extractor']
        self.anomaly_threshold = model_data['anomaly_threshold']

        print(f"📂 Anomaly detection model loaded: {model_path}")

async def test_anomaly_detector():
    """Test the anomaly detection engine"""
    print("🧪 Testing VulnHunter Ψ Anomaly Detector")
    print("=" * 50)

    detector = AnomalyDetectionEngine()

    # Generate test data
    test_features = detector._generate_synthetic_baseline()

    # Train baseline
    detector.isolation_detector.fit(test_features[:50])
    detector.baseline_features = test_features[:50]

    # Test anomaly detection
    test_results = detector.isolation_detector.detect_anomalies(test_features[50:60])

    print(f"📊 Test Results:")
    print(f"   Training samples: 50")
    print(f"   Test samples: 10")
    print(f"   Anomaly scores: {[f'{score:.3f}' for score in test_results[:5]]}")

    print("✅ Anomaly detector test completed")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_anomaly_detector())