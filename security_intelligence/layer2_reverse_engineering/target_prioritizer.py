"""
Target Prioritization Engine

This module implements intelligent target prioritization for reverse engineering
and vulnerability research, using ML-based risk assessment and attack surface analysis.
"""

import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import json
import hashlib
from collections import defaultdict
import math

class TargetType(Enum):
    """Types of analysis targets"""
    BINARY_EXECUTABLE = "binary_executable"
    SHARED_LIBRARY = "shared_library"
    KERNEL_MODULE = "kernel_module"
    FIRMWARE = "firmware"
    WEB_APPLICATION = "web_application"
    MOBILE_APP = "mobile_app"
    EMBEDDED_SYSTEM = "embedded_system"

class RiskLevel(Enum):
    """Risk assessment levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AnalysisTarget:
    """Represents a target for analysis"""
    target_id: str
    name: str
    path: str
    target_type: TargetType
    size: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_factors: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    complexity_score: float = 0.0
    priority_score: float = 0.0
    estimated_analysis_time: int = 0
    dependencies: List[str] = field(default_factory=list)

@dataclass
class PrioritizationResult:
    """Result of target prioritization"""
    target: AnalysisTarget
    priority_rank: int
    justification: str
    recommended_analysis_depth: str
    estimated_effort: str
    key_focus_areas: List[str]

class AttackSurfaceAnalyzer:
    """Analyzes attack surface characteristics of targets"""

    def __init__(self):
        self.surface_metrics = {
            'network_exposure': self._assess_network_exposure,
            'input_vectors': self._assess_input_vectors,
            'privilege_level': self._assess_privilege_level,
            'data_sensitivity': self._assess_data_sensitivity,
            'update_frequency': self._assess_update_frequency,
            'deployment_scope': self._assess_deployment_scope
        }

    def analyze_attack_surface(self, target: AnalysisTarget) -> Dict[str, float]:
        """Comprehensive attack surface analysis"""
        surface_scores = {}

        for metric_name, analyzer in self.surface_metrics.items():
            try:
                score = analyzer(target)
                surface_scores[metric_name] = score
            except Exception as e:
                logging.warning(f"Failed to analyze {metric_name} for {target.name}: {e}")
                surface_scores[metric_name] = 0.5

        overall_score = self._calculate_overall_surface_score(surface_scores)
        target.attack_surface_score = overall_score

        return surface_scores

    def _assess_network_exposure(self, target: AnalysisTarget) -> float:
        """Assess network exposure level"""
        exposure_indicators = {
            'web_server': 0.9,
            'database': 0.8,
            'api_service': 0.9,
            'ssh_daemon': 0.7,
            'ftp_server': 0.8,
            'mail_server': 0.7,
            'dns_server': 0.6,
            'client_application': 0.3,
            'standalone': 0.1
        }

        target_name = target.name.lower()
        path_lower = target.path.lower()

        for indicator, score in exposure_indicators.items():
            if indicator in target_name or indicator in path_lower:
                return score

        if target.target_type in [TargetType.WEB_APPLICATION, TargetType.FIRMWARE]:
            return 0.8
        elif target.target_type == TargetType.KERNEL_MODULE:
            return 0.9
        elif target.target_type == TargetType.MOBILE_APP:
            return 0.6

        return 0.5

    def _assess_input_vectors(self, target: AnalysisTarget) -> float:
        """Assess number and complexity of input vectors"""
        input_complexity = 0.0

        file_extensions = target.metadata.get('file_extensions', [])
        if any(ext in ['.cgi', '.php', '.asp', '.jsp'] for ext in file_extensions):
            input_complexity += 0.3

        imported_functions = target.metadata.get('imported_functions', [])
        risky_functions = ['gets', 'strcpy', 'sprintf', 'scanf', 'system', 'exec']
        if any(func in imported_functions for func in risky_functions):
            input_complexity += 0.4

        network_functions = ['socket', 'accept', 'recv', 'send', 'connect']
        if any(func in imported_functions for func in network_functions):
            input_complexity += 0.3

        if target.target_type == TargetType.WEB_APPLICATION:
            input_complexity += 0.4

        return min(input_complexity, 1.0)

    def _assess_privilege_level(self, target: AnalysisTarget) -> float:
        """Assess privilege level required/granted"""
        privilege_indicators = {
            'root': 1.0,
            'admin': 0.9,
            'system': 0.9,
            'kernel': 1.0,
            'service': 0.7,
            'user': 0.3
        }

        target_path = target.path.lower()
        for indicator, score in privilege_indicators.items():
            if indicator in target_path:
                return score

        if target.target_type == TargetType.KERNEL_MODULE:
            return 1.0
        elif target.target_type == TargetType.FIRMWARE:
            return 0.9
        elif '/bin/' in target.path or '/sbin/' in target.path:
            return 0.8

        return 0.5

    def _assess_data_sensitivity(self, target: AnalysisTarget) -> float:
        """Assess sensitivity of data handled"""
        sensitive_indicators = [
            'password', 'credential', 'auth', 'crypto', 'key',
            'certificate', 'token', 'session', 'payment', 'financial',
            'medical', 'personal', 'private', 'confidential'
        ]

        target_name = target.name.lower()
        sensitivity_score = 0.0

        for indicator in sensitive_indicators:
            if indicator in target_name:
                sensitivity_score += 0.2

        strings = target.metadata.get('strings', [])
        for string in strings:
            string_lower = string.lower()
            for indicator in sensitive_indicators:
                if indicator in string_lower:
                    sensitivity_score += 0.1
                    break

        return min(sensitivity_score, 1.0)

    def _assess_update_frequency(self, target: AnalysisTarget) -> float:
        """Assess how frequently the target is updated"""
        last_modified = target.metadata.get('last_modified', 0)
        creation_time = target.metadata.get('creation_time', 0)

        if last_modified and creation_time:
            age_days = (last_modified - creation_time) / (24 * 3600)
            if age_days > 365:
                return 0.8
            elif age_days > 180:
                return 0.6
            elif age_days > 30:
                return 0.4
            else:
                return 0.2

        return 0.5

    def _assess_deployment_scope(self, target: AnalysisTarget) -> float:
        """Assess deployment scope and reach"""
        scope_indicators = {
            'system32': 0.9,
            'program files': 0.7,
            'usr/bin': 0.8,
            'usr/sbin': 0.9,
            'lib': 0.6,
            'temp': 0.2,
            'local': 0.3
        }

        target_path = target.path.lower()
        for indicator, score in scope_indicators.items():
            if indicator in target_path:
                return score

        if target.target_type in [TargetType.KERNEL_MODULE, TargetType.FIRMWARE]:
            return 0.9
        elif target.target_type == TargetType.SHARED_LIBRARY:
            return 0.7

        return 0.5

    def _calculate_overall_surface_score(self, surface_scores: Dict[str, float]) -> float:
        """Calculate weighted overall attack surface score"""
        weights = {
            'network_exposure': 0.25,
            'input_vectors': 0.20,
            'privilege_level': 0.20,
            'data_sensitivity': 0.15,
            'update_frequency': 0.10,
            'deployment_scope': 0.10
        }

        weighted_score = sum(
            surface_scores.get(metric, 0.5) * weight
            for metric, weight in weights.items()
        )

        return min(weighted_score, 1.0)

class ComplexityAnalyzer:
    """Analyzes complexity characteristics of targets"""

    def __init__(self):
        self.complexity_factors = {
            'code_size': self._analyze_code_size,
            'cyclomatic_complexity': self._analyze_cyclomatic_complexity,
            'dependency_complexity': self._analyze_dependency_complexity,
            'encryption_usage': self._analyze_encryption_usage,
            'obfuscation_level': self._analyze_obfuscation_level,
            'architecture_complexity': self._analyze_architecture_complexity
        }

    def analyze_complexity(self, target: AnalysisTarget) -> Dict[str, float]:
        """Comprehensive complexity analysis"""
        complexity_scores = {}

        for factor_name, analyzer in self.complexity_factors.items():
            try:
                score = analyzer(target)
                complexity_scores[factor_name] = score
            except Exception as e:
                logging.warning(f"Failed to analyze {factor_name} for {target.name}: {e}")
                complexity_scores[factor_name] = 0.5

        overall_complexity = self._calculate_overall_complexity(complexity_scores)
        target.complexity_score = overall_complexity

        return complexity_scores

    def _analyze_code_size(self, target: AnalysisTarget) -> float:
        """Analyze complexity based on code size"""
        size_bytes = target.size

        if size_bytes < 10 * 1024:
            return 0.1
        elif size_bytes < 100 * 1024:
            return 0.3
        elif size_bytes < 1024 * 1024:
            return 0.5
        elif size_bytes < 10 * 1024 * 1024:
            return 0.7
        else:
            return 0.9

    def _analyze_cyclomatic_complexity(self, target: AnalysisTarget) -> float:
        """Analyze cyclomatic complexity"""
        num_functions = target.metadata.get('num_functions', 0)
        avg_complexity = target.metadata.get('avg_cyclomatic_complexity', 0)

        if num_functions == 0:
            return 0.2

        complexity_factor = min(avg_complexity / 20.0, 1.0)
        function_factor = min(num_functions / 1000.0, 1.0)

        return (complexity_factor + function_factor) / 2

    def _analyze_dependency_complexity(self, target: AnalysisTarget) -> float:
        """Analyze dependency complexity"""
        dependencies = len(target.dependencies)
        imported_functions = len(target.metadata.get('imported_functions', []))

        dep_score = min(dependencies / 50.0, 1.0)
        import_score = min(imported_functions / 200.0, 1.0)

        return (dep_score + import_score) / 2

    def _analyze_encryption_usage(self, target: AnalysisTarget) -> float:
        """Analyze encryption and cryptographic complexity"""
        crypto_indicators = [
            'aes', 'rsa', 'des', 'sha', 'md5', 'crypto', 'cipher',
            'encrypt', 'decrypt', 'hash', 'signature', 'certificate',
            'ssl', 'tls', 'openssl'
        ]

        imported_functions = target.metadata.get('imported_functions', [])
        strings = target.metadata.get('strings', [])

        crypto_score = 0.0

        for func in imported_functions:
            func_lower = func.lower()
            for indicator in crypto_indicators:
                if indicator in func_lower:
                    crypto_score += 0.1
                    break

        for string in strings:
            string_lower = string.lower()
            for indicator in crypto_indicators:
                if indicator in string_lower:
                    crypto_score += 0.05
                    break

        return min(crypto_score, 1.0)

    def _analyze_obfuscation_level(self, target: AnalysisTarget) -> float:
        """Analyze obfuscation and anti-analysis measures"""
        obfuscation_indicators = [
            'upx', 'packed', 'compressed', 'encrypted',
            'obfuscated', 'anti_debug', 'vm_detect',
            'breakpoint_detect', 'debugger_detect'
        ]

        obfuscation_score = 0.0

        for indicator in obfuscation_indicators:
            if indicator in target.metadata.get('packer_info', '').lower():
                obfuscation_score += 0.2

        entropy = target.metadata.get('entropy', 0)
        if entropy > 7.5:
            obfuscation_score += 0.3
        elif entropy > 7.0:
            obfuscation_score += 0.2

        return min(obfuscation_score, 1.0)

    def _analyze_architecture_complexity(self, target: AnalysisTarget) -> float:
        """Analyze architectural complexity"""
        architecture = target.metadata.get('architecture', 'unknown').lower()

        arch_complexity = {
            'x86': 0.5,
            'x86_64': 0.6,
            'arm': 0.7,
            'arm64': 0.7,
            'mips': 0.8,
            'sparc': 0.8,
            'powerpc': 0.7,
            'unknown': 0.5
        }

        base_complexity = arch_complexity.get(architecture, 0.5)

        if target.target_type == TargetType.FIRMWARE:
            base_complexity += 0.2
        elif target.target_type == TargetType.KERNEL_MODULE:
            base_complexity += 0.3

        return min(base_complexity, 1.0)

    def _calculate_overall_complexity(self, complexity_scores: Dict[str, float]) -> float:
        """Calculate weighted overall complexity score"""
        weights = {
            'code_size': 0.15,
            'cyclomatic_complexity': 0.25,
            'dependency_complexity': 0.15,
            'encryption_usage': 0.20,
            'obfuscation_level': 0.15,
            'architecture_complexity': 0.10
        }

        weighted_score = sum(
            complexity_scores.get(factor, 0.5) * weight
            for factor, weight in weights.items()
        )

        return min(weighted_score, 1.0)

class MLPrioritizationModel(nn.Module):
    """Neural network model for target prioritization"""

    def __init__(self, input_dim: int = 64, hidden_dim: int = 128):
        super().__init__()
        self.feature_encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, 64),
            nn.ReLU()
        )

        self.priority_head = nn.Linear(64, 1)
        self.risk_head = nn.Linear(64, 5)
        self.effort_head = nn.Linear(64, 1)

    def forward(self, x):
        features = self.feature_encoder(x)

        priority_score = torch.sigmoid(self.priority_head(features))
        risk_scores = torch.softmax(self.risk_head(features), dim=-1)
        effort_estimate = torch.sigmoid(self.effort_head(features))

        return {
            'priority_score': priority_score,
            'risk_distribution': risk_scores,
            'effort_estimate': effort_estimate
        }

class TargetPrioritizer:
    """Main target prioritization engine"""

    def __init__(self, model_path: Optional[str] = None):
        self.attack_surface_analyzer = AttackSurfaceAnalyzer()
        self.complexity_analyzer = ComplexityAnalyzer()
        self.ml_model = MLPrioritizationModel()
        self.prioritization_history = []

        if model_path and Path(model_path).exists():
            self.load_model(model_path)

    def load_model(self, model_path: str):
        """Load pre-trained prioritization model"""
        try:
            checkpoint = torch.load(model_path, map_location='cpu')
            self.ml_model.load_state_dict(checkpoint['model_state_dict'])
            self.ml_model.eval()
            logging.info(f"Loaded prioritization model from {model_path}")
        except Exception as e:
            logging.error(f"Failed to load model: {e}")

    def prioritize_targets(self, targets: List[AnalysisTarget]) -> List[PrioritizationResult]:
        """Prioritize a list of analysis targets"""
        prioritization_results = []

        for target in targets:
            try:
                result = self._prioritize_single_target(target)
                prioritization_results.append(result)
            except Exception as e:
                logging.error(f"Failed to prioritize target {target.name}: {e}")
                continue

        prioritization_results.sort(key=lambda x: x.target.priority_score, reverse=True)

        for i, result in enumerate(prioritization_results):
            result.priority_rank = i + 1

        self.prioritization_history.extend(prioritization_results)

        return prioritization_results

    def _prioritize_single_target(self, target: AnalysisTarget) -> PrioritizationResult:
        """Prioritize a single target"""
        surface_scores = self.attack_surface_analyzer.analyze_attack_surface(target)
        complexity_scores = self.complexity_analyzer.analyze_complexity(target)

        features = self._extract_prioritization_features(target, surface_scores, complexity_scores)

        with torch.no_grad():
            features_tensor = torch.FloatTensor(features).unsqueeze(0)
            predictions = self.ml_model(features_tensor)

            priority_score = predictions['priority_score'].item()
            risk_distribution = predictions['risk_distribution'].squeeze()
            effort_estimate = predictions['effort_estimate'].item()

        target.priority_score = priority_score

        risk_level = self._determine_risk_level(risk_distribution)
        analysis_depth = self._recommend_analysis_depth(priority_score, target.complexity_score)
        effort_category = self._categorize_effort(effort_estimate)
        focus_areas = self._identify_focus_areas(surface_scores, complexity_scores)
        justification = self._generate_justification(target, surface_scores, complexity_scores)

        return PrioritizationResult(
            target=target,
            priority_rank=0,
            justification=justification,
            recommended_analysis_depth=analysis_depth,
            estimated_effort=effort_category,
            key_focus_areas=focus_areas
        )

    def _extract_prioritization_features(self, target: AnalysisTarget,
                                       surface_scores: Dict[str, float],
                                       complexity_scores: Dict[str, float]) -> np.ndarray:
        """Extract features for ML prioritization"""
        features = []

        features.extend(surface_scores.values())
        features.extend(complexity_scores.values())

        features.append(target.size / (1024 * 1024))
        features.append(len(target.dependencies) / 100.0)
        features.append(len(target.risk_factors) / 10.0)

        type_encoding = [0.0] * len(TargetType)
        type_encoding[list(TargetType).index(target.target_type)] = 1.0
        features.extend(type_encoding)

        metadata_features = [
            target.metadata.get('num_functions', 0) / 1000.0,
            target.metadata.get('num_strings', 0) / 1000.0,
            target.metadata.get('entropy', 0) / 8.0,
            len(target.metadata.get('imported_functions', [])) / 200.0,
            target.metadata.get('avg_cyclomatic_complexity', 0) / 50.0
        ]
        features.extend(metadata_features)

        while len(features) < 64:
            features.append(0.0)

        return np.array(features[:64])

    def _determine_risk_level(self, risk_distribution: torch.Tensor) -> RiskLevel:
        """Determine risk level from risk distribution"""
        risk_levels = list(RiskLevel)
        max_idx = torch.argmax(risk_distribution).item()
        return risk_levels[max_idx]

    def _recommend_analysis_depth(self, priority_score: float, complexity_score: float) -> str:
        """Recommend analysis depth based on priority and complexity"""
        if priority_score > 0.8 and complexity_score > 0.7:
            return "comprehensive"
        elif priority_score > 0.6:
            return "thorough"
        elif priority_score > 0.4:
            return "standard"
        else:
            return "basic"

    def _categorize_effort(self, effort_estimate: float) -> str:
        """Categorize effort estimate"""
        if effort_estimate > 0.8:
            return "high_effort"
        elif effort_estimate > 0.6:
            return "medium_effort"
        elif effort_estimate > 0.3:
            return "low_effort"
        else:
            return "minimal_effort"

    def _identify_focus_areas(self, surface_scores: Dict[str, float],
                            complexity_scores: Dict[str, float]) -> List[str]:
        """Identify key focus areas for analysis"""
        focus_areas = []

        if surface_scores.get('network_exposure', 0) > 0.7:
            focus_areas.append("network_security")

        if surface_scores.get('input_vectors', 0) > 0.6:
            focus_areas.append("input_validation")

        if surface_scores.get('privilege_level', 0) > 0.8:
            focus_areas.append("privilege_escalation")

        if complexity_scores.get('encryption_usage', 0) > 0.6:
            focus_areas.append("cryptographic_implementation")

        if complexity_scores.get('obfuscation_level', 0) > 0.5:
            focus_areas.append("anti_analysis_techniques")

        if not focus_areas:
            focus_areas.append("general_vulnerability_assessment")

        return focus_areas

    def _generate_justification(self, target: AnalysisTarget,
                              surface_scores: Dict[str, float],
                              complexity_scores: Dict[str, float]) -> str:
        """Generate human-readable justification for prioritization"""
        justifications = []

        if target.attack_surface_score > 0.7:
            justifications.append(f"High attack surface exposure ({target.attack_surface_score:.2f})")

        if target.complexity_score > 0.7:
            justifications.append(f"High complexity ({target.complexity_score:.2f})")

        if surface_scores.get('privilege_level', 0) > 0.8:
            justifications.append("Runs with elevated privileges")

        if surface_scores.get('network_exposure', 0) > 0.7:
            justifications.append("Network-facing service")

        if len(target.risk_factors) > 3:
            justifications.append(f"Multiple risk factors identified ({len(target.risk_factors)})")

        if not justifications:
            justifications.append("Standard analysis target")

        return "; ".join(justifications)

    def generate_prioritization_report(self, results: List[PrioritizationResult]) -> str:
        """Generate comprehensive prioritization report"""
        report = []
        report.append("Target Prioritization Analysis Report")
        report.append("=" * 50)
        report.append(f"Total targets analyzed: {len(results)}")
        report.append("")

        for result in results[:10]:
            target = result.target
            report.append(f"Rank #{result.priority_rank}: {target.name}")
            report.append("-" * 30)
            report.append(f"Path: {target.path}")
            report.append(f"Type: {target.target_type.value}")
            report.append(f"Priority Score: {target.priority_score:.3f}")
            report.append(f"Attack Surface: {target.attack_surface_score:.3f}")
            report.append(f"Complexity: {target.complexity_score:.3f}")
            report.append(f"Recommended Analysis: {result.recommended_analysis_depth}")
            report.append(f"Estimated Effort: {result.estimated_effort}")
            report.append(f"Focus Areas: {', '.join(result.key_focus_areas)}")
            report.append(f"Justification: {result.justification}")
            report.append("")

        return "\n".join(report)