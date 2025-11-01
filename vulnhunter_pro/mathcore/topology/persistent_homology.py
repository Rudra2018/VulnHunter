#!/usr/bin/env python3
"""
Persistent Homology for Vulnerability Detection
===============================================

Uses topological data analysis to detect vulnerability patterns in control flow graphs.
Based on the Vietoris-Rips filtration and persistent homology computation.
"""

import numpy as np
import networkx as nx
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass


@dataclass
class PersistentFeatures:
    """Persistent homology features for vulnerability analysis"""
    h0_features: List[Tuple[float, float]]  # Connected components
    h1_features: List[Tuple[float, float]]  # Loops/cycles
    bottleneck_distance: float = 0.0
    betti_numbers: List[int] = None
    vulnerability_signature: str = ""


def cfg_to_distance_matrix(cfg: nx.DiGraph) -> np.ndarray:
    """
    Convert control flow graph to distance matrix for persistent homology analysis

    Args:
        cfg: NetworkX directed graph representing control flow

    Returns:
        Distance matrix for topological analysis
    """
    nodes = list(cfg.nodes)
    n = len(nodes)

    if n == 0:
        return np.array([[]])

    # Initialize distance matrix
    D = np.full((n, n), np.inf)

    # Node mapping
    node_to_idx = {node: i for i, node in enumerate(nodes)}

    # Set diagonal to 0
    np.fill_diagonal(D, 0)

    # Direct edges have distance 1
    for u, v in cfg.edges():
        i, j = node_to_idx[u], node_to_idx[v]
        D[i, j] = 1

    # Use Floyd-Warshall for shortest paths
    for k in range(n):
        for i in range(n):
            for j in range(n):
                if D[i, k] + D[k, j] < D[i, j]:
                    D[i, j] = D[i, k] + D[k, j]

    # Replace infinite distances with large finite value
    D[D == np.inf] = n + 1

    return D


def compute_persistent_homology(distance_matrix: np.ndarray, max_dim: int = 1) -> PersistentFeatures:
    """
    Compute persistent homology from distance matrix

    Args:
        distance_matrix: Pairwise distance matrix
        max_dim: Maximum homology dimension to compute

    Returns:
        Persistent features for analysis
    """
    try:
        # Try to use ripser if available
        from ripser import ripser
        from persim import plot_diagrams

        # Compute persistence diagrams
        diagrams = ripser(distance_matrix, maxdim=max_dim, distance_matrix=True)['dgms']

        # Extract features
        h0_features = [(birth, death) for birth, death in diagrams[0] if death < np.inf]
        h1_features = [(birth, death) for birth, death in diagrams[1]] if len(diagrams) > 1 else []

        # Calculate Betti numbers
        betti_numbers = [len(h0_features), len(h1_features)]

        return PersistentFeatures(
            h0_features=h0_features,
            h1_features=h1_features,
            betti_numbers=betti_numbers,
            vulnerability_signature=_compute_vulnerability_signature(h0_features, h1_features)
        )

    except ImportError:
        # Fallback implementation without ripser
        return _compute_persistent_homology_fallback(distance_matrix, max_dim)


def _compute_persistent_homology_fallback(distance_matrix: np.ndarray, max_dim: int) -> PersistentFeatures:
    """Fallback implementation of persistent homology computation"""
    n = distance_matrix.shape[0]

    # Simple connected components analysis (H0)
    # Create adjacency matrix from distance matrix
    threshold = 1.5  # Connection threshold
    adj_matrix = distance_matrix <= threshold

    # Find connected components
    graph = nx.from_numpy_array(adj_matrix)
    components = list(nx.connected_components(graph))

    # H0 features (births at 0, deaths when components merge)
    h0_features = [(0.0, 1.0) for _ in range(len(components))]

    # Simple cycle detection for H1
    cycles = list(nx.simple_cycles(nx.from_numpy_array(distance_matrix <= 1)))
    h1_features = [(1.0, 2.0) for _ in cycles[:5]]  # Limit to avoid explosion

    return PersistentFeatures(
        h0_features=h0_features,
        h1_features=h1_features,
        betti_numbers=[len(h0_features), len(h1_features)],
        vulnerability_signature=_compute_vulnerability_signature(h0_features, h1_features)
    )


def _compute_vulnerability_signature(h0_features: List[Tuple[float, float]],
                                   h1_features: List[Tuple[float, float]]) -> str:
    """Compute vulnerability signature from persistent features"""
    h0_count = len(h0_features)
    h1_count = len(h1_features)

    # Calculate persistence of features
    h0_persistence = sum(death - birth for birth, death in h0_features)
    h1_persistence = sum(death - birth for birth, death in h1_features)

    # Generate signature
    if h1_count > 3 and h1_persistence > 2.0:
        return "complex_loops_high_risk"
    elif h1_count > 1 and h1_persistence > 1.0:
        return "moderate_complexity"
    elif h0_count > 5:
        return "disconnected_components"
    else:
        return "simple_structure"


def detect_loops(cfg: nx.DiGraph, max_dim: int = 1) -> Dict[str, Any]:
    """
    Enhanced loop detection and topological vulnerability analysis

    Args:
        cfg: Control flow graph
        max_dim: Maximum homology dimension

    Returns:
        Dictionary with comprehensive topological analysis
    """
    if len(cfg.nodes) == 0:
        return {"safe": True, "reason": "empty_graph"}

    # Convert to distance matrix
    D = cfg_to_distance_matrix(cfg)

    # Compute persistent homology
    features = compute_persistent_homology(D, max_dim)

    # Enhanced Ricci curvature analysis
    ricci_analysis = ricci_curvature_analysis(cfg)

    # Analyze for vulnerabilities
    analysis = {
        "persistent_features": features,
        "h0_components": len(features.h0_features),
        "h1_loops": len(features.h1_features),
        "vulnerability_signature": features.vulnerability_signature,
        "topological_complexity": _calculate_topological_complexity(features),
        "security_risk": _assess_security_risk(features),
        "recommendations": _generate_recommendations(features),
        "ricci_analysis": ricci_analysis,
        "mathematical_proof": _generate_topological_proof(features, ricci_analysis),
        "vuln_patterns": _detect_vulnerability_patterns(features, ricci_analysis)
    }

    return analysis

def _generate_topological_proof(features: PersistentFeatures, ricci_analysis: Dict[str, Any]) -> str:
    """Generate mathematical proof of topological vulnerability"""
    h1_count = len(features.h1_features)
    hotspot_count = ricci_analysis.get('hotspot_count', 0)

    if h1_count > 5 and hotspot_count > 2:
        return f"∃ complex_cycle_structure: |H₁| = {h1_count} ∧ ricci_hotspots = {hotspot_count} → vulnerability_risk = HIGH"
    elif h1_count > 2:
        return f"∃ moderate_cycle_structure: |H₁| = {h1_count} → vulnerability_risk = MEDIUM"
    else:
        return f"∀ cycles: |H₁| = {h1_count} < 3 → vulnerability_risk = LOW"

def _detect_vulnerability_patterns(features: PersistentFeatures, ricci_analysis: Dict[str, Any]) -> List[str]:
    """Detect specific vulnerability patterns using topology"""
    patterns = []

    h1_count = len(features.h1_features)
    h0_count = len(features.h0_features)
    hotspots = ricci_analysis.get('vulnerability_hotspots', [])

    # Reentrancy pattern
    if h1_count > 3:
        patterns.append("REENTRANCY_RISK: Complex loop structure detected")

    # Race condition pattern
    if h0_count > 1 and h1_count > 1:
        patterns.append("RACE_CONDITION_RISK: Disconnected components with shared loops")

    # Buffer overflow pattern
    if len(hotspots) > 2:
        patterns.append("BUFFER_OVERFLOW_RISK: Multiple negative curvature hotspots")

    # Infinite loop pattern
    for birth, death in features.h1_features:
        if death - birth > 10.0:  # Very persistent loop
            patterns.append("INFINITE_LOOP_RISK: Highly persistent cycle detected")
            break

    return patterns


def _calculate_topological_complexity(features: PersistentFeatures) -> float:
    """Calculate topological complexity score"""
    h0_weight = 0.3
    h1_weight = 0.7

    h0_score = min(1.0, len(features.h0_features) / 10.0)
    h1_score = min(1.0, len(features.h1_features) / 5.0)

    return h0_weight * h0_score + h1_weight * h1_score


def _assess_security_risk(features: PersistentFeatures) -> str:
    """Assess security risk based on topological features"""
    h1_count = len(features.h1_features)
    complexity = _calculate_topological_complexity(features)

    if h1_count >= 5 or complexity > 0.8:
        return "high"
    elif h1_count >= 3 or complexity > 0.6:
        return "medium"
    elif h1_count >= 1 or complexity > 0.3:
        return "low"
    else:
        return "minimal"


def _generate_recommendations(features: PersistentFeatures) -> List[str]:
    """Generate security recommendations based on topological analysis"""
    recommendations = []

    if len(features.h1_features) > 5:
        recommendations.append("High number of loops detected - review for reentrancy vulnerabilities")

    if len(features.h0_features) > 10:
        recommendations.append("Many disconnected components - check for unreachable sanitization code")

    if features.vulnerability_signature == "complex_loops_high_risk":
        recommendations.append("Complex loop structure detected - implement proper bounds checking")

    if not recommendations:
        recommendations.append("Topological structure appears secure")

    return recommendations


def ricci_curvature_analysis(cfg: nx.DiGraph) -> Dict[str, Any]:
    """
    Analyze Ricci curvature of control flow graph for vulnerability hotspots

    Args:
        cfg: Control flow graph

    Returns:
        Ricci curvature analysis results
    """
    try:
        # Try to use NetworkX Ricci curvature if available
        import networkx as nx

        if len(cfg.nodes) < 2:
            return {"ricci_analysis": "insufficient_nodes"}

        # Simplified Ricci curvature computation
        ricci_values = {}

        for u, v in cfg.edges():
            # Simplified Ricci curvature approximation
            degree_u = cfg.degree(u)
            degree_v = cfg.degree(v)

            # Negative curvature indicates potential vulnerability hotspot
            ricci = 1 - (degree_u + degree_v) / 4.0
            ricci_values[(u, v)] = ricci

        # Find negative curvature edges (potential hotspots)
        hotspots = [(edge, curvature) for edge, curvature in ricci_values.items() if curvature < -0.5]

        return {
            "ricci_curvatures": ricci_values,
            "vulnerability_hotspots": hotspots,
            "avg_curvature": np.mean(list(ricci_values.values())) if ricci_values else 0.0,
            "hotspot_count": len(hotspots)
        }

    except Exception as e:
        return {"ricci_analysis": f"error: {str(e)}"}


def bottleneck_distance(features1: PersistentFeatures, features2: PersistentFeatures) -> float:
    """
    Compute bottleneck distance between two persistence diagrams
    Used for comparing vulnerable vs patched CFGs
    """
    try:
        # Simplified bottleneck distance computation
        # In practice, would use gudhi or persim library

        h1_1 = features1.h1_features
        h1_2 = features2.h1_features

        if not h1_1 and not h1_2:
            return 0.0

        if not h1_1 or not h1_2:
            return 1.0  # Maximum distance

        # Simple approximation of bottleneck distance
        max_persistence_1 = max((death - birth) for birth, death in h1_1)
        max_persistence_2 = max((death - birth) for birth, death in h1_2)

        return abs(max_persistence_1 - max_persistence_2)

    except Exception:
        return 1.0  # Return maximum distance on error