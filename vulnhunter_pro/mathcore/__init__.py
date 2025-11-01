#!/usr/bin/env python3
"""
MathCore - Mathematical Foundation for VulnHunter Professional
==============================================================

The Mathematical Layer that powers all vulnerability detection components with:
- Topological Analysis (Persistent Homology, Ricci Curvature)
- Algebraic Methods (Taint Semiring, Z3 SMT)
- Geometric Processing (CFG Embeddings, Manifold Learning)
- Formal Logic (Hoare Logic, Separation Logic)
- Category Theory (Unified Artifact Abstraction)
- Symbolic Execution (Angr, Z3, SymPy)
"""

__version__ = "1.0.0"
__author__ = "VulnHunter MathCore Team"

from .topology.persistent_homology import detect_loops, cfg_to_distance_matrix
from .algebra.taint_semiring import TaintLattice, analyze_data_flow
from .logic.formal_verification import Z3Verifier, HoareTriple
from .symbolic.constraint_solver import SymbolicAnalyzer
from .geometry.manifold_analysis import RiemannianAnalyzer

__all__ = [
    'detect_loops',
    'cfg_to_distance_matrix',
    'TaintLattice',
    'analyze_data_flow',
    'Z3Verifier',
    'HoareTriple',
    'SymbolicAnalyzer',
    'RiemannianAnalyzer'
]