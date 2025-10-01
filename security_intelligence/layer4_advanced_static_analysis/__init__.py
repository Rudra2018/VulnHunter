"""
Layer 4: Advanced Static Analysis (SAST+)
=========================================

Next-generation static analysis capabilities with AI enhancement:
- Multi-language AST and CFG analysis
- Deep semantic vulnerability detection
- Context-aware taint analysis
- AI-powered code understanding and pattern recognition
- Integration with commercial SAST tools for comparison
- Advanced dataflow and control flow analysis
"""

from .static_analyzer import StaticAnalyzer
from .semantic_analyzer import SemanticAnalyzer
from .taint_analyzer import AdvancedTaintAnalyzer
from .pattern_detector import VulnerabilityPatternDetector

__all__ = [
    'StaticAnalyzer',
    'SemanticAnalyzer',
    'AdvancedTaintAnalyzer',
    'VulnerabilityPatternDetector'
]