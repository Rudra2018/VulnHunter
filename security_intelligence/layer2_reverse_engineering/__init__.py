"""
Layer 2: AI-Assisted Reverse Engineering
=====================================

Advanced reverse engineering capabilities powered by machine learning:
- Automated vulnerability pattern recognition in assembly
- Function similarity analysis across binaries
- Taint analysis for input propagation tracking
- Constraint solving for path exploration
- ML-based vulnerability prediction in binaries
"""

from .ai_assistant import AIReverseEngineeringAssistant
from .target_prioritizer import TargetPrioritizer
from .exploitability_analyzer import ExploitabilityAnalyzer

__all__ = [
    'AIReverseEngineeringAssistant',
    'TargetPrioritizer',
    'ExploitabilityAnalyzer'
]