"""
Layer 3: Intelligent Fuzzing Orchestration
==========================================

Advanced fuzzing capabilities with AI-driven optimization:
- Coverage-guided fuzzing with AFL++ integration
- Machine learning for input generation and mutation
- Multi-target fuzzing orchestration
- Intelligent seed corpus management
- Crash analysis and vulnerability classification
- Performance optimization and resource management
"""

from .fuzzing_orchestrator import FuzzingOrchestrator
from .coverage_analyzer import CoverageAnalyzer
from .crash_analyzer import CrashAnalyzer
from .seed_manager import SeedManager

__all__ = [
    'FuzzingOrchestrator',
    'CoverageAnalyzer',
    'CrashAnalyzer',
    'SeedManager'
]