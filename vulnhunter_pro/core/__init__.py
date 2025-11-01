#!/usr/bin/env python3
"""
VulnHunter Professional Core Engine
====================================
Production-ready vulnerability analysis platform with comprehensive coverage.
"""

__version__ = "5.0.0"
__author__ = "VulnHunter Research Team"
__email__ = "security@vulnhunter.ai"

from .engine import VulnHunterEngine
from .plugin_manager import PluginManager
from .vulnerability import Vulnerability, VulnSeverity, VulnType
from .analysis_result import AnalysisResult
from .config import Config

__all__ = [
    'VulnHunterEngine',
    'PluginManager',
    'Vulnerability',
    'VulnSeverity',
    'VulnType',
    'AnalysisResult',
    'Config'
]