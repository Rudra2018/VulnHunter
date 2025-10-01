"""
Security Intelligence Framework
===============================

Comprehensive 5-layer security intelligence framework for advanced
vulnerability research, analysis, and automated security testing.

Layers:
1. Binary Analysis & Reconnaissance Engine
2. AI-Assisted Reverse Engineering
3. Intelligent Fuzzing Orchestration
4. Advanced Static Analysis (SAST+)
5. Dynamic Application Testing (DAST++)

Plus Intelligence Orchestration Engine for coordinated analysis.
"""

from .orchestration_engine import (
    IntelligenceOrchestrationEngine,
    AnalysisType,
    Priority,
    AnalysisTask,
    AnalysisResult
)

# Layer 1 imports
from .layer1_binary_analysis import (
    BinaryAnalyzer,
    ReconnaissanceEngine
)

# Layer 2 imports
from .layer2_reverse_engineering import (
    AIDisassembler,
    CodeAnalyzer
)

# Layer 3 imports
from .layer3_fuzzing_orchestration import (
    IntelligentFuzzer,
    CoverageAnalyzer
)

# Layer 4 imports
from .layer4_advanced_static_analysis import (
    ASTAnalyzer,
    PatternDetector
)

# Layer 5 imports
from .layer5_dynamic_testing import (
    IntelligentWebCrawler,
    AdvancedVulnerabilityScanner,
    APISecurityTester,
    AuthenticationHandler
)

__version__ = "1.0.0"
__author__ = "Security Intelligence Framework Team"

__all__ = [
    # Core orchestration
    'IntelligenceOrchestrationEngine',
    'AnalysisType',
    'Priority',
    'AnalysisTask',
    'AnalysisResult',

    # Layer 1: Binary Analysis & Reconnaissance
    'BinaryAnalyzer',
    'ReconnaissanceEngine',

    # Layer 2: AI-Assisted Reverse Engineering
    'AIDisassembler',
    'CodeAnalyzer',

    # Layer 3: Intelligent Fuzzing Orchestration
    'IntelligentFuzzer',
    'CoverageAnalyzer',

    # Layer 4: Advanced Static Analysis (SAST+)
    'ASTAnalyzer',
    'PatternDetector',

    # Layer 5: Dynamic Application Testing (DAST++)
    'IntelligentWebCrawler',
    'AdvancedVulnerabilityScanner',
    'APISecurityTester',
    'AuthenticationHandler'
]