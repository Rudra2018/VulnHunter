"""
VulnHunter Core Engine
=====================

Central engine for coordinating vulnerability detection across all domains.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import json
from datetime import datetime

from ..models.manager import ModelManager
from ..analyzers.source_code import SourceCodeAnalyzer
from ..analyzers.http_requests import HTTPRequestAnalyzer
from ..analyzers.mobile_apps import MobileAppAnalyzer
from ..analyzers.executables import ExecutableAnalyzer
from ..analyzers.smart_contracts import SmartContractAnalyzer
from .config import VulnHunterConfig

logger = logging.getLogger(__name__)

class VulnHunterEngine:
    """
    Central engine for VulnHunter vulnerability detection.

    Coordinates analysis across all domains and provides unified results.
    """

    def __init__(self, config: Optional[VulnHunterConfig] = None):
        """Initialize VulnHunter engine with configuration."""
        self.config = config or VulnHunterConfig()
        self.model_manager = ModelManager(self.config)

        # Initialize analyzers
        self.analyzers = {
            'source_code': SourceCodeAnalyzer(self.model_manager),
            'http_requests': HTTPRequestAnalyzer(self.model_manager),
            'mobile_apps': MobileAppAnalyzer(self.model_manager),
            'executables': ExecutableAnalyzer(self.model_manager),
            'smart_contracts': SmartContractAnalyzer(self.model_manager)
        }

        self._initialized = False
        logger.info("VulnHunter Engine initialized")

    async def initialize(self) -> bool:
        """Initialize the engine and load models."""
        try:
            # Load all models
            await self.model_manager.load_all_models()

            # Initialize analyzers
            for analyzer_name, analyzer in self.analyzers.items():
                if hasattr(analyzer, 'initialize'):
                    await analyzer.initialize()
                logger.info(f"Initialized {analyzer_name} analyzer")

            self._initialized = True
            logger.info("VulnHunter Engine fully initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize VulnHunter Engine: {e}")
            return False

    async def analyze(self,
                     target: Union[str, bytes, Dict, Path],
                     analysis_type: str = "auto",
                     confidence_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze a target for vulnerabilities.

        Args:
            target: The target to analyze (file, URL, code, etc.)
            analysis_type: Type of analysis or 'auto' for automatic detection
            confidence_threshold: Minimum confidence threshold for results

        Returns:
            Dict containing analysis results
        """
        if not self._initialized:
            raise RuntimeError("Engine not initialized. Call initialize() first.")

        analysis_id = f"vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        logger.info(f"Starting analysis {analysis_id} for target type: {analysis_type}")

        try:
            if analysis_type == "auto":
                analysis_type = self._detect_target_type(target)

            if analysis_type not in self.analyzers:
                raise ValueError(f"Unknown analysis type: {analysis_type}")

            analyzer = self.analyzers[analysis_type]
            result = await analyzer.analyze(target, confidence_threshold)

            # Enhance result with metadata
            enhanced_result = {
                "analysis_id": analysis_id,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": analysis_type,
                "target_info": self._get_target_info(target),
                "engine_version": "2.0.0",
                "confidence_threshold": confidence_threshold,
                **result
            }

            logger.info(f"Analysis {analysis_id} completed successfully")
            return enhanced_result

        except Exception as e:
            logger.error(f"Analysis {analysis_id} failed: {e}")
            return {
                "analysis_id": analysis_id,
                "timestamp": datetime.now().isoformat(),
                "status": "error",
                "error": str(e),
                "analysis_type": analysis_type
            }

    async def batch_analyze(self,
                           targets: List[Dict[str, Any]],
                           max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """
        Analyze multiple targets concurrently.

        Args:
            targets: List of target dictionaries with 'target' and 'type' keys
            max_concurrent: Maximum concurrent analyses

        Returns:
            List of analysis results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_single(target_info):
            async with semaphore:
                return await self.analyze(
                    target_info['target'],
                    target_info.get('type', 'auto'),
                    target_info.get('confidence_threshold', 0.5)
                )

        tasks = [analyze_single(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "analysis_id": f"error_{i}",
                    "timestamp": datetime.now().isoformat(),
                    "status": "error",
                    "error": str(result),
                    "target": str(targets[i]['target'])
                })
            else:
                processed_results.append(result)

        return processed_results

    def get_supported_types(self) -> List[str]:
        """Get list of supported analysis types."""
        return list(self.analyzers.keys())

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return self.model_manager.get_model_info()

    def get_engine_stats(self) -> Dict[str, Any]:
        """Get engine statistics and status."""
        return {
            "version": "2.0.0",
            "initialized": self._initialized,
            "supported_types": self.get_supported_types(),
            "loaded_models": len(self.model_manager.loaded_models),
            "model_info": self.get_model_info(),
            "config": self.config.to_dict()
        }

    def _detect_target_type(self, target: Union[str, bytes, Dict, Path]) -> str:
        """Automatically detect the type of target for analysis."""
        if isinstance(target, Path):
            suffix = target.suffix.lower()
            if suffix in ['.py', '.js', '.java', '.cpp', '.c', '.go', '.rs']:
                return 'source_code'
            elif suffix in ['.apk', '.ipa']:
                return 'mobile_apps'
            elif suffix in ['.exe', '.deb', '.rpm', '.dmg']:
                return 'executables'
            elif suffix in ['.sol', '.vy']:
                return 'smart_contracts'

        elif isinstance(target, str):
            if target.startswith(('http://', 'https://')):
                return 'http_requests'
            elif target.startswith('0x') and len(target) == 42:
                return 'smart_contracts'

        elif isinstance(target, Dict):
            if 'method' in target and 'url' in target:
                return 'http_requests'

        # Default to source code analysis
        return 'source_code'

    def _get_target_info(self, target: Union[str, bytes, Dict, Path]) -> Dict[str, Any]:
        """Extract information about the target."""
        info = {"type": type(target).__name__}

        if isinstance(target, Path):
            info.update({
                "path": str(target),
                "size": target.stat().st_size if target.exists() else 0,
                "extension": target.suffix
            })
        elif isinstance(target, str):
            info["content_length"] = len(target)
        elif isinstance(target, bytes):
            info["size"] = len(target)
        elif isinstance(target, Dict):
            info["keys"] = list(target.keys())

        return info