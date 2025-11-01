#!/usr/bin/env python3
"""
VulnHunter Professional Engine - The core orchestrator
"""

import os
import sys
import time
import logging
import psutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from .plugin_manager import PluginManager
from .vulnerability import Vulnerability
from .analysis_result import AnalysisResult, PerformanceMetrics, QualityMetrics
from .config import Config


class VulnHunterEngine:
    """Core analysis engine for VulnHunter Professional"""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        self.plugin_manager = PluginManager(self.config.plugin_dirs)

        # Performance tracking
        self._start_time = 0.0
        self._start_memory = 0.0

        # Setup logging
        self._setup_logging()

        self.logger.info("VulnHunter Professional Engine initialized")
        self.logger.info(f"Loaded {len(self.plugin_manager.list_plugins())} plugins")

    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(self.config.log_file) if self.config.log_file else logging.NullHandler()
            ]
        )

    def analyze_file(self, file_path: str, context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """Analyze a single file"""
        self.logger.info(f"Analyzing file: {file_path}")
        self._start_performance_tracking()

        result = AnalysisResult(
            analysis_id=f"file_{int(time.time())}",
            target_path=file_path,
            analysis_type="sast",
            started_at=datetime.utcnow()
        )

        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Analyze with plugins
            vulnerabilities = self.plugin_manager.analyze_with_plugins(file_path, content, context)
            result.vulnerabilities = vulnerabilities

            # Calculate metrics
            result.performance_metrics = self._calculate_performance_metrics(1, len(content.splitlines()))
            result.quality_metrics = self._calculate_quality_metrics(vulnerabilities)

            result.status = "completed"
            result.completed_at = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        result.calculate_summary()
        return result

    def analyze_directory(self, directory_path: str, recursive: bool = True,
                         file_extensions: Optional[List[str]] = None) -> AnalysisResult:
        """Analyze all files in a directory"""
        self.logger.info(f"Analyzing directory: {directory_path}")
        self._start_performance_tracking()

        result = AnalysisResult(
            analysis_id=f"dir_{int(time.time())}",
            target_path=directory_path,
            analysis_type="sast",
            started_at=datetime.utcnow()
        )

        try:
            # Find files to analyze
            files_to_analyze = self._find_files_to_analyze(directory_path, recursive, file_extensions)
            total_files = len(files_to_analyze)
            total_lines = 0

            self.logger.info(f"Found {total_files} files to analyze")

            # Analyze each file
            for i, file_path in enumerate(files_to_analyze):
                try:
                    self.logger.debug(f"Analyzing {file_path} ({i+1}/{total_files})")

                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    total_lines += len(content.splitlines())

                    # Analyze with plugins
                    context = {'project_root': directory_path, 'file_index': i}
                    vulnerabilities = self.plugin_manager.analyze_with_plugins(file_path, content, context)
                    result.vulnerabilities.extend(vulnerabilities)

                except Exception as e:
                    self.logger.warning(f"Error analyzing {file_path}: {e}")
                    result.warnings.append(f"Failed to analyze {file_path}: {str(e)}")

            # Calculate metrics
            result.performance_metrics = self._calculate_performance_metrics(total_files, total_lines)
            result.quality_metrics = self._calculate_quality_metrics(result.vulnerabilities)

            result.status = "completed"
            result.completed_at = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error analyzing directory {directory_path}: {e}")
            result.errors.append(str(e))
            result.status = "failed"

        result.calculate_summary()
        return result

    def analyze_project(self, project_path: str) -> AnalysisResult:
        """Analyze an entire project with comprehensive analysis"""
        self.logger.info(f"Analyzing project: {project_path}")

        # Detect project type and structure
        project_info = self._detect_project_structure(project_path)

        # Perform comprehensive analysis
        result = self.analyze_directory(
            project_path,
            recursive=True,
            file_extensions=project_info.get('file_extensions')
        )

        result.analysis_type = "project"
        result.environment_info = project_info

        return result

    def _find_files_to_analyze(self, directory_path: str, recursive: bool,
                             file_extensions: Optional[List[str]]) -> List[str]:
        """Find all files that should be analyzed"""
        files = []
        path = Path(directory_path)

        # Default file extensions for source code
        default_extensions = {
            '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt',
            '.sol', '.vy', '.jsx', '.tsx', '.vue', '.scala', '.pl'
        }

        extensions = set(file_extensions) if file_extensions else default_extensions

        # Find files
        pattern = "**/*" if recursive else "*"
        for file_path in path.glob(pattern):
            if (file_path.is_file() and
                file_path.suffix.lower() in extensions and
                not self._should_skip_file(file_path)):
                files.append(str(file_path))

        return sorted(files)

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during analysis"""
        skip_patterns = {
            'node_modules', '.git', '.svn', '.hg', '__pycache__',
            '.pytest_cache', '.venv', 'venv', 'env', 'build',
            'dist', 'target', '.idea', '.vscode'
        }

        # Check if any parent directory matches skip patterns
        for parent in file_path.parents:
            if parent.name in skip_patterns:
                return True

        # Check file size (skip very large files)
        try:
            if file_path.stat().st_size > self.config.max_file_size_mb * 1024 * 1024:
                return True
        except OSError:
            return True

        return False

    def _detect_project_structure(self, project_path: str) -> Dict[str, Any]:
        """Detect project type and structure"""
        path = Path(project_path)
        project_info = {
            'type': 'unknown',
            'language': 'unknown',
            'framework': 'unknown',
            'file_extensions': None,
            'config_files': []
        }

        # Check for common project files
        config_files = [
            'package.json', 'requirements.txt', 'pom.xml', 'build.gradle',
            'Cargo.toml', 'composer.json', 'Gemfile', 'go.mod'
        ]

        for config_file in config_files:
            config_path = path / config_file
            if config_path.exists():
                project_info['config_files'].append(config_file)

        # Detect language/framework
        if (path / 'package.json').exists():
            project_info['language'] = 'javascript'
            project_info['type'] = 'nodejs'
        elif (path / 'requirements.txt').exists() or (path / 'setup.py').exists():
            project_info['language'] = 'python'
            project_info['type'] = 'python'
        elif (path / 'pom.xml').exists() or (path / 'build.gradle').exists():
            project_info['language'] = 'java'
            project_info['type'] = 'java'
        elif (path / 'Cargo.toml').exists():
            project_info['language'] = 'rust'
            project_info['type'] = 'rust'

        return project_info

    def _start_performance_tracking(self) -> None:
        """Start tracking performance metrics"""
        self._start_time = time.time()
        self._start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB

    def _calculate_performance_metrics(self, files_analyzed: int, lines_of_code: int) -> PerformanceMetrics:
        """Calculate performance metrics"""
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB

        return PerformanceMetrics(
            analysis_time_ms=(end_time - self._start_time) * 1000,
            memory_usage_mb=max(0, end_memory - self._start_memory),
            cpu_usage_percent=psutil.cpu_percent(),
            files_analyzed=files_analyzed,
            lines_of_code=lines_of_code,
            plugins_used=self.plugin_manager.list_plugins()
        )

    def _calculate_quality_metrics(self, vulnerabilities: List[Vulnerability]) -> QualityMetrics:
        """Calculate quality metrics for the analysis"""
        if not vulnerabilities:
            return QualityMetrics(
                confidence_avg=0.0,
                false_positive_rate=0.0,
                coverage_percentage=100.0,  # Assume 100% if no vulns found
                completeness_score=1.0
            )

        # Calculate average confidence
        confidence_avg = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)

        # Estimate false positive rate based on confidence scores
        low_confidence_count = sum(1 for v in vulnerabilities if v.confidence < 0.7)
        false_positive_rate = low_confidence_count / len(vulnerabilities)

        # Coverage percentage (simplified metric)
        coverage_percentage = min(100.0, len(vulnerabilities) * 10)  # Rough estimate

        # Completeness score based on diversity of vulnerability types
        unique_types = len(set(v.vuln_type for v in vulnerabilities))
        completeness_score = min(1.0, unique_types / 10)  # Normalize to 0-1

        return QualityMetrics(
            confidence_avg=confidence_avg,
            false_positive_rate=false_positive_rate,
            coverage_percentage=coverage_percentage,
            completeness_score=completeness_score
        )

    def get_engine_info(self) -> Dict[str, Any]:
        """Get information about the engine"""
        return {
            'version': '5.0.0',
            'plugins_loaded': len(self.plugin_manager.list_plugins()),
            'plugin_info': self.plugin_manager.get_plugin_info(),
            'config': self.config.to_dict(),
            'system_info': {
                'python_version': sys.version,
                'platform': sys.platform,
                'cpu_count': psutil.cpu_count(),
                'memory_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024
            }
        }