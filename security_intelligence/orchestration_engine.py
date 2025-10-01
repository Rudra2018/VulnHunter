"""
Intelligence Orchestration Engine
================================

Central orchestration system that coordinates all security intelligence layers,
manages distributed analysis, and provides unified reporting and decision making.
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
import yaml

# Import all layer components
from .layer1_binary_analysis.binary_analyzer import BinaryAnalyzer
from .layer1_binary_analysis.reconnaissance_engine import ReconnaissanceEngine
from .layer2_reverse_engineering.ai_disassembler import AIDisassembler
from .layer2_reverse_engineering.code_analyzer import CodeAnalyzer
from .layer3_fuzzing_orchestration.intelligent_fuzzer import IntelligentFuzzer
from .layer3_fuzzing_orchestration.coverage_analyzer import CoverageAnalyzer
from .layer4_advanced_static_analysis.ast_analyzer import ASTAnalyzer
from .layer4_advanced_static_analysis.pattern_detector import PatternDetector
from .layer5_dynamic_testing.web_crawler import IntelligentWebCrawler
from .layer5_dynamic_testing.vulnerability_scanner import AdvancedVulnerabilityScanner
from .layer5_dynamic_testing.api_tester import APISecurityTester
from .layer5_dynamic_testing.auth_handler import AuthenticationHandler


class AnalysisType(Enum):
    """Supported analysis types"""
    BINARY = "binary"
    SOURCE_CODE = "source_code"
    WEB_APPLICATION = "web_application"
    API = "api"
    MOBILE_APP = "mobile_app"
    EMBEDDED_FIRMWARE = "embedded_firmware"
    FULL_STACK = "full_stack"


class Priority(Enum):
    """Task priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AnalysisTask:
    """Individual analysis task definition"""
    task_id: str
    target: str
    analysis_type: AnalysisType
    layers: List[str]
    priority: Priority
    config: Dict[str, Any]
    created_at: float
    estimated_duration: Optional[int] = None
    dependencies: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AnalysisResult:
    """Consolidated analysis result"""
    task_id: str
    target: str
    analysis_type: AnalysisType
    layers_completed: List[str]
    findings: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    risk_score: float
    confidence: float
    execution_time: float
    metadata: Dict[str, Any]
    recommendations: List[str]
    artifacts: Dict[str, Any]


class TaskScheduler:
    """Intelligent task scheduling and resource management"""

    def __init__(self, max_concurrent_tasks: int = 5):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_queue: List[AnalysisTask] = []
        self.running_tasks: Dict[str, AnalysisTask] = {}
        self.completed_tasks: Dict[str, AnalysisResult] = {}
        self.failed_tasks: Dict[str, tuple] = {}
        self.logger = logging.getLogger(__name__)

    def add_task(self, task: AnalysisTask) -> bool:
        """Add task to scheduling queue"""
        try:
            # Check dependencies
            if task.dependencies:
                for dep_id in task.dependencies:
                    if dep_id not in self.completed_tasks:
                        self.logger.warning(f"Task {task.task_id} depends on incomplete task {dep_id}")

            # Insert task based on priority
            inserted = False
            for i, queued_task in enumerate(self.task_queue):
                if task.priority.value > queued_task.priority.value:
                    self.task_queue.insert(i, task)
                    inserted = True
                    break

            if not inserted:
                self.task_queue.append(task)

            self.logger.info(f"Added task {task.task_id} to queue (priority: {task.priority.name})")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add task {task.task_id}: {e}")
            return False

    def get_next_task(self) -> Optional[AnalysisTask]:
        """Get next available task for execution"""
        if len(self.running_tasks) >= self.max_concurrent_tasks:
            return None

        for i, task in enumerate(self.task_queue):
            # Check if dependencies are satisfied
            if task.dependencies:
                deps_satisfied = all(
                    dep_id in self.completed_tasks
                    for dep_id in task.dependencies
                )
                if not deps_satisfied:
                    continue

            # Remove from queue and mark as running
            self.task_queue.pop(i)
            self.running_tasks[task.task_id] = task
            return task

        return None

    def complete_task(self, task_id: str, result: AnalysisResult) -> bool:
        """Mark task as completed"""
        try:
            if task_id in self.running_tasks:
                del self.running_tasks[task_id]
                self.completed_tasks[task_id] = result
                self.logger.info(f"Completed task {task_id}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to complete task {task_id}: {e}")
            return False

    def fail_task(self, task_id: str, error: Exception) -> bool:
        """Mark task as failed"""
        try:
            if task_id in self.running_tasks:
                task = self.running_tasks[task_id]
                del self.running_tasks[task_id]
                self.failed_tasks[task_id] = (task, error)
                self.logger.error(f"Failed task {task_id}: {error}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to fail task {task_id}: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        return {
            'queued_tasks': len(self.task_queue),
            'running_tasks': len(self.running_tasks),
            'completed_tasks': len(self.completed_tasks),
            'failed_tasks': len(self.failed_tasks),
            'running_task_ids': list(self.running_tasks.keys())
        }


class LayerCoordinator:
    """Coordinates execution across security intelligence layers"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Initialize layer components
        self.binary_analyzer = BinaryAnalyzer()
        self.recon_engine = ReconnaissanceEngine()
        self.ai_disassembler = AIDisassembler()
        self.code_analyzer = CodeAnalyzer()
        self.intelligent_fuzzer = IntelligentFuzzer()
        self.coverage_analyzer = CoverageAnalyzer()
        self.ast_analyzer = ASTAnalyzer()
        self.pattern_detector = PatternDetector()
        self.web_crawler = IntelligentWebCrawler()
        self.vuln_scanner = AdvancedVulnerabilityScanner()
        self.api_tester = APISecurityTester()
        self.auth_handler = AuthenticationHandler()

        # Layer execution mapping
        self.layer_executors = {
            'layer1_binary': self._execute_layer1,
            'layer1_recon': self._execute_layer1_recon,
            'layer2_disassembly': self._execute_layer2_disassembly,
            'layer2_code_analysis': self._execute_layer2_code_analysis,
            'layer3_fuzzing': self._execute_layer3_fuzzing,
            'layer3_coverage': self._execute_layer3_coverage,
            'layer4_ast': self._execute_layer4_ast,
            'layer4_patterns': self._execute_layer4_patterns,
            'layer5_crawling': self._execute_layer5_crawling,
            'layer5_scanning': self._execute_layer5_scanning,
            'layer5_api_testing': self._execute_layer5_api_testing,
            'layer5_auth_testing': self._execute_layer5_auth_testing
        }

    async def execute_layers(self, task: AnalysisTask) -> AnalysisResult:
        """Execute specified layers for analysis task"""
        start_time = time.time()
        findings = []
        vulnerabilities = []
        artifacts = {}
        completed_layers = []

        try:
            for layer in task.layers:
                if layer not in self.layer_executors:
                    self.logger.warning(f"Unknown layer: {layer}")
                    continue

                self.logger.info(f"Executing layer: {layer}")
                layer_result = await self.layer_executors[layer](task)

                if layer_result:
                    findings.extend(layer_result.get('findings', []))
                    vulnerabilities.extend(layer_result.get('vulnerabilities', []))
                    artifacts[layer] = layer_result.get('artifacts', {})
                    completed_layers.append(layer)

            # Calculate overall risk score and confidence
            risk_score = self._calculate_risk_score(vulnerabilities)
            confidence = self._calculate_confidence(completed_layers, findings)

            # Generate recommendations
            recommendations = self._generate_recommendations(vulnerabilities, findings)

            execution_time = time.time() - start_time

            return AnalysisResult(
                task_id=task.task_id,
                target=task.target,
                analysis_type=task.analysis_type,
                layers_completed=completed_layers,
                findings=findings,
                vulnerabilities=vulnerabilities,
                risk_score=risk_score,
                confidence=confidence,
                execution_time=execution_time,
                metadata=task.metadata or {},
                recommendations=recommendations,
                artifacts=artifacts
            )

        except Exception as e:
            self.logger.error(f"Layer execution failed for task {task.task_id}: {e}")
            raise

    async def _execute_layer1(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 1: Binary Analysis"""
        try:
            if task.analysis_type in [AnalysisType.BINARY, AnalysisType.EMBEDDED_FIRMWARE]:
                analysis_result = await self.binary_analyzer.analyze_binary(
                    task.target,
                    task.config.get('binary_config', {})
                )
                return {
                    'findings': analysis_result.get('findings', []),
                    'vulnerabilities': analysis_result.get('vulnerabilities', []),
                    'artifacts': analysis_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 1 execution failed: {e}")
            return {}

    async def _execute_layer1_recon(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 1: Reconnaissance"""
        try:
            recon_result = await self.recon_engine.reconnaissance_scan(
                task.target,
                task.config.get('recon_config', {})
            )
            return {
                'findings': recon_result.get('findings', []),
                'vulnerabilities': recon_result.get('vulnerabilities', []),
                'artifacts': recon_result.get('artifacts', {})
            }
        except Exception as e:
            self.logger.error(f"Layer 1 recon execution failed: {e}")
            return {}

    async def _execute_layer2_disassembly(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 2: AI-Assisted Disassembly"""
        try:
            if task.analysis_type in [AnalysisType.BINARY, AnalysisType.EMBEDDED_FIRMWARE]:
                disasm_result = await self.ai_disassembler.disassemble_with_ai(
                    task.target,
                    task.config.get('disasm_config', {})
                )
                return {
                    'findings': disasm_result.get('findings', []),
                    'vulnerabilities': disasm_result.get('vulnerabilities', []),
                    'artifacts': disasm_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 2 disassembly execution failed: {e}")
            return {}

    async def _execute_layer2_code_analysis(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 2: Code Analysis"""
        try:
            if task.analysis_type == AnalysisType.SOURCE_CODE:
                code_result = await self.code_analyzer.analyze_code(
                    task.target,
                    task.config.get('code_config', {})
                )
                return {
                    'findings': code_result.get('findings', []),
                    'vulnerabilities': code_result.get('vulnerabilities', []),
                    'artifacts': code_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 2 code analysis execution failed: {e}")
            return {}

    async def _execute_layer3_fuzzing(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 3: Intelligent Fuzzing"""
        try:
            fuzz_result = await self.intelligent_fuzzer.fuzz_target(
                task.target,
                task.config.get('fuzz_config', {})
            )
            return {
                'findings': fuzz_result.get('findings', []),
                'vulnerabilities': fuzz_result.get('vulnerabilities', []),
                'artifacts': fuzz_result.get('artifacts', {})
            }
        except Exception as e:
            self.logger.error(f"Layer 3 fuzzing execution failed: {e}")
            return {}

    async def _execute_layer3_coverage(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 3: Coverage Analysis"""
        try:
            coverage_result = await self.coverage_analyzer.analyze_coverage(
                task.target,
                task.config.get('coverage_config', {})
            )
            return {
                'findings': coverage_result.get('findings', []),
                'vulnerabilities': coverage_result.get('vulnerabilities', []),
                'artifacts': coverage_result.get('artifacts', {})
            }
        except Exception as e:
            self.logger.error(f"Layer 3 coverage execution failed: {e}")
            return {}

    async def _execute_layer4_ast(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 4: AST Analysis"""
        try:
            if task.analysis_type == AnalysisType.SOURCE_CODE:
                ast_result = await self.ast_analyzer.analyze_ast(
                    task.target,
                    task.config.get('ast_config', {})
                )
                return {
                    'findings': ast_result.get('findings', []),
                    'vulnerabilities': ast_result.get('vulnerabilities', []),
                    'artifacts': ast_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 4 AST execution failed: {e}")
            return {}

    async def _execute_layer4_patterns(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 4: Pattern Detection"""
        try:
            pattern_result = await self.pattern_detector.detect_patterns(
                task.target,
                task.config.get('pattern_config', {})
            )
            return {
                'findings': pattern_result.get('findings', []),
                'vulnerabilities': pattern_result.get('vulnerabilities', []),
                'artifacts': pattern_result.get('artifacts', {})
            }
        except Exception as e:
            self.logger.error(f"Layer 4 pattern detection execution failed: {e}")
            return {}

    async def _execute_layer5_crawling(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 5: Web Crawling"""
        try:
            if task.analysis_type in [AnalysisType.WEB_APPLICATION, AnalysisType.FULL_STACK]:
                crawl_result = await self.web_crawler.crawl_application(
                    task.target,
                    task.config.get('crawl_config', {})
                )
                return {
                    'findings': crawl_result.get('findings', []),
                    'vulnerabilities': crawl_result.get('vulnerabilities', []),
                    'artifacts': crawl_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 5 crawling execution failed: {e}")
            return {}

    async def _execute_layer5_scanning(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 5: Vulnerability Scanning"""
        try:
            if task.analysis_type in [AnalysisType.WEB_APPLICATION, AnalysisType.FULL_STACK]:
                scan_result = await self.vuln_scanner.scan_for_vulnerabilities(
                    task.target,
                    task.config.get('scan_config', {})
                )
                return {
                    'findings': scan_result.get('findings', []),
                    'vulnerabilities': scan_result.get('vulnerabilities', []),
                    'artifacts': scan_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 5 scanning execution failed: {e}")
            return {}

    async def _execute_layer5_api_testing(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 5: API Testing"""
        try:
            if task.analysis_type in [AnalysisType.API, AnalysisType.WEB_APPLICATION, AnalysisType.FULL_STACK]:
                api_result = await self.api_tester.test_api_security(
                    task.target,
                    task.config.get('api_config', {})
                )
                return {
                    'findings': api_result.get('findings', []),
                    'vulnerabilities': api_result.get('vulnerabilities', []),
                    'artifacts': api_result.get('artifacts', {})
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 5 API testing execution failed: {e}")
            return {}

    async def _execute_layer5_auth_testing(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute Layer 5: Authentication Testing"""
        try:
            if task.analysis_type in [AnalysisType.WEB_APPLICATION, AnalysisType.API, AnalysisType.FULL_STACK]:
                auth_result = await self.auth_handler.test_authentication_bypass(
                    task.target,
                    task.config.get('auth_config', {})
                )
                return {
                    'findings': [asdict(result) for result in auth_result if result.success],
                    'vulnerabilities': [asdict(result) for result in auth_result if result.bypass_techniques_used],
                    'artifacts': {'auth_tests': len(auth_result)}
                }
            return {}
        except Exception as e:
            self.logger.error(f"Layer 5 auth testing execution failed: {e}")
            return {}

    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0

        total_score = 0.0
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            weight = severity_weights.get(severity, 1.0)
            confidence = vuln.get('confidence', 0.5)
            total_score += weight * confidence

        # Normalize to 0-10 scale
        max_possible = len(vulnerabilities) * 10.0
        return min(10.0, (total_score / max_possible) * 10.0) if max_possible > 0 else 0.0

    def _calculate_confidence(self, completed_layers: List[str], findings: List[Dict[str, Any]]) -> float:
        """Calculate confidence level based on analysis completeness"""
        layer_weights = {
            'layer1': 0.15,
            'layer2': 0.20,
            'layer3': 0.20,
            'layer4': 0.25,
            'layer5': 0.20
        }

        total_weight = 0.0
        for layer in completed_layers:
            layer_prefix = layer.split('_')[0] + '_' + layer.split('_')[1] if '_' in layer else layer
            weight = layer_weights.get(layer_prefix, 0.0)
            total_weight += weight

        # Factor in number of findings
        findings_factor = min(1.0, len(findings) / 10.0)

        return min(1.0, total_weight + (findings_factor * 0.1))

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]],
                                findings: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Vulnerability-based recommendations
        vuln_types = set()
        for vuln in vulnerabilities:
            vuln_types.add(vuln.get('type', 'unknown'))

        vuln_recommendations = {
            'sql_injection': 'Implement parameterized queries and input validation',
            'xss': 'Implement output encoding and Content Security Policy',
            'csrf': 'Implement CSRF tokens and SameSite cookie attributes',
            'command_injection': 'Use parameterized commands and input sanitization',
            'path_traversal': 'Implement path canonicalization and access controls',
            'buffer_overflow': 'Use memory-safe programming practices and bounds checking',
            'insecure_crypto': 'Use modern cryptographic algorithms and proper key management'
        }

        for vuln_type in vuln_types:
            if vuln_type in vuln_recommendations:
                recommendations.append(vuln_recommendations[vuln_type])

        # General security recommendations
        if len(vulnerabilities) > 5:
            recommendations.append('Implement comprehensive security testing in CI/CD pipeline')

        if not any('authentication' in str(finding) for finding in findings):
            recommendations.append('Implement multi-factor authentication')

        recommendations.append('Regular security assessments and penetration testing')
        recommendations.append('Security awareness training for development team')

        return recommendations


class IntelligenceOrchestrationEngine:
    """Main orchestration engine for the Security Intelligence Framework"""

    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.logger = self._setup_logging()

        self.scheduler = TaskScheduler(
            max_concurrent_tasks=self.config.get('max_concurrent_tasks', 5)
        )
        self.coordinator = LayerCoordinator()

        self.running = False
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 10)
        )

    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'max_concurrent_tasks': 5,
            'max_workers': 10,
            'log_level': 'INFO',
            'result_storage_path': './results',
            'enable_distributed': False,
            'redis_url': 'redis://localhost:6379',
            'database_url': 'sqlite:///security_intelligence.db'
        }

        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
                    default_config.update(file_config)
            except Exception as e:
                logging.warning(f"Failed to load config file {config_file}: {e}")

        return default_config

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, self.config.get('log_level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    async def submit_analysis(self, target: str, analysis_type: AnalysisType,
                            layers: Optional[List[str]] = None,
                            priority: Priority = Priority.MEDIUM,
                            config: Optional[Dict[str, Any]] = None) -> str:
        """Submit new analysis task"""
        task_id = str(uuid.uuid4())

        # Default layers based on analysis type
        if layers is None:
            layers = self._get_default_layers(analysis_type)

        task = AnalysisTask(
            task_id=task_id,
            target=target,
            analysis_type=analysis_type,
            layers=layers,
            priority=priority,
            config=config or {},
            created_at=time.time()
        )

        if self.scheduler.add_task(task):
            self.logger.info(f"Submitted analysis task {task_id} for target {target}")
            return task_id
        else:
            raise Exception(f"Failed to submit task {task_id}")

    def _get_default_layers(self, analysis_type: AnalysisType) -> List[str]:
        """Get default layers for analysis type"""
        layer_mapping = {
            AnalysisType.BINARY: [
                'layer1_binary', 'layer1_recon', 'layer2_disassembly', 'layer3_fuzzing'
            ],
            AnalysisType.SOURCE_CODE: [
                'layer2_code_analysis', 'layer4_ast', 'layer4_patterns'
            ],
            AnalysisType.WEB_APPLICATION: [
                'layer1_recon', 'layer5_crawling', 'layer5_scanning', 'layer5_auth_testing'
            ],
            AnalysisType.API: [
                'layer1_recon', 'layer5_api_testing', 'layer5_auth_testing'
            ],
            AnalysisType.MOBILE_APP: [
                'layer1_binary', 'layer2_disassembly', 'layer4_ast', 'layer5_api_testing'
            ],
            AnalysisType.EMBEDDED_FIRMWARE: [
                'layer1_binary', 'layer1_recon', 'layer2_disassembly', 'layer3_fuzzing'
            ],
            AnalysisType.FULL_STACK: [
                'layer1_recon', 'layer4_ast', 'layer4_patterns', 'layer5_crawling',
                'layer5_scanning', 'layer5_api_testing', 'layer5_auth_testing'
            ]
        }
        return layer_mapping.get(analysis_type, ['layer1_recon'])

    async def start_engine(self):
        """Start the orchestration engine"""
        self.running = True
        self.logger.info("Starting Intelligence Orchestration Engine")

        # Start main processing loop
        await self._main_processing_loop()

    async def stop_engine(self):
        """Stop the orchestration engine"""
        self.running = False
        self.executor.shutdown(wait=True)
        self.logger.info("Stopped Intelligence Orchestration Engine")

    async def _main_processing_loop(self):
        """Main processing loop for task execution"""
        while self.running:
            try:
                # Get next task from scheduler
                task = self.scheduler.get_next_task()

                if task:
                    # Execute task asynchronously
                    asyncio.create_task(self._execute_task(task))
                else:
                    # No tasks available, wait before checking again
                    await asyncio.sleep(1)

            except Exception as e:
                self.logger.error(f"Error in main processing loop: {e}")
                await asyncio.sleep(5)

    async def _execute_task(self, task: AnalysisTask):
        """Execute individual analysis task"""
        try:
            self.logger.info(f"Starting execution of task {task.task_id}")

            # Execute layers through coordinator
            result = await self.coordinator.execute_layers(task)

            # Complete task in scheduler
            self.scheduler.complete_task(task.task_id, result)

            # Store result
            await self._store_result(result)

            self.logger.info(f"Completed task {task.task_id} in {result.execution_time:.2f} seconds")

        except Exception as e:
            self.logger.error(f"Task {task.task_id} failed: {e}")
            self.scheduler.fail_task(task.task_id, e)

    async def _store_result(self, result: AnalysisResult):
        """Store analysis result"""
        try:
            result_path = Path(self.config['result_storage_path'])
            result_path.mkdir(exist_ok=True)

            result_file = result_path / f"{result.task_id}.json"
            with open(result_file, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)

        except Exception as e:
            self.logger.error(f"Failed to store result for task {result.task_id}: {e}")

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific task"""
        # Check completed tasks
        if task_id in self.scheduler.completed_tasks:
            result = self.scheduler.completed_tasks[task_id]
            return {
                'status': 'completed',
                'result': asdict(result)
            }

        # Check running tasks
        if task_id in self.scheduler.running_tasks:
            task = self.scheduler.running_tasks[task_id]
            return {
                'status': 'running',
                'task': asdict(task)
            }

        # Check failed tasks
        if task_id in self.scheduler.failed_tasks:
            task, error = self.scheduler.failed_tasks[task_id]
            return {
                'status': 'failed',
                'task': asdict(task),
                'error': str(error)
            }

        # Check queued tasks
        for task in self.scheduler.task_queue:
            if task.task_id == task_id:
                return {
                    'status': 'queued',
                    'task': asdict(task)
                }

        return None

    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            'engine_running': self.running,
            'scheduler_status': self.scheduler.get_status(),
            'config': self.config,
            'uptime': time.time()
        }

    async def generate_report(self, task_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        if task_ids is None:
            # Include all completed tasks
            results = list(self.scheduler.completed_tasks.values())
        else:
            results = [
                self.scheduler.completed_tasks[tid]
                for tid in task_ids
                if tid in self.scheduler.completed_tasks
            ]

        if not results:
            return {'error': 'No completed tasks found'}

        # Aggregate statistics
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in results)
        avg_risk_score = sum(r.risk_score for r in results) / len(results)
        total_execution_time = sum(r.execution_time for r in results)

        # Vulnerability breakdown
        vuln_types = {}
        for result in results:
            for vuln in result.vulnerabilities:
                vuln_type = vuln.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            results, total_vulnerabilities, avg_risk_score
        )

        return {
            'executive_summary': executive_summary,
            'statistics': {
                'total_tasks': len(results),
                'total_vulnerabilities': total_vulnerabilities,
                'average_risk_score': avg_risk_score,
                'total_execution_time': total_execution_time,
                'vulnerability_breakdown': vuln_types
            },
            'detailed_results': [asdict(result) for result in results],
            'generated_at': time.time()
        }

    def _generate_executive_summary(self, results: List[AnalysisResult],
                                  total_vulns: int, avg_risk: float) -> str:
        """Generate executive summary for report"""
        risk_level = "Low"
        if avg_risk >= 7.0:
            risk_level = "Critical"
        elif avg_risk >= 5.0:
            risk_level = "High"
        elif avg_risk >= 3.0:
            risk_level = "Medium"

        return f"""
Security Intelligence Framework Analysis Report

EXECUTIVE SUMMARY:
Analysis of {len(results)} targets has been completed using the integrated
5-layer security intelligence framework.

RISK ASSESSMENT:
- Overall Risk Level: {risk_level}
- Average Risk Score: {avg_risk:.2f}/10.0
- Total Vulnerabilities Found: {total_vulns}

RECOMMENDATIONS:
Immediate attention required for {risk_level.lower()} risk findings.
Implement comprehensive security controls and conduct regular assessments.
        """.strip()


# Example usage and configuration
if __name__ == "__main__":
    async def main():
        # Initialize orchestration engine
        engine = IntelligenceOrchestrationEngine()

        # Submit various analysis tasks
        task1_id = await engine.submit_analysis(
            target="https://example.com",
            analysis_type=AnalysisType.WEB_APPLICATION,
            priority=Priority.HIGH
        )

        task2_id = await engine.submit_analysis(
            target="/path/to/binary",
            analysis_type=AnalysisType.BINARY,
            priority=Priority.MEDIUM
        )

        # Start engine (this would run continuously)
        # await engine.start_engine()

        print(f"Submitted tasks: {task1_id}, {task2_id}")

    # Run example
    # asyncio.run(main())