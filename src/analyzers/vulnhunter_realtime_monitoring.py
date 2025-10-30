#!/usr/bin/env python3
"""
VulnHunter Ω Real-time Code Monitoring System
Advanced live code analysis with instant vulnerability detection
"""

import asyncio
import os
import sys
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

import torch
import numpy as np
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
import websockets
# import asyncio_mqtt  # Optional MQTT support
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil
from queue import Queue, Empty
import threading
import signal

from vulnhunter_large_model_integration import VulnHunterLargeModelIntegration
from vulnhunter_deep_learning_integration import DeepLearningVulnerabilityModel

@dataclass
class CodeChangeEvent:
    """Real-time code change event"""
    file_path: str
    event_type: str  # 'created', 'modified', 'deleted'
    timestamp: datetime
    file_size: int
    file_hash: str
    language: str
    content_preview: str

@dataclass
class VulnerabilityAlert:
    """Real-time vulnerability detection alert"""
    file_path: str
    vulnerability_type: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    timestamp: datetime
    detection_time_ms: float

class RealtimeFileMonitor(FileSystemEventHandler):
    """Advanced file system monitor for real-time code analysis"""

    def __init__(self, analyzer_queue: Queue, config: Dict[str, Any]):
        super().__init__()
        self.analyzer_queue = analyzer_queue
        self.config = config
        self.monitored_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.cpp', '.c', '.h', '.php'}
        self.file_hashes = {}
        self.debounce_delay = config.get('debounce_delay', 0.5)
        self.last_events = {}
        self.logger = logging.getLogger('RealtimeMonitor')

    def should_monitor_file(self, file_path: str) -> bool:
        """Check if file should be monitored"""
        path = Path(file_path)

        # Check extension
        if path.suffix not in self.monitored_extensions:
            return False

        # Skip hidden files and directories
        if any(part.startswith('.') for part in path.parts):
            return False

        # Skip common build/cache directories
        skip_dirs = {'node_modules', '__pycache__', '.git', 'build', 'dist', 'target', '.venv'}
        if any(skip_dir in path.parts for skip_dir in skip_dirs):
            return False

        return True

    def get_file_hash(self, file_path: str) -> str:
        """Calculate file content hash"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""

    def get_file_language(self, file_path: str) -> str:
        """Detect file programming language"""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.go': 'go',
            '.rs': 'rust',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.php': 'php'
        }
        return extension_map.get(Path(file_path).suffix, 'unknown')

    def get_content_preview(self, file_path: str, max_lines: int = 5) -> str:
        """Get file content preview"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines).strip()
        except Exception:
            return ""

    def on_modified(self, event):
        """Handle file modification events"""
        if not isinstance(event, FileModifiedEvent) or event.is_directory:
            return

        self._handle_file_event(event.src_path, 'modified')

    def on_created(self, event):
        """Handle file creation events"""
        if not isinstance(event, FileCreatedEvent) or event.is_directory:
            return

        self._handle_file_event(event.src_path, 'created')

    def _handle_file_event(self, file_path: str, event_type: str):
        """Handle file system events with debouncing"""
        if not self.should_monitor_file(file_path):
            return

        current_time = time.time()

        # Debounce rapid events on same file
        if file_path in self.last_events:
            if current_time - self.last_events[file_path] < self.debounce_delay:
                return

        self.last_events[file_path] = current_time

        # Check if file actually changed
        file_hash = self.get_file_hash(file_path)
        if file_path in self.file_hashes and self.file_hashes[file_path] == file_hash:
            return

        self.file_hashes[file_path] = file_hash

        # Create change event
        try:
            file_size = os.path.getsize(file_path)
            change_event = CodeChangeEvent(
                file_path=file_path,
                event_type=event_type,
                timestamp=datetime.now(),
                file_size=file_size,
                file_hash=file_hash,
                language=self.get_file_language(file_path),
                content_preview=self.get_content_preview(file_path)
            )

            # Queue for analysis
            try:
                self.analyzer_queue.put_nowait(change_event)
                self.logger.info(f"Queued {event_type} event for {file_path}")
            except Exception as e:
                self.logger.error(f"Failed to queue event: {e}")

        except Exception as e:
            self.logger.error(f"Error handling file event {file_path}: {e}")

class RealtimeVulnerabilityAnalyzer:
    """Real-time vulnerability analysis engine"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('RealtimeAnalyzer')

        # Initialize analysis engines
        self.large_model = VulnHunterLargeModelIntegration()

        # Initialize deep learning model with proper config object
        try:
            from dataclasses import dataclass

            @dataclass
            class DLConfig:
                model_path: str = 'models/vulnhunter_deep_learning.pth'
                device: str = 'cpu'
                max_length: int = 512
                hidden_size: int = 768
                vocab_size: int = 30000

            dl_config = DLConfig()
            self.deep_learning = DeepLearningVulnerabilityModel(dl_config)
        except Exception as e:
            self.logger.warning(f"Could not initialize deep learning model: {e}")
            self.deep_learning = None

        # Analysis queue and workers
        self.analysis_queue = Queue(maxsize=config.get('queue_size', 1000))
        self.alert_queue = Queue()
        self.num_workers = config.get('analysis_workers', 4)
        self.workers = []
        self.running = False

        # Performance monitoring
        self.analysis_count = 0
        self.total_analysis_time = 0.0
        self.start_time = time.time()

    async def start(self):
        """Start real-time analysis system"""
        self.running = True
        self.logger.info("Starting real-time vulnerability analyzer")

        # Start worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._analysis_worker,
                name=f"AnalysisWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)

        self.logger.info(f"Started {self.num_workers} analysis workers")

    def stop(self):
        """Stop real-time analysis system"""
        self.running = False
        self.logger.info("Stopping real-time analyzer")

    def _analysis_worker(self):
        """Analysis worker thread"""
        worker_name = threading.current_thread().name
        self.logger.info(f"Started {worker_name}")

        while self.running:
            try:
                # Get change event from queue
                try:
                    change_event = self.analysis_queue.get(timeout=1.0)
                except Empty:
                    continue

                # Analyze for vulnerabilities
                start_time = time.time()
                alerts = self._analyze_code_change(change_event)
                analysis_time = (time.time() - start_time) * 1000

                # Update statistics
                self.analysis_count += 1
                self.total_analysis_time += analysis_time

                # Queue alerts
                for alert in alerts:
                    alert.detection_time_ms = analysis_time
                    try:
                        self.alert_queue.put_nowait(alert)
                    except Exception as e:
                        self.logger.error(f"Failed to queue alert: {e}")

                self.analysis_queue.task_done()

            except Exception as e:
                self.logger.error(f"Analysis worker error: {e}")

        self.logger.info(f"Stopped {worker_name}")

    def _analyze_code_change(self, change_event: CodeChangeEvent) -> List[VulnerabilityAlert]:
        """Analyze code change for vulnerabilities"""
        alerts = []

        try:
            # Read file content
            with open(change_event.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            if not code_content.strip():
                return alerts

            # Multi-engine analysis
            engines = []

            # Large model analysis
            try:
                large_result = self.large_model.analyze_code(
                    code_content,
                    language=change_event.language,
                    mode='production'
                )
                engines.append(('large_model', large_result))
            except Exception as e:
                self.logger.debug(f"Large model analysis failed: {e}")

            # Deep learning analysis
            if self.deep_learning:
                try:
                    # Deep learning model expects different interface
                    dl_result = self.deep_learning.analyze_vulnerability(code_content)
                    # Format result to match expected structure
                    formatted_result = {
                        'vulnerabilities': [{
                            'type': 'code_vulnerability',
                            'confidence': dl_result.get('confidence', 0.5),
                            'description': 'Deep learning detected potential vulnerability',
                            'line': 1,
                            'code': code_content[:100],
                            'recommendation': 'Review code for security issues'
                        }] if dl_result.get('confidence', 0) > 0.5 else []
                    }
                    engines.append(('deep_learning', formatted_result))
                except Exception as e:
                    self.logger.debug(f"Deep learning analysis failed: {e}")

            # Process results and create alerts
            for engine_name, result in engines:
                if result and result.get('vulnerabilities'):
                    for vuln in result['vulnerabilities']:
                        severity = self._calculate_severity(vuln)
                        if severity in ['critical', 'high']:  # Only alert on high-severity issues
                            alert = VulnerabilityAlert(
                                file_path=change_event.file_path,
                                vulnerability_type=vuln.get('type', 'unknown'),
                                severity=severity,
                                confidence=vuln.get('confidence', 0.0),
                                line_number=vuln.get('line', 1),
                                code_snippet=vuln.get('code', ''),
                                description=vuln.get('description', ''),
                                recommendation=vuln.get('recommendation', ''),
                                timestamp=datetime.now(),
                                detection_time_ms=0.0
                            )
                            alerts.append(alert)

        except Exception as e:
            self.logger.error(f"Analysis error for {change_event.file_path}: {e}")

        return alerts

    def _calculate_severity(self, vulnerability: Dict[str, Any]) -> str:
        """Calculate vulnerability severity"""
        confidence = vulnerability.get('confidence', 0.0)
        vuln_type = vulnerability.get('type', '').lower()

        # Critical vulnerabilities
        critical_types = ['sql_injection', 'xss', 'command_injection', 'path_traversal']
        if any(crit in vuln_type for crit in critical_types) and confidence > 0.8:
            return 'critical'

        # High severity
        if confidence > 0.7:
            return 'high'
        elif confidence > 0.5:
            return 'medium'
        else:
            return 'low'

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        uptime = time.time() - self.start_time
        avg_analysis_time = self.total_analysis_time / max(self.analysis_count, 1)

        return {
            'uptime_seconds': uptime,
            'analyses_completed': self.analysis_count,
            'average_analysis_time_ms': avg_analysis_time,
            'queue_size': self.analysis_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'analyses_per_second': self.analysis_count / max(uptime, 1)
        }

class RealtimeNotificationSystem:
    """Real-time notification and alerting system"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('RealtimeNotifications')
        self.websocket_clients = set()
        self.running = False

    async def start_websocket_server(self):
        """Start WebSocket server for real-time notifications"""
        port = self.config.get('websocket_port', 8765)

        async def handle_client(websocket, path):
            self.websocket_clients.add(websocket)
            self.logger.info(f"WebSocket client connected: {websocket.remote_address}")

            try:
                await websocket.wait_closed()
            finally:
                self.websocket_clients.discard(websocket)
                self.logger.info(f"WebSocket client disconnected: {websocket.remote_address}")

        start_server = websockets.serve(handle_client, "localhost", port)
        self.logger.info(f"WebSocket server starting on port {port}")
        return start_server

    async def broadcast_alert(self, alert: VulnerabilityAlert):
        """Broadcast alert to all connected clients"""
        if not self.websocket_clients:
            return

        message = {
            'type': 'vulnerability_alert',
            'data': {
                **asdict(alert),
                'timestamp': alert.timestamp.isoformat()
            }
        }

        json_message = json.dumps(message)

        # Broadcast to all clients
        disconnected = set()
        for client in self.websocket_clients:
            try:
                await client.send(json_message)
            except Exception as e:
                self.logger.debug(f"Failed to send to client: {e}")
                disconnected.add(client)

        # Remove disconnected clients
        self.websocket_clients -= disconnected

class VulnHunterRealtimeSystem:
    """Main real-time vulnerability monitoring system"""

    def __init__(self, config_path: str = "config/realtime_config.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()

        # System components
        self.file_monitor = None
        self.observer = None
        self.analyzer = RealtimeVulnerabilityAnalyzer(self.config)
        self.notifications = RealtimeNotificationSystem(self.config)

        # Control
        self.running = False
        self.stats_interval = self.config.get('stats_interval', 60)

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration"""
        default_config = {
            'monitor_paths': ['.'],
            'debounce_delay': 0.5,
            'queue_size': 1000,
            'analysis_workers': 4,
            'websocket_port': 8765,
            'stats_interval': 60,
            'log_level': 'INFO'
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}")

        return default_config

    def _setup_logging(self) -> logging.Logger:
        """Setup logging system"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))

        # Create logs directory
        os.makedirs('logs', exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('logs/vulnhunter_realtime.log', mode='a')
            ]
        )

        return logging.getLogger('VulnHunterRealtime')

    async def start(self):
        """Start real-time monitoring system"""
        self.running = True
        self.logger.info("🚀 Starting VulnHunter Ω Real-time Monitoring System")

        # Create logs directory
        os.makedirs('logs', exist_ok=True)

        # Start analyzer
        await self.analyzer.start()

        # Start file monitoring
        self.file_monitor = RealtimeFileMonitor(
            self.analyzer.analysis_queue,
            self.config
        )

        self.observer = Observer()
        for path in self.config.get('monitor_paths', ['.']):
            if os.path.exists(path):
                self.observer.schedule(self.file_monitor, path, recursive=True)
                self.logger.info(f"Monitoring path: {path}")
            else:
                self.logger.warning(f"Monitor path does not exist: {path}")

        self.observer.start()

        # Start WebSocket server
        websocket_server = await self.notifications.start_websocket_server()

        # Start alert processing
        alert_task = asyncio.create_task(self._process_alerts())
        stats_task = asyncio.create_task(self._log_statistics())

        self.logger.info("✅ Real-time monitoring system started successfully")

        try:
            # Run until stopped
            await asyncio.gather(
                websocket_server,
                alert_task,
                stats_task
            )
        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
        finally:
            await self.stop()

    async def stop(self):
        """Stop real-time monitoring system"""
        self.running = False
        self.logger.info("Stopping real-time monitoring system")

        if self.observer:
            self.observer.stop()
            self.observer.join()

        self.analyzer.stop()

        self.logger.info("✅ Real-time monitoring system stopped")

    async def _process_alerts(self):
        """Process and broadcast vulnerability alerts"""
        while self.running:
            try:
                # Check for new alerts
                try:
                    alert = self.analyzer.alert_queue.get_nowait()

                    # Log alert
                    self.logger.warning(
                        f"🚨 {alert.severity.upper()} vulnerability detected: "
                        f"{alert.vulnerability_type} in {alert.file_path}:{alert.line_number}"
                    )

                    # Broadcast to clients
                    await self.notifications.broadcast_alert(alert)

                except:
                    await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
                await asyncio.sleep(1)

    async def _log_statistics(self):
        """Log system statistics periodically"""
        while self.running:
            try:
                await asyncio.sleep(self.stats_interval)

                stats = self.analyzer.get_statistics()
                memory_usage = psutil.Process().memory_info().rss / 1024 / 1024  # MB

                self.logger.info(
                    f"📊 Stats - Analyses: {stats['analyses_completed']}, "
                    f"Avg time: {stats['average_analysis_time_ms']:.1f}ms, "
                    f"Rate: {stats['analyses_per_second']:.1f}/s, "
                    f"Memory: {memory_usage:.1f}MB"
                )

            except Exception as e:
                self.logger.error(f"Statistics logging error: {e}")

async def main():
    """Main entry point"""
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start system
    system = VulnHunterRealtimeSystem()
    await system.start()

if __name__ == "__main__":
    print("🔍 VulnHunter Ω Real-time Monitoring System")
    print("=" * 50)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)