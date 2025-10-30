#!/usr/bin/env python3
"""
VulnHunter Ω Real-Time Monitoring System
Advanced real-time code monitoring with live vulnerability detection

Features:
- File system monitoring using watchdog
- Real-time vulnerability analysis
- WebSocket-based live updates
- Git integration for commit analysis
- IDE plugin support
- Configurable monitoring rules
- Performance metrics and alerting
"""

import os
import sys
import json
import time
import logging
import asyncio
import threading
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta
import hashlib

# File monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

# Web server for real-time updates
from http.server import HTTPServer, BaseHTTPRequestHandler
import websockets
import json
from urllib.parse import parse_qs, urlparse

# Git integration
import subprocess

# Core VulnHunter components
try:
    from vulnhunter_production_platform import VulnHunterProductionPlatform
    from vulnhunter_transformer_lite import VulnHunterTransformerLiteEngine
except ImportError:
    logging.warning("Could not import VulnHunter components. Using fallback analysis.")

# Scientific computing
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@dataclass
class MonitoringConfig:
    """Configuration for real-time monitoring"""
    watch_directories: List[str]
    file_extensions: List[str] = None
    excluded_directories: List[str] = None
    max_file_size_mb: int = 50
    analysis_timeout_seconds: int = 30
    websocket_port: int = 8765
    http_port: int = 8080
    enable_git_hooks: bool = True
    enable_ide_integration: bool = True
    alert_threshold: float = 0.8
    batch_analysis_delay: float = 2.0  # Seconds to wait before batch processing
    max_concurrent_analyses: int = 5

    def __post_init__(self):
        if self.file_extensions is None:
            self.file_extensions = [
                '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp',
                '.sol', '.php', '.rb', '.go', '.rs', '.cs', '.swift',
                '.scala', '.kt', '.dart'
            ]
        if self.excluded_directories is None:
            self.excluded_directories = [
                '.git', '.svn', '.hg', 'node_modules', '__pycache__',
                '.venv', 'venv', 'env', 'build', 'dist', 'target'
            ]

@dataclass
class AnalysisResult:
    """Result of real-time analysis"""
    file_path: str
    timestamp: datetime
    vulnerability_detected: bool
    confidence: float
    vulnerability_type: str
    risk_level: str
    analysis_time: float
    file_hash: str
    line_numbers: List[int] = None
    details: Dict[str, Any] = None

@dataclass
class MonitoringStats:
    """Monitoring statistics"""
    files_monitored: int = 0
    total_analyses: int = 0
    vulnerabilities_detected: int = 0
    false_positives: int = 0
    average_analysis_time: float = 0.0
    start_time: datetime = None
    last_analysis_time: datetime = None

class VulnHunterFileHandler(FileSystemEventHandler):
    """File system event handler for real-time monitoring"""

    def __init__(self, monitor: 'VulnHunterRealTimeMonitor'):
        self.monitor = monitor
        self.config = monitor.config
        self.logger = logging.getLogger(self.__class__.__name__)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_change(event.src_path, 'modified')

    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_change(event.src_path, 'created')

    def _handle_file_change(self, file_path: str, event_type: str):
        """Handle file change events"""
        try:
            # Check if file should be monitored
            if not self._should_monitor_file(file_path):
                return

            # Check file size
            if os.path.getsize(file_path) > self.config.max_file_size_mb * 1024 * 1024:
                self.logger.warning(f"File {file_path} exceeds size limit, skipping")
                return

            # Add to analysis queue
            self.monitor.queue_file_for_analysis(file_path, event_type)

        except Exception as e:
            self.logger.error(f"Error handling file change {file_path}: {e}")

    def _should_monitor_file(self, file_path: str) -> bool:
        """Check if file should be monitored"""
        file_path = Path(file_path)

        # Check file extension
        if file_path.suffix.lower() not in self.config.file_extensions:
            return False

        # Check excluded directories
        for excluded in self.config.excluded_directories:
            if excluded in file_path.parts:
                return False

        # Check if file exists and is readable
        if not file_path.exists() or not file_path.is_file():
            return False

        return True

class VulnHunterRealTimeMonitor:
    """
    Main real-time monitoring system for VulnHunter Ω

    Features:
    - Continuous file system monitoring
    - Real-time vulnerability analysis
    - WebSocket-based live updates
    - Performance optimization
    - Configurable monitoring rules
    """

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize analysis engines
        self.production_platform = None
        self.transformer_engine = None
        self._initialize_analysis_engines()

        # Monitoring state
        self.is_monitoring = False
        self.observer = None
        self.analysis_queue = asyncio.Queue()
        self.analysis_semaphore = asyncio.Semaphore(config.max_concurrent_analyses)

        # Results and statistics
        self.recent_results: List[AnalysisResult] = []
        self.stats = MonitoringStats(start_time=datetime.now())
        self.file_hashes: Dict[str, str] = {}  # Track file changes

        # WebSocket connections
        self.websocket_clients: Set = set()

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []

    def _initialize_analysis_engines(self):
        """Initialize VulnHunter analysis engines"""
        try:
            self.logger.info("Initializing VulnHunter analysis engines...")
            self.production_platform = VulnHunterProductionPlatform()
            self.transformer_engine = VulnHunterTransformerLiteEngine()
            self.logger.info("✅ Analysis engines initialized successfully")
        except Exception as e:
            self.logger.warning(f"Could not initialize analysis engines: {e}")
            self.logger.info("Using fallback analysis methods")

    def start_monitoring(self):
        """Start real-time monitoring"""
        self.logger.info("🚀 Starting VulnHunter Ω Real-Time Monitoring")
        self.logger.info(f"📁 Monitoring directories: {self.config.watch_directories}")
        self.logger.info(f"📄 File extensions: {self.config.file_extensions}")

        self.is_monitoring = True
        self.stats.start_time = datetime.now()

        # Start file system monitoring
        self.observer = Observer()
        handler = VulnHunterFileHandler(self)

        for directory in self.config.watch_directories:
            if os.path.exists(directory):
                self.observer.schedule(handler, directory, recursive=True)
                self.logger.info(f"👀 Watching directory: {directory}")
            else:
                self.logger.warning(f"Directory not found: {directory}")

        self.observer.start()

        # Start async event loop for analysis
        asyncio.run(self._start_async_services())

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.logger.info("🛑 Stopping VulnHunter Ω Real-Time Monitoring")

        self.is_monitoring = False

        if self.observer:
            self.observer.stop()
            self.observer.join()

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        self.logger.info("✅ Monitoring stopped successfully")

    async def _start_async_services(self):
        """Start async services (WebSocket server, analysis worker)"""
        try:
            # Start WebSocket server
            websocket_task = asyncio.create_task(
                websockets.serve(self._websocket_handler, "localhost", self.config.websocket_port)
            )
            self.background_tasks.append(websocket_task)

            # Start analysis worker
            analysis_task = asyncio.create_task(self._analysis_worker())
            self.background_tasks.append(analysis_task)

            # Start statistics updater
            stats_task = asyncio.create_task(self._stats_updater())
            self.background_tasks.append(stats_task)

            self.logger.info(f"🌐 WebSocket server started on port {self.config.websocket_port}")
            self.logger.info("🔄 Analysis worker started")

            # Keep services running
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
            self.stop_monitoring()
        except Exception as e:
            self.logger.error(f"Error in async services: {e}")
            self.stop_monitoring()

    async def _websocket_handler(self, websocket, path):
        """Handle WebSocket connections"""
        self.websocket_clients.add(websocket)
        self.logger.info(f"🔌 New WebSocket client connected: {websocket.remote_address}")

        try:
            # Send initial status
            await self._send_to_client(websocket, {
                'type': 'status',
                'data': {
                    'monitoring': self.is_monitoring,
                    'stats': asdict(self.stats),
                    'recent_results': [asdict(r) for r in self.recent_results[-10:]]
                }
            })

            # Keep connection alive
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self._handle_websocket_message(websocket, data)
                except json.JSONDecodeError:
                    await self._send_to_client(websocket, {'type': 'error', 'message': 'Invalid JSON'})

        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"🔌 WebSocket client disconnected: {websocket.remote_address}")
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            self.websocket_clients.discard(websocket)

    async def _handle_websocket_message(self, websocket, data):
        """Handle WebSocket messages from clients"""
        message_type = data.get('type')

        if message_type == 'analyze_file':
            file_path = data.get('file_path')
            if file_path and os.path.exists(file_path):
                self.queue_file_for_analysis(file_path, 'manual')
                await self._send_to_client(websocket, {
                    'type': 'analysis_queued',
                    'file_path': file_path
                })
            else:
                await self._send_to_client(websocket, {
                    'type': 'error',
                    'message': 'File not found'
                })

        elif message_type == 'get_stats':
            await self._send_to_client(websocket, {
                'type': 'stats',
                'data': asdict(self.stats)
            })

        elif message_type == 'get_recent_results':
            await self._send_to_client(websocket, {
                'type': 'recent_results',
                'data': [asdict(r) for r in self.recent_results[-20:]]
            })

    async def _send_to_client(self, websocket, message):
        """Send message to WebSocket client"""
        try:
            await websocket.send(json.dumps(message, default=str))
        except Exception as e:
            self.logger.error(f"Error sending to WebSocket client: {e}")

    async def _broadcast_to_clients(self, message):
        """Broadcast message to all WebSocket clients"""
        if self.websocket_clients:
            await asyncio.gather(
                *[self._send_to_client(client, message) for client in self.websocket_clients],
                return_exceptions=True
            )

    def queue_file_for_analysis(self, file_path: str, event_type: str):
        """Queue file for analysis"""
        # Check if file content has changed
        current_hash = self._calculate_file_hash(file_path)
        if current_hash is None:
            return

        previous_hash = self.file_hashes.get(file_path)
        if previous_hash == current_hash:
            return  # File content hasn't changed

        self.file_hashes[file_path] = current_hash

        # Add to queue
        asyncio.create_task(self.analysis_queue.put({
            'file_path': file_path,
            'event_type': event_type,
            'hash': current_hash,
            'timestamp': datetime.now()
        }))

        self.logger.debug(f"📝 Queued file for analysis: {file_path} ({event_type})")

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate hash of file content"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            self.logger.warning(f"Could not calculate hash for {file_path}: {e}")
            return None

    async def _analysis_worker(self):
        """Background worker for processing analysis queue"""
        while self.is_monitoring:
            try:
                # Wait for files to analyze
                file_info = await asyncio.wait_for(self.analysis_queue.get(), timeout=1.0)

                # Use semaphore to limit concurrent analyses
                async with self.analysis_semaphore:
                    await self._analyze_file_async(file_info)

            except asyncio.TimeoutError:
                continue  # No files to analyze, continue loop
            except Exception as e:
                self.logger.error(f"Error in analysis worker: {e}")

    async def _analyze_file_async(self, file_info: Dict[str, Any]):
        """Analyze file asynchronously"""
        file_path = file_info['file_path']
        event_type = file_info['event_type']
        file_hash = file_info['hash']

        start_time = time.time()

        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            # Perform analysis
            if self.production_platform:
                # Use production platform for comprehensive analysis
                result = await asyncio.to_thread(
                    self.production_platform.analyze_vulnerability_production,
                    code_content,
                    'quick',
                    {'timeout': self.config.analysis_timeout_seconds}
                )
            elif self.transformer_engine:
                # Use transformer engine
                result = await asyncio.to_thread(
                    self.transformer_engine.analyze_code_transformer,
                    code_content
                )
            else:
                # Fallback analysis
                result = self._fallback_analysis(code_content)

            analysis_time = time.time() - start_time

            # Create analysis result
            analysis_result = AnalysisResult(
                file_path=file_path,
                timestamp=datetime.now(),
                vulnerability_detected=result.get('vulnerability_detected', False),
                confidence=result.get('confidence', 0.0),
                vulnerability_type=result.get('vulnerability_type', 'unknown'),
                risk_level=self._calculate_risk_level(result.get('confidence', 0.0)),
                analysis_time=analysis_time,
                file_hash=file_hash,
                details=result
            )

            # Update statistics
            self.stats.total_analyses += 1
            self.stats.last_analysis_time = datetime.now()
            if analysis_result.vulnerability_detected:
                self.stats.vulnerabilities_detected += 1

            # Update average analysis time
            if self.stats.total_analyses > 0:
                self.stats.average_analysis_time = (
                    (self.stats.average_analysis_time * (self.stats.total_analyses - 1) + analysis_time) /
                    self.stats.total_analyses
                )

            # Store result
            self.recent_results.append(analysis_result)
            if len(self.recent_results) > 1000:  # Keep only recent results
                self.recent_results = self.recent_results[-1000:]

            # Log result
            status = "🚨 VULNERABLE" if analysis_result.vulnerability_detected else "✅ SAFE"
            self.logger.info(
                f"{status} | {file_path} | "
                f"Confidence: {analysis_result.confidence:.3f} | "
                f"Type: {analysis_result.vulnerability_type} | "
                f"Time: {analysis_time:.3f}s"
            )

            # Broadcast to WebSocket clients
            await self._broadcast_to_clients({
                'type': 'analysis_result',
                'data': asdict(analysis_result)
            })

            # Check for high-risk vulnerabilities
            if analysis_result.vulnerability_detected and analysis_result.confidence >= self.config.alert_threshold:
                await self._send_alert(analysis_result)

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")

    def _fallback_analysis(self, code: str) -> Dict[str, Any]:
        """Fallback analysis using pattern matching"""
        import re

        vulnerability_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'injection': [r'execute\s*\(\s*["\'].*\+.*["\']', r'eval\s*\('],
            'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
            'reentrancy': [r'\.call\s*\{.*value.*\}', r'\.send\s*\('],
            'access_control': [r'require\s*\(\s*msg\.sender\s*==', r'onlyOwner']
        }

        detected_vulnerabilities = []
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detected_vulnerabilities.append(vuln_type)
                    break

        vulnerability_detected = len(detected_vulnerabilities) > 0
        primary_vuln = detected_vulnerabilities[0] if detected_vulnerabilities else 'buffer_overflow'

        return {
            'vulnerability_detected': vulnerability_detected,
            'confidence': 0.8 if vulnerability_detected else 0.2,
            'vulnerability_type': primary_vuln,
            'detected_patterns': detected_vulnerabilities,
            'analysis_method': 'pattern_matching_fallback'
        }

    def _calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level based on confidence"""
        if confidence >= 0.8:
            return 'HIGH'
        elif confidence >= 0.6:
            return 'MEDIUM'
        elif confidence >= 0.3:
            return 'LOW'
        else:
            return 'MINIMAL'

    async def _send_alert(self, result: AnalysisResult):
        """Send alert for high-risk vulnerabilities"""
        alert_message = {
            'type': 'alert',
            'severity': 'high',
            'data': {
                'message': f"High-risk vulnerability detected in {result.file_path}",
                'vulnerability_type': result.vulnerability_type,
                'confidence': result.confidence,
                'risk_level': result.risk_level,
                'timestamp': result.timestamp,
                'file_path': result.file_path
            }
        }

        # Broadcast alert
        await self._broadcast_to_clients(alert_message)

        # Log alert
        self.logger.warning(
            f"🚨 HIGH RISK ALERT: {result.vulnerability_type} in {result.file_path} "
            f"(confidence: {result.confidence:.3f})"
        )

    async def _stats_updater(self):
        """Background task to update monitoring statistics"""
        while self.is_monitoring:
            try:
                # Update file count
                total_files = 0
                for directory in self.config.watch_directories:
                    if os.path.exists(directory):
                        for ext in self.config.file_extensions:
                            pattern = f"**/*{ext}"
                            files = list(Path(directory).glob(pattern))
                            total_files += len(files)

                self.stats.files_monitored = total_files

                # Broadcast updated stats
                await self._broadcast_to_clients({
                    'type': 'stats_update',
                    'data': asdict(self.stats)
                })

                # Wait before next update
                await asyncio.sleep(30)  # Update every 30 seconds

            except Exception as e:
                self.logger.error(f"Error in stats updater: {e}")
                await asyncio.sleep(60)  # Longer wait on error

    def generate_monitoring_report(self) -> Dict[str, Any]:
        """Generate comprehensive monitoring report"""
        uptime = datetime.now() - self.stats.start_time if self.stats.start_time else timedelta(0)

        # Calculate detection rate
        detection_rate = (
            self.stats.vulnerabilities_detected / self.stats.total_analyses
            if self.stats.total_analyses > 0 else 0.0
        )

        # Group results by vulnerability type
        vuln_type_counts = {}
        for result in self.recent_results:
            if result.vulnerability_detected:
                vuln_type = result.vulnerability_type
                vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        # Calculate performance metrics
        analysis_times = [r.analysis_time for r in self.recent_results]
        avg_analysis_time = np.mean(analysis_times) if analysis_times else 0.0
        max_analysis_time = max(analysis_times) if analysis_times else 0.0
        min_analysis_time = min(analysis_times) if analysis_times else 0.0

        return {
            'monitoring_period': {
                'start_time': self.stats.start_time,
                'uptime_seconds': uptime.total_seconds(),
                'uptime_formatted': str(uptime)
            },
            'analysis_statistics': {
                'total_analyses': self.stats.total_analyses,
                'vulnerabilities_detected': self.stats.vulnerabilities_detected,
                'detection_rate': detection_rate,
                'false_positives': self.stats.false_positives,
                'files_monitored': self.stats.files_monitored
            },
            'performance_metrics': {
                'average_analysis_time': avg_analysis_time,
                'max_analysis_time': max_analysis_time,
                'min_analysis_time': min_analysis_time,
                'analyses_per_hour': (
                    self.stats.total_analyses / (uptime.total_seconds() / 3600)
                    if uptime.total_seconds() > 0 else 0.0
                )
            },
            'vulnerability_breakdown': vuln_type_counts,
            'recent_high_risk_vulnerabilities': [
                asdict(r) for r in self.recent_results
                if r.vulnerability_detected and r.confidence >= 0.8
            ][-10:],  # Last 10 high-risk vulnerabilities
            'configuration': asdict(self.config)
        }

class MonitoringDashboard:
    """Simple HTTP dashboard for monitoring"""

    def __init__(self, monitor: VulnHunterRealTimeMonitor, port: int = 8080):
        self.monitor = monitor
        self.port = port

    def start_dashboard(self):
        """Start HTTP dashboard"""
        class DashboardHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self._generate_dashboard_html().encode())
                elif self.path == '/api/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    stats = asdict(self.monitor.stats)
                    self.wfile.write(json.dumps(stats, default=str).encode())
                elif self.path == '/api/report':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    report = self.monitor.generate_monitoring_report()
                    self.wfile.write(json.dumps(report, default=str).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def _generate_dashboard_html(self):
                return '''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>VulnHunter Ω Real-Time Monitor</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                        .container { max-width: 1200px; margin: 0 auto; }
                        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
                        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
                        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                        .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
                        .stat-label { color: #7f8c8d; margin-top: 5px; }
                        .results { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
                        .vulnerable { color: #e74c3c; font-weight: bold; }
                        .safe { color: #27ae60; font-weight: bold; }
                        .refresh-btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🚀 VulnHunter Ω Real-Time Monitor</h1>
                            <p>Advanced vulnerability detection with real-time monitoring</p>
                        </div>

                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-value" id="totalAnalyses">0</div>
                                <div class="stat-label">Total Analyses</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="vulnerabilitiesDetected">0</div>
                                <div class="stat-label">Vulnerabilities Detected</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="filesMonitored">0</div>
                                <div class="stat-label">Files Monitored</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value" id="avgAnalysisTime">0.0s</div>
                                <div class="stat-label">Avg Analysis Time</div>
                            </div>
                        </div>

                        <div class="results">
                            <h3>Recent Analysis Results</h3>
                            <button class="refresh-btn" onclick="refreshData()">Refresh</button>
                            <div id="recentResults">Loading...</div>
                        </div>
                    </div>

                    <script>
                        function refreshData() {
                            fetch('/api/stats')
                                .then(response => response.json())
                                .then(data => {
                                    document.getElementById('totalAnalyses').textContent = data.total_analyses;
                                    document.getElementById('vulnerabilitiesDetected').textContent = data.vulnerabilities_detected;
                                    document.getElementById('filesMonitored').textContent = data.files_monitored;
                                    document.getElementById('avgAnalysisTime').textContent = data.average_analysis_time.toFixed(3) + 's';
                                });
                        }

                        // Auto-refresh every 5 seconds
                        setInterval(refreshData, 5000);
                        refreshData();
                    </script>
                </body>
                </html>
                '''

        server = HTTPServer(('localhost', self.port), DashboardHandler)
        logging.info(f"🌐 Dashboard available at http://localhost:{self.port}")
        server.serve_forever()

def main():
    """Main function for running real-time monitor"""

    print("🚀 Initializing VulnHunter Ω Real-Time Monitor...")

    # Configuration
    config = MonitoringConfig(
        watch_directories=[
            ".",  # Current directory
            "scripts/",  # Scripts directory
        ],
        file_extensions=['.py', '.js', '.ts', '.java', '.c', '.cpp', '.sol'],
        max_file_size_mb=10,
        analysis_timeout_seconds=15,
        websocket_port=8765,
        http_port=8080,
        alert_threshold=0.7,
        max_concurrent_analyses=3
    )

    # Initialize monitor
    monitor = VulnHunterRealTimeMonitor(config)

    # Start dashboard in separate thread
    dashboard = MonitoringDashboard(monitor, config.http_port)
    dashboard_thread = threading.Thread(target=dashboard.start_dashboard, daemon=True)
    dashboard_thread.start()

    try:
        # Start monitoring
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")
        monitor.stop_monitoring()
    except Exception as e:
        print(f"❌ Error: {e}")
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()