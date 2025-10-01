"""
Intelligent Fuzzing Orchestration Engine

This module provides comprehensive fuzzing orchestration with:
- Multi-target fuzzing coordination
- AFL++ integration and optimization
- ML-driven input generation
- Resource allocation and scheduling
- Performance monitoring and optimization
"""

import os
import subprocess
import multiprocessing
import threading
import time
import signal
import json
import logging
import shutil
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict, deque
import hashlib
import pickle
import tempfile

class FuzzingStatus(Enum):
    """Fuzzing campaign status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CRASHED = "crashed"

class FuzzerType(Enum):
    """Types of fuzzers"""
    AFL_PLUS_PLUS = "afl++"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    CUSTOM_ML = "custom_ml"
    HYBRID = "hybrid"

@dataclass
class FuzzingTarget:
    """Represents a fuzzing target"""
    target_id: str
    binary_path: str
    command_line: List[str]
    input_type: str
    timeout: int = 5
    memory_limit: str = "200M"
    dictionary_path: Optional[str] = None
    seed_corpus_path: Optional[str] = None
    output_dir: Optional[str] = None
    instrumentation_type: str = "source"
    priority: int = 1
    max_runtime: int = 3600
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FuzzingCampaign:
    """Represents a fuzzing campaign"""
    campaign_id: str
    targets: List[FuzzingTarget]
    fuzzer_configs: Dict[FuzzerType, Dict[str, Any]]
    resource_allocation: Dict[str, Any]
    strategy: str = "parallel"
    max_total_runtime: int = 86400
    status: FuzzingStatus = FuzzingStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    results_dir: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FuzzingResult:
    """Results from a fuzzing session"""
    target_id: str
    fuzzer_type: FuzzerType
    total_executions: int
    crashes_found: int
    unique_crashes: int
    coverage_achieved: float
    runtime_seconds: int
    paths_found: int
    hangs_found: int
    crash_details: List[Dict[str, Any]]
    coverage_map: Optional[bytes] = None
    performance_metrics: Dict[str, float] = field(default_factory=dict)

class MLInputGenerator(nn.Module):
    """Neural network for generating fuzzing inputs"""

    def __init__(self, input_dim: int = 256, hidden_dim: int = 512, output_dim: int = 1024):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

        self.generator = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, output_dim),
            nn.Tanh()
        )

        self.coverage_predictor = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, seed_input, coverage_feedback=None):
        encoded = self.encoder(seed_input)
        generated = self.generator(encoded)
        coverage_pred = self.coverage_predictor(encoded)

        return {
            'generated_input': generated,
            'coverage_prediction': coverage_pred,
            'features': encoded
        }

class AFLPlusPlusManager:
    """Manager for AFL++ fuzzing instances"""

    def __init__(self):
        self.active_instances = {}
        self.instance_configs = {}
        self.performance_monitor = {}

    def setup_afl_environment(self, target: FuzzingTarget) -> bool:
        """Setup AFL++ environment for target"""
        try:
            if not shutil.which('afl-fuzz'):
                logging.error("AFL++ not found. Please install AFL++")
                return False

            output_dir = target.output_dir or f"/tmp/afl_output_{target.target_id}"
            os.makedirs(output_dir, exist_ok=True)

            if target.seed_corpus_path and os.path.exists(target.seed_corpus_path):
                corpus_dir = f"{output_dir}/corpus"
                if os.path.exists(corpus_dir):
                    shutil.rmtree(corpus_dir)
                shutil.copytree(target.seed_corpus_path, corpus_dir)
            else:
                corpus_dir = f"{output_dir}/corpus"
                os.makedirs(corpus_dir, exist_ok=True)
                with open(f"{corpus_dir}/seed1", "wb") as f:
                    f.write(b"FUZZ")

            target.output_dir = output_dir
            return True

        except Exception as e:
            logging.error(f"Failed to setup AFL++ environment: {e}")
            return False

    def start_afl_instance(self, target: FuzzingTarget, instance_id: int = 0) -> Optional[subprocess.Popen]:
        """Start AFL++ fuzzing instance"""
        try:
            if not self.setup_afl_environment(target):
                return None

            cmd = [
                'afl-fuzz',
                '-i', f"{target.output_dir}/corpus",
                '-o', f"{target.output_dir}/findings",
                '-t', str(target.timeout * 1000),
                '-m', target.memory_limit,
            ]

            if target.dictionary_path and os.path.exists(target.dictionary_path):
                cmd.extend(['-x', target.dictionary_path])

            if instance_id == 0:
                cmd.extend(['-M', f'main_{target.target_id}'])
            else:
                cmd.extend(['-S', f'secondary_{target.target_id}_{instance_id}'])

            cmd.append('--')
            cmd.extend(target.command_line)

            env = os.environ.copy()
            env['AFL_SKIP_CPUFREQ'] = '1'
            env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'

            process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )

            instance_key = f"{target.target_id}_{instance_id}"
            self.active_instances[instance_key] = process
            self.instance_configs[instance_key] = {
                'target': target,
                'instance_id': instance_id,
                'start_time': time.time(),
                'command': cmd
            }

            logging.info(f"Started AFL++ instance {instance_key}")
            return process

        except Exception as e:
            logging.error(f"Failed to start AFL++ instance: {e}")
            return None

    def stop_afl_instance(self, instance_key: str) -> bool:
        """Stop AFL++ instance"""
        try:
            if instance_key in self.active_instances:
                process = self.active_instances[instance_key]

                os.killpg(os.getpgid(process.pid), signal.SIGTERM)

                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    process.wait()

                del self.active_instances[instance_key]
                del self.instance_configs[instance_key]

                logging.info(f"Stopped AFL++ instance {instance_key}")
                return True

        except Exception as e:
            logging.error(f"Failed to stop AFL++ instance {instance_key}: {e}")

        return False

    def get_afl_stats(self, target: FuzzingTarget) -> Dict[str, Any]:
        """Get AFL++ statistics for target"""
        try:
            stats_file = f"{target.output_dir}/findings/main_{target.target_id}/fuzzer_stats"

            if not os.path.exists(stats_file):
                return {}

            stats = {}
            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        key = key.strip()
                        value = value.strip()

                        try:
                            if value.isdigit():
                                stats[key] = int(value)
                            elif '.' in value and value.replace('.', '').isdigit():
                                stats[key] = float(value)
                            else:
                                stats[key] = value
                        except ValueError:
                            stats[key] = value

            return stats

        except Exception as e:
            logging.error(f"Failed to get AFL++ stats: {e}")
            return {}

    def collect_afl_crashes(self, target: FuzzingTarget) -> List[Dict[str, Any]]:
        """Collect crash information from AFL++"""
        crashes = []

        try:
            crashes_dir = f"{target.output_dir}/findings/main_{target.target_id}/crashes"

            if not os.path.exists(crashes_dir):
                return crashes

            for crash_file in os.listdir(crashes_dir):
                if crash_file.startswith('id:'):
                    crash_path = os.path.join(crashes_dir, crash_file)

                    crash_info = {
                        'filename': crash_file,
                        'path': crash_path,
                        'size': os.path.getsize(crash_path),
                        'timestamp': os.path.getmtime(crash_path)
                    }

                    try:
                        with open(crash_path, 'rb') as f:
                            crash_info['content_hash'] = hashlib.md5(f.read()).hexdigest()
                    except:
                        crash_info['content_hash'] = 'unknown'

                    crashes.append(crash_info)

        except Exception as e:
            logging.error(f"Failed to collect AFL++ crashes: {e}")

        return crashes

class ResourceManager:
    """Manages fuzzing resources and allocation"""

    def __init__(self):
        self.cpu_cores = multiprocessing.cpu_count()
        self.available_memory = self._get_available_memory()
        self.allocated_resources = {}
        self.resource_limits = {
            'max_cpu_per_target': 0.8,
            'max_memory_per_target': 0.6,
            'max_concurrent_targets': 4
        }

    def _get_available_memory(self) -> int:
        """Get available system memory in MB"""
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemAvailable:'):
                        return int(line.split()[1]) // 1024
        except:
            pass

        return 8192

    def allocate_resources(self, campaign: FuzzingCampaign) -> Dict[str, Dict[str, Any]]:
        """Allocate resources for fuzzing campaign"""
        allocation = {}

        num_targets = len(campaign.targets)
        max_targets = min(num_targets, self.resource_limits['max_concurrent_targets'])

        for i, target in enumerate(campaign.targets[:max_targets]):
            target_allocation = {
                'cpu_cores': max(1, self.cpu_cores // max_targets),
                'memory_mb': min(
                    self.available_memory // max_targets,
                    int(self.available_memory * self.resource_limits['max_memory_per_target'])
                ),
                'priority': target.priority,
                'instances': self._calculate_instances(target, max_targets)
            }

            allocation[target.target_id] = target_allocation
            self.allocated_resources[target.target_id] = target_allocation

        return allocation

    def _calculate_instances(self, target: FuzzingTarget, max_targets: int) -> int:
        """Calculate number of fuzzing instances for target"""
        base_instances = max(1, self.cpu_cores // (max_targets * 2))

        if target.priority > 3:
            return min(base_instances * 2, 4)
        elif target.priority > 1:
            return base_instances
        else:
            return 1

    def monitor_resource_usage(self) -> Dict[str, float]:
        """Monitor current resource usage"""
        try:
            import psutil

            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io': psutil.disk_io_counters().read_bytes + psutil.disk_io_counters().write_bytes
            }
        except ImportError:
            return {
                'cpu_percent': 50.0,
                'memory_percent': 30.0,
                'disk_io': 0
            }

class FuzzingOrchestrator:
    """Main fuzzing orchestration engine"""

    def __init__(self, work_dir: str = "/tmp/fuzzing_orchestrator"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)

        self.afl_manager = AFLPlusPlusManager()
        self.resource_manager = ResourceManager()
        self.ml_generator = MLInputGenerator()

        self.active_campaigns = {}
        self.campaign_results = {}
        self.performance_history = defaultdict(list)

        self.monitoring_thread = None
        self.monitoring_active = False

    def create_campaign(self, targets: List[FuzzingTarget],
                       strategy: str = "parallel",
                       max_runtime: int = 86400) -> str:
        """Create new fuzzing campaign"""
        campaign_id = f"campaign_{int(time.time())}_{len(self.active_campaigns)}"

        fuzzer_configs = {
            FuzzerType.AFL_PLUS_PLUS: {
                'timeout': 5000,
                'memory_limit': '200M',
                'deterministic_mode': False,
                'havoc_mode': True
            }
        }

        campaign = FuzzingCampaign(
            campaign_id=campaign_id,
            targets=targets,
            fuzzer_configs=fuzzer_configs,
            resource_allocation={},
            strategy=strategy,
            max_total_runtime=max_runtime,
            results_dir=str(self.work_dir / campaign_id)
        )

        os.makedirs(campaign.results_dir, exist_ok=True)

        resource_allocation = self.resource_manager.allocate_resources(campaign)
        campaign.resource_allocation = resource_allocation

        self.active_campaigns[campaign_id] = campaign

        logging.info(f"Created fuzzing campaign {campaign_id} with {len(targets)} targets")
        return campaign_id

    def start_campaign(self, campaign_id: str) -> bool:
        """Start fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            logging.error(f"Campaign {campaign_id} not found")
            return False

        campaign = self.active_campaigns[campaign_id]

        try:
            campaign.status = FuzzingStatus.RUNNING
            campaign.start_time = time.time()

            for target in campaign.targets:
                if target.target_id in campaign.resource_allocation:
                    allocation = campaign.resource_allocation[target.target_id]

                    target.output_dir = os.path.join(campaign.results_dir, target.target_id)
                    os.makedirs(target.output_dir, exist_ok=True)

                    for instance_id in range(allocation['instances']):
                        process = self.afl_manager.start_afl_instance(target, instance_id)
                        if process is None:
                            logging.error(f"Failed to start fuzzing for target {target.target_id}")
                            continue

            if not self.monitoring_active:
                self.start_monitoring()

            logging.info(f"Started fuzzing campaign {campaign_id}")
            return True

        except Exception as e:
            logging.error(f"Failed to start campaign {campaign_id}: {e}")
            campaign.status = FuzzingStatus.FAILED
            return False

    def stop_campaign(self, campaign_id: str) -> bool:
        """Stop fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            return False

        campaign = self.active_campaigns[campaign_id]

        try:
            for target in campaign.targets:
                for instance_id in range(campaign.resource_allocation.get(target.target_id, {}).get('instances', 1)):
                    instance_key = f"{target.target_id}_{instance_id}"
                    self.afl_manager.stop_afl_instance(instance_key)

            campaign.status = FuzzingStatus.COMPLETED
            campaign.end_time = time.time()

            results = self.collect_campaign_results(campaign_id)
            self.campaign_results[campaign_id] = results

            logging.info(f"Stopped fuzzing campaign {campaign_id}")
            return True

        except Exception as e:
            logging.error(f"Failed to stop campaign {campaign_id}: {e}")
            return False

    def pause_campaign(self, campaign_id: str) -> bool:
        """Pause fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            return False

        campaign = self.active_campaigns[campaign_id]

        try:
            for instance_key in list(self.afl_manager.active_instances.keys()):
                if campaign_id in instance_key:
                    process = self.afl_manager.active_instances[instance_key]
                    os.kill(process.pid, signal.SIGSTOP)

            campaign.status = FuzzingStatus.PAUSED
            logging.info(f"Paused fuzzing campaign {campaign_id}")
            return True

        except Exception as e:
            logging.error(f"Failed to pause campaign {campaign_id}: {e}")
            return False

    def resume_campaign(self, campaign_id: str) -> bool:
        """Resume paused fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            return False

        campaign = self.active_campaigns[campaign_id]

        if campaign.status != FuzzingStatus.PAUSED:
            return False

        try:
            for instance_key in list(self.afl_manager.active_instances.keys()):
                if campaign_id in instance_key:
                    process = self.afl_manager.active_instances[instance_key]
                    os.kill(process.pid, signal.SIGCONT)

            campaign.status = FuzzingStatus.RUNNING
            logging.info(f"Resumed fuzzing campaign {campaign_id}")
            return True

        except Exception as e:
            logging.error(f"Failed to resume campaign {campaign_id}: {e}")
            return False

    def collect_campaign_results(self, campaign_id: str) -> Dict[str, FuzzingResult]:
        """Collect results from fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            return {}

        campaign = self.active_campaigns[campaign_id]
        results = {}

        for target in campaign.targets:
            try:
                stats = self.afl_manager.get_afl_stats(target)
                crashes = self.afl_manager.collect_afl_crashes(target)

                result = FuzzingResult(
                    target_id=target.target_id,
                    fuzzer_type=FuzzerType.AFL_PLUS_PLUS,
                    total_executions=stats.get('execs_done', 0),
                    crashes_found=len(crashes),
                    unique_crashes=len(set(c['content_hash'] for c in crashes)),
                    coverage_achieved=float(stats.get('bitmap_cvg', 0)),
                    runtime_seconds=int(time.time() - campaign.start_time),
                    paths_found=stats.get('paths_found', 0),
                    hangs_found=stats.get('hangs_found', 0),
                    crash_details=crashes,
                    performance_metrics={
                        'exec_speed': stats.get('exec_speed', 0),
                        'stability': stats.get('stability', 0),
                        'pending_favs': stats.get('pending_favs', 0)
                    }
                )

                results[target.target_id] = result

            except Exception as e:
                logging.error(f"Failed to collect results for target {target.target_id}: {e}")

        return results

    def start_monitoring(self):
        """Start monitoring thread for campaigns"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()

    def stop_monitoring(self):
        """Stop monitoring thread"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_campaign_timeouts()
                self._collect_performance_metrics()
                self._optimize_resource_allocation()

                time.sleep(30)

            except Exception as e:
                logging.error(f"Monitoring error: {e}")
                time.sleep(60)

    def _check_campaign_timeouts(self):
        """Check for campaign timeouts"""
        current_time = time.time()

        for campaign_id, campaign in list(self.active_campaigns.items()):
            if campaign.status == FuzzingStatus.RUNNING and campaign.start_time:
                runtime = current_time - campaign.start_time

                if runtime > campaign.max_total_runtime:
                    logging.info(f"Campaign {campaign_id} timed out after {runtime:.1f} seconds")
                    self.stop_campaign(campaign_id)

    def _collect_performance_metrics(self):
        """Collect performance metrics for active campaigns"""
        resource_usage = self.resource_manager.monitor_resource_usage()

        for campaign_id, campaign in self.active_campaigns.items():
            if campaign.status == FuzzingStatus.RUNNING:
                campaign_metrics = {
                    'timestamp': time.time(),
                    'resource_usage': resource_usage,
                    'active_targets': len(campaign.targets),
                    'total_instances': sum(
                        alloc.get('instances', 0)
                        for alloc in campaign.resource_allocation.values()
                    )
                }

                self.performance_history[campaign_id].append(campaign_metrics)

    def _optimize_resource_allocation(self):
        """Optimize resource allocation based on performance"""
        for campaign_id, campaign in self.active_campaigns.items():
            if campaign.status != FuzzingStatus.RUNNING:
                continue

            try:
                for target in campaign.targets:
                    stats = self.afl_manager.get_afl_stats(target)
                    exec_speed = stats.get('exec_speed', 0)

                    if exec_speed < 100:
                        logging.warning(f"Low execution speed for target {target.target_id}: {exec_speed} exec/s")

            except Exception as e:
                logging.error(f"Resource optimization error: {e}")

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get status of fuzzing campaign"""
        if campaign_id not in self.active_campaigns:
            return None

        campaign = self.active_campaigns[campaign_id]

        status_info = {
            'campaign_id': campaign_id,
            'status': campaign.status.value,
            'targets': len(campaign.targets),
            'start_time': campaign.start_time,
            'runtime': time.time() - campaign.start_time if campaign.start_time else 0,
            'max_runtime': campaign.max_total_runtime,
            'resource_allocation': campaign.resource_allocation
        }

        if campaign.status == FuzzingStatus.RUNNING:
            target_stats = {}
            for target in campaign.targets:
                stats = self.afl_manager.get_afl_stats(target)
                target_stats[target.target_id] = stats

            status_info['target_statistics'] = target_stats

        return status_info

    def generate_campaign_report(self, campaign_id: str) -> str:
        """Generate comprehensive campaign report"""
        if campaign_id not in self.active_campaigns:
            return f"Campaign {campaign_id} not found"

        campaign = self.active_campaigns[campaign_id]
        results = self.campaign_results.get(campaign_id, self.collect_campaign_results(campaign_id))

        report = []
        report.append(f"Fuzzing Campaign Report: {campaign_id}")
        report.append("=" * 50)
        report.append(f"Status: {campaign.status.value}")
        report.append(f"Strategy: {campaign.strategy}")
        report.append(f"Total Targets: {len(campaign.targets)}")

        if campaign.start_time:
            runtime = (campaign.end_time or time.time()) - campaign.start_time
            report.append(f"Runtime: {runtime:.1f} seconds")

        report.append("")

        if results:
            total_executions = sum(r.total_executions for r in results.values())
            total_crashes = sum(r.crashes_found for r in results.values())
            total_unique_crashes = sum(r.unique_crashes for r in results.values())

            report.append("Overall Results:")
            report.append(f"  Total Executions: {total_executions:,}")
            report.append(f"  Total Crashes: {total_crashes}")
            report.append(f"  Unique Crashes: {total_unique_crashes}")
            report.append("")

            report.append("Target Results:")
            for target_id, result in results.items():
                report.append(f"  {target_id}:")
                report.append(f"    Executions: {result.total_executions:,}")
                report.append(f"    Crashes: {result.crashes_found}")
                report.append(f"    Unique Crashes: {result.unique_crashes}")
                report.append(f"    Coverage: {result.coverage_achieved:.2f}%")
                report.append(f"    Paths Found: {result.paths_found}")
                report.append(f"    Exec Speed: {result.performance_metrics.get('exec_speed', 0):.1f}/s")
                report.append("")

        return "\n".join(report)