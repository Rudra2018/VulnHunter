"""
Coverage Analysis Engine

This module provides advanced coverage analysis capabilities for fuzzing:
- Real-time coverage monitoring and visualization
- Coverage-guided input prioritization
- Branch and edge coverage analysis
- Coverage correlation with vulnerability discovery
- Performance optimization based on coverage feedback
"""

import os
import struct
import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging
import json
import time
import hashlib
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import pickle

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

@dataclass
class CoverageData:
    """Represents coverage information"""
    target_id: str
    timestamp: float
    total_edges: int
    covered_edges: int
    coverage_percentage: float
    edge_bitmap: bytes
    new_edges: Set[int]
    execution_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CoverageEvolution:
    """Tracks coverage evolution over time"""
    target_id: str
    coverage_history: List[CoverageData]
    coverage_rate: float
    saturation_point: Optional[float]
    peak_coverage: float
    convergence_time: Optional[float]

class CoverageBitmapAnalyzer:
    """Analyzes AFL++ coverage bitmaps"""

    def __init__(self):
        self.bitmap_size = 65536
        self.edge_threshold = 1
        self.coverage_cache = {}

    def parse_afl_bitmap(self, bitmap_path: str) -> Optional[np.ndarray]:
        """Parse AFL++ coverage bitmap"""
        try:
            if not os.path.exists(bitmap_path):
                return None

            with open(bitmap_path, 'rb') as f:
                bitmap_data = f.read()

            if len(bitmap_data) != self.bitmap_size:
                logging.warning(f"Unexpected bitmap size: {len(bitmap_data)}")
                return None

            bitmap_array = np.frombuffer(bitmap_data, dtype=np.uint8)
            return bitmap_array

        except Exception as e:
            logging.error(f"Failed to parse AFL bitmap: {e}")
            return None

    def analyze_bitmap_differences(self, bitmap1: np.ndarray, bitmap2: np.ndarray) -> Dict[str, Any]:
        """Analyze differences between two coverage bitmaps"""
        if bitmap1.shape != bitmap2.shape:
            return {'error': 'Bitmap size mismatch'}

        diff = bitmap2 - bitmap1
        new_edges = np.where(diff > 0)[0]
        lost_edges = np.where(diff < 0)[0]

        coverage_increase = len(new_edges)
        coverage_decrease = len(lost_edges)

        return {
            'new_edges': new_edges.tolist(),
            'lost_edges': lost_edges.tolist(),
            'coverage_increase': coverage_increase,
            'coverage_decrease': coverage_decrease,
            'net_change': coverage_increase - coverage_decrease,
            'total_affected_edges': len(new_edges) + len(lost_edges)
        }

    def calculate_coverage_metrics(self, bitmap: np.ndarray) -> Dict[str, float]:
        """Calculate various coverage metrics from bitmap"""
        total_edges = len(bitmap)
        covered_edges = np.count_nonzero(bitmap > self.edge_threshold)
        coverage_percentage = (covered_edges / total_edges) * 100

        edge_density = np.mean(bitmap[bitmap > 0]) if covered_edges > 0 else 0
        coverage_entropy = self._calculate_entropy(bitmap)

        hot_edges = np.count_nonzero(bitmap > 10)
        cold_edges = np.count_nonzero((bitmap > 0) & (bitmap <= 2))

        return {
            'total_edges': total_edges,
            'covered_edges': covered_edges,
            'coverage_percentage': coverage_percentage,
            'edge_density': edge_density,
            'coverage_entropy': coverage_entropy,
            'hot_edges': hot_edges,
            'cold_edges': cold_edges,
            'hot_edge_ratio': hot_edges / max(covered_edges, 1),
            'cold_edge_ratio': cold_edges / max(covered_edges, 1)
        }

    def _calculate_entropy(self, bitmap: np.ndarray) -> float:
        """Calculate Shannon entropy of coverage bitmap"""
        try:
            non_zero = bitmap[bitmap > 0]
            if len(non_zero) == 0:
                return 0.0

            _, counts = np.unique(non_zero, return_counts=True)
            probabilities = counts / len(non_zero)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

            return entropy
        except:
            return 0.0

    def identify_coverage_patterns(self, bitmap: np.ndarray) -> Dict[str, Any]:
        """Identify patterns in coverage bitmap"""
        patterns = {
            'sequential_blocks': [],
            'sparse_regions': [],
            'dense_regions': [],
            'coverage_gaps': []
        }

        try:
            covered_indices = np.where(bitmap > 0)[0]

            if len(covered_indices) > 1:
                gaps = np.diff(covered_indices)
                large_gaps = covered_indices[1:][gaps > 100]
                patterns['coverage_gaps'] = large_gaps.tolist()

                sequential_starts = covered_indices[:-1][gaps == 1]
                if len(sequential_starts) > 0:
                    patterns['sequential_blocks'] = self._find_sequential_blocks(covered_indices)

            chunk_size = 1000
            for i in range(0, len(bitmap), chunk_size):
                chunk = bitmap[i:i+chunk_size]
                coverage_ratio = np.count_nonzero(chunk) / len(chunk)

                if coverage_ratio > 0.7:
                    patterns['dense_regions'].append((i, i+chunk_size, coverage_ratio))
                elif coverage_ratio < 0.1 and coverage_ratio > 0:
                    patterns['sparse_regions'].append((i, i+chunk_size, coverage_ratio))

        except Exception as e:
            logging.error(f"Pattern identification failed: {e}")

        return patterns

    def _find_sequential_blocks(self, indices: np.ndarray) -> List[Tuple[int, int]]:
        """Find sequential blocks in coverage indices"""
        blocks = []
        if len(indices) == 0:
            return blocks

        block_start = indices[0]
        prev_idx = indices[0]

        for idx in indices[1:]:
            if idx - prev_idx > 1:
                if prev_idx - block_start > 5:
                    blocks.append((block_start, prev_idx))
                block_start = idx

            prev_idx = idx

        if prev_idx - block_start > 5:
            blocks.append((block_start, prev_idx))

        return blocks

class CoveragePredictor(nn.Module):
    """Neural network for predicting coverage outcomes"""

    def __init__(self, input_dim: int = 1024, hidden_dim: int = 256):
        super().__init__()
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

        self.coverage_predictor = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

        self.edge_predictor = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.Softmax(dim=-1)
        )

    def forward(self, input_features):
        features = self.feature_extractor(input_features)

        coverage_pred = self.coverage_predictor(features)
        edge_distribution = self.edge_predictor(features)

        return {
            'coverage_prediction': coverage_pred,
            'edge_distribution': edge_distribution,
            'features': features
        }

class CoverageOptimizer:
    """Optimizes fuzzing based on coverage feedback"""

    def __init__(self):
        self.coverage_history = defaultdict(list)
        self.edge_importance = defaultdict(float)
        self.stagnation_threshold = 300
        self.optimization_strategies = [
            'diversify_inputs',
            'focus_on_sparse_regions',
            'exploit_recent_discoveries',
            'restart_from_high_coverage_seeds'
        ]

    def analyze_coverage_stagnation(self, target_id: str, recent_coverage: List[CoverageData]) -> Dict[str, Any]:
        """Analyze if coverage has stagnated"""
        if len(recent_coverage) < 10:
            return {'stagnated': False, 'reason': 'insufficient_data'}

        recent_percentages = [c.coverage_percentage for c in recent_coverage[-10:]]
        coverage_variance = np.var(recent_percentages)
        coverage_trend = np.polyfit(range(len(recent_percentages)), recent_percentages, 1)[0]

        time_since_last_improvement = 0
        if len(recent_coverage) > 1:
            last_coverage = recent_coverage[-1].coverage_percentage
            for i in range(len(recent_coverage) - 2, -1, -1):
                if recent_coverage[i].coverage_percentage < last_coverage - 0.1:
                    break
                time_since_last_improvement = recent_coverage[-1].timestamp - recent_coverage[i].timestamp

        stagnated = (
            coverage_variance < 0.01 and
            abs(coverage_trend) < 0.001 and
            time_since_last_improvement > self.stagnation_threshold
        )

        return {
            'stagnated': stagnated,
            'variance': coverage_variance,
            'trend': coverage_trend,
            'time_without_improvement': time_since_last_improvement,
            'recommended_action': self._recommend_optimization_strategy(stagnated, coverage_trend)
        }

    def _recommend_optimization_strategy(self, stagnated: bool, trend: float) -> str:
        """Recommend optimization strategy based on coverage analysis"""
        if not stagnated:
            return 'continue_current_strategy'

        if trend < -0.001:
            return 'restart_from_high_coverage_seeds'
        elif len(self.coverage_history) > 0:
            return 'diversify_inputs'
        else:
            return 'focus_on_sparse_regions'

    def prioritize_inputs_by_coverage(self, inputs: List[Dict[str, Any]],
                                    coverage_predictions: List[float]) -> List[Dict[str, Any]]:
        """Prioritize inputs based on predicted coverage"""
        if len(inputs) != len(coverage_predictions):
            return inputs

        input_priority_pairs = list(zip(inputs, coverage_predictions))
        input_priority_pairs.sort(key=lambda x: x[1], reverse=True)

        return [input_data for input_data, _ in input_priority_pairs]

    def update_edge_importance(self, target_id: str, new_edges: Set[int], vulnerability_found: bool):
        """Update edge importance based on vulnerability discovery"""
        importance_boost = 2.0 if vulnerability_found else 1.0

        for edge in new_edges:
            self.edge_importance[edge] += importance_boost

        max_importance = max(self.edge_importance.values()) if self.edge_importance else 1.0
        for edge in self.edge_importance:
            self.edge_importance[edge] = min(self.edge_importance[edge], max_importance * 1.5)

class CoverageAnalyzer:
    """Main coverage analysis engine"""

    def __init__(self, work_dir: str = "/tmp/coverage_analysis"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)

        self.bitmap_analyzer = CoverageBitmapAnalyzer()
        self.coverage_predictor = CoveragePredictor()
        self.coverage_optimizer = CoverageOptimizer()

        self.coverage_data = defaultdict(list)
        self.evolution_data = {}
        self.monitoring_active = False

    def monitor_coverage(self, target_id: str, afl_output_dir: str) -> Optional[CoverageData]:
        """Monitor coverage for a specific target"""
        try:
            bitmap_path = os.path.join(afl_output_dir, 'main_' + target_id, 'fuzz_bitmap')

            if not os.path.exists(bitmap_path):
                return None

            bitmap = self.bitmap_analyzer.parse_afl_bitmap(bitmap_path)
            if bitmap is None:
                return None

            metrics = self.bitmap_analyzer.calculate_coverage_metrics(bitmap)

            new_edges = set()
            if self.coverage_data[target_id]:
                last_coverage = self.coverage_data[target_id][-1]
                last_bitmap = np.frombuffer(last_coverage.edge_bitmap, dtype=np.uint8)
                diff_analysis = self.bitmap_analyzer.analyze_bitmap_differences(last_bitmap, bitmap)
                new_edges = set(diff_analysis['new_edges'])

            coverage_data = CoverageData(
                target_id=target_id,
                timestamp=time.time(),
                total_edges=metrics['total_edges'],
                covered_edges=metrics['covered_edges'],
                coverage_percentage=metrics['coverage_percentage'],
                edge_bitmap=bitmap.tobytes(),
                new_edges=new_edges,
                execution_count=self._get_execution_count(afl_output_dir, target_id),
                metadata={
                    'edge_density': metrics['edge_density'],
                    'coverage_entropy': metrics['coverage_entropy'],
                    'hot_edges': metrics['hot_edges'],
                    'cold_edges': metrics['cold_edges']
                }
            )

            self.coverage_data[target_id].append(coverage_data)

            if len(new_edges) > 0:
                self.coverage_optimizer.update_edge_importance(target_id, new_edges, False)

            return coverage_data

        except Exception as e:
            logging.error(f"Coverage monitoring failed for {target_id}: {e}")
            return None

    def _get_execution_count(self, afl_output_dir: str, target_id: str) -> int:
        """Get execution count from AFL stats"""
        try:
            stats_file = os.path.join(afl_output_dir, 'main_' + target_id, 'fuzzer_stats')

            if not os.path.exists(stats_file):
                return 0

            with open(stats_file, 'r') as f:
                for line in f:
                    if line.startswith('execs_done'):
                        return int(line.split(':')[1].strip())

            return 0

        except Exception:
            return 0

    def analyze_coverage_evolution(self, target_id: str) -> Optional[CoverageEvolution]:
        """Analyze coverage evolution for target"""
        if target_id not in self.coverage_data or len(self.coverage_data[target_id]) < 2:
            return None

        coverage_history = self.coverage_data[target_id]

        percentages = [c.coverage_percentage for c in coverage_history]
        timestamps = [c.timestamp for c in coverage_history]

        if len(percentages) > 1:
            coverage_rate = self._calculate_coverage_rate(timestamps, percentages)
        else:
            coverage_rate = 0.0

        peak_coverage = max(percentages)
        saturation_point = self._detect_saturation_point(percentages)
        convergence_time = self._estimate_convergence_time(timestamps, percentages)

        evolution = CoverageEvolution(
            target_id=target_id,
            coverage_history=coverage_history,
            coverage_rate=coverage_rate,
            saturation_point=saturation_point,
            peak_coverage=peak_coverage,
            convergence_time=convergence_time
        )

        self.evolution_data[target_id] = evolution
        return evolution

    def _calculate_coverage_rate(self, timestamps: List[float], percentages: List[float]) -> float:
        """Calculate coverage increase rate"""
        if len(timestamps) < 2:
            return 0.0

        try:
            time_diffs = np.diff(timestamps)
            coverage_diffs = np.diff(percentages)

            valid_indices = (time_diffs > 0) & (coverage_diffs >= 0)
            if not np.any(valid_indices):
                return 0.0

            rates = coverage_diffs[valid_indices] / time_diffs[valid_indices]
            return np.mean(rates)

        except Exception:
            return 0.0

    def _detect_saturation_point(self, percentages: List[float]) -> Optional[float]:
        """Detect coverage saturation point"""
        if len(percentages) < 10:
            return None

        try:
            window_size = min(10, len(percentages) // 3)

            for i in range(len(percentages) - window_size):
                window = percentages[i:i + window_size]
                if max(window) - min(window) < 0.5:
                    return percentages[i]

            return None

        except Exception:
            return None

    def _estimate_convergence_time(self, timestamps: List[float], percentages: List[float]) -> Optional[float]:
        """Estimate time to coverage convergence"""
        if len(percentages) < 5:
            return None

        try:
            recent_percentages = percentages[-5:]
            if max(recent_percentages) - min(recent_percentages) < 0.1:
                return timestamps[-1] - timestamps[0]

            target_coverage = max(percentages) * 0.95

            for i, percentage in enumerate(percentages):
                if percentage >= target_coverage:
                    return timestamps[i] - timestamps[0]

            return None

        except Exception:
            return None

    def generate_coverage_visualization(self, target_id: str, output_path: str):
        """Generate coverage visualization"""
        if target_id not in self.coverage_data:
            return

        coverage_history = self.coverage_data[target_id]

        timestamps = [c.timestamp for c in coverage_history]
        percentages = [c.coverage_percentage for c in coverage_history]
        execution_counts = [c.execution_count for c in coverage_history]

        relative_times = [(t - timestamps[0]) / 3600 for t in timestamps]

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))

        ax1.plot(relative_times, percentages, 'b-', linewidth=2, label='Coverage %')
        ax1.set_xlabel('Time (hours)')
        ax1.set_ylabel('Coverage Percentage')
        ax1.set_title(f'Coverage Evolution for {target_id}')
        ax1.grid(True, alpha=0.3)
        ax1.legend()

        ax2.plot(relative_times, execution_counts, 'r-', linewidth=2, label='Executions')
        ax2.set_xlabel('Time (hours)')
        ax2.set_ylabel('Total Executions')
        ax2.set_title(f'Execution Count for {target_id}')
        ax2.grid(True, alpha=0.3)
        ax2.legend()

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

    def optimize_fuzzing_strategy(self, target_id: str) -> Dict[str, Any]:
        """Optimize fuzzing strategy based on coverage analysis"""
        if target_id not in self.coverage_data:
            return {'error': 'No coverage data available'}

        recent_coverage = self.coverage_data[target_id][-20:]
        stagnation_analysis = self.coverage_optimizer.analyze_coverage_stagnation(target_id, recent_coverage)

        recommendations = {
            'stagnation_detected': stagnation_analysis['stagnated'],
            'recommended_action': stagnation_analysis['recommended_action'],
            'coverage_trend': stagnation_analysis['trend'],
            'optimization_priority': 'high' if stagnation_analysis['stagnated'] else 'low'
        }

        if len(recent_coverage) > 0:
            latest_coverage = recent_coverage[-1]
            bitmap = np.frombuffer(latest_coverage.edge_bitmap, dtype=np.uint8)
            patterns = self.bitmap_analyzer.identify_coverage_patterns(bitmap)

            recommendations['coverage_patterns'] = patterns

            if len(patterns['sparse_regions']) > 0:
                recommendations['focus_areas'] = 'sparse_regions'
            elif len(patterns['coverage_gaps']) > 5:
                recommendations['focus_areas'] = 'coverage_gaps'
            else:
                recommendations['focus_areas'] = 'general_exploration'

        return recommendations

    def export_coverage_data(self, target_id: str, output_path: str):
        """Export coverage data to file"""
        if target_id not in self.coverage_data:
            return

        try:
            export_data = {
                'target_id': target_id,
                'coverage_history': [],
                'evolution_analysis': None
            }

            for coverage in self.coverage_data[target_id]:
                coverage_dict = {
                    'timestamp': coverage.timestamp,
                    'coverage_percentage': coverage.coverage_percentage,
                    'covered_edges': coverage.covered_edges,
                    'total_edges': coverage.total_edges,
                    'new_edges_count': len(coverage.new_edges),
                    'execution_count': coverage.execution_count,
                    'metadata': coverage.metadata
                }
                export_data['coverage_history'].append(coverage_dict)

            if target_id in self.evolution_data:
                evolution = self.evolution_data[target_id]
                export_data['evolution_analysis'] = {
                    'coverage_rate': evolution.coverage_rate,
                    'peak_coverage': evolution.peak_coverage,
                    'saturation_point': evolution.saturation_point,
                    'convergence_time': evolution.convergence_time
                }

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

        except Exception as e:
            logging.error(f"Failed to export coverage data: {e}")

    def generate_coverage_report(self, target_id: str) -> str:
        """Generate comprehensive coverage report"""
        if target_id not in self.coverage_data:
            return f"No coverage data available for target {target_id}"

        coverage_history = self.coverage_data[target_id]

        if not coverage_history:
            return f"Empty coverage history for target {target_id}"

        latest_coverage = coverage_history[-1]
        evolution = self.evolution_data.get(target_id)

        report = []
        report.append(f"Coverage Analysis Report: {target_id}")
        report.append("=" * 50)
        report.append(f"Data Points: {len(coverage_history)}")
        report.append(f"Current Coverage: {latest_coverage.coverage_percentage:.2f}%")
        report.append(f"Covered Edges: {latest_coverage.covered_edges:,}")
        report.append(f"Total Edges: {latest_coverage.total_edges:,}")
        report.append(f"Executions: {latest_coverage.execution_count:,}")
        report.append("")

        if evolution:
            report.append("Evolution Analysis:")
            report.append(f"  Coverage Rate: {evolution.coverage_rate:.4f}%/hour")
            report.append(f"  Peak Coverage: {evolution.peak_coverage:.2f}%")

            if evolution.saturation_point:
                report.append(f"  Saturation Point: {evolution.saturation_point:.2f}%")

            if evolution.convergence_time:
                report.append(f"  Convergence Time: {evolution.convergence_time:.1f} seconds")

            report.append("")

        optimization = self.optimize_fuzzing_strategy(target_id)
        report.append("Optimization Recommendations:")
        report.append(f"  Stagnation Detected: {optimization.get('stagnation_detected', False)}")
        report.append(f"  Recommended Action: {optimization.get('recommended_action', 'continue')}")
        report.append(f"  Focus Areas: {optimization.get('focus_areas', 'general')}")

        return "\n".join(report)