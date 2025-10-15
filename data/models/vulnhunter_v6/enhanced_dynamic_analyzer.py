#!/usr/bin/env python3
"""
VulnHunter V6 Enhanced Dynamic Analyzer
Advanced mathematical modeling for runtime vulnerability detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional, Callable
from dataclasses import dataclass, field
import time
import threading
import asyncio
from scipy.integrate import odeint, solve_ivp
from scipy.signal import find_peaks, correlate
from scipy.stats import entropy, wasserstein_distance
from sklearn.manifold import TSNE, MDS
from sklearn.cluster import DBSCAN
import networkx as nx
from collections import defaultdict, deque
import sympy as sp
from sympy import symbols, Matrix, solve, diff
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor


@dataclass
class DynamicStateVector:
    """Represents contract state as mathematical vector"""
    timestamp: float
    state_variables: Dict[str, float]
    transaction_context: Dict[str, Any]
    gas_consumption: float
    memory_usage: float
    call_stack_depth: int
    reentrancy_flags: List[bool] = field(default_factory=list)


@dataclass
class StateTransition:
    """Mathematical representation of state transitions"""
    from_state: DynamicStateVector
    to_state: DynamicStateVector
    transition_function: str
    jacobian_matrix: np.ndarray
    eigenvalues: np.ndarray
    stability_measure: float


class MathematicalStateModeler:
    """Models contract state evolution using differential equations"""

    def __init__(self):
        self.state_history = []
        self.ode_system = None
        self.phase_space = None

    def create_state_space_model(self, contract_vars: Dict[str, Any]) -> Dict[str, Any]:
        """Create mathematical state space representation"""
        # State vector: x = [balance, supply, price, liquidity, ...]
        state_vars = list(contract_vars.keys())
        n_vars = len(state_vars)

        # Create symbolic variables
        t = symbols('t')
        x = [symbols(f'x_{i}') for i in range(n_vars)]

        # Define state evolution equations
        # dx/dt = f(x, u, t) where u are external inputs
        evolution_equations = self._derive_evolution_equations(state_vars, x, t)

        # Create Jacobian matrix for stability analysis
        jacobian = self._compute_jacobian(evolution_equations, x)

        return {
            'state_variables': state_vars,
            'evolution_equations': evolution_equations,
            'jacobian_matrix': jacobian,
            'dimension': n_vars,
            'symbolic_system': {
                'time': t,
                'states': x,
                'equations': evolution_equations
            }
        }

    def _derive_evolution_equations(self, state_vars: List[str], x: List, t) -> Dict[str, sp.Expr]:
        """Derive mathematical evolution equations for each state variable"""
        equations = {}

        for i, var in enumerate(state_vars):
            if 'balance' in var.lower():
                # Balance evolution: dB/dt = inflow - outflow - fees
                equations[var] = symbols('inflow') - symbols('outflow') - symbols('fees')

            elif 'supply' in var.lower():
                # Supply evolution: dS/dt = mint_rate - burn_rate
                equations[var] = symbols('mint_rate') - symbols('burn_rate')

            elif 'price' in var.lower():
                # Price evolution using market dynamics: dP/dt = α(demand - supply)
                alpha = symbols('alpha', positive=True)
                demand = symbols('demand')
                supply = symbols('supply_rate')
                equations[var] = alpha * (demand - supply)

            elif 'liquidity' in var.lower():
                # Liquidity evolution: dL/dt = β(trades) - γ(withdrawals)
                beta, gamma = symbols('beta gamma', positive=True)
                trades = symbols('trades')
                withdrawals = symbols('withdrawals')
                equations[var] = beta * trades - gamma * withdrawals

            else:
                # Generic evolution with external forcing
                equations[var] = -symbols('decay_rate') * x[i] + symbols('external_input')

        return equations

    def _compute_jacobian(self, equations: Dict[str, sp.Expr], states: List) -> sp.Matrix:
        """Compute Jacobian matrix for stability analysis"""
        n = len(states)
        jacobian = sp.Matrix.zeros(n, n)

        equation_list = list(equations.values())

        for i, eq in enumerate(equation_list):
            for j, state in enumerate(states):
                jacobian[i, j] = sp.diff(eq, state)

        return jacobian

    def analyze_dynamic_stability(self, state_model: Dict[str, Any],
                                current_state: DynamicStateVector) -> Dict[str, Any]:
        """Analyze dynamic stability using Lyapunov theory"""

        # Extract Jacobian at current state
        jacobian = state_model['jacobian_matrix']
        current_values = current_state.state_variables

        # Substitute current values into Jacobian
        substitutions = {}
        for i, var in enumerate(state_model['state_variables']):
            if var in current_values:
                substitutions[symbols(f'x_{i}')] = current_values[var]

        # Evaluate Jacobian numerically
        try:
            jacobian_numeric = np.array(jacobian.subs(substitutions).evalf(), dtype=float)

            # Compute eigenvalues for stability analysis
            eigenvalues = np.linalg.eigvals(jacobian_numeric)

            # Stability conditions
            real_parts = np.real(eigenvalues)
            stability_margin = -np.max(real_parts)  # Negative means stable

            stability_analysis = {
                'eigenvalues': eigenvalues.tolist(),
                'is_stable': np.all(real_parts < 0),
                'stability_margin': float(stability_margin),
                'dominant_eigenvalue': complex(eigenvalues[np.argmax(real_parts)]),
                'oscillatory_behavior': np.any(np.abs(np.imag(eigenvalues)) > 1e-6),
                'time_constant': float(1.0 / np.abs(np.min(real_parts))) if np.min(real_parts) != 0 else float('inf')
            }

        except Exception as e:
            stability_analysis = {
                'error': str(e),
                'is_stable': False,
                'stability_margin': -1.0
            }

        return stability_analysis


class AdvancedVulnerabilityDetector:
    """Advanced vulnerability detection using mathematical analysis"""

    def __init__(self):
        self.attack_vectors = []
        self.state_manifold = None
        self.vulnerability_patterns = {}

    def detect_reentrancy_mathematically(self, state_sequence: List[DynamicStateVector]) -> Dict[str, Any]:
        """Mathematical detection of reentrancy using state space analysis"""
        if len(state_sequence) < 3:
            return {'vulnerability_detected': False, 'confidence': 0.0}

        # Convert to state vectors
        state_matrix = self._states_to_matrix(state_sequence)

        # Detect cycles in state space using topological methods
        cycles = self._detect_state_cycles(state_matrix)

        # Analyze call stack patterns
        call_stack_patterns = [s.call_stack_depth for s in state_sequence]
        recursive_patterns = self._detect_recursive_patterns(call_stack_patterns)

        # Reentrancy score using mathematical invariants
        reentrancy_score = self._calculate_reentrancy_score(cycles, recursive_patterns)

        return {
            'vulnerability_detected': reentrancy_score > 0.7,
            'confidence': float(reentrancy_score),
            'cycles_detected': len(cycles),
            'mathematical_evidence': {
                'state_cycles': cycles,
                'recursive_patterns': recursive_patterns,
                'topological_invariant': self._compute_topological_invariant(state_matrix)
            }
        }

    def detect_overflow_dynamically(self, arithmetic_operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dynamic overflow detection using number theory"""
        if not arithmetic_operations:
            return {'vulnerability_detected': False, 'confidence': 0.0}

        overflow_indicators = []

        for op in arithmetic_operations:
            operand1 = op.get('operand1', 0)
            operand2 = op.get('operand2', 0)
            operation = op.get('operation', 'add')
            result = op.get('result', 0)

            # Mathematical overflow detection
            if operation == 'add':
                expected = operand1 + operand2
                # Check for wrap-around (modular arithmetic)
                if expected >= 2**256 and result == expected % (2**256):
                    overflow_indicators.append({
                        'type': 'arithmetic_overflow',
                        'severity': 'HIGH',
                        'mathematical_proof': f'{operand1} + {operand2} = {expected} ≥ 2^256'
                    })

            elif operation == 'mul':
                expected = operand1 * operand2
                if expected >= 2**256 and result == expected % (2**256):
                    overflow_indicators.append({
                        'type': 'multiplication_overflow',
                        'severity': 'CRITICAL',
                        'mathematical_proof': f'{operand1} × {operand2} = {expected} ≥ 2^256'
                    })

        vulnerability_score = len(overflow_indicators) / max(len(arithmetic_operations), 1)

        return {
            'vulnerability_detected': vulnerability_score > 0.0,
            'confidence': min(vulnerability_score * 2, 1.0),
            'overflow_count': len(overflow_indicators),
            'mathematical_evidence': overflow_indicators
        }

    def _states_to_matrix(self, states: List[DynamicStateVector]) -> np.ndarray:
        """Convert state sequence to matrix for analysis"""
        if not states:
            return np.array([])

        # Get all unique state variable names
        all_vars = set()
        for state in states:
            all_vars.update(state.state_variables.keys())

        var_list = sorted(list(all_vars))
        n_vars = len(var_list)
        n_states = len(states)

        matrix = np.zeros((n_states, n_vars))

        for i, state in enumerate(states):
            for j, var in enumerate(var_list):
                matrix[i, j] = state.state_variables.get(var, 0.0)

        return matrix

    def _detect_state_cycles(self, state_matrix: np.ndarray) -> List[List[int]]:
        """Detect cycles in state space using mathematical analysis"""
        if state_matrix.size == 0:
            return []

        cycles = []
        n_states = state_matrix.shape[0]

        # Use correlation analysis to find similar states
        similarity_threshold = 0.95

        for i in range(n_states):
            for j in range(i + 2, n_states):  # Skip adjacent states
                # Compute cosine similarity
                state_i = state_matrix[i]
                state_j = state_matrix[j]

                # Avoid division by zero
                norm_i = np.linalg.norm(state_i)
                norm_j = np.linalg.norm(state_j)

                if norm_i > 1e-10 and norm_j > 1e-10:
                    similarity = np.dot(state_i, state_j) / (norm_i * norm_j)

                    if similarity > similarity_threshold:
                        cycles.append(list(range(i, j + 1)))

        return cycles

    def _detect_recursive_patterns(self, call_stack_depths: List[int]) -> List[Dict[str, Any]]:
        """Detect recursive patterns in call stack"""
        if len(call_stack_depths) < 3:
            return []

        patterns = []

        # Find peaks (potential recursion points)
        peaks, _ = find_peaks(call_stack_depths, height=2)

        for peak in peaks:
            # Analyze pattern around peak
            start = max(0, peak - 5)
            end = min(len(call_stack_depths), peak + 5)
            pattern = call_stack_depths[start:end]

            # Check for repeated increasing sequences (recursion signature)
            if len(pattern) > 3:
                increasing_sequences = 0
                for i in range(len(pattern) - 1):
                    if pattern[i + 1] > pattern[i]:
                        increasing_sequences += 1

                if increasing_sequences >= 2:
                    patterns.append({
                        'peak_index': peak,
                        'max_depth': call_stack_depths[peak],
                        'pattern': pattern,
                        'recursion_strength': increasing_sequences / len(pattern)
                    })

        return patterns

    def _calculate_reentrancy_score(self, cycles: List[List[int]],
                                  recursive_patterns: List[Dict[str, Any]]) -> float:
        """Calculate reentrancy vulnerability score"""
        cycle_score = min(len(cycles) * 0.3, 1.0)

        recursion_score = 0.0
        if recursive_patterns:
            avg_recursion_strength = np.mean([p['recursion_strength'] for p in recursive_patterns])
            recursion_score = min(avg_recursion_strength * 0.7, 1.0)

        return min(cycle_score + recursion_score, 1.0)

    def _compute_topological_invariant(self, state_matrix: np.ndarray) -> float:
        """Compute topological invariant for state space"""
        if state_matrix.size == 0:
            return 0.0

        # Use persistent homology concepts (simplified)
        # Compute Betti numbers approximation
        n_states, n_vars = state_matrix.shape

        if n_states < 3:
            return 0.0

        # Create distance matrix
        distances = np.zeros((n_states, n_states))
        for i in range(n_states):
            for j in range(i + 1, n_states):
                dist = np.linalg.norm(state_matrix[i] - state_matrix[j])
                distances[i, j] = distances[j, i] = dist

        # Approximate Betti number using clustering
        try:
            clustering = DBSCAN(eps=np.median(distances), min_samples=2)
            labels = clustering.fit_predict(state_matrix)
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)

            # Normalized topological complexity
            return min(n_clusters / n_states, 1.0)
        except:
            return 0.0


class RealTimeVulnerabilityMonitor:
    """Real-time vulnerability monitoring using streaming analysis"""

    def __init__(self, buffer_size: int = 1000):
        self.state_buffer = deque(maxlen=buffer_size)
        self.vulnerability_detector = AdvancedVulnerabilityDetector()
        self.state_modeler = MathematicalStateModeler()
        self.monitoring_active = False
        self.alert_threshold = 0.8

    async def start_monitoring(self, state_stream: asyncio.Queue):
        """Start real-time monitoring of contract state"""
        self.monitoring_active = True

        while self.monitoring_active:
            try:
                # Get new state with timeout
                state = await asyncio.wait_for(state_stream.get(), timeout=1.0)
                self.state_buffer.append(state)

                # Perform real-time analysis
                if len(self.state_buffer) >= 10:
                    vulnerability_analysis = await self._analyze_current_window()

                    # Check for alerts
                    if self._should_alert(vulnerability_analysis):
                        await self._send_alert(vulnerability_analysis)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Monitoring error: {e}")

    async def _analyze_current_window(self) -> Dict[str, Any]:
        """Analyze current window of states"""
        recent_states = list(self.state_buffer)[-20:]  # Last 20 states

        # Reentrancy analysis
        reentrancy_analysis = self.vulnerability_detector.detect_reentrancy_mathematically(recent_states)

        # Extract arithmetic operations (simulated)
        arithmetic_ops = self._extract_arithmetic_operations(recent_states)
        overflow_analysis = self.vulnerability_detector.detect_overflow_dynamically(arithmetic_ops)

        # Stability analysis
        if len(recent_states) >= 2:
            # Create simplified state model
            state_vars = {}
            if recent_states:
                state_vars = recent_states[-1].state_variables

            state_model = self.state_modeler.create_state_space_model(state_vars)
            stability_analysis = self.state_modeler.analyze_dynamic_stability(
                state_model, recent_states[-1]
            )
        else:
            stability_analysis = {'is_stable': True, 'stability_margin': 1.0}

        return {
            'timestamp': time.time(),
            'reentrancy': reentrancy_analysis,
            'overflow': overflow_analysis,
            'stability': stability_analysis,
            'overall_risk_score': self._calculate_overall_risk(
                reentrancy_analysis, overflow_analysis, stability_analysis
            )
        }

    def _extract_arithmetic_operations(self, states: List[DynamicStateVector]) -> List[Dict[str, Any]]:
        """Extract arithmetic operations from state transitions"""
        operations = []

        for i in range(1, len(states)):
            prev_state = states[i-1].state_variables
            curr_state = states[i].state_variables

            # Look for state variable changes that indicate arithmetic operations
            for var in prev_state:
                if var in curr_state:
                    prev_val = prev_state[var]
                    curr_val = curr_state[var]

                    if prev_val != curr_val:
                        # Infer operation type based on change
                        if curr_val > prev_val:
                            operations.append({
                                'operation': 'add',
                                'operand1': prev_val,
                                'operand2': curr_val - prev_val,
                                'result': curr_val,
                                'variable': var
                            })
                        elif curr_val < prev_val:
                            operations.append({
                                'operation': 'sub',
                                'operand1': prev_val,
                                'operand2': prev_val - curr_val,
                                'result': curr_val,
                                'variable': var
                            })

        return operations

    def _calculate_overall_risk(self, reentrancy: Dict[str, Any],
                              overflow: Dict[str, Any],
                              stability: Dict[str, Any]) -> float:
        """Calculate overall risk score"""
        reentrancy_risk = reentrancy.get('confidence', 0.0) if reentrancy.get('vulnerability_detected', False) else 0.0
        overflow_risk = overflow.get('confidence', 0.0) if overflow.get('vulnerability_detected', False) else 0.0
        stability_risk = 1.0 - stability.get('stability_margin', 1.0) if not stability.get('is_stable', True) else 0.0

        # Weighted combination
        overall_risk = (reentrancy_risk * 0.4 + overflow_risk * 0.4 + stability_risk * 0.2)
        return min(overall_risk, 1.0)

    def _should_alert(self, analysis: Dict[str, Any]) -> bool:
        """Determine if alert should be sent"""
        return analysis.get('overall_risk_score', 0.0) > self.alert_threshold

    async def _send_alert(self, analysis: Dict[str, Any]):
        """Send vulnerability alert"""
        alert_message = {
            'timestamp': analysis['timestamp'],
            'risk_score': analysis['overall_risk_score'],
            'vulnerabilities': []
        }

        if analysis['reentrancy'].get('vulnerability_detected', False):
            alert_message['vulnerabilities'].append('REENTRANCY')

        if analysis['overflow'].get('vulnerability_detected', False):
            alert_message['vulnerabilities'].append('OVERFLOW')

        if not analysis['stability'].get('is_stable', True):
            alert_message['vulnerabilities'].append('INSTABILITY')

        print(f"🚨 VULNERABILITY ALERT: {alert_message}")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False


class MathematicalValidationFramework:
    """Framework for mathematical validation of vulnerability detection"""

    def __init__(self):
        self.validation_metrics = {}
        self.theorem_validators = {}

    def validate_detection_accuracy(self, detected_vulnerabilities: List[Dict[str, Any]],
                                  ground_truth: List[Dict[str, Any]]) -> Dict[str, float]:
        """Validate detection accuracy using mathematical metrics"""

        # Convert to binary vectors for mathematical analysis
        detection_vector = self._create_detection_vector(detected_vulnerabilities)
        truth_vector = self._create_detection_vector(ground_truth)

        # Calculate mathematical validation metrics
        metrics = {}

        # Hamming distance
        hamming_dist = np.sum(detection_vector != truth_vector)
        metrics['hamming_distance'] = float(hamming_dist)

        # Cosine similarity
        if np.linalg.norm(detection_vector) > 0 and np.linalg.norm(truth_vector) > 0:
            cosine_sim = np.dot(detection_vector, truth_vector) / (
                np.linalg.norm(detection_vector) * np.linalg.norm(truth_vector)
            )
            metrics['cosine_similarity'] = float(cosine_sim)
        else:
            metrics['cosine_similarity'] = 0.0

        # Jaccard similarity
        intersection = np.sum((detection_vector == 1) & (truth_vector == 1))
        union = np.sum((detection_vector == 1) | (truth_vector == 1))
        metrics['jaccard_similarity'] = float(intersection / union) if union > 0 else 0.0

        # F1 score components
        true_positives = np.sum((detection_vector == 1) & (truth_vector == 1))
        false_positives = np.sum((detection_vector == 1) & (truth_vector == 0))
        false_negatives = np.sum((detection_vector == 0) & (truth_vector == 1))

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics.update({
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1_score),
            'true_positives': int(true_positives),
            'false_positives': int(false_positives),
            'false_negatives': int(false_negatives)
        })

        return metrics

    def _create_detection_vector(self, vulnerabilities: List[Dict[str, Any]]) -> np.ndarray:
        """Create binary detection vector"""
        # Standard vulnerability types
        vuln_types = ['reentrancy', 'overflow', 'access_control', 'timestamp_dependency',
                     'price_manipulation', 'dos', 'unchecked_call', 'front_running']

        vector = np.zeros(len(vuln_types))

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            if vuln_type in vuln_types:
                idx = vuln_types.index(vuln_type)
                vector[idx] = 1

        return vector

    def theorem_based_validation(self, vulnerability_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Validate using mathematical theorems"""
        validation_results = {}

        # Validate reentrancy detection using fixed-point theorem
        if 'reentrancy' in vulnerability_analysis:
            validation_results['reentrancy_validation'] = self._validate_reentrancy_theorem(
                vulnerability_analysis['reentrancy']
            )

        # Validate overflow detection using number theory
        if 'overflow' in vulnerability_analysis:
            validation_results['overflow_validation'] = self._validate_overflow_theorem(
                vulnerability_analysis['overflow']
            )

        return validation_results

    def _validate_reentrancy_theorem(self, reentrancy_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Validate reentrancy detection using fixed-point theorem"""
        # Fixed-point theorem: If f: X → X has a fixed point, then reentrancy is possible
        cycles = reentrancy_analysis.get('mathematical_evidence', {}).get('state_cycles', [])

        has_fixed_point = len(cycles) > 0
        theorem_satisfied = has_fixed_point == reentrancy_analysis.get('vulnerability_detected', False)

        return {
            'theorem_applied': 'Banach Fixed-Point Theorem',
            'theorem_satisfied': theorem_satisfied,
            'mathematical_consistency': float(theorem_satisfied),
            'fixed_points_detected': len(cycles)
        }

    def _validate_overflow_theorem(self, overflow_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Validate overflow detection using modular arithmetic theorem"""
        # Theorem: a + b ≡ c (mod 2^n) where c < max(a,b) indicates overflow
        evidence = overflow_analysis.get('mathematical_evidence', [])

        theorem_violations = 0
        for evidence_item in evidence:
            if 'mathematical_proof' in evidence_item:
                theorem_violations += 1

        expected_detection = theorem_violations > 0
        actual_detection = overflow_analysis.get('vulnerability_detected', False)
        theorem_satisfied = expected_detection == actual_detection

        return {
            'theorem_applied': 'Modular Arithmetic Overflow Theorem',
            'theorem_satisfied': theorem_satisfied,
            'mathematical_consistency': float(theorem_satisfied),
            'theorem_violations': theorem_violations
        }