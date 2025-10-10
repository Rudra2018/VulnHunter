#!/usr/bin/env python3
"""
Advanced Mathematical Foundations for Cybersecurity
Comprehensive implementation of theorem-based security analysis
"""

import numpy as np
import pandas as pd
import networkx as nx
from collections import defaultdict, deque
import heapq
import math
import scipy.optimize as optimize
from scipy.stats import entropy as scipy_entropy
from typing import Dict, List, Tuple, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedGraphAlgorithms:
    """
    Advanced graph algorithms for cybersecurity analysis
    """

    @staticmethod
    def dijkstra_security_paths(graph: Dict[str, Dict[str, float]], start: str,
                               security_weights: bool = True) -> Dict[str, Tuple[float, List[str]]]:
        """
        Dijkstra's Algorithm - The GPS of Cybersecurity

        Formula: d[v] = min(d[u] + w(u,v)) for all edges (u,v)

        Simple Explanation: Like GPS finding shortest route, but for security paths.
        Finds the "safest" or "most vulnerable" path through code or networks.

        Security Application:
        - Find shortest attack paths in networks
        - Identify critical vulnerability chains
        - Optimize security resource allocation

        Example: Finds that attacker can reach database in 3 hops through
        "web->auth->api->db" rather than 5 hops through other paths.
        """
        distances = {node: float('inf') for node in graph}
        distances[start] = 0
        previous = {node: None for node in graph}
        paths = {node: [] for node in graph}
        paths[start] = [start]

        # Priority queue: (distance, node)
        pq = [(0, start)]
        visited = set()

        while pq:
            current_dist, current = heapq.heappop(pq)

            if current in visited:
                continue

            visited.add(current)

            for neighbor, weight in graph.get(current, {}).items():
                # For security analysis, we might want to invert weights
                # Higher security risk = lower weight (more attractive to attackers)
                if security_weights:
                    # Invert weight for vulnerability analysis
                    adjusted_weight = 1.0 / (weight + 0.001)  # Avoid division by zero
                else:
                    adjusted_weight = weight

                distance = current_dist + adjusted_weight

                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous[neighbor] = current

                    # Reconstruct path
                    new_path = paths[current] + [neighbor]
                    paths[neighbor] = new_path

                    heapq.heappush(pq, (distance, neighbor))

        # Return distances and paths
        result = {}
        for node in graph:
            if distances[node] != float('inf'):
                result[node] = (distances[node], paths[node])

        return result

    @staticmethod
    def bfs_security_exploration(graph: Dict[str, List[str]], start: str,
                                max_depth: int = None) -> Dict[str, Dict[str, Any]]:
        """
        Breadth-First Search - The Systematic Explorer

        Algorithm: Explore all neighbors before going deeper

        Simple Explanation: Like exploring a building floor by floor.
        Systematically examines all immediate threats before looking at distant ones.

        Security Application:
        - Lateral movement analysis
        - Privilege escalation path discovery
        - Network topology mapping
        - Vulnerability impact assessment

        Example: From compromised workstation, finds all systems reachable
        in 1 hop (immediate lateral movement), then 2 hops, etc.
        """
        queue = deque([(start, 0)])  # (node, depth)
        visited = {start}
        exploration_result = {
            start: {
                'depth': 0,
                'reachable_from': None,
                'exploration_order': 0,
                'neighbors_count': len(graph.get(start, [])),
                'security_criticality': 0  # Will be calculated
            }
        }

        order = 0

        while queue:
            current, depth = queue.popleft()

            if max_depth is not None and depth >= max_depth:
                continue

            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    order += 1

                    exploration_result[neighbor] = {
                        'depth': depth + 1,
                        'reachable_from': current,
                        'exploration_order': order,
                        'neighbors_count': len(graph.get(neighbor, [])),
                        'security_criticality': depth + 1  # Further = less critical for immediate response
                    }

                    queue.append((neighbor, depth + 1))

        return exploration_result

    @staticmethod
    def max_flow_min_cut_security(graph: Dict[str, Dict[str, float]],
                                 source: str, sink: str) -> Dict[str, Any]:
        """
        Max-Flow Min-Cut Theorem - The Bottleneck Finder

        Theorem: Maximum flow = Minimum cut capacity

        Simple Explanation: Like finding the narrowest point in a pipe system.
        The maximum data/attack flow is limited by the smallest bottleneck.

        Security Applications:
        - Network bandwidth attack analysis
        - Critical infrastructure bottleneck identification
        - Resource allocation optimization
        - DDoS impact assessment

        Example: Network can handle 100GB/s traffic, but one router at 10GB/s
        creates bottleneck - that's your critical security point.
        """
        try:
            # Create NetworkX graph for max flow calculation
            G = nx.DiGraph()

            for source_node, edges in graph.items():
                for target_node, capacity in edges.items():
                    G.add_edge(source_node, target_node, capacity=capacity)

            # Calculate maximum flow
            max_flow_value, flow_dict = nx.maximum_flow(G, source, sink)

            # Find minimum cut
            cut_value, (reachable, non_reachable) = nx.minimum_cut(G, source, sink)

            # Identify bottleneck edges
            bottleneck_edges = []
            for u in reachable:
                for v in non_reachable:
                    if G.has_edge(u, v):
                        bottleneck_edges.append((u, v, G[u][v]['capacity']))

            return {
                'max_flow_value': max_flow_value,
                'min_cut_value': cut_value,
                'bottleneck_edges': bottleneck_edges,
                'reachable_nodes': list(reachable),
                'non_reachable_nodes': list(non_reachable),
                'flow_distribution': dict(flow_dict),
                'security_implications': {
                    'critical_links': bottleneck_edges,
                    'flow_capacity': max_flow_value,
                    'vulnerability_points': len(bottleneck_edges)
                }
            }

        except Exception as e:
            logger.warning(f"Max-flow calculation failed: {e}")
            return {
                'max_flow_value': 0,
                'min_cut_value': 0,
                'bottleneck_edges': [],
                'error': str(e)
            }

class GameTheoryOptimization:
    """
    Game Theory and Optimization for Security Analysis
    """

    @staticmethod
    def nash_equilibrium_security(attacker_payoffs: np.ndarray,
                                 defender_payoffs: np.ndarray) -> Dict[str, Any]:
        """
        Nash Equilibrium - The Strategic Balance Point

        Definition: Point where no player can improve by unilaterally changing strategy

        Simple Explanation: Like a standoff where neither attacker nor defender
        wants to change their strategy because they'd be worse off.

        Security Application:
        - Optimal security investment strategies
        - Attacker-defender resource allocation
        - Security policy equilibrium analysis
        - Threat modeling with strategic adversaries

        Example: Company spends $100K on firewall, attackers spend $50K on exploits.
        Neither wants to change because current strategy is their best response.
        """

        try:
            # Simple 2x2 game Nash equilibrium calculation
            if attacker_payoffs.shape != (2, 2) or defender_payoffs.shape != (2, 2):
                return {'error': 'Currently supports only 2x2 games'}

            # Check for pure strategy Nash equilibria
            pure_equilibria = []

            for i in range(2):
                for j in range(2):
                    # Check if (i,j) is a Nash equilibrium
                    # Attacker's best response to defender's strategy j
                    attacker_best = np.argmax(attacker_payoffs[:, j])
                    # Defender's best response to attacker's strategy i
                    defender_best = np.argmax(defender_payoffs[i, :])

                    if attacker_best == i and defender_best == j:
                        pure_equilibria.append({
                            'attacker_strategy': i,
                            'defender_strategy': j,
                            'attacker_payoff': attacker_payoffs[i, j],
                            'defender_payoff': defender_payoffs[i, j]
                        })

            # Calculate mixed strategy equilibrium (if no pure strategy exists)
            mixed_equilibrium = None
            if not pure_equilibria:
                # For 2x2 games, calculate mixed strategy Nash equilibrium
                # Attacker is indifferent: p * payoff[0,0] + (1-p) * payoff[0,1] = p * payoff[1,0] + (1-p) * payoff[1,1]
                try:
                    denominator_a = (attacker_payoffs[0,0] - attacker_payoffs[0,1]) - (attacker_payoffs[1,0] - attacker_payoffs[1,1])
                    if abs(denominator_a) > 1e-10:
                        q_star = (attacker_payoffs[1,1] - attacker_payoffs[0,1]) / denominator_a

                    denominator_d = (defender_payoffs[0,0] - defender_payoffs[1,0]) - (defender_payoffs[0,1] - defender_payoffs[1,1])
                    if abs(denominator_d) > 1e-10:
                        p_star = (defender_payoffs[1,1] - defender_payoffs[1,0]) / denominator_d

                        if 0 <= p_star <= 1 and 0 <= q_star <= 1:
                            mixed_equilibrium = {
                                'attacker_strategy_prob': [p_star, 1 - p_star],
                                'defender_strategy_prob': [q_star, 1 - q_star],
                                'expected_attacker_payoff': p_star * q_star * attacker_payoffs[0,0] +
                                                          p_star * (1-q_star) * attacker_payoffs[0,1] +
                                                          (1-p_star) * q_star * attacker_payoffs[1,0] +
                                                          (1-p_star) * (1-q_star) * attacker_payoffs[1,1]
                            }
                except:
                    mixed_equilibrium = None

            return {
                'pure_equilibria': pure_equilibria,
                'mixed_equilibrium': mixed_equilibrium,
                'security_implications': {
                    'stable_strategies': len(pure_equilibria),
                    'predictable_outcome': len(pure_equilibria) == 1,
                    'recommendation': 'Pure strategy' if pure_equilibria else 'Mixed strategy'
                }
            }

        except Exception as e:
            return {'error': f'Nash equilibrium calculation failed: {e}'}

    @staticmethod
    def lagrange_multipliers_optimization(objective_func, constraints,
                                        initial_guess: np.ndarray) -> Dict[str, Any]:
        """
        Lagrange Multipliers - The Optimal Compromise Finder

        Formula: ∇f(x) = λ∇g(x) at optimal point

        Simple Explanation: Like finding the best compromise when you have
        conflicting goals. Maximizes security while staying within budget.

        Security Applications:
        - Optimal security budget allocation
        - Resource distribution across security controls
        - Risk-cost optimization
        - Performance vs security trade-offs

        Example: Maximize network security (f) subject to budget constraint (g).
        Finds optimal mix: 60% firewalls, 30% IDS, 10% training.
        """

        try:
            def lagrangian(x):
                """Simplified Lagrangian for security optimization"""
                # Example: Maximize security coverage while minimizing cost
                security_coverage = np.sum(x * np.log(x + 0.001))  # Diminishing returns
                cost_penalty = np.sum(x**2)  # Quadratic cost
                return -(security_coverage - cost_penalty)  # Negative for minimization

            # Constraint: sum of allocations = 1 (normalized budget)
            constraint = {'type': 'eq', 'fun': lambda x: np.sum(x) - 1}

            # Bounds: each allocation between 0 and 1
            bounds = [(0, 1) for _ in range(len(initial_guess))]

            # Optimize
            result = optimize.minimize(
                lagrangian,
                initial_guess,
                method='SLSQP',
                constraints=constraint,
                bounds=bounds
            )

            if result.success:
                optimal_allocation = result.x
                optimal_value = -result.fun  # Convert back from minimization

                return {
                    'optimal_allocation': optimal_allocation.tolist(),
                    'optimal_value': optimal_value,
                    'iterations': result.nit,
                    'converged': result.success,
                    'security_implications': {
                        'resource_distribution': {
                            f'security_control_{i}': f'{alloc:.3f}'
                            for i, alloc in enumerate(optimal_allocation)
                        },
                        'efficiency_score': optimal_value,
                        'balanced_approach': np.std(optimal_allocation) < 0.3  # Low variance = balanced
                    }
                }
            else:
                return {
                    'error': 'Optimization failed to converge',
                    'message': result.message
                }

        except Exception as e:
            return {'error': f'Lagrange optimization failed: {e}'}

class BayesianSecurityAnalysis:
    """
    Enhanced Bayesian Analysis for Security
    """

    @staticmethod
    def bayes_evidence_updater(prior_belief: float, evidence_likelihood: float,
                              evidence_base_rate: float) -> Dict[str, float]:
        """
        Bayes' Theorem - The Evidence Updater (Enhanced)

        Formula: P(threat|evidence) = P(evidence|threat) * P(threat) / P(evidence)

        Simple Explanation: Updates your belief about threats when new evidence appears.
        Like updating your guess about rain when you see clouds.

        Security Applications:
        - Real-time threat assessment updates
        - False positive reduction
        - Incident response prioritization
        - Adaptive security policies

        Example:
        - Prior: 5% chance of APT attack
        - Evidence: Suspicious PowerShell activity detected
        - Likelihood: 80% of APT attacks use PowerShell
        - Base rate: 10% of all activities involve PowerShell
        - Updated belief: 33% chance of APT attack
        """

        # Calculate posterior probability using Bayes' theorem
        posterior = (evidence_likelihood * prior_belief) / evidence_base_rate

        # Ensure probability is valid
        posterior = max(0, min(1, posterior))

        # Calculate confidence metrics
        evidence_strength = evidence_likelihood / evidence_base_rate
        belief_change = abs(posterior - prior_belief)

        return {
            'prior_belief': prior_belief,
            'posterior_belief': posterior,
            'evidence_strength': evidence_strength,
            'belief_change': belief_change,
            'confidence_level': min(0.95, evidence_strength * 0.8),
            'security_action': {
                'priority': 'HIGH' if posterior > 0.7 else 'MEDIUM' if posterior > 0.3 else 'LOW',
                'recommendation': 'Investigate immediately' if posterior > 0.7
                                else 'Monitor closely' if posterior > 0.3
                                else 'Routine monitoring'
            }
        }

    @staticmethod
    def bayesian_threat_fusion(evidence_list: List[Dict[str, float]]) -> Dict[str, Any]:
        """
        Fuse multiple pieces of evidence using Bayesian updating

        Sequential updating: P(H|E1,E2,E3) = P(H|E1) updated by E2, then by E3
        """

        if not evidence_list:
            return {'error': 'No evidence provided'}

        # Start with first piece of evidence
        current_belief = evidence_list[0].get('prior', 0.1)  # Default 10% prior

        evidence_chain = []

        for i, evidence in enumerate(evidence_list):
            likelihood = evidence.get('likelihood', 0.5)
            base_rate = evidence.get('base_rate', 0.1)

            # Update belief
            updated = BayesianSecurityAnalysis.bayes_evidence_updater(
                current_belief, likelihood, base_rate
            )

            evidence_chain.append({
                'step': i + 1,
                'evidence_type': evidence.get('type', f'evidence_{i}'),
                'prior': current_belief,
                'posterior': updated['posterior_belief'],
                'strength': updated['evidence_strength']
            })

            current_belief = updated['posterior_belief']

        return {
            'final_threat_probability': current_belief,
            'evidence_chain': evidence_chain,
            'cumulative_strength': np.prod([e['strength'] for e in evidence_chain]),
            'security_recommendation': {
                'threat_level': 'CRITICAL' if current_belief > 0.8
                              else 'HIGH' if current_belief > 0.6
                              else 'MEDIUM' if current_belief > 0.3
                              else 'LOW',
                'confidence': min(0.95, len(evidence_list) * 0.2),
                'action_required': current_belief > 0.5
            }
        }

class AdvancedMathematicalFoundations:
    """
    Comprehensive mathematical foundation combining all advanced techniques
    """

    def __init__(self):
        self.graph_algorithms = AdvancedGraphAlgorithms()
        self.game_theory = GameTheoryOptimization()
        self.bayesian_analysis = BayesianSecurityAnalysis()

    def comprehensive_security_analysis(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis using all mathematical foundations
        """

        results = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'analysis_components': []
        }

        # 1. Graph-based analysis
        if 'network_graph' in security_data:
            graph = security_data['network_graph']
            source = security_data.get('source_node', list(graph.keys())[0])

            # Dijkstra for attack paths
            if 'target_node' in security_data:
                attack_paths = self.graph_algorithms.dijkstra_security_paths(
                    graph, source, security_weights=True
                )
                results['attack_path_analysis'] = attack_paths
                results['analysis_components'].append('dijkstra_attack_paths')

            # BFS for lateral movement
            lateral_movement = self.graph_algorithms.bfs_security_exploration(
                {k: list(v.keys()) for k, v in graph.items()}, source, max_depth=3
            )
            results['lateral_movement_analysis'] = lateral_movement
            results['analysis_components'].append('bfs_lateral_movement')

            # Max-flow for bottleneck analysis
            if 'sink_node' in security_data:
                bottleneck_analysis = self.graph_algorithms.max_flow_min_cut_security(
                    graph, source, security_data['sink_node']
                )
                results['bottleneck_analysis'] = bottleneck_analysis
                results['analysis_components'].append('max_flow_bottlenecks')

        # 2. Game theory analysis
        if 'attacker_payoffs' in security_data and 'defender_payoffs' in security_data:
            nash_analysis = self.game_theory.nash_equilibrium_security(
                np.array(security_data['attacker_payoffs']),
                np.array(security_data['defender_payoffs'])
            )
            results['strategic_analysis'] = nash_analysis
            results['analysis_components'].append('nash_equilibrium')

        # 3. Optimization analysis
        if 'security_budget_allocation' in security_data:
            initial_allocation = np.array(security_data['security_budget_allocation'])
            optimization_result = self.game_theory.lagrange_multipliers_optimization(
                None, None, initial_allocation
            )
            results['resource_optimization'] = optimization_result
            results['analysis_components'].append('lagrange_optimization')

        # 4. Bayesian threat assessment
        if 'threat_evidence' in security_data:
            evidence_list = security_data['threat_evidence']
            threat_assessment = self.bayesian_analysis.bayesian_threat_fusion(evidence_list)
            results['threat_assessment'] = threat_assessment
            results['analysis_components'].append('bayesian_threat_fusion')

        # 5. Comprehensive risk score
        risk_factors = []

        if 'attack_path_analysis' in results:
            # Shorter attack paths = higher risk
            min_path_length = min([len(path) for _, path in results['attack_path_analysis'].values()]
                                 if results['attack_path_analysis'] else [10])
            risk_factors.append(max(0, 1 - min_path_length / 10))

        if 'threat_assessment' in results:
            risk_factors.append(results['threat_assessment']['final_threat_probability'])

        if 'bottleneck_analysis' in results:
            # More bottlenecks = higher risk
            bottleneck_count = len(results['bottleneck_analysis'].get('bottleneck_edges', []))
            risk_factors.append(min(1, bottleneck_count / 5))

        if risk_factors:
            results['comprehensive_risk_score'] = np.mean(risk_factors)
            results['risk_level'] = (
                'CRITICAL' if results['comprehensive_risk_score'] > 0.8
                else 'HIGH' if results['comprehensive_risk_score'] > 0.6
                else 'MEDIUM' if results['comprehensive_risk_score'] > 0.3
                else 'LOW'
            )

        return results

def main():
    """Demonstrate advanced mathematical foundations"""

    print("🧮 ADVANCED MATHEMATICAL FOUNDATIONS FOR CYBERSECURITY")
    print("=" * 80)

    foundations = AdvancedMathematicalFoundations()

    # Example security scenario
    security_scenario = {
        'network_graph': {
            'workstation': {'firewall': 0.8, 'switch': 0.6},
            'firewall': {'router': 0.9, 'dmz': 0.7},
            'switch': {'server': 0.5, 'database': 0.3},
            'router': {'internet': 0.4},
            'dmz': {'web_server': 0.8},
            'server': {'database': 0.9},
            'web_server': {'database': 0.6},
            'database': {},
            'internet': {}
        },
        'source_node': 'workstation',
        'target_node': 'database',
        'sink_node': 'database',
        'attacker_payoffs': [[3, 1], [0, 2]],  # [attack_firewall, attack_endpoint] vs [strong_defense, weak_defense]
        'defender_payoffs': [[1, 3], [2, 0]],  # Defender's payoffs for same strategies
        'security_budget_allocation': [0.4, 0.3, 0.2, 0.1],  # Initial allocation across 4 security controls
        'threat_evidence': [
            {'type': 'network_anomaly', 'likelihood': 0.7, 'base_rate': 0.1, 'prior': 0.05},
            {'type': 'malware_signature', 'likelihood': 0.9, 'base_rate': 0.02},
            {'type': 'user_behavior', 'likelihood': 0.6, 'base_rate': 0.3}
        ]
    }

    # Perform comprehensive analysis
    print("\n🔍 Performing comprehensive security analysis...")
    results = foundations.comprehensive_security_analysis(security_scenario)

    # Display results
    print(f"\n📊 ANALYSIS RESULTS")
    print(f"Risk Level: {results.get('risk_level', 'UNKNOWN')}")
    print(f"Risk Score: {results.get('comprehensive_risk_score', 0):.3f}")
    print(f"Components Analyzed: {', '.join(results.get('analysis_components', []))}")

    if 'attack_path_analysis' in results:
        print(f"\n🎯 Attack Path Analysis (Dijkstra):")
        for target, (distance, path) in results['attack_path_analysis'].items():
            if target == 'database':
                print(f"  Shortest attack path to database: {' -> '.join(path)}")
                print(f"  Attack difficulty score: {distance:.3f}")

    if 'threat_assessment' in results:
        print(f"\n🚨 Bayesian Threat Assessment:")
        ta = results['threat_assessment']
        print(f"  Final threat probability: {ta['final_threat_probability']:.3f}")
        print(f"  Threat level: {ta['security_recommendation']['threat_level']}")
        print(f"  Action required: {ta['security_recommendation']['action_required']}")

    if 'strategic_analysis' in results:
        print(f"\n⚖️  Game Theory Analysis (Nash Equilibrium):")
        sa = results['strategic_analysis']
        if sa.get('pure_equilibria'):
            eq = sa['pure_equilibria'][0]
            print(f"  Optimal attacker strategy: {eq['attacker_strategy']}")
            print(f"  Optimal defender strategy: {eq['defender_strategy']}")
        elif sa.get('mixed_equilibrium'):
            print(f"  Mixed strategy equilibrium found")

    if 'resource_optimization' in results:
        print(f"\n💰 Resource Optimization (Lagrange Multipliers):")
        ro = results['resource_optimization']
        if 'optimal_allocation' in ro:
            print(f"  Optimal budget allocation: {[f'{x:.3f}' for x in ro['optimal_allocation']]}")
            print(f"  Efficiency score: {ro['optimal_value']:.3f}")

    print(f"\n✅ Advanced mathematical analysis complete!")

    return foundations, results

if __name__ == "__main__":
    foundations, results = main()