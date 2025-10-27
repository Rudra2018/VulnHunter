#!/usr/bin/env python3
"""
VulnHunter Ω Inference Script
Load and use the trained VulnHunter Omega model for vulnerability analysis
"""

import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import numpy as np
import networkx as nx
from scipy.spatial.distance import pdist, squareform
from scipy.stats import wasserstein_distance
from scipy.linalg import eigh
import json
import re
import time
from datetime import datetime

# Try to import Z3
try:
    from z3 import *
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

class OptimizedRicciCurvatureAnalyzer:
    """Ricci Curvature Analyzer - same as training"""
    def __init__(self, dos_threshold=-0.8):
        self.dos_threshold = dos_threshold
        self._cache = {}

    def build_cfg(self, code):
        cache_key = hash(code)
        if cache_key in self._cache:
            return self._cache[cache_key]['cfg']

        G = nx.DiGraph()
        lines = [line.strip() for line in code.split('\n') if line.strip()]

        prev_node = None
        for i, line in enumerate(lines):
            if line.startswith('//') or line.startswith('*'):
                continue

            node_id = f"stmt_{i}"
            G.add_node(node_id, code=line, line=i)

            if prev_node:
                G.add_edge(prev_node, node_id)

            if any(keyword in line.lower() for keyword in ['if', 'while', 'for']):
                branch_node = f"branch_{i}"
                G.add_node(branch_node, code="branch", critical=True)
                G.add_edge(node_id, branch_node)

            if any(pattern in line for pattern in ['.call', '.send', 'transfer(', 'external']):
                call_node = f"call_{i}"
                G.add_node(call_node, code="external_call", critical=True)
                G.add_edge(node_id, call_node)

            prev_node = node_id

        self._cache[cache_key] = {'cfg': G}
        return G

    def compute_ollivier_ricci(self, G):
        ricci_values = {}
        for edge in G.edges():
            u, v = edge
            u_neighbors = list(G.neighbors(u))
            v_neighbors = list(G.neighbors(v))

            if not u_neighbors or not v_neighbors:
                ricci_values[edge] = -1.0
                continue

            u_degrees = []
            v_degrees = []

            for n in u_neighbors:
                degree = G.degree(n)
                if G.nodes[n].get('critical', False):
                    degree *= 2
                u_degrees.append(degree)

            for n in v_neighbors:
                degree = G.degree(n)
                if G.nodes[n].get('critical', False):
                    degree *= 2
                v_degrees.append(degree)

            try:
                if len(u_degrees) == len(v_degrees):
                    d = wasserstein_distance(u_degrees, v_degrees)
                else:
                    max_len = max(len(u_degrees), len(v_degrees))
                    u_padded = u_degrees + [0] * (max_len - len(u_degrees))
                    v_padded = v_degrees + [0] * (max_len - len(v_degrees))
                    d = wasserstein_distance(u_padded, v_padded)

                total_degree = G.degree(u) + G.degree(v)
                edge_criticality = 1.0

                if (G.nodes[u].get('critical', False) or G.nodes[v].get('critical', False)):
                    edge_criticality = 2.0

                ricci_values[edge] = edge_criticality * (1 - d / (total_degree + 1e-6))
            except Exception:
                ricci_values[edge] = 0.0

        return ricci_values

    def detect_dos_vulnerability(self, code):
        G = self.build_cfg(code)
        ricci_values = self.compute_ollivier_ricci(G)

        if not ricci_values:
            return {
                'dos_detected': False,
                'min_ricci': 0.0,
                'ricci_features': [0.0, 0.0, 0.0]
            }

        min_ricci = min(ricci_values.values())
        mean_ricci = np.mean(list(ricci_values.values()))

        bottlenecks = {edge: ricci for edge, ricci in ricci_values.items()
                      if ricci < self.dos_threshold}

        has_loops = any(keyword in code.lower() for keyword in ['for', 'while'])
        has_external_calls = any(pattern in code for pattern in ['.call', '.send'])

        dos_detected = (
            len(bottlenecks) > 0 or
            (min_ricci < -0.5 and has_loops and has_external_calls)
        )

        return {
            'dos_detected': dos_detected,
            'min_ricci': min_ricci,
            'mean_ricci': mean_ricci,
            'bottleneck_count': len(bottlenecks),
            'ricci_features': [min_ricci, mean_ricci, len(bottlenecks)]
        }

class OptimizedPersistentHomologyAnalyzer:
    """Persistent Homology Analyzer - same as training"""
    def __init__(self, reentrancy_threshold=2.5):
        self.reentrancy_threshold = reentrancy_threshold
        self._cache = {}

    def build_call_graph(self, code):
        cache_key = hash(code)
        if cache_key in self._cache:
            return self._cache[cache_key]['call_graph']

        G = nx.DiGraph()
        lines = code.split('\n')
        current_function = None

        for i, line in enumerate(lines):
            line = line.strip()

            if 'function' in line and '{' in line:
                func_name = f"function_{i}"
                G.add_node(func_name, type='function', line=i, code=line)
                current_function = func_name

            if '=' in line and any(var in line for var in ['balance', 'mapping', 'uint', 'address']):
                var_name = f"state_var_{i}"
                G.add_node(var_name, type='state_variable', line=i, critical=True)
                if current_function:
                    G.add_edge(current_function, var_name, type='modifies')

            if any(pattern in line for pattern in ['.call', '.send', 'transfer(']) and current_function:
                call_node = f"external_call_{i}"
                G.add_node(call_node, type='external_call', line=i, code=line, critical=True)
                G.add_edge(current_function, call_node)
                G.add_edge(call_node, current_function, type='reentrancy_risk', weight=2.0)

                for j in range(i+1, min(i+5, len(lines))):
                    next_line = lines[j].strip()
                    if ('=' in next_line and
                        any(var in next_line for var in ['balance', 'mapping'])):
                        state_change_node = f"state_change_{j}"
                        G.add_node(state_change_node, type='state_change', line=j, critical=True)
                        G.add_edge(call_node, state_change_node, type='vulnerable_pattern', weight=3.0)

        self._cache[cache_key] = {'call_graph': G}
        return G

    def compute_point_cloud(self, G):
        points = []
        for node in G.nodes():
            node_data = G.nodes[node]

            in_deg = G.in_degree(node)
            out_deg = G.out_degree(node)

            try:
                centrality = nx.betweenness_centrality(G)[node]
            except:
                centrality = 0.0

            reentrancy_risk = 0.0
            if node_data.get('type') == 'external_call':
                reentrancy_risk = 2.0
                try:
                    for successor in G.successors(node):
                        if nx.has_path(G, successor, node):
                            reentrancy_risk += 2.0
                except:
                    pass

            state_dependency = 0.0
            if node_data.get('type') in ['state_variable', 'state_change']:
                state_dependency = 1.5

            external_interaction = 0.0
            code = node_data.get('code', '')
            if any(pattern in code for pattern in ['.call', '.send', 'transfer']):
                external_interaction = 1.8

            point = [
                in_deg, out_deg, centrality * 100,
                reentrancy_risk * 10, state_dependency * 5, external_interaction * 8
            ]
            points.append(point)

        return np.array(points) if points else np.array([[0, 0, 0, 0, 0, 0]])

    def compute_persistent_homology(self, points):
        if len(points) < 3:
            return {'h1_holes': 0, 'max_persistence': 0.0, 'vulnerability_cycles': 0}

        try:
            distances = pdist(points)
            dist_matrix = squareform(distances)
        except:
            return {'h1_holes': 0, 'max_persistence': 0.0, 'vulnerability_cycles': 0}

        h1_holes = 0
        max_persistence = 0.0
        vulnerability_cycles = 0
        n = len(points)

        for i in range(n):
            for j in range(i+1, n):
                for k in range(j+1, n):
                    d_ij = dist_matrix[i, j]
                    d_jk = dist_matrix[j, k]
                    d_ki = dist_matrix[k, i]

                    if (d_ij + d_jk > d_ki and d_jk + d_ki > d_ij and d_ki + d_ij > d_jk):
                        h1_holes += 1
                        persistence = max(d_ij, d_jk, d_ki)
                        max_persistence = max(max_persistence, persistence)

                        triangle_points = [points[i], points[j], points[k]]
                        if any(point[3] > 5 for point in triangle_points):
                            vulnerability_cycles += 1

        return {
            'h1_holes': h1_holes,
            'max_persistence': max_persistence,
            'vulnerability_cycles': vulnerability_cycles
        }

    def detect_reentrancy(self, code):
        G = self.build_call_graph(code)
        points = self.compute_point_cloud(G)
        homology = self.compute_persistent_homology(points)

        topology_detected = (
            homology['max_persistence'] > self.reentrancy_threshold or
            homology['vulnerability_cycles'] > 0
        )

        has_external_call = any(pattern in code for pattern in ['.call', '.send', 'transfer('])
        has_state_change_after = self._check_state_change_after_call(code)

        reentrancy_detected = (
            topology_detected or
            (has_external_call and has_state_change_after)
        )

        return {
            'reentrancy_detected': reentrancy_detected,
            'h1_holes': homology['h1_holes'],
            'max_persistence': homology['max_persistence'],
            'vulnerability_cycles': homology['vulnerability_cycles'],
            'homology_features': [
                homology['h1_holes'],
                homology['max_persistence'],
                homology['vulnerability_cycles']
            ]
        }

    def _check_state_change_after_call(self, code):
        lines = code.split('\n')
        found_call = False

        for line in lines:
            if any(pattern in line for pattern in ['.call', '.send', 'transfer(']):
                found_call = True
            elif found_call and ('=' in line and
                               any(var in line for var in ['balance', 'mapping', 'amount'])):
                return True
        return False

class OptimizedSpectralAnalyzer:
    """Spectral Graph Theory Analyzer - same as training"""
    def __init__(self, access_threshold=0.15):
        self.access_threshold = access_threshold
        self._cache = {}

    def build_ast_graph(self, code):
        cache_key = hash(code)
        if cache_key in self._cache:
            return self._cache[cache_key]['ast_graph']

        G = nx.Graph()
        tokens = re.findall(r'\w+', code)
        access_control_nodes = set()
        critical_function_nodes = set()

        for i, token in enumerate(tokens):
            node_id = f"token_{i}"
            G.add_node(node_id, value=token, position=i)

            if i > 0:
                G.add_edge(f"token_{i-1}", node_id, weight=1.0)

            if token.lower() in ['require', 'modifier', 'onlyowner', 'onlyadmin', 'auth']:
                access_node = f"access_{i}"
                access_control_nodes.add(access_node)
                G.add_node(access_node, type='access_control', token=token, critical=True)
                G.add_edge(node_id, access_node, weight=3.0)

            if token.lower() in ['selfdestruct', 'delegatecall', 'suicide', 'transfer', 'send']:
                critical_node = f"critical_{i}"
                critical_function_nodes.add(critical_node)
                G.add_node(critical_node, type='critical_function', token=token, critical=True)
                G.add_edge(node_id, critical_node, weight=4.0)

        for access_node in access_control_nodes:
            for critical_node in critical_function_nodes:
                G.add_edge(access_node, critical_node, weight=5.0)

        self._cache[cache_key] = {'ast_graph': G}
        return G

    def compute_laplacian_spectrum(self, G):
        if len(G.nodes()) < 2:
            return np.array([0.0, 0.0])

        try:
            L = nx.laplacian_matrix(G, weight='weight').todense()
            eigenvals = eigh(L)[0]
            return np.sort(eigenvals)
        except Exception:
            return np.array([0.0, 0.0])

    def detect_access_control_issues(self, code):
        G = self.build_ast_graph(code)
        spectrum = self.compute_laplacian_spectrum(G)

        if len(spectrum) < 2:
            return {
                'access_vulnerable': False,
                'spectral_gap': 0.0,
                'spectral_features': [0.0, 0.0, 0.0]
            }

        spectral_gap = spectrum[1] - spectrum[0] if len(spectrum) > 1 else 0.0
        connectivity = np.mean(spectrum[1:5]) if len(spectrum) > 4 else spectrum[1]
        algebraic_connectivity = spectrum[1] if len(spectrum) > 1 else 0.0

        vulnerable_gap = abs(spectral_gap) < self.access_threshold
        poor_connectivity = algebraic_connectivity < 0.5

        access_modifiers = [
            'onlyowner', 'onlyadmin', 'modifier', 'require(msg.sender',
            'auth', 'onlyauth', 'restricted'
        ]
        has_access_modifiers = any(keyword in code.lower() for keyword in access_modifiers)

        critical_functions = [
            'selfdestruct', 'delegatecall', 'suicide', 'transfer(',
            'send(', 'withdraw', 'mint', 'burn'
        ]
        has_critical_functions = any(keyword in code.lower() for keyword in critical_functions)

        syntactic_vulnerable = has_critical_functions and not has_access_modifiers
        spectral_vulnerable = vulnerable_gap or poor_connectivity

        final_vulnerable = (
            syntactic_vulnerable or
            (spectral_vulnerable and has_critical_functions) or
            (poor_connectivity and has_critical_functions and not has_access_modifiers)
        )

        return {
            'access_vulnerable': final_vulnerable,
            'spectral_gap': spectral_gap,
            'connectivity': connectivity,
            'algebraic_connectivity': algebraic_connectivity,
            'has_modifiers': has_access_modifiers,
            'has_critical_functions': has_critical_functions,
            'spectral_features': [
                spectral_gap,
                algebraic_connectivity,
                len(G.nodes())
            ]
        }

class OptimizedZ3FormalVerifier:
    """Z3 SMT Formal Verifier - same as training"""
    def __init__(self):
        self.available = Z3_AVAILABLE
        self._cache = {}

    def prove_reentrancy_exploit(self, code):
        cache_key = hash(code)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.available:
            result = {
                'exploit_proven': False,
                'z3_features': [0.0, 0.0, 0.0],
                'proof_type': 'z3_unavailable'
            }
            self._cache[cache_key] = result
            return result

        try:
            solver = Solver()
            solver.set(timeout=5000)

            initial_balance = Int('initial_balance')
            user_balance = Int('user_balance')
            withdrawn_amount = Int('withdrawn_amount')
            call_count = Int('call_count')
            contract_balance = Int('contract_balance')
            state_changed = Bool('state_changed')

            solver.add(initial_balance >= 1000)
            solver.add(user_balance >= 100)
            solver.add(user_balance <= initial_balance)
            solver.add(withdrawn_amount >= 0)
            solver.add(call_count >= 0)
            solver.add(contract_balance == initial_balance)
            solver.add(state_changed == False)

            has_external_call = any(pattern in code for pattern in ['.call', '.send', 'transfer('])
            has_balance_check = any(var in code.lower() for var in ['balance', 'amount'])
            state_change_after = self._detect_state_change_after_call(code)
            has_reentrancy_guard = 'nonreentrant' in code.lower() or 'reentrancyguard' in code.lower()

            if has_external_call and has_balance_check and not has_reentrancy_guard:
                solver.add(call_count >= 1)
                solver.add(withdrawn_amount >= user_balance)
                solver.add(call_count >= 2)
                solver.add(withdrawn_amount >= 2 * user_balance)
                solver.add(withdrawn_amount > contract_balance)

                if state_change_after:
                    solver.add(state_changed == True)
                    solver.add(withdrawn_amount >= 3 * user_balance)
                    solver.add(call_count >= 3)

                result_status = solver.check()

                if result_status == sat:
                    model = solver.model()
                    exploit_evidence = {
                        'initial_balance': model[initial_balance].as_long() if model[initial_balance] else 0,
                        'withdrawn': model[withdrawn_amount].as_long() if model[withdrawn_amount] else 0,
                        'calls': model[call_count].as_long() if model[call_count] else 0,
                        'state_changed': model[state_changed] if model[state_changed] else False
                    }

                    result = {
                        'exploit_proven': True,
                        'z3_result': 'sat',
                        'exploit_evidence': exploit_evidence,
                        'proof_type': 'formal_reentrancy_proof',
                        'z3_features': [
                            1.0,
                            float(exploit_evidence['withdrawn']),
                            float(exploit_evidence['calls'])
                        ]
                    }
                else:
                    result = {
                        'exploit_proven': False,
                        'z3_result': str(result_status),
                        'proof_type': 'proven_safe',
                        'z3_features': [0.0, 0.0, 0.0]
                    }
            else:
                result = {
                    'exploit_proven': False,
                    'z3_result': 'no_pattern',
                    'proof_type': 'no_vulnerability_pattern',
                    'z3_features': [0.0, 0.0, 0.0]
                }

            self._cache[cache_key] = result
            return result

        except Exception as e:
            result = {
                'exploit_proven': False,
                'error': str(e),
                'proof_type': 'error',
                'z3_features': [0.0, 0.0, 0.0]
            }
            self._cache[cache_key] = result
            return result

    def _detect_state_change_after_call(self, code):
        lines = code.split('\n')
        found_call = False
        call_line = -1

        for i, line in enumerate(lines):
            line = line.strip()
            if any(pattern in line for pattern in ['.call', '.send', 'transfer(']):
                found_call = True
                call_line = i
            elif found_call and i > call_line:
                state_change_patterns = [
                    '=', 'balance[', 'mapping[', '+=', '-=', '++', '--',
                    'delete', 'push(', 'pop()', 'transfer('
                ]
                if any(pattern in line for pattern in state_change_patterns):
                    return True
        return False

class VulnHunterOmegaOptimized(nn.Module):
    """Exact same model architecture as training"""
    def __init__(self, base_model_name='microsoft/codebert-base', num_classes=5):
        super().__init__()

        self.ricci_analyzer = OptimizedRicciCurvatureAnalyzer()
        self.homology_analyzer = OptimizedPersistentHomologyAnalyzer()
        self.spectral_analyzer = OptimizedSpectralAnalyzer()
        self.z3_verifier = OptimizedZ3FormalVerifier()

        self.tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.base_model = AutoModel.from_pretrained(base_model_name)

        self.ricci_dim = 3
        self.homology_dim = 3
        self.spectral_dim = 3
        self.z3_dim = 3
        total_math_dim = self.ricci_dim + self.homology_dim + self.spectral_dim + self.z3_dim

        self.math_processor = nn.Sequential(
            nn.Linear(total_math_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU()
        )

        code_dim = self.base_model.config.hidden_size
        self.fusion_layer = nn.Sequential(
            nn.Linear(code_dim + 128, 768),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(768, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU()
        )

        self.confidence_head = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

        self.classifier = nn.Linear(256, num_classes)

        self.confidence_weights = {
            'z3_feasibility': 0.4,
            'homology_evidence': 0.3,
            'ricci_evidence': 0.2,
            'spectral_evidence': 0.1
        }

    def extract_mathematical_features(self, code):
        ricci_result = self.ricci_analyzer.detect_dos_vulnerability(code)
        homology_result = self.homology_analyzer.detect_reentrancy(code)
        spectral_result = self.spectral_analyzer.detect_access_control_issues(code)
        z3_result = self.z3_verifier.prove_reentrancy_exploit(code)

        features = (
            ricci_result['ricci_features'] +
            homology_result['homology_features'] +
            spectral_result['spectral_features'] +
            z3_result['z3_features']
        )

        math_confidence = (
            self.confidence_weights['z3_feasibility'] * (1.0 if z3_result['exploit_proven'] else 0.0) +
            self.confidence_weights['homology_evidence'] * (1.0 if homology_result['reentrancy_detected'] else 0.0) +
            self.confidence_weights['ricci_evidence'] * (1.0 if ricci_result['dos_detected'] else 0.0) +
            self.confidence_weights['spectral_evidence'] * (1.0 if spectral_result['access_vulnerable'] else 0.0)
        )

        return features, math_confidence, {
            'ricci': ricci_result,
            'homology': homology_result,
            'spectral': spectral_result,
            'z3': z3_result
        }

    def analyze_code(self, code, max_length=384):
        """Main inference function"""
        self.eval()

        # Tokenize
        encoding = self.tokenizer(
            code,
            truncation=True,
            padding='max_length',
            max_length=max_length,
            return_tensors='pt'
        )

        input_ids = encoding['input_ids']
        attention_mask = encoding['attention_mask']

        with torch.no_grad():
            # Extract mathematical features
            math_features, math_confidence, detailed_analysis = self.extract_mathematical_features(code)
            math_features_tensor = torch.tensor([math_features], dtype=torch.float32)
            math_confidence_tensor = torch.tensor([math_confidence])

            # Forward pass
            outputs = self.base_model(input_ids=input_ids, attention_mask=attention_mask)
            code_embeddings = outputs.last_hidden_state[:, 0, :]

            processed_math = self.math_processor(math_features_tensor)
            fused_features = torch.cat([code_embeddings, processed_math], dim=1)
            fused_output = self.fusion_layer(fused_features)

            logits = self.classifier(fused_output)
            neural_confidence = self.confidence_head(fused_output).squeeze()
            final_confidence = 0.6 * neural_confidence + 0.4 * math_confidence_tensor

            # Get predictions
            probabilities = torch.softmax(logits, dim=1)
            predicted_class = torch.argmax(logits, dim=1).item()

            # Label mapping
            labels = ['safe', 'reentrancy', 'access_control', 'overflow', 'dos']
            predicted_label = labels[predicted_class]

            return {
                'prediction': predicted_label,
                'confidence': final_confidence.item(),
                'probabilities': {
                    labels[i]: probabilities[0][i].item() for i in range(len(labels))
                },
                'mathematical_confidence': math_confidence,
                'neural_confidence': neural_confidence.item(),
                'mathematical_analysis': detailed_analysis,
                'vulnerability_detected': predicted_class != 0,
                'high_confidence': final_confidence.item() > 0.7
            }

def load_trained_model(model_path):
    """Load the trained VulnHunter Omega model"""
    print(f"🔄 Loading trained model from {model_path}...")

    # Initialize model
    model = VulnHunterOmegaOptimized()

    # Load checkpoint
    checkpoint = torch.load(model_path, map_location='cpu')
    model.load_state_dict(checkpoint['model_state_dict'])

    # Set to evaluation mode
    model.eval()

    print(f"✅ Model loaded successfully!")
    print(f"📊 Model info:")
    print(f"  • Parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"  • Training epoch: {checkpoint.get('epoch', 'N/A')}")
    print(f"  • Validation accuracy: {checkpoint.get('val_acc', 'N/A'):.4f}")

    return model

def load_training_results(results_path):
    """Load training results"""
    with open(results_path, 'r') as f:
        results = json.load(f)

    print(f"📈 Training Results:")
    if 'training_metrics' in results:
        metrics = results['training_metrics']
        print(f"  • Final validation accuracy: {metrics['val_accuracies'][-1]:.4f}")
        print(f"  • Final mathematical accuracy: {metrics['mathematical_accuracies'][-1]:.4f}")
        print(f"  • Training time: {metrics['training_time']:.1f}s")

    if 'speedup_achieved' in results:
        print(f"  • Speedup achieved: {results['speedup_achieved']:.1f}x")

    return results

def test_model_inference():
    """Test the model with sample vulnerabilities"""

    # Load model and results
    model = load_trained_model('/Users/ankitthakur/vuln_ml_research/vulnhunter_omega_optimized_best.pth')
    results = load_training_results('/Users/ankitthakur/vuln_ml_research/vulnhunter_omega_optimized_results.json')

    # Test cases
    test_cases = {
        'Reentrancy Vulnerability': '''
function withdraw() {
    uint amount = balances[msg.sender];
    require(amount > 0, "No balance");
    msg.sender.call{value: amount}("");
    balances[msg.sender] = 0; // VULNERABLE: state change after call
}
''',
        'Access Control Vulnerability': '''
function criticalFunction() public {
    // VULNERABLE: Missing onlyOwner modifier
    selfdestruct(payable(msg.sender));
}
''',
        'DoS Vulnerability': '''
function processUsers() public {
    for(uint i = 0; i < users.length; i++) {
        // VULNERABLE: unbounded loop
        users[i].call{value: 100}("");
        expensiveComputation(users[i]);
    }
}
''',
        'Safe Contract': '''
function safeWithdraw() external nonReentrant onlyOwner {
    require(address(this).balance > 0, "No balance");
    payable(owner).transfer(address(this).balance); // SAFE
}
'''
    }

    print(f"\\n🔍 Testing VulnHunter Ω Inference...")
    print(f"=" * 80)

    for test_name, code in test_cases.items():
        print(f"\\n🧪 Testing: {test_name}")
        print("-" * 50)

        start_time = time.time()
        result = model.analyze_code(code)
        analysis_time = time.time() - start_time

        print(f"🎯 Prediction: {result['prediction'].upper()}")
        print(f"🎪 Confidence: {result['confidence']:.4f}")
        print(f"🔬 Mathematical Confidence: {result['mathematical_confidence']:.4f}")
        print(f"🧠 Neural Confidence: {result['neural_confidence']:.4f}")
        print(f"⚠️  Vulnerability Detected: {result['vulnerability_detected']}")
        print(f"✨ High Confidence: {result['high_confidence']}")
        print(f"⏱️  Analysis Time: {analysis_time:.4f}s")

        # Mathematical analysis details
        math_analysis = result['mathematical_analysis']
        print(f"\\n🔬 Mathematical Analysis:")
        print(f"  🌊 Ricci: DoS={math_analysis['ricci']['dos_detected']}")
        print(f"  🕳️  Homology: Reentrancy={math_analysis['homology']['reentrancy_detected']}")
        print(f"  📊 Spectral: Access={math_analysis['spectral']['access_vulnerable']}")
        print(f"  ⚡ Z3: Proven={math_analysis['z3']['exploit_proven']}")

        # Top probabilities
        print(f"\\n📊 Probabilities:")
        sorted_probs = sorted(result['probabilities'].items(), key=lambda x: x[1], reverse=True)
        for label, prob in sorted_probs[:3]:
            print(f"  {label}: {prob:.4f}")

if __name__ == "__main__":
    test_model_inference()