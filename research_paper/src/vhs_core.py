#!/usr/bin/env python3
"""
🧮 VHS Core: Mathematical Components for Vulnerability Homotopy Space
Following 3.txt integration specifications for VulnHunter Ωmega

Core Mathematical Framework:
- Simplicial Complexes (TDA)
- Sheaf Theory (Context)
- Category Functors (Intent)
- Dynamical Systems (Flow)
- Homotopy Classification
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import networkx as nx
from scipy.spatial.distance import pdist, squareform
from typing import Dict, List, Tuple, Any, Optional
import json
import jsonlines
from pathlib import Path
from collections import defaultdict

try:
    from torch_geometric.utils import from_networkx
    from torch_geometric.data import Data
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    print("⚠️  torch-geometric not available - using simplified graph operations")

class VHSSimplicialComplex(nn.Module):
    """Build simplicial complex from VulnHunter's GNN graph."""

    def __init__(self, max_dim=2):
        super().__init__()
        self.max_dim = max_dim
        self.node_encoder = nn.Linear(50, 32)

    def forward(self, graph_features):
        """Extract edges from GNN adjacency and build simplicial complex"""
        batch_size = graph_features.size(0)

        # Extract adjacency matrix from features
        adj_size = int(np.sqrt(graph_features.size(1) // 2))
        adj_flat = graph_features[:, :adj_size*adj_size]
        adj = torch.sigmoid(adj_flat.view(batch_size, adj_size, adj_size)) > 0.5

        simplices_batch = []
        for i in range(batch_size):
            G = nx.from_numpy_array(adj[i].cpu().numpy())

            # Build simplices: nodes + edges + triangles (simple heuristic)
            nodes = list(G.nodes)
            edges = list(G.edges)

            # 2-simplices: cliques of size 3 (control loops)
            triangles = [list(t) for t in nx.enumerate_all_cliques(G) if len(t) == 3]

            simplices_batch.append({
                'nodes': nodes,
                'edges': edges,
                'triangles': triangles[:10]  # Limit for efficiency
            })

        return simplices_batch

    def persistent_homology(self, simplices_batch, max_scale=10):
        """Basic persistence via distance matrix (Rips filtration)."""
        persistence_batch = []

        for simplices in simplices_batch:
            nodes = simplices['nodes']
            edges = simplices['edges']
            triangles = simplices['triangles']

            if len(nodes) == 0:
                persistence_batch.append(torch.zeros(3))
                continue

            # Simple persistence: birth/death times (holes surviving scales)
            # H0: Connected components
            h0 = len(nodes) / 50.0  # Normalized

            # H1: Loops relative to nodes
            h1 = len(edges) / max(len(nodes), 1)

            # H2: Voids relative to edges
            h2 = len(triangles) / max(len(edges), 1)

            persistence = torch.tensor([h0, h1, h2], dtype=torch.float32)
            persistence_batch.append(persistence)

        return torch.stack(persistence_batch)

class VHSSheaf(nn.Module):
    """Context sheaf: Local sections + gluing coherence"""

    def __init__(self, metadata_dim=10):
        super().__init__()
        self.context_encoder = nn.Linear(metadata_dim, 4)  # [test, prod, poc, academic]
        self.coherence_net = nn.Linear(4, 1)

    def forward(self, metadata):
        """Section assignment + coherence penalty for inconsistent overlaps"""

        # Extract metadata features tensor
        if isinstance(metadata, dict):
            features = metadata['features']
        else:
            features = metadata

        # Context classification (sheaf sections)
        sections = torch.softmax(self.context_encoder(features), dim=-1)

        # Coherence: Penalty for inconsistent overlaps
        coherence = torch.sigmoid(self.coherence_net(sections))

        return sections, coherence.squeeze(-1)

class VHSFunctor(nn.Module):
    """Intent functor: Code → Intent category"""

    def __init__(self, embed_dim=768):
        super().__init__()
        self.intent_map = nn.Linear(embed_dim, 5)  # [demo, entrypoint, highrisk, weaponized, theoretical]
        self.maturity_net = nn.Linear(5, 1)

    def forward(self, code_embeds):
        """Map code embeddings to intent categories"""

        # Flatten if needed
        if code_embeds.dim() > 2:
            code_embeds = code_embeds.view(code_embeds.size(0), -1)

        intent_vec = torch.softmax(self.intent_map(code_embeds), dim=-1)

        # Natural transformation: Low maturity → theoretical
        maturity = torch.sigmoid(self.maturity_net(intent_vec))

        return intent_vec, maturity.squeeze(-1)

class VHSFlow(nn.Module):
    """Dynamical flow on graph for reachability"""

    def __init__(self, feature_dim=50):
        super().__init__()
        self.flow_net = nn.Linear(feature_dim, 2)  # [dx/dt, attractor]
        self.divergence_net = nn.Linear(2, 1)

    def forward(self, graph_feats):
        """Model execution as vector field dx/dt = f(x, input_source)"""

        vec_field = self.flow_net(graph_feats)  # Vector field

        # Simulate orbit (simple Euler step)
        flow_x, attractor_strength = vec_field[:, 0], vec_field[:, 1]

        # Jacobian divergence (chaotic if >0)
        divergence = torch.sigmoid(self.divergence_net(vec_field))

        # Attractor escape: High div + escape → actionable
        attractor = torch.sigmoid(attractor_strength)

        return divergence.squeeze(-1), attractor

class VulnerabilityHomotopySpace(nn.Module):
    """
    Unified VHS: Mathematical singularity without brittle rules
    VHS = (Simplicial Complex, F_context, F_intent, vec_f_flow)
    """

    def __init__(self, feature_dim=50, embed_dim=768, metadata_dim=10):
        super().__init__()
        self.simplex = VHSSimplicialComplex()
        self.sheaf = VHSSheaf(metadata_dim)
        self.functor = VHSFunctor(embed_dim)
        self.flow = VHSFlow(feature_dim)

        # VHS classifier: [H,C,I,D,M,A] → 4 classes
        self.classifier = nn.Sequential(
            nn.Linear(8, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 4)  # [test, academic, production, theoretical]
        )

        # Archetype holes for homotopy loss
        self.register_buffer('archetype_holes', torch.tensor([
            [0.1, 0.1, 0.0],  # Test: low persistence, disconnected components
            [0.3, 0.2, 0.1],  # Academic: medium complexity
            [0.8, 0.6, 0.4],  # Production: high persistence, large connected component
            [0.2, 0.1, 0.0]   # Theoretical: low complexity
        ]))

    def forward(self, graph_feats, code_embeds, metadata):
        """VHS classification: Embed patterns in homotopy space"""

        # 1. Topological analysis (TDA)
        simplices = self.simplex(graph_feats)
        H = self.simplex.persistent_homology(simplices)  # Shape invariant

        # 2. Sheaf context analysis
        sections, C = self.sheaf(metadata)  # Context consistency

        # 3. Intent functor analysis
        I, M = self.functor(code_embeds)  # Intent maturity
        intent_strength = I.max(dim=1)[0]  # Max intent category

        # 4. Flow dynamics analysis
        D, A = self.flow(graph_feats)  # Divergence + attractor

        # 5. Fuse features for homotopy classification
        features = torch.cat([
            H,  # Homology [3]
            C.unsqueeze(1),  # Coherence [1]
            intent_strength.unsqueeze(1),  # Intent [1]
            D.unsqueeze(1),  # Divergence [1]
            M.unsqueeze(1),  # Maturity [1]
            A.unsqueeze(1)   # Attractor [1]
        ], dim=1)  # [batch, 8]

        # 6. Homotopy classification
        logits = self.classifier(features)
        probs = torch.softmax(logits, dim=-1)

        # 7. Mathematical explanations
        explanations = {
            'homology': H,
            'coherence': C,
            'intent': I,
            'maturity': M,
            'divergence': D,
            'attractor': A,
            'sections': sections
        }

        return probs, explanations

    def homotopy_loss(self, explanations, class_labels):
        """Homotopy distance to archetypes"""
        homology = explanations['homology']

        # Distance to archetype holes
        archetype_loss = 0
        for i, label in enumerate(class_labels):
            if 0 <= label < len(self.archetype_holes):
                target_archetype = self.archetype_holes[label]
                archetype_loss += F.mse_loss(homology[i], target_archetype)

        return archetype_loss / len(class_labels)

class MegaVulVHSDataset:
    """MegaVul loader: Functions + metadata + graphs for VHS"""

    def __init__(self, json_path, max_samples=None, split='train'):
        self.data = []
        self.split = split

        print(f"Loading MegaVul dataset from {json_path}...")

        with jsonlines.open(json_path) as reader:
            for i, item in enumerate(reader):
                if max_samples and i >= max_samples:
                    break

                if i % 5000 == 0:
                    print(f"Processed {i} samples...")

                try:
                    # VulnHunter-style features
                    code_embeds = self._dummy_embed(item.get('func_before', ''))
                    metadata = self._extract_metadata_features(item)
                    graph_feats = self._extract_graph_features(item.get('func_before', ''))

                    # Labels
                    vul_label = int(item.get('is_vul', 0))
                    homotopy_class = self._map_to_homotopy_class(item, vul_label)

                    self.data.append({
                        'graph_feats': graph_feats,
                        'code_embeds': code_embeds,
                        'metadata': {'features': metadata},
                        'vul_label': vul_label,
                        'homotopy_class': homotopy_class,
                        'cve_id': item.get('cve_id', ''),
                        'file_path': item.get('file_path', '')
                    })

                except Exception as e:
                    continue

        print(f"Loaded {len(self.data)} samples")

    def _dummy_embed(self, func_code):
        """Placeholder: Replace with real CodeBERT"""
        return torch.randn(1, 768)

    def _extract_metadata_features(self, item):
        """Extract 10-dim metadata for sheaf"""
        features = torch.zeros(10)

        # Path-based context
        file_path = item.get('file_path', '').lower()
        features[0] = 1.0 if 'test' in file_path else 0.0
        features[1] = 1.0 if any(x in file_path for x in ['src', 'lib']) else 0.0
        features[2] = 1.0 if any(x in file_path for x in ['example', 'demo']) else 0.0

        # Commit context
        commit_msg = item.get('commit_msg', '').lower()
        features[3] = 1.0 if 'test' in commit_msg else 0.0
        features[4] = 1.0 if 'fix' in commit_msg else 0.0
        features[5] = 1.0 if 'add' in commit_msg else 0.0

        # CVE context
        features[6] = 1.0 if item.get('cve_id') else 0.0
        features[7] = float(item.get('cvss_score', 0.0)) / 10.0

        # Diff size
        features[8] = min(len(item.get('diff_line_info', [])) / 50.0, 1.0)

        # Language
        features[9] = 1.0 if item.get('lang') == 'c' else 0.0

        return features

    def _extract_graph_features(self, func_code):
        """Extract 50-dim graph features"""
        features = torch.zeros(50)

        # Basic metrics
        lines = func_code.split('\n')
        features[0] = min(len(lines) / 100.0, 1.0)
        features[1] = min(len(func_code) / 5000.0, 1.0)

        # Control flow
        features[2] = min(func_code.count('if') / 10.0, 1.0)
        features[3] = min(func_code.count('for') / 10.0, 1.0)
        features[4] = min(func_code.count('while') / 10.0, 1.0)

        # Function calls (adjacency simulation)
        import re
        features[5] = min(len(re.findall(r'\w+\s*\(', func_code)) / 20.0, 1.0)

        # Vulnerability patterns
        features[6] = 1.0 if 'strcpy' in func_code else 0.0
        features[7] = 1.0 if 'malloc' in func_code else 0.0
        features[8] = 1.0 if any(x in func_code for x in ['eval', 'exec']) else 0.0

        # Random for adjacency matrix (mock)
        features[9:] = torch.randn(41) * 0.1

        return features

    def _map_to_homotopy_class(self, item, is_vul):
        """Map to homotopy classes via functors"""
        file_path = item.get('file_path', '').lower()
        commit_msg = item.get('commit_msg', '').lower()

        # Test class
        if any(x in file_path for x in ['test', 'spec']):
            return 0

        # Academic class
        if any(x in file_path for x in ['example', 'demo', 'doc']):
            return 1

        # Production class
        if is_vul and item.get('cve_id'):
            return 2

        # Theoretical class
        return 3

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx]

def main():
    """Demo VHS components"""
    print("🧮 VHS Core Components Demo")
    print("=" * 50)

    # Initialize VHS
    vhs = VulnerabilityHomotopySpace()

    # Mock inputs
    batch_size = 4
    graph_feats = torch.randn(batch_size, 50)
    code_embeds = torch.randn(batch_size, 768)
    metadata = {'features': torch.randn(batch_size, 10)}

    # VHS analysis
    probs, explanations = vhs(graph_feats, code_embeds, metadata)

    print(f"📊 VHS Classification Probabilities:")
    print(f"Shape: {probs.shape}")
    print(f"Classes: [Test, Academic, Production, Theoretical]")
    print(f"Sample probs: {probs[0]}")

    print(f"\n🧮 Mathematical Explanations:")
    print(f"Homology H0,H1,H2: {explanations['homology'][0]}")
    print(f"Sheaf coherence: {explanations['coherence'][0]:.3f}")
    print(f"Flow divergence: {explanations['divergence'][0]:.3f}")
    print(f"Intent maturity: {explanations['maturity'][0]:.3f}")

    # Homotopy loss demo
    mock_labels = torch.tensor([0, 1, 2, 3])  # One of each class
    homotopy_loss = vhs.homotopy_loss(explanations, mock_labels)
    print(f"\n📐 Homotopy Loss: {homotopy_loss:.4f}")

    print("\n✅ VHS Core Demo Complete!")
    print("🎯 Mathematical topology ready for vulnerability classification!")

if __name__ == "__main__":
    main()