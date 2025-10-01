"""
Intelligent Seed Management System

This module provides advanced seed corpus management for fuzzing:
- ML-driven seed selection and prioritization
- Automatic seed corpus generation and optimization
- Mutation strategy optimization based on coverage feedback
- Cross-target seed sharing and correlation
- Performance-based seed pruning and enhancement
"""

import os
import hashlib
import json
import time
import random
import pickle
import shutil
import tempfile
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict, deque
import heapq

class SeedType(Enum):
    """Types of seeds"""
    INITIAL = "initial"
    GENERATED = "generated"
    MUTATED = "mutated"
    MINIMIZED = "minimized"
    HIGH_COVERAGE = "high_coverage"
    CRASH_INDUCING = "crash_inducing"
    CROSSOVER = "crossover"

class MutationStrategy(Enum):
    """Mutation strategies"""
    RANDOM_BIT_FLIP = "random_bit_flip"
    BYTE_REPLACEMENT = "byte_replacement"
    BLOCK_INSERTION = "block_insertion"
    BLOCK_DELETION = "block_deletion"
    ARITHMETIC = "arithmetic"
    DICTIONARY_BASED = "dictionary_based"
    STRUCTURE_AWARE = "structure_aware"
    ML_GUIDED = "ml_guided"

@dataclass
class SeedMetrics:
    """Metrics for seed evaluation"""
    coverage_score: float
    execution_speed: float
    crash_potential: float
    uniqueness_score: float
    stability_score: float
    generation_cost: float
    success_rate: float
    last_updated: float

@dataclass
class SeedInfo:
    """Complete seed information"""
    seed_id: str
    file_path: str
    content_hash: str
    size: int
    seed_type: SeedType
    parent_seed_id: Optional[str]
    mutation_strategy: Optional[MutationStrategy]
    metrics: SeedMetrics
    target_ids: Set[str]
    creation_time: float
    last_used: float
    use_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

class SeedEvaluator(nn.Module):
    """Neural network for evaluating seed quality"""

    def __init__(self, input_dim: int = 512, hidden_dim: int = 256):
        super().__init__()

        self.content_encoder = nn.Sequential(
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

        self.crash_predictor = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

        self.quality_scorer = nn.Sequential(
            nn.Linear(hidden_dim + 2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, seed_features):
        encoded = self.content_encoder(seed_features)

        coverage_pred = self.coverage_predictor(encoded)
        crash_pred = self.crash_predictor(encoded)

        combined_features = torch.cat([encoded, coverage_pred, crash_pred], dim=-1)
        quality_score = self.quality_scorer(combined_features)

        return {
            'coverage_prediction': coverage_pred,
            'crash_prediction': crash_pred,
            'quality_score': quality_score,
            'features': encoded
        }

class SeedGenerator:
    """Generates new seeds using various strategies"""

    def __init__(self):
        self.generation_strategies = {
            'random': self._generate_random_seed,
            'template_based': self._generate_template_based_seed,
            'grammar_based': self._generate_grammar_based_seed,
            'evolutionary': self._generate_evolutionary_seed,
            'ml_guided': self._generate_ml_guided_seed
        }

        self.templates = self._load_seed_templates()
        self.dictionaries = self._load_dictionaries()

    def _load_seed_templates(self) -> Dict[str, List[bytes]]:
        """Load seed templates for different file types"""
        templates = {
            'text': [
                b'Hello World',
                b'Test input',
                b'AAAA',
                b'%s%s%s%s',
                b'../../../etc/passwd'
            ],
            'binary': [
                b'\x00\x01\x02\x03',
                b'\xff\xfe\xfd\xfc',
                b'\x7f\x45\x4c\x46',  # ELF header
                b'\x89\x50\x4e\x47',  # PNG header
            ],
            'json': [
                b'{"key": "value"}',
                b'{"array": [1,2,3]}',
                b'{"nested": {"key": "value"}}',
            ],
            'xml': [
                b'<root></root>',
                b'<root><child>value</child></root>',
                b'<?xml version="1.0"?><root/>',
            ]
        }
        return templates

    def _load_dictionaries(self) -> Dict[str, List[bytes]]:
        """Load mutation dictionaries"""
        dictionaries = {
            'common_words': [
                b'admin', b'root', b'test', b'user', b'password',
                b'login', b'guest', b'anonymous', b'default'
            ],
            'format_strings': [
                b'%s', b'%d', b'%x', b'%n', b'%p',
                b'%08x', b'%016x', b'%.8x'
            ],
            'special_chars': [
                b'\x00', b'\xff', b'\x7f', b'\x80',
                b'\n', b'\r', b'\t', b' '
            ],
            'magic_numbers': [
                b'\x7f\x45\x4c\x46',  # ELF
                b'\x89\x50\x4e\x47',  # PNG
                b'\xff\xd8\xff',      # JPEG
                b'\x50\x4b\x03\x04',  # ZIP
            ]
        }
        return dictionaries

    def generate_seed(self, strategy: str, size: int = 1024,
                     parent_seed: Optional[bytes] = None,
                     metadata: Dict[str, Any] = None) -> bytes:
        """Generate new seed using specified strategy"""
        if strategy not in self.generation_strategies:
            strategy = 'random'

        try:
            return self.generation_strategies[strategy](size, parent_seed, metadata or {})
        except Exception as e:
            logging.error(f"Seed generation failed with strategy {strategy}: {e}")
            return self._generate_random_seed(size, parent_seed, metadata or {})

    def _generate_random_seed(self, size: int, parent_seed: Optional[bytes], metadata: Dict[str, Any]) -> bytes:
        """Generate random seed"""
        return bytes(random.randint(0, 255) for _ in range(size))

    def _generate_template_based_seed(self, size: int, parent_seed: Optional[bytes], metadata: Dict[str, Any]) -> bytes:
        """Generate seed based on templates"""
        file_type = metadata.get('file_type', 'text')
        templates = self.templates.get(file_type, self.templates['text'])

        base_template = random.choice(templates)

        if len(base_template) >= size:
            return base_template[:size]

        # Pad or repeat template to reach desired size
        repetitions = (size // len(base_template)) + 1
        extended = base_template * repetitions
        return extended[:size]

    def _generate_grammar_based_seed(self, size: int, parent_seed: Optional[bytes], metadata: Dict[str, Any]) -> bytes:
        """Generate seed using grammar rules"""
        # Simple grammar-based generation for JSON
        if metadata.get('format') == 'json':
            return self._generate_json_seed(size)
        elif metadata.get('format') == 'xml':
            return self._generate_xml_seed(size)
        else:
            return self._generate_random_seed(size, parent_seed, metadata)

    def _generate_json_seed(self, size: int) -> bytes:
        """Generate JSON seed"""
        structures = [
            '{"key": "value"}',
            '{"number": 123}',
            '{"array": [1, 2, 3]}',
            '{"nested": {"inner": "value"}}',
            '{"bool": true}',
            '{"null": null}'
        ]

        seed_str = random.choice(structures)

        # Extend to desired size
        while len(seed_str) < size:
            seed_str += ', "extra": "padding"'

        return seed_str.encode()[:size]

    def _generate_xml_seed(self, size: int) -> bytes:
        """Generate XML seed"""
        structures = [
            '<root></root>',
            '<root><child>value</child></root>',
            '<?xml version="1.0"?><root><item>test</item></root>',
            '<root attr="value"><child>text</child></root>'
        ]

        seed_str = random.choice(structures)

        # Extend to desired size
        while len(seed_str) < size:
            seed_str = seed_str[:-7] + '<extra>padding</extra></root>'

        return seed_str.encode()[:size]

    def _generate_evolutionary_seed(self, size: int, parent_seed: Optional[bytes], metadata: Dict[str, Any]) -> bytes:
        """Generate seed using evolutionary approach"""
        if parent_seed is None:
            return self._generate_random_seed(size, None, metadata)

        # Apply multiple mutations to parent
        seed = bytearray(parent_seed[:size] if len(parent_seed) >= size else parent_seed + b'\x00' * (size - len(parent_seed)))

        mutation_count = random.randint(1, min(5, len(seed) // 10))

        for _ in range(mutation_count):
            mutation_type = random.choice(['bit_flip', 'byte_change', 'insert', 'delete'])

            if mutation_type == 'bit_flip':
                if len(seed) > 0:
                    pos = random.randint(0, len(seed) - 1)
                    bit = random.randint(0, 7)
                    seed[pos] ^= (1 << bit)

            elif mutation_type == 'byte_change':
                if len(seed) > 0:
                    pos = random.randint(0, len(seed) - 1)
                    seed[pos] = random.randint(0, 255)

            elif mutation_type == 'insert':
                if len(seed) < size:
                    pos = random.randint(0, len(seed))
                    seed.insert(pos, random.randint(0, 255))

            elif mutation_type == 'delete':
                if len(seed) > 1:
                    pos = random.randint(0, len(seed) - 1)
                    del seed[pos]

        return bytes(seed[:size])

    def _generate_ml_guided_seed(self, size: int, parent_seed: Optional[bytes], metadata: Dict[str, Any]) -> bytes:
        """Generate seed using ML guidance"""
        # For now, use evolutionary approach with bias towards successful patterns
        return self._generate_evolutionary_seed(size, parent_seed, metadata)

class SeedMutator:
    """Mutates existing seeds using various strategies"""

    def __init__(self):
        self.mutation_strategies = {
            MutationStrategy.RANDOM_BIT_FLIP: self._mutate_bit_flip,
            MutationStrategy.BYTE_REPLACEMENT: self._mutate_byte_replacement,
            MutationStrategy.BLOCK_INSERTION: self._mutate_block_insertion,
            MutationStrategy.BLOCK_DELETION: self._mutate_block_deletion,
            MutationStrategy.ARITHMETIC: self._mutate_arithmetic,
            MutationStrategy.DICTIONARY_BASED: self._mutate_dictionary,
            MutationStrategy.STRUCTURE_AWARE: self._mutate_structure_aware,
            MutationStrategy.ML_GUIDED: self._mutate_ml_guided
        }

    def mutate_seed(self, seed_data: bytes, strategy: MutationStrategy,
                   intensity: float = 0.1, metadata: Dict[str, Any] = None) -> bytes:
        """Mutate seed using specified strategy"""
        if strategy not in self.mutation_strategies:
            strategy = MutationStrategy.RANDOM_BIT_FLIP

        try:
            return self.mutation_strategies[strategy](seed_data, intensity, metadata or {})
        except Exception as e:
            logging.error(f"Mutation failed with strategy {strategy}: {e}")
            return seed_data

    def _mutate_bit_flip(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Flip random bits"""
        if len(seed_data) == 0:
            return seed_data

        mutated = bytearray(seed_data)
        num_flips = max(1, int(len(seed_data) * intensity * 8))

        for _ in range(num_flips):
            byte_pos = random.randint(0, len(mutated) - 1)
            bit_pos = random.randint(0, 7)
            mutated[byte_pos] ^= (1 << bit_pos)

        return bytes(mutated)

    def _mutate_byte_replacement(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Replace random bytes"""
        if len(seed_data) == 0:
            return seed_data

        mutated = bytearray(seed_data)
        num_replacements = max(1, int(len(seed_data) * intensity))

        for _ in range(num_replacements):
            pos = random.randint(0, len(mutated) - 1)
            mutated[pos] = random.randint(0, 255)

        return bytes(mutated)

    def _mutate_block_insertion(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Insert random blocks"""
        mutated = bytearray(seed_data)
        num_insertions = max(1, int(len(seed_data) * intensity / 10))

        for _ in range(num_insertions):
            pos = random.randint(0, len(mutated))
            block_size = random.randint(1, 16)
            block = bytes(random.randint(0, 255) for _ in range(block_size))
            mutated[pos:pos] = block

        return bytes(mutated)

    def _mutate_block_deletion(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Delete random blocks"""
        if len(seed_data) <= 1:
            return seed_data

        mutated = bytearray(seed_data)
        num_deletions = max(1, int(len(seed_data) * intensity / 10))

        for _ in range(num_deletions):
            if len(mutated) <= 1:
                break

            start = random.randint(0, len(mutated) - 1)
            length = random.randint(1, min(16, len(mutated) - start))
            del mutated[start:start + length]

        return bytes(mutated) if mutated else b'\x00'

    def _mutate_arithmetic(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Apply arithmetic mutations"""
        if len(seed_data) < 4:
            return self._mutate_byte_replacement(seed_data, intensity, metadata)

        mutated = bytearray(seed_data)
        num_mutations = max(1, int(len(seed_data) * intensity / 4))

        for _ in range(num_mutations):
            if len(mutated) < 4:
                break

            pos = random.randint(0, len(mutated) - 4)

            # Interpret as 32-bit integer and apply arithmetic
            try:
                value = int.from_bytes(mutated[pos:pos+4], byteorder='little')

                operation = random.choice(['add', 'sub', 'mul', 'xor'])
                operand = random.randint(1, 1000)

                if operation == 'add':
                    value = (value + operand) & 0xFFFFFFFF
                elif operation == 'sub':
                    value = (value - operand) & 0xFFFFFFFF
                elif operation == 'mul':
                    value = (value * operand) & 0xFFFFFFFF
                elif operation == 'xor':
                    value = value ^ operand

                mutated[pos:pos+4] = value.to_bytes(4, byteorder='little')

            except Exception:
                # Fallback to byte replacement
                mutated[pos] = random.randint(0, 255)

        return bytes(mutated)

    def _mutate_dictionary(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Use dictionary-based mutations"""
        dictionary_words = [
            b'admin', b'root', b'test', b'password', b'login',
            b'%s', b'%d', b'%x', b'%n', b'../../../',
            b'\x00', b'\xff', b'\x7f', b'\x41\x41\x41\x41'
        ]

        mutated = bytearray(seed_data)
        num_insertions = max(1, int(intensity * 5))

        for _ in range(num_insertions):
            word = random.choice(dictionary_words)
            pos = random.randint(0, len(mutated))
            mutated[pos:pos] = word

        return bytes(mutated)

    def _mutate_structure_aware(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """Structure-aware mutations"""
        file_format = metadata.get('format', 'unknown')

        if file_format == 'json':
            return self._mutate_json_structure(seed_data, intensity)
        elif file_format == 'xml':
            return self._mutate_xml_structure(seed_data, intensity)
        else:
            return self._mutate_byte_replacement(seed_data, intensity, metadata)

    def _mutate_json_structure(self, seed_data: bytes, intensity: float) -> bytes:
        """JSON-aware mutations"""
        try:
            json_str = seed_data.decode('utf-8', errors='ignore')

            # Simple JSON mutations
            mutations = [
                lambda s: s.replace('"', "'"),
                lambda s: s.replace(':', '='),
                lambda s: s.replace('[', '{'),
                lambda s: s.replace(']', '}'),
                lambda s: s + ',"extra":"value"'
            ]

            mutation = random.choice(mutations)
            mutated_str = mutation(json_str)

            return mutated_str.encode()

        except Exception:
            return self._mutate_byte_replacement(seed_data, intensity, {})

    def _mutate_xml_structure(self, seed_data: bytes, intensity: float) -> bytes:
        """XML-aware mutations"""
        try:
            xml_str = seed_data.decode('utf-8', errors='ignore')

            # Simple XML mutations
            mutations = [
                lambda s: s.replace('<', '&lt;'),
                lambda s: s.replace('>', '&gt;'),
                lambda s: s.replace('"', "'"),
                lambda s: s.replace('</root>', '<extra>value</extra></root>')
            ]

            mutation = random.choice(mutations)
            mutated_str = mutation(xml_str)

            return mutated_str.encode()

        except Exception:
            return self._mutate_byte_replacement(seed_data, intensity, {})

    def _mutate_ml_guided(self, seed_data: bytes, intensity: float, metadata: Dict[str, Any]) -> bytes:
        """ML-guided mutations"""
        # For now, use combination of strategies based on feedback
        strategies = [
            MutationStrategy.RANDOM_BIT_FLIP,
            MutationStrategy.BYTE_REPLACEMENT,
            MutationStrategy.DICTIONARY_BASED
        ]

        chosen_strategy = random.choice(strategies)
        return self.mutate_seed(seed_data, chosen_strategy, intensity, metadata)

class SeedOptimizer:
    """Optimizes seed corpus for better performance"""

    def __init__(self):
        self.optimization_strategies = [
            'remove_duplicates',
            'minimize_seeds',
            'merge_similar_seeds',
            'prioritize_by_coverage',
            'remove_low_performers'
        ]

    def optimize_corpus(self, seeds: List[SeedInfo], max_corpus_size: int = 1000) -> List[SeedInfo]:
        """Optimize seed corpus"""
        optimized_seeds = seeds.copy()

        for strategy in self.optimization_strategies:
            try:
                if strategy == 'remove_duplicates':
                    optimized_seeds = self._remove_duplicates(optimized_seeds)
                elif strategy == 'minimize_seeds':
                    optimized_seeds = self._minimize_seeds(optimized_seeds)
                elif strategy == 'prioritize_by_coverage':
                    optimized_seeds = self._prioritize_by_coverage(optimized_seeds)
                elif strategy == 'remove_low_performers':
                    optimized_seeds = self._remove_low_performers(optimized_seeds)

            except Exception as e:
                logging.error(f"Optimization strategy {strategy} failed: {e}")

        # Limit corpus size
        if len(optimized_seeds) > max_corpus_size:
            optimized_seeds.sort(key=lambda s: s.metrics.coverage_score, reverse=True)
            optimized_seeds = optimized_seeds[:max_corpus_size]

        return optimized_seeds

    def _remove_duplicates(self, seeds: List[SeedInfo]) -> List[SeedInfo]:
        """Remove duplicate seeds"""
        seen_hashes = set()
        unique_seeds = []

        for seed in seeds:
            if seed.content_hash not in seen_hashes:
                seen_hashes.add(seed.content_hash)
                unique_seeds.append(seed)

        return unique_seeds

    def _minimize_seeds(self, seeds: List[SeedInfo]) -> List[SeedInfo]:
        """Minimize seed sizes while preserving coverage"""
        # This is a simplified minimization - real implementation would
        # require running the target and checking coverage
        return seeds

    def _prioritize_by_coverage(self, seeds: List[SeedInfo]) -> List[SeedInfo]:
        """Sort seeds by coverage potential"""
        return sorted(seeds, key=lambda s: s.metrics.coverage_score, reverse=True)

    def _remove_low_performers(self, seeds: List[SeedInfo]) -> List[SeedInfo]:
        """Remove seeds with low performance"""
        if len(seeds) <= 10:
            return seeds

        # Remove bottom 10% of performers
        threshold_index = int(len(seeds) * 0.9)
        seeds_sorted = sorted(seeds, key=lambda s: s.metrics.coverage_score, reverse=True)

        return seeds_sorted[:threshold_index]

class SeedManager:
    """Main seed management system"""

    def __init__(self, corpus_dir: str = "/tmp/seed_corpus"):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(exist_ok=True)

        self.generator = SeedGenerator()
        self.mutator = SeedMutator()
        self.optimizer = SeedOptimizer()
        self.evaluator = SeedEvaluator()

        self.seeds = {}
        self.target_seeds = defaultdict(set)
        self.performance_history = defaultdict(list)

        self.load_existing_corpus()

    def load_existing_corpus(self):
        """Load existing seed corpus from disk"""
        try:
            metadata_file = self.corpus_dir / "corpus_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)

                for seed_data in metadata.get('seeds', []):
                    seed_info = self._deserialize_seed_info(seed_data)
                    if seed_info and Path(seed_info.file_path).exists():
                        self.seeds[seed_info.seed_id] = seed_info
                        for target_id in seed_info.target_ids:
                            self.target_seeds[target_id].add(seed_info.seed_id)

            logging.info(f"Loaded {len(self.seeds)} seeds from corpus")

        except Exception as e:
            logging.error(f"Failed to load existing corpus: {e}")

    def save_corpus_metadata(self):
        """Save corpus metadata to disk"""
        try:
            metadata = {
                'seeds': [self._serialize_seed_info(seed) for seed in self.seeds.values()],
                'last_updated': time.time(),
                'corpus_stats': self.get_corpus_statistics()
            }

            metadata_file = self.corpus_dir / "corpus_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

        except Exception as e:
            logging.error(f"Failed to save corpus metadata: {e}")

    def add_seed(self, seed_data: bytes, target_id: str, seed_type: SeedType = SeedType.INITIAL,
                parent_seed_id: Optional[str] = None, mutation_strategy: Optional[MutationStrategy] = None) -> str:
        """Add new seed to corpus"""
        try:
            content_hash = hashlib.md5(seed_data).hexdigest()
            seed_id = f"{target_id}_{content_hash[:8]}_{int(time.time())}"

            # Check for duplicates
            existing_seed = self._find_seed_by_hash(content_hash)
            if existing_seed:
                existing_seed.target_ids.add(target_id)
                self.target_seeds[target_id].add(existing_seed.seed_id)
                return existing_seed.seed_id

            # Save seed to file
            seed_file = self.corpus_dir / f"{seed_id}.seed"
            with open(seed_file, 'wb') as f:
                f.write(seed_data)

            # Create seed info
            metrics = SeedMetrics(
                coverage_score=0.5,
                execution_speed=1.0,
                crash_potential=0.1,
                uniqueness_score=1.0,
                stability_score=1.0,
                generation_cost=0.1,
                success_rate=0.0,
                last_updated=time.time()
            )

            seed_info = SeedInfo(
                seed_id=seed_id,
                file_path=str(seed_file),
                content_hash=content_hash,
                size=len(seed_data),
                seed_type=seed_type,
                parent_seed_id=parent_seed_id,
                mutation_strategy=mutation_strategy,
                metrics=metrics,
                target_ids={target_id},
                creation_time=time.time(),
                last_used=time.time(),
                use_count=0
            )

            self.seeds[seed_id] = seed_info
            self.target_seeds[target_id].add(seed_id)

            logging.info(f"Added seed {seed_id} for target {target_id}")
            return seed_id

        except Exception as e:
            logging.error(f"Failed to add seed: {e}")
            return ""

    def generate_seeds(self, target_id: str, count: int = 100,
                      strategy: str = 'random', metadata: Dict[str, Any] = None) -> List[str]:
        """Generate multiple seeds for target"""
        generated_seed_ids = []

        for i in range(count):
            try:
                size = random.randint(16, 4096)
                parent_seed = self._get_random_parent_seed(target_id)

                seed_data = self.generator.generate_seed(
                    strategy=strategy,
                    size=size,
                    parent_seed=parent_seed,
                    metadata=metadata or {}
                )

                seed_id = self.add_seed(
                    seed_data=seed_data,
                    target_id=target_id,
                    seed_type=SeedType.GENERATED
                )

                if seed_id:
                    generated_seed_ids.append(seed_id)

            except Exception as e:
                logging.error(f"Failed to generate seed {i}: {e}")

        logging.info(f"Generated {len(generated_seed_ids)} seeds for target {target_id}")
        return generated_seed_ids

    def mutate_seed(self, seed_id: str, target_id: str, strategy: MutationStrategy = MutationStrategy.RANDOM_BIT_FLIP,
                   intensity: float = 0.1) -> Optional[str]:
        """Mutate existing seed"""
        if seed_id not in self.seeds:
            return None

        try:
            original_seed = self.seeds[seed_id]

            with open(original_seed.file_path, 'rb') as f:
                seed_data = f.read()

            mutated_data = self.mutator.mutate_seed(
                seed_data=seed_data,
                strategy=strategy,
                intensity=intensity,
                metadata=original_seed.metadata
            )

            mutated_seed_id = self.add_seed(
                seed_data=mutated_data,
                target_id=target_id,
                seed_type=SeedType.MUTATED,
                parent_seed_id=seed_id,
                mutation_strategy=strategy
            )

            return mutated_seed_id

        except Exception as e:
            logging.error(f"Failed to mutate seed {seed_id}: {e}")
            return None

    def get_seeds_for_target(self, target_id: str, limit: int = None) -> List[SeedInfo]:
        """Get seeds for specific target"""
        seed_ids = self.target_seeds.get(target_id, set())
        seeds = [self.seeds[sid] for sid in seed_ids if sid in self.seeds]

        # Sort by coverage score
        seeds.sort(key=lambda s: s.metrics.coverage_score, reverse=True)

        if limit:
            seeds = seeds[:limit]

        return seeds

    def update_seed_metrics(self, seed_id: str, coverage_increase: float = 0.0,
                           execution_time: float = 0.0, crash_found: bool = False):
        """Update seed performance metrics"""
        if seed_id not in self.seeds:
            return

        seed = self.seeds[seed_id]
        metrics = seed.metrics

        # Update metrics
        if coverage_increase > 0:
            metrics.coverage_score = min(1.0, metrics.coverage_score + coverage_increase * 0.1)

        if execution_time > 0:
            metrics.execution_speed = 1.0 / (execution_time + 0.001)

        if crash_found:
            metrics.crash_potential = min(1.0, metrics.crash_potential + 0.2)
            seed.seed_type = SeedType.CRASH_INDUCING

        metrics.last_updated = time.time()
        seed.last_used = time.time()
        seed.use_count += 1

        # Update success rate
        total_uses = seed.use_count
        successful_uses = int(coverage_increase > 0) + int(crash_found)
        metrics.success_rate = successful_uses / max(total_uses, 1)

        self.performance_history[seed_id].append({
            'timestamp': time.time(),
            'coverage_score': metrics.coverage_score,
            'crash_potential': metrics.crash_potential
        })

    def optimize_corpus_for_target(self, target_id: str, max_seeds: int = 500) -> int:
        """Optimize seed corpus for specific target"""
        seeds = self.get_seeds_for_target(target_id)

        if not seeds:
            return 0

        optimized_seeds = self.optimizer.optimize_corpus(seeds, max_seeds)

        # Update target seeds
        self.target_seeds[target_id] = {seed.seed_id for seed in optimized_seeds}

        # Remove unreferenced seeds
        removed_count = len(seeds) - len(optimized_seeds)

        logging.info(f"Optimized corpus for {target_id}: {len(optimized_seeds)} seeds (removed {removed_count})")
        return removed_count

    def cross_pollinate_seeds(self, source_target: str, dest_target: str, count: int = 50) -> int:
        """Cross-pollinate seeds between targets"""
        source_seeds = self.get_seeds_for_target(source_target, count)

        if not source_seeds:
            return 0

        cross_pollinated = 0

        for seed in source_seeds:
            if seed.metrics.coverage_score > 0.7 or seed.seed_type == SeedType.CRASH_INDUCING:
                seed.target_ids.add(dest_target)
                self.target_seeds[dest_target].add(seed.seed_id)
                cross_pollinated += 1

        logging.info(f"Cross-pollinated {cross_pollinated} seeds from {source_target} to {dest_target}")
        return cross_pollinated

    def get_corpus_statistics(self) -> Dict[str, Any]:
        """Get corpus statistics"""
        total_seeds = len(self.seeds)

        by_type = defaultdict(int)
        by_target = defaultdict(int)
        total_size = 0
        avg_coverage = 0.0

        for seed in self.seeds.values():
            by_type[seed.seed_type.value] += 1
            total_size += seed.size
            avg_coverage += seed.metrics.coverage_score

            for target_id in seed.target_ids:
                by_target[target_id] += 1

        if total_seeds > 0:
            avg_coverage /= total_seeds

        return {
            'total_seeds': total_seeds,
            'total_size_bytes': total_size,
            'average_coverage_score': avg_coverage,
            'seeds_by_type': dict(by_type),
            'seeds_by_target': dict(by_target),
            'last_updated': time.time()
        }

    def _find_seed_by_hash(self, content_hash: str) -> Optional[SeedInfo]:
        """Find seed by content hash"""
        for seed in self.seeds.values():
            if seed.content_hash == content_hash:
                return seed
        return None

    def _get_random_parent_seed(self, target_id: str) -> Optional[bytes]:
        """Get random parent seed for mutation"""
        seeds = self.get_seeds_for_target(target_id, 10)

        if not seeds:
            return None

        parent_seed = random.choice(seeds)

        try:
            with open(parent_seed.file_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

    def _serialize_seed_info(self, seed: SeedInfo) -> Dict[str, Any]:
        """Serialize seed info for storage"""
        return {
            'seed_id': seed.seed_id,
            'file_path': seed.file_path,
            'content_hash': seed.content_hash,
            'size': seed.size,
            'seed_type': seed.seed_type.value,
            'parent_seed_id': seed.parent_seed_id,
            'mutation_strategy': seed.mutation_strategy.value if seed.mutation_strategy else None,
            'metrics': {
                'coverage_score': seed.metrics.coverage_score,
                'execution_speed': seed.metrics.execution_speed,
                'crash_potential': seed.metrics.crash_potential,
                'uniqueness_score': seed.metrics.uniqueness_score,
                'stability_score': seed.metrics.stability_score,
                'generation_cost': seed.metrics.generation_cost,
                'success_rate': seed.metrics.success_rate,
                'last_updated': seed.metrics.last_updated
            },
            'target_ids': list(seed.target_ids),
            'creation_time': seed.creation_time,
            'last_used': seed.last_used,
            'use_count': seed.use_count,
            'metadata': seed.metadata
        }

    def _deserialize_seed_info(self, data: Dict[str, Any]) -> Optional[SeedInfo]:
        """Deserialize seed info from storage"""
        try:
            metrics = SeedMetrics(**data['metrics'])

            return SeedInfo(
                seed_id=data['seed_id'],
                file_path=data['file_path'],
                content_hash=data['content_hash'],
                size=data['size'],
                seed_type=SeedType(data['seed_type']),
                parent_seed_id=data.get('parent_seed_id'),
                mutation_strategy=MutationStrategy(data['mutation_strategy']) if data.get('mutation_strategy') else None,
                metrics=metrics,
                target_ids=set(data['target_ids']),
                creation_time=data['creation_time'],
                last_used=data['last_used'],
                use_count=data['use_count'],
                metadata=data.get('metadata', {})
            )
        except Exception as e:
            logging.error(f"Failed to deserialize seed info: {e}")
            return None

    def generate_seed_report(self, target_id: str) -> str:
        """Generate seed corpus report"""
        seeds = self.get_seeds_for_target(target_id)
        stats = self.get_corpus_statistics()

        report = []
        report.append(f"Seed Corpus Report: {target_id}")
        report.append("=" * 40)
        report.append(f"Total Seeds: {len(seeds)}")

        if seeds:
            avg_coverage = sum(s.metrics.coverage_score for s in seeds) / len(seeds)
            report.append(f"Average Coverage Score: {avg_coverage:.3f}")

            best_seed = max(seeds, key=lambda s: s.metrics.coverage_score)
            report.append(f"Best Coverage: {best_seed.metrics.coverage_score:.3f} ({best_seed.seed_id})")

            crash_seeds = [s for s in seeds if s.seed_type == SeedType.CRASH_INDUCING]
            report.append(f"Crash-Inducing Seeds: {len(crash_seeds)}")

            by_type = defaultdict(int)
            for seed in seeds:
                by_type[seed.seed_type.value] += 1

            report.append("")
            report.append("Seeds by Type:")
            for seed_type, count in by_type.items():
                report.append(f"  {seed_type}: {count}")

        return "\n".join(report)