#!/usr/bin/env python3
"""
🔍 VulnHunter Ψ Differential Analysis - Phase 5 Q1 Component
=============================================================
Advanced differential analysis for zero-day discovery

Implementation from 1.txt requirements:
- gumtree + AST diff analysis
- Compare main vs. forks, PRs, releases
- Identify semantic changes not in training data
- Integration with autonomous crawler

Key Techniques:
- AST-based change detection
- Semantic diff analysis
- Security-relevant pattern identification
- Change impact scoring
"""

import ast
import os
import json
import time
import hashlib
import subprocess
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import tempfile
from pathlib import Path

# Git analysis libraries
import git
from git import Repo

# AST parsing and analysis
import astor  # AST to source code
try:
    import tree_sitter  # For multi-language AST parsing
except ImportError:
    tree_sitter = None

# Import crawler integration
from autonomous_crawler import CrawlResult

@dataclass
class CodeChange:
    """Represents a single code change"""
    file_path: str
    change_type: str  # 'added', 'modified', 'deleted'
    lines_added: int
    lines_removed: int
    before_hash: str
    after_hash: str
    ast_changes: Dict[str, Any]
    security_relevance_score: float
    change_patterns: List[str]

@dataclass
class DiffAnalysisResult:
    """Result of differential analysis"""
    repo_name: str
    comparison_type: str  # 'fork_vs_main', 'pr_vs_main', 'release_vs_release'
    total_changes: int
    security_relevant_changes: int
    high_risk_changes: List[CodeChange]
    novel_patterns: List[str]
    anomaly_score: float
    analysis_timestamp: str
    git_refs: Dict[str, str]  # Reference SHAs

@dataclass
class SemanticPattern:
    """Security-relevant semantic pattern"""
    pattern_type: str
    description: str
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    code_patterns: List[str]
    ast_signatures: List[str]

class ASTAnalyzer:
    """Advanced AST analysis for security-relevant changes"""

    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        self.ast_cache = {}

    def _load_security_patterns(self) -> List[SemanticPattern]:
        """Load known security-relevant AST patterns"""
        return [
            SemanticPattern(
                pattern_type="unsafe_deserialization",
                description="Potential unsafe deserialization vulnerability",
                risk_level="critical",
                code_patterns=[
                    "pickle.loads", "pickle.load", "cPickle.loads",
                    "yaml.load", "marshal.loads", "eval("
                ],
                ast_signatures=["Call.func.id='loads'", "Call.func.attr='load'"]
            ),
            SemanticPattern(
                pattern_type="command_injection",
                description="Potential command injection vulnerability",
                risk_level="critical",
                code_patterns=[
                    "subprocess.call", "os.system", "subprocess.run",
                    "exec(", "eval(", "shell=True"
                ],
                ast_signatures=["Call.func.id='system'", "keyword.arg='shell'"]
            ),
            SemanticPattern(
                pattern_type="sql_injection",
                description="Potential SQL injection vulnerability",
                risk_level="high",
                code_patterns=[
                    "execute(", "query(", "cursor.execute",
                    ".format(", "% ", "+ "
                ],
                ast_signatures=["Call.func.attr='execute'", "BinOp.op=Add"]
            ),
            SemanticPattern(
                pattern_type="path_traversal",
                description="Potential path traversal vulnerability",
                risk_level="high",
                code_patterns=[
                    "open(", "file(", "os.path.join",
                    "../", "..\\", "request."
                ],
                ast_signatures=["Call.func.id='open'", "Str.s='../'"]
            ),
            SemanticPattern(
                pattern_type="crypto_weakness",
                description="Cryptographic weakness",
                risk_level="medium",
                code_patterns=[
                    "md5(", "sha1(", "DES", "RC4",
                    "random.random", "time.time"
                ],
                ast_signatures=["Call.func.id='md5'", "Call.func.id='sha1'"]
            ),
            SemanticPattern(
                pattern_type="access_control_bypass",
                description="Potential access control bypass",
                risk_level="high",
                code_patterns=[
                    "admin", "root", "bypass", "skip",
                    "is_authenticated", "permission", "authorize"
                ],
                ast_signatures=["Compare.ops=Eq", "NameConstant.value=True"]
            )
        ]

    def parse_ast(self, file_path: str, content: str) -> Optional[ast.AST]:
        """Parse source code into AST"""

        # Cache for performance
        content_hash = hashlib.md5(content.encode()).hexdigest()
        if content_hash in self.ast_cache:
            return self.ast_cache[content_hash]

        try:
            if file_path.endswith('.py'):
                tree = ast.parse(content)
                self.ast_cache[content_hash] = tree
                return tree
            else:
                # For non-Python files, would use tree-sitter
                # Simplified for now
                return None
        except SyntaxError:
            return None
        except Exception as e:
            print(f"⚠️ AST parsing failed for {file_path}: {e}")
            return None

    def analyze_ast_changes(self, before_ast: ast.AST, after_ast: ast.AST) -> Dict[str, Any]:
        """Analyze changes between two ASTs"""

        changes = {
            'nodes_added': [],
            'nodes_removed': [],
            'nodes_modified': [],
            'security_patterns_added': [],
            'security_patterns_removed': [],
            'complexity_change': 0,
            'risk_score': 0.0
        }

        # Convert ASTs to comparable format
        before_nodes = self._extract_ast_nodes(before_ast)
        after_nodes = self._extract_ast_nodes(after_ast)

        # Find differences
        before_signatures = set(before_nodes.keys())
        after_signatures = set(after_nodes.keys())

        changes['nodes_added'] = list(after_signatures - before_signatures)
        changes['nodes_removed'] = list(before_signatures - after_signatures)
        changes['nodes_modified'] = [
            sig for sig in before_signatures & after_signatures
            if before_nodes[sig] != after_nodes[sig]
        ]

        # Analyze security pattern changes
        before_patterns = self._find_security_patterns(before_ast)
        after_patterns = self._find_security_patterns(after_ast)

        changes['security_patterns_added'] = [
            p for p in after_patterns if p not in before_patterns
        ]
        changes['security_patterns_removed'] = [
            p for p in before_patterns if p not in after_patterns
        ]

        # Calculate risk score
        risk_score = 0.0
        for pattern in changes['security_patterns_added']:
            if pattern['risk_level'] == 'critical':
                risk_score += 1.0
            elif pattern['risk_level'] == 'high':
                risk_score += 0.7
            elif pattern['risk_level'] == 'medium':
                risk_score += 0.4

        changes['risk_score'] = risk_score

        return changes

    def _extract_ast_nodes(self, tree: ast.AST) -> Dict[str, str]:
        """Extract nodes from AST for comparison"""
        nodes = {}

        for node in ast.walk(tree):
            # Create signature for node type and key attributes
            signature = f"{type(node).__name__}"

            # Add specific attributes based on node type
            if isinstance(node, ast.FunctionDef):
                signature += f":{node.name}"
            elif isinstance(node, ast.ClassDef):
                signature += f":{node.name}"
            elif isinstance(node, ast.Call) and hasattr(node.func, 'id'):
                signature += f":{node.func.id}"
            elif isinstance(node, ast.Call) and hasattr(node.func, 'attr'):
                signature += f":{node.func.attr}"

            # Add position for uniqueness
            if hasattr(node, 'lineno'):
                signature += f"@{node.lineno}"

            nodes[signature] = str(node)

        return nodes

    def _find_security_patterns(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Find security-relevant patterns in AST"""
        found_patterns = []

        for node in ast.walk(tree):
            for pattern in self.security_patterns:
                if self._matches_pattern(node, pattern):
                    found_patterns.append({
                        'pattern_type': pattern.pattern_type,
                        'description': pattern.description,
                        'risk_level': pattern.risk_level,
                        'location': getattr(node, 'lineno', 0),
                        'node_type': type(node).__name__
                    })

        return found_patterns

    def _matches_pattern(self, node: ast.AST, pattern: SemanticPattern) -> bool:
        """Check if AST node matches security pattern"""

        # Check AST signatures
        for signature in pattern.ast_signatures:
            if self._matches_ast_signature(node, signature):
                return True

        # Convert node to source and check code patterns
        try:
            source = astor.to_source(node).strip()
            for code_pattern in pattern.code_patterns:
                if code_pattern in source:
                    return True
        except:
            pass

        return False

    def _matches_ast_signature(self, node: ast.AST, signature: str) -> bool:
        """Check if node matches AST signature pattern"""

        # Simple signature matching (could be made more sophisticated)
        if signature.startswith("Call.func.id="):
            expected_id = signature.split("=")[1].strip("'\"")
            return (isinstance(node, ast.Call) and
                   hasattr(node.func, 'id') and
                   node.func.id == expected_id)
        elif signature.startswith("Call.func.attr="):
            expected_attr = signature.split("=")[1].strip("'\"")
            return (isinstance(node, ast.Call) and
                   hasattr(node.func, 'attr') and
                   node.func.attr == expected_attr)

        return False

class GitDiffAnalyzer:
    """Analyzes Git diffs for security-relevant changes"""

    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()

    def analyze_repository_changes(self, repo_path: str,
                                 ref1: str = "HEAD~1",
                                 ref2: str = "HEAD") -> DiffAnalysisResult:
        """Analyze changes between two Git references"""

        print(f"🔍 Analyzing changes: {ref1} → {ref2}")

        try:
            repo = Repo(repo_path)

            # Get commits
            commit1 = repo.commit(ref1)
            commit2 = repo.commit(ref2)

            # Get diff
            diff = commit1.diff(commit2)

            changes = []
            for item in diff:
                if item.a_path and item.a_path.endswith(('.py', '.js', '.java', '.cpp', '.c')):
                    change = self._analyze_file_change(repo_path, item)
                    if change:
                        changes.append(change)

            # Calculate overall metrics
            security_relevant_changes = [c for c in changes if c.security_relevance_score > 0.3]
            high_risk_changes = [c for c in changes if c.security_relevance_score > 0.7]

            # Extract novel patterns
            novel_patterns = self._identify_novel_patterns(changes)

            # Calculate anomaly score
            anomaly_score = self._calculate_anomaly_score(changes)

            return DiffAnalysisResult(
                repo_name=os.path.basename(repo_path),
                comparison_type=f"{ref1}_vs_{ref2}",
                total_changes=len(changes),
                security_relevant_changes=len(security_relevant_changes),
                high_risk_changes=high_risk_changes,
                novel_patterns=novel_patterns,
                anomaly_score=anomaly_score,
                analysis_timestamp=datetime.now().isoformat(),
                git_refs={'ref1': str(commit1), 'ref2': str(commit2)}
            )

        except Exception as e:
            print(f"❌ Git diff analysis failed: {e}")
            return DiffAnalysisResult(
                repo_name=os.path.basename(repo_path),
                comparison_type=f"{ref1}_vs_{ref2}",
                total_changes=0,
                security_relevant_changes=0,
                high_risk_changes=[],
                novel_patterns=[],
                anomaly_score=0.0,
                analysis_timestamp=datetime.now().isoformat(),
                git_refs={}
            )

    def _analyze_file_change(self, repo_path: str, diff_item) -> Optional[CodeChange]:
        """Analyze changes in a single file"""

        try:
            # Get before and after content
            before_content = diff_item.a_blob.data_stream.read().decode('utf-8') if diff_item.a_blob else ""
            after_content = diff_item.b_blob.data_stream.read().decode('utf-8') if diff_item.b_blob else ""

            # Calculate basic metrics
            before_lines = before_content.split('\n') if before_content else []
            after_lines = after_content.split('\n') if after_content else []

            lines_added = len(after_lines) - len(before_lines) if len(after_lines) > len(before_lines) else 0
            lines_removed = len(before_lines) - len(after_lines) if len(before_lines) > len(after_lines) else 0

            # AST analysis
            ast_changes = {}
            if diff_item.a_path.endswith('.py'):
                before_ast = self.ast_analyzer.parse_ast(diff_item.a_path, before_content)
                after_ast = self.ast_analyzer.parse_ast(diff_item.a_path, after_content)

                if before_ast and after_ast:
                    ast_changes = self.ast_analyzer.analyze_ast_changes(before_ast, after_ast)

            # Calculate security relevance score
            security_score = self._calculate_security_relevance(ast_changes, before_content, after_content)

            # Identify change patterns
            patterns = self._identify_change_patterns(before_content, after_content, ast_changes)

            return CodeChange(
                file_path=diff_item.a_path or diff_item.b_path,
                change_type=self._determine_change_type(diff_item),
                lines_added=lines_added,
                lines_removed=lines_removed,
                before_hash=hashlib.md5(before_content.encode()).hexdigest(),
                after_hash=hashlib.md5(after_content.encode()).hexdigest(),
                ast_changes=ast_changes,
                security_relevance_score=security_score,
                change_patterns=patterns
            )

        except Exception as e:
            print(f"⚠️ File change analysis failed for {diff_item.a_path}: {e}")
            return None

    def _determine_change_type(self, diff_item) -> str:
        """Determine type of change"""
        if diff_item.new_file:
            return 'added'
        elif diff_item.deleted_file:
            return 'deleted'
        else:
            return 'modified'

    def _calculate_security_relevance(self, ast_changes: Dict[str, Any],
                                    before_content: str, after_content: str) -> float:
        """Calculate security relevance score for a change"""

        score = 0.0

        # AST-based scoring
        if ast_changes:
            score += ast_changes.get('risk_score', 0.0) * 0.6

            # Additional factors
            if ast_changes.get('security_patterns_added'):
                score += len(ast_changes['security_patterns_added']) * 0.2

            if ast_changes.get('nodes_added') or ast_changes.get('nodes_modified'):
                score += 0.1

        # Content-based scoring
        security_keywords = [
            'password', 'auth', 'token', 'secret', 'key', 'crypto',
            'security', 'permission', 'access', 'admin', 'root',
            'bypass', 'exploit', 'vulnerability', 'injection'
        ]

        added_content = after_content.replace(before_content, '')
        keyword_matches = sum(1 for keyword in security_keywords if keyword in added_content.lower())
        score += keyword_matches * 0.05

        # Cap at 1.0
        return min(score, 1.0)

    def _identify_change_patterns(self, before_content: str, after_content: str,
                                ast_changes: Dict[str, Any]) -> List[str]:
        """Identify semantic patterns in the change"""

        patterns = []

        # AST-based patterns
        if ast_changes:
            if ast_changes.get('security_patterns_added'):
                patterns.extend([p['pattern_type'] for p in ast_changes['security_patterns_added']])

        # Simple text-based patterns
        if 'eval(' in after_content and 'eval(' not in before_content:
            patterns.append('dynamic_code_execution_added')

        if 'shell=True' in after_content and 'shell=True' not in before_content:
            patterns.append('shell_execution_enabled')

        if 'admin' in after_content and 'admin' not in before_content:
            patterns.append('admin_access_added')

        return patterns

    def _identify_novel_patterns(self, changes: List[CodeChange]) -> List[str]:
        """Identify novel patterns across all changes"""

        all_patterns = []
        for change in changes:
            all_patterns.extend(change.change_patterns)

        # Group and count patterns
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        # Consider patterns that appear multiple times as potentially novel
        novel_patterns = [
            pattern for pattern, count in pattern_counts.items()
            if count >= 2  # Appears in multiple files
        ]

        return novel_patterns

    def _calculate_anomaly_score(self, changes: List[CodeChange]) -> float:
        """Calculate overall anomaly score for the changeset"""

        if not changes:
            return 0.0

        # Average security relevance
        avg_security_relevance = sum(c.security_relevance_score for c in changes) / len(changes)

        # High-risk change ratio
        high_risk_ratio = len([c for c in changes if c.security_relevance_score > 0.7]) / len(changes)

        # Pattern diversity
        all_patterns = set()
        for change in changes:
            all_patterns.update(change.change_patterns)
        pattern_diversity = len(all_patterns) / max(len(changes), 1)

        # Combine factors
        anomaly_score = (avg_security_relevance * 0.5 +
                        high_risk_ratio * 0.3 +
                        pattern_diversity * 0.2)

        return min(anomaly_score, 1.0)

class DifferentialAnalysisEngine:
    """
    Main differential analysis engine for VulnHunter Ψ
    Orchestrates analysis of repository changes for zero-day discovery
    """

    def __init__(self):
        self.git_analyzer = GitDiffAnalyzer()
        self.analysis_results: List[DiffAnalysisResult] = []

    async def analyze_crawled_repositories(self, crawl_results: List[CrawlResult]) -> List[DiffAnalysisResult]:
        """Analyze all crawled repositories for interesting changes"""

        print(f"🔍 Starting differential analysis on {len(crawl_results)} repositories")

        analysis_results = []

        for i, crawl_result in enumerate(crawl_results):
            if not crawl_result.analysis_ready:
                continue

            print(f"📊 Analyzing [{i+1}/{len(crawl_results)}]: {crawl_result.repo_target.repo_name}")

            # Analyze recent changes in the repository
            repo_analysis = await self._analyze_repository_changes(crawl_result)

            if repo_analysis:
                analysis_results.append(repo_analysis)

        self.analysis_results.extend(analysis_results)

        print(f"✅ Differential analysis complete: {len(analysis_results)} repositories analyzed")
        return analysis_results

    async def _analyze_repository_changes(self, crawl_result: CrawlResult) -> Optional[DiffAnalysisResult]:
        """Analyze changes in a single repository"""

        try:
            repo_path = crawl_result.clone_path

            # Analyze recent commits (last 10)
            result = self.git_analyzer.analyze_repository_changes(
                repo_path, ref1="HEAD~10", ref2="HEAD"
            )

            # Only return if we found interesting changes
            if result.security_relevant_changes > 0 or result.anomaly_score > 0.3:
                return result

            return None

        except Exception as e:
            print(f"⚠️ Repository analysis failed for {crawl_result.repo_target.repo_name}: {e}")
            return None

    def get_high_risk_findings(self, min_anomaly_score: float = 0.5) -> List[DiffAnalysisResult]:
        """Get high-risk findings from all analyzed repositories"""

        return [
            result for result in self.analysis_results
            if result.anomaly_score >= min_anomaly_score or result.security_relevant_changes >= 3
        ]

    def save_analysis_results(self, output_path: str):
        """Save all analysis results"""

        output_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_repositories_analyzed': len(self.analysis_results),
            'high_risk_repositories': len(self.get_high_risk_findings()),
            'results': [asdict(result) for result in self.analysis_results]
        }

        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)

        print(f"💾 Differential analysis results saved: {output_path}")

async def test_differential_analysis():
    """Test the differential analysis engine"""
    print("🧪 Testing VulnHunter Ψ Differential Analysis")
    print("=" * 50)

    # Create test analyzer
    analyzer = DifferentialAnalysisEngine()

    # Test with current repository
    test_repo = "/Users/ankitthakur/VulnHunter"

    if os.path.exists(os.path.join(test_repo, '.git')):
        result = analyzer.git_analyzer.analyze_repository_changes(
            test_repo, ref1="HEAD~1", ref2="HEAD"
        )

        print(f"📊 Analysis Results:")
        print(f"   Total changes: {result.total_changes}")
        print(f"   Security relevant: {result.security_relevant_changes}")
        print(f"   High risk changes: {len(result.high_risk_changes)}")
        print(f"   Anomaly score: {result.anomaly_score:.3f}")
        print(f"   Novel patterns: {result.novel_patterns}")

    print("✅ Differential analysis test completed")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_differential_analysis())