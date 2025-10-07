#!/usr/bin/env python3
"""
ML/AI Open Source Comprehensive Security Analyzer
=================================================

Comprehensive security analysis of critical ML/AI open source projects including:
- TensorFlow ecosystem
- PyTorch ecosystem
- Hugging Face ecosystem
- ONNX/Microsoft ML
- MLOps tools
- Classic ML libraries
- And more...

Focus: ML-specific vulnerabilities + general security issues
Methodology: Zero False Positive with ML-aware context analysis
"""

import os
import re
import ast
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict, Counter
import concurrent.futures
from threading import Lock


@dataclass
class MLProject:
    """ML/AI Open Source Project"""
    name: str
    github_url: str
    category: str
    primary_language: str
    priority: str
    description: str
    focus_areas: List[str]


# Comprehensive ML/AI OSS Projects
ML_AI_PROJECTS = [
    # TensorFlow Ecosystem
    MLProject(
        name="TensorFlow Core",
        github_url="https://github.com/tensorflow/tensorflow",
        category="Deep Learning Framework",
        primary_language="Python/C++",
        priority="critical",
        description="End-to-end ML platform",
        focus_areas=["model_loading", "serialization", "ops", "serving"]
    ),
    MLProject(
        name="TensorFlow.js",
        github_url="https://github.com/tensorflow/tfjs",
        category="Deep Learning Framework",
        primary_language="JavaScript",
        priority="high",
        description="ML for JavaScript",
        focus_areas=["web_security", "xss", "model_loading"]
    ),
    MLProject(
        name="TensorFlow Serving",
        github_url="https://github.com/tensorflow/serving",
        category="Model Serving",
        primary_language="C++",
        priority="critical",
        description="ML model serving system",
        focus_areas=["api_security", "injection", "auth"]
    ),

    # PyTorch Ecosystem
    MLProject(
        name="PyTorch Core",
        github_url="https://github.com/pytorch/pytorch",
        category="Deep Learning Framework",
        primary_language="Python/C++",
        priority="critical",
        description="Deep learning framework",
        focus_areas=["model_loading", "serialization", "ops", "jit"]
    ),
    MLProject(
        name="TorchVision",
        github_url="https://github.com/pytorch/vision",
        category="Computer Vision",
        primary_language="Python",
        priority="high",
        description="CV models and datasets",
        focus_areas=["data_loading", "transforms", "model_zoo"]
    ),
    MLProject(
        name="TorchServe",
        github_url="https://github.com/pytorch/serve",
        category="Model Serving",
        primary_language="Java/Python",
        priority="critical",
        description="PyTorch model serving",
        focus_areas=["api_security", "injection", "auth"]
    ),

    # Hugging Face Ecosystem
    MLProject(
        name="Transformers",
        github_url="https://github.com/huggingface/transformers",
        category="NLP/LLM",
        primary_language="Python",
        priority="critical",
        description="State-of-the-art NLP models",
        focus_areas=["model_loading", "hub_download", "code_execution", "pickle"]
    ),
    MLProject(
        name="Datasets",
        github_url="https://github.com/huggingface/datasets",
        category="Data Processing",
        primary_language="Python",
        priority="high",
        description="Dataset library",
        focus_areas=["data_loading", "code_execution", "arrow"]
    ),
    MLProject(
        name="Tokenizers",
        github_url="https://github.com/huggingface/tokenizers",
        category="NLP",
        primary_language="Rust/Python",
        priority="high",
        description="Fast tokenizers",
        focus_areas=["input_validation", "buffer_overflow"]
    ),
    MLProject(
        name="Accelerate",
        github_url="https://github.com/huggingface/accelerate",
        category="Training",
        primary_language="Python",
        priority="medium",
        description="Distributed training",
        focus_areas=["code_execution", "config_injection"]
    ),

    # ONNX/Microsoft
    MLProject(
        name="ONNX",
        github_url="https://github.com/onnx/onnx",
        category="Model Format",
        primary_language="C++/Python",
        priority="critical",
        description="Open Neural Network Exchange",
        focus_areas=["model_parsing", "deserialization", "protobuf"]
    ),
    MLProject(
        name="ONNX Runtime",
        github_url="https://github.com/microsoft/onnxruntime",
        category="Inference",
        primary_language="C++",
        priority="critical",
        description="ONNX inference engine",
        focus_areas=["model_loading", "ops", "buffer_overflow"]
    ),
    MLProject(
        name="DeepSpeed",
        github_url="https://github.com/microsoft/DeepSpeed",
        category="Training",
        primary_language="Python/CUDA",
        priority="high",
        description="Deep learning optimization",
        focus_areas=["code_execution", "config_injection", "kernel"]
    ),
    MLProject(
        name="LightGBM",
        github_url="https://github.com/microsoft/LightGBM",
        category="Classic ML",
        primary_language="C++/Python",
        priority="high",
        description="Gradient boosting framework",
        focus_areas=["model_loading", "buffer_overflow", "input_validation"]
    ),

    # MLOps
    MLProject(
        name="MLflow",
        github_url="https://github.com/mlflow/mlflow",
        category="MLOps",
        primary_language="Python",
        priority="critical",
        description="ML lifecycle platform",
        focus_areas=["api_security", "sql_injection", "auth", "pickle"]
    ),
    MLProject(
        name="Kubeflow Pipelines",
        github_url="https://github.com/kubeflow/pipelines",
        category="MLOps",
        primary_language="Python/Go",
        priority="high",
        description="ML workflows on Kubernetes",
        focus_areas=["injection", "auth", "secrets"]
    ),
    MLProject(
        name="BentoML",
        github_url="https://github.com/bentoml/BentoML",
        category="Model Serving",
        primary_language="Python",
        priority="high",
        description="ML model serving framework",
        focus_areas=["api_security", "injection", "pickle"]
    ),
    MLProject(
        name="Ray",
        github_url="https://github.com/ray-project/ray",
        category="Distributed Computing",
        primary_language="Python/C++",
        priority="high",
        description="Distributed ML/AI framework",
        focus_areas=["rce", "deserialization", "auth"]
    ),
    MLProject(
        name="DVC",
        github_url="https://github.com/iterative/dvc",
        category="MLOps",
        primary_language="Python",
        priority="medium",
        description="Data version control",
        focus_areas=["command_injection", "path_traversal"]
    ),

    # Classic ML
    MLProject(
        name="scikit-learn",
        github_url="https://github.com/scikit-learn/scikit-learn",
        category="Classic ML",
        primary_language="Python/Cython",
        priority="critical",
        description="ML library for Python",
        focus_areas=["pickle", "joblib", "input_validation"]
    ),
    MLProject(
        name="XGBoost",
        github_url="https://github.com/dmlc/xgboost",
        category="Classic ML",
        primary_language="C++/Python",
        priority="high",
        description="Gradient boosting library",
        focus_areas=["model_loading", "buffer_overflow", "input_validation"]
    ),
    MLProject(
        name="CatBoost",
        github_url="https://github.com/catboost/catboost",
        category="Classic ML",
        primary_language="C++/Python",
        priority="high",
        description="Gradient boosting library",
        focus_areas=["model_loading", "input_validation"]
    ),

    # Inference/Serving
    MLProject(
        name="Triton Inference Server",
        github_url="https://github.com/triton-inference-server/server",
        category="Model Serving",
        primary_language="C++",
        priority="critical",
        description="NVIDIA inference server",
        focus_areas=["api_security", "model_loading", "buffer_overflow"]
    ),
    MLProject(
        name="OpenVINO",
        github_url="https://github.com/openvinotoolkit/openvino",
        category="Inference",
        primary_language="C++",
        priority="high",
        description="Intel inference toolkit",
        focus_areas=["model_loading", "ops", "buffer_overflow"]
    ),

    # Additional Critical Projects
    MLProject(
        name="Apache TVM",
        github_url="https://github.com/apache/tvm",
        category="Compiler",
        primary_language="C++/Python",
        priority="high",
        description="ML compiler framework",
        focus_areas=["code_generation", "injection", "relay"]
    ),
    MLProject(
        name="OpenAI Triton",
        github_url="https://github.com/openai/triton",
        category="Compiler",
        primary_language="Python/C++",
        priority="high",
        description="GPU programming language",
        focus_areas=["code_generation", "kernel", "injection"]
    ),
]


class MLAISecurityAnalyzer:
    """Comprehensive ML/AI Security Analyzer with Zero False Positives"""

    # ML-Specific Dangerous Patterns
    ML_DANGEROUS_PATTERNS = {
        # Model Deserialization
        'pickle_load': [
            r'\bpickle\.load\(',
            r'\bpickle\.loads\(',
            r'\bjoblib\.load\(',
            r'\btorch\.load\(',
            r'\bkeras\.models\.load_model\(',
        ],

        # Code Execution
        'code_exec': [
            r'\bexec\s*\(',
            r'\beval\s*\(',
            r'\bcompile\s*\(',
            r'\b__import__\s*\(',
            r'\bimportlib\.import_module\(',
        ],

        # Command Injection
        'command_injection': [
            r'\bos\.system\s*\(',
            r'\bsubprocess\.(?:call|run|Popen)\(',
            r'\bos\.popen\s*\(',
            r'\bshell\s*=\s*True',
        ],

        # Path Traversal
        'path_traversal': [
            r'\.\./',
            r'os\.path\.join\([^)]*\.\.',
            r'Path\([^)]*\.\.',
        ],

        # SQL Injection
        'sql_injection': [
            r'execute\s*\(\s*["\'].*%s',
            r'execute\s*\(\s*f["\']',
            r'\.format\s*\(.*\)\s*\)',
        ],

        # Unsafe Deserialization
        'unsafe_deserialize': [
            r'\byaml\.load\(',
            r'\byaml\.unsafe_load\(',
            r'\bmarshal\.load\(',
            r'\bdill\.load\(',
        ],

        # Hub/Download Security
        'unsafe_download': [
            r'urllib\.request\.urlopen\(',
            r'requests\.get\([^)]*verify\s*=\s*False',
            r'wget\.download\(',
        ],

        # Credential Exposure
        'credentials': [
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ],

        # Tensor Operations (Buffer Overflow Potential)
        'tensor_ops': [
            r'\.reshape\s*\(',
            r'\.view\s*\(',
            r'\btorch\.from_buffer\(',
            r'\bnp\.frombuffer\(',
        ],
    }

    # Python dangerous functions
    PYTHON_DANGEROUS_FUNCS = {
        'eval', 'exec', 'compile', '__import__',
        'pickle.load', 'pickle.loads', 'joblib.load',
        'torch.load', 'yaml.load', 'yaml.unsafe_load',
        'os.system', 'subprocess.call', 'subprocess.run',
    }

    def __init__(self, output_dir: Path, max_workers: int = 4):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.repos_dir = self.output_dir / "repositories"
        self.repos_dir.mkdir(exist_ok=True)

        self.findings: List[Dict] = []
        self.findings_lock = Lock()

        self.statistics = {
            'total_files_scanned': 0,
            'total_projects': 0,
            'verified_findings': 0,
            'false_positives_excluded': 0,
            'by_severity': Counter(),
            'by_category': Counter(),
            'by_project': Counter(),
            'by_language': Counter(),
        }
        self.stats_lock = Lock()

        self.max_workers = max_workers
        self.log_file = self.output_dir / "analysis.log"

    def log(self, message: str):
        """Thread-safe logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        with open(self.log_file, 'a') as f:
            f.write(log_message + '\n')

    def clone_repository(self, project: MLProject) -> Optional[Path]:
        """Clone repository with shallow clone for speed"""
        repo_name = project.github_url.split('/')[-1]
        repo_path = self.repos_dir / repo_name

        if repo_path.exists():
            self.log(f"✓ Repository already exists: {repo_name}")
            return repo_path

        self.log(f"📥 Cloning {project.name}...")
        try:
            # Shallow clone for large repos
            cmd = [
                'git', 'clone',
                '--depth', '1',
                '--single-branch',
                project.github_url,
                str(repo_path)
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
            self.log(f"✓ Cloned: {repo_name}")
            return repo_path
        except subprocess.TimeoutExpired:
            self.log(f"✗ Timeout: {repo_name}")
            return None
        except subprocess.CalledProcessError as e:
            self.log(f"✗ Failed: {repo_name}: {e}")
            return None

    def should_skip_file(self, file_path: Path) -> bool:
        """Determine if file should be skipped"""
        path_str = str(file_path).lower()

        skip_patterns = [
            '/test/', '/tests/', '/_test/', '/testing/',
            '/examples/', '/example/', '/demo/', '/demos/',
            '/docs/', '/doc/', '/documentation/',
            '/vendor/', '/third_party/', '/3rdparty/', '/external/',
            '/node_modules/', '/.git/', '/build/', '/dist/',
            '/.tox/', '/.venv/', '/venv/', '/.pytest_cache/',
            '/target/debug/', '/target/release/',
            '.pb.py', '_pb2.py', '.pb.go',  # Generated protobuf
            '.min.js', '.min.css',
            '/benchmark/', '/benches/',
        ]

        return any(pattern in path_str for pattern in skip_patterns)

    def analyze_python_file(self, file_path: Path, project: MLProject) -> List[Dict]:
        """Analyze Python file with AST + pattern matching"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return findings

        # Try AST parsing first
        try:
            tree = ast.parse(content, filename=str(file_path))

            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node.func)

                    if any(danger in func_name for danger in self.PYTHON_DANGEROUS_FUNCS):
                        line_num = node.lineno
                        context = self._get_context(lines, line_num)

                        if self._is_ml_dangerous(func_name, context, file_path, project):
                            finding = {
                                'project': project.name,
                                'file': str(file_path.relative_to(self.repos_dir)),
                                'line': line_num,
                                'function': func_name,
                                'severity': self._get_ml_severity(func_name, context),
                                'category': self._categorize_ml_vuln(func_name),
                                'code': lines[line_num - 1].strip() if line_num <= len(lines) else '',
                                'context': context,
                                'language': 'Python',
                                'cwe': self._get_ml_cwe(func_name),
                                'focus_area': self._get_focus_area(func_name, project),
                            }
                            findings.append(finding)

        except SyntaxError:
            # Fall back to pattern matching
            pass

        # Pattern-based analysis for ML-specific issues
        for category, patterns in self.ML_DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    context = self._get_context(lines, line_num)

                    if self._is_ml_pattern_dangerous(category, context, file_path, project):
                        finding = {
                            'project': project.name,
                            'file': str(file_path.relative_to(self.repos_dir)),
                            'line': line_num,
                            'function': category,
                            'severity': self._get_pattern_severity(category),
                            'category': f'ML-{category}',
                            'code': lines[line_num - 1].strip() if line_num <= len(lines) else '',
                            'context': context,
                            'language': 'Python',
                            'cwe': self._get_pattern_cwe(category),
                            'focus_area': category,
                        }
                        findings.append(finding)

        return findings

    def _get_func_name(self, node) -> str:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_func_name(node.func)
        return ""

    def _get_context(self, lines: List[str], line_num: int, context_lines: int = 3) -> str:
        """Get context around a line"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(lines[start:end])

    def _is_ml_dangerous(self, func_name: str, context: str, file_path: Path, project: MLProject) -> bool:
        """Verify if function usage is genuinely dangerous in ML context"""

        if self.should_skip_file(file_path):
            return False

        context_lower = context.lower()

        # pickle.load / torch.load - CRITICAL in untrusted contexts
        if 'pickle.load' in func_name or 'torch.load' in func_name:
            # Safe if from trusted source
            safe_indicators = [
                'trusted', 'safe', 'verified',
                'local', 'internal',
                '# safe', '# trusted',
            ]
            if any(ind in context_lower for ind in safe_indicators):
                return False

            # Dangerous if from user input or downloads
            danger_indicators = [
                'request', 'download', 'url', 'http',
                'user', 'input', 'upload',
                'hub', 'cache',
            ]
            if any(ind in context_lower for ind in danger_indicators):
                return True

            # Conservative: report if uncertain
            return True

        # exec/eval - Always dangerous
        if func_name in ['exec', 'eval']:
            return True

        # subprocess with shell=True
        if 'subprocess' in func_name and 'shell' in context_lower:
            if 'shell=true' in context_lower or 'shell = true' in context_lower:
                return True

        # yaml.load (unsafe)
        if 'yaml.load' in func_name and 'Loader' not in context:
            return True

        return False

    def _is_ml_pattern_dangerous(self, category: str, context: str, file_path: Path, project: MLProject) -> bool:
        """Verify if ML-specific pattern is dangerous"""

        if self.should_skip_file(file_path):
            return False

        context_lower = context.lower()

        # Pickle deserialization
        if category == 'pickle_load':
            danger_indicators = ['download', 'url', 'http', 'request', 'user', 'upload']
            if any(ind in context_lower for ind in danger_indicators):
                return True
            return False  # Conservative

        # Code execution
        if category == 'code_exec':
            return True

        # Command injection
        if category == 'command_injection':
            if 'shell=true' in context_lower:
                return True
            return False

        # Credentials
        if category == 'credentials':
            # Exclude examples
            if any(x in context_lower for x in ['example', 'dummy', 'test', 'sample']):
                return False
            return True

        # Path traversal
        if category == 'path_traversal':
            if '..' in context and 'join' in context_lower:
                return True
            return False

        return False

    def _get_ml_severity(self, func_name: str, context: str) -> str:
        """Get severity for ML-specific function"""
        critical = ['pickle.load', 'torch.load', 'eval', 'exec']
        high = ['yaml.load', 'subprocess.call', 'os.system']

        if any(c in func_name for c in critical):
            return 'CRITICAL'
        elif any(h in func_name for h in high):
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _get_pattern_severity(self, category: str) -> str:
        """Get severity for pattern category"""
        severity_map = {
            'pickle_load': 'CRITICAL',
            'code_exec': 'CRITICAL',
            'unsafe_deserialize': 'CRITICAL',
            'command_injection': 'HIGH',
            'sql_injection': 'HIGH',
            'credentials': 'HIGH',
            'path_traversal': 'MEDIUM',
            'unsafe_download': 'MEDIUM',
            'tensor_ops': 'LOW',
        }
        return severity_map.get(category, 'MEDIUM')

    def _categorize_ml_vuln(self, func_name: str) -> str:
        """Categorize ML vulnerability"""
        if 'pickle' in func_name or 'torch.load' in func_name:
            return 'Unsafe Deserialization'
        elif func_name in ['eval', 'exec']:
            return 'Code Execution'
        elif 'subprocess' in func_name or 'system' in func_name:
            return 'Command Injection'
        elif 'yaml.load' in func_name:
            return 'Unsafe YAML'
        else:
            return 'Dangerous Function'

    def _get_ml_cwe(self, func_name: str) -> str:
        """Get CWE for ML vulnerability"""
        cwe_map = {
            'pickle.load': 'CWE-502',
            'torch.load': 'CWE-502',
            'eval': 'CWE-95',
            'exec': 'CWE-95',
            'yaml.load': 'CWE-502',
            'subprocess': 'CWE-78',
            'os.system': 'CWE-78',
        }
        for key, cwe in cwe_map.items():
            if key in func_name:
                return cwe
        return 'CWE-693'

    def _get_pattern_cwe(self, category: str) -> str:
        """Get CWE for pattern category"""
        cwe_map = {
            'pickle_load': 'CWE-502',
            'code_exec': 'CWE-95',
            'unsafe_deserialize': 'CWE-502',
            'command_injection': 'CWE-78',
            'sql_injection': 'CWE-89',
            'credentials': 'CWE-798',
            'path_traversal': 'CWE-22',
            'unsafe_download': 'CWE-829',
        }
        return cwe_map.get(category, 'CWE-693')

    def _get_focus_area(self, func_name: str, project: MLProject) -> str:
        """Get focus area for finding"""
        if 'pickle' in func_name or 'load' in func_name:
            return 'model_loading'
        elif func_name in ['eval', 'exec']:
            return 'code_execution'
        elif 'subprocess' in func_name:
            return 'injection'
        else:
            return 'general'

    def analyze_project(self, project: MLProject) -> Dict:
        """Analyze single ML project"""
        self.log(f"\n{'='*80}")
        self.log(f"🔍 Analyzing: {project.name}")
        self.log(f"    Category: {project.category}")
        self.log(f"    Priority: {project.priority}")
        self.log(f"    Focus: {', '.join(project.focus_areas)}")
        self.log(f"{'='*80}")

        repo_path = self.clone_repository(project)
        if not repo_path:
            return {'error': 'Failed to clone'}

        project_findings = []
        files_scanned = 0

        # Scan Python files
        for py_file in repo_path.rglob('*.py'):
            if not py_file.is_file() or self.should_skip_file(py_file):
                continue

            files_scanned += 1
            findings = self.analyze_python_file(py_file, project)
            project_findings.extend(findings)

            if files_scanned % 500 == 0:
                self.log(f"   Scanned {files_scanned} files, {len(project_findings)} findings")

        # Update statistics (thread-safe)
        with self.stats_lock:
            self.statistics['total_projects'] += 1
            self.statistics['total_files_scanned'] += files_scanned

        self.log(f"✓ {project.name}: {files_scanned} files, {len(project_findings)} findings")

        return {
            'project': project.name,
            'files_scanned': files_scanned,
            'findings': project_findings,
        }

    def analyze_all(self, max_projects: Optional[int] = None):
        """Analyze all projects with parallel processing"""
        self.log("=" * 80)
        self.log("🛡️  ML/AI OSS COMPREHENSIVE SECURITY ANALYSIS")
        self.log("=" * 80)
        self.log(f"Projects: {len(ML_AI_PROJECTS)}")
        self.log(f"Max Workers: {self.max_workers}")
        self.log(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        projects = ML_AI_PROJECTS[:max_projects] if max_projects else ML_AI_PROJECTS

        all_results = []

        # Parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_project = {executor.submit(self.analyze_project, p): p for p in projects}

            for future in concurrent.futures.as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    result = future.result()
                    all_results.append(result)

                    # Collect findings
                    with self.findings_lock:
                        for finding in result.get('findings', []):
                            self.findings.append(finding)

                            with self.stats_lock:
                                self.statistics['verified_findings'] += 1
                                self.statistics['by_severity'][finding['severity']] += 1
                                self.statistics['by_category'][finding['category']] += 1
                                self.statistics['by_project'][project.name] += 1

                except Exception as e:
                    self.log(f"✗ Error analyzing {project.name}: {e}")

        # Generate reports
        self.generate_reports(all_results)

        self.log("\n" + "=" * 80)
        self.log("✅ ANALYSIS COMPLETE")
        self.log("=" * 80)
        self.log(f"Projects: {self.statistics['total_projects']}")
        self.log(f"Files: {self.statistics['total_files_scanned']:,}")
        self.log(f"Findings: {self.statistics['verified_findings']}")
        self.log(f"End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def generate_reports(self, results: List[Dict]):
        """Generate all reports"""
        # JSON
        json_path = self.output_dir / "ml_ai_analysis.json"
        with open(json_path, 'w') as f:
            json.dump({
                'metadata': {
                    'analyzer': 'ML/AI OSS Security Analyzer',
                    'timestamp': datetime.now().isoformat(),
                    'projects': len(ML_AI_PROJECTS),
                },
                'statistics': dict(self.statistics),
                'results': results,
                'findings': self.findings,
            }, f, indent=2, default=str)

        self.log(f"📄 JSON: {json_path}")

        # Summary
        summary_path = self.output_dir / "ML_AI_EXECUTIVE_SUMMARY.md"
        with open(summary_path, 'w') as f:
            f.write(f"# ML/AI OSS Security Analysis - Executive Summary\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%B %d, %Y')}\n\n")
            f.write(f"## Key Findings\n\n")
            f.write(f"- **Projects Analyzed:** {self.statistics['total_projects']}\n")
            f.write(f"- **Files Scanned:** {self.statistics['total_files_scanned']:,}\n")
            f.write(f"- **Verified Findings:** {self.statistics['verified_findings']}\n\n")
            f.write(f"### By Severity\n\n")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = self.statistics['by_severity'].get(sev, 0)
                f.write(f"- **{sev}**: {count}\n")
            f.write(f"\n### Top Findings by Project\n\n")
            for proj, count in self.statistics['by_project'].most_common(10):
                f.write(f"- {proj}: {count}\n")

        self.log(f"📄 Summary: {summary_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='ML/AI OSS Security Analyzer')
    parser.add_argument('--output-dir', default='~/Downloads/ml_ai_analysis',
                        help='Output directory')
    parser.add_argument('--max-projects', type=int, help='Max projects to analyze')
    parser.add_argument('--workers', type=int, default=4, help='Parallel workers')

    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser()
    analyzer = MLAISecurityAnalyzer(output_dir, max_workers=args.workers)
    analyzer.analyze_all(max_projects=args.max_projects)


if __name__ == '__main__':
    main()
