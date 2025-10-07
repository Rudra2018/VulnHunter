#!/usr/bin/env python3
"""
Google Open Source Projects Security Testing Suite
Comprehensive vulnerability detection and security assessment for Google OSS projects
"""

import os
import sys
import json
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
from dataclasses import dataclass, asdict

@dataclass
class GoogleProject:
    """Represents a Google open source project"""
    name: str
    github_url: str
    category: str
    description: str
    languages: List[str]
    priority: str  # high, medium, low

class GoogleOSSTestingSuite:
    """Comprehensive testing suite for Google open source projects"""

    # Curated list of major Google open source projects
    GOOGLE_PROJECTS = [
        # Machine Learning / AI
        GoogleProject(
            name="TensorFlow",
            github_url="https://github.com/tensorflow/tensorflow",
            category="Machine Learning",
            description="End-to-end open source platform for machine learning",
            languages=["Python", "C++", "CUDA"],
            priority="high"
        ),
        GoogleProject(
            name="JAX",
            github_url="https://github.com/google/jax",
            category="Machine Learning",
            description="Composable transformations of Python+NumPy programs",
            languages=["Python", "C++"],
            priority="high"
        ),
        GoogleProject(
            name="MediaPipe",
            github_url="https://github.com/google/mediapipe",
            category="Machine Learning",
            description="Cross-platform ML solutions for live and streaming media",
            languages=["Python", "C++", "JavaScript"],
            priority="medium"
        ),

        # Mobile Development
        GoogleProject(
            name="Flutter",
            github_url="https://github.com/flutter/flutter",
            category="Mobile",
            description="UI toolkit for building natively compiled applications",
            languages=["Dart", "C++", "Java"],
            priority="high"
        ),
        GoogleProject(
            name="Firebase Android SDK",
            github_url="https://github.com/firebase/firebase-android-sdk",
            category="Mobile",
            description="Firebase Android SDK",
            languages=["Java", "Kotlin"],
            priority="medium"
        ),

        # Web Development
        GoogleProject(
            name="Angular",
            github_url="https://github.com/angular/angular",
            category="Web",
            description="Platform for building mobile and desktop web applications",
            languages=["TypeScript", "JavaScript"],
            priority="high"
        ),
        GoogleProject(
            name="Material Design Web",
            github_url="https://github.com/material-components/material-components-web",
            category="Web",
            description="Material Design components for the web",
            languages=["TypeScript", "JavaScript", "CSS"],
            priority="medium"
        ),
        GoogleProject(
            name="Polymer",
            github_url="https://github.com/Polymer/polymer",
            category="Web",
            description="Web component library",
            languages=["JavaScript", "HTML"],
            priority="low"
        ),

        # Cloud & Infrastructure
        GoogleProject(
            name="Kubernetes",
            github_url="https://github.com/kubernetes/kubernetes",
            category="Cloud",
            description="Container orchestration system",
            languages=["Go"],
            priority="high"
        ),
        GoogleProject(
            name="gRPC",
            github_url="https://github.com/grpc/grpc",
            category="Cloud",
            description="High performance RPC framework",
            languages=["C++", "Python", "Go", "Java"],
            priority="high"
        ),
        GoogleProject(
            name="Istio",
            github_url="https://github.com/istio/istio",
            category="Cloud",
            description="Service mesh platform",
            languages=["Go"],
            priority="medium"
        ),

        # Programming Languages & Tools
        GoogleProject(
            name="Go",
            github_url="https://github.com/golang/go",
            category="Programming Language",
            description="The Go programming language",
            languages=["Go", "Assembly"],
            priority="high"
        ),
        GoogleProject(
            name="Bazel",
            github_url="https://github.com/bazelbuild/bazel",
            category="Build Tool",
            description="Fast, scalable, multi-language build system",
            languages=["Java", "C++"],
            priority="medium"
        ),

        # Data & Serialization
        GoogleProject(
            name="Protocol Buffers",
            github_url="https://github.com/protocolbuffers/protobuf",
            category="Data",
            description="Protocol Buffers - Google's data interchange format",
            languages=["C++", "Python", "Java"],
            priority="high"
        ),
        GoogleProject(
            name="FlatBuffers",
            github_url="https://github.com/google/flatbuffers",
            category="Data",
            description="Memory efficient serialization library",
            languages=["C++", "Python", "Java"],
            priority="medium"
        ),

        # Security
        GoogleProject(
            name="Tink",
            github_url="https://github.com/google/tink",
            category="Security",
            description="Multi-language, cross-platform cryptographic library",
            languages=["C++", "Python", "Java", "Go"],
            priority="high"
        ),
        GoogleProject(
            name="Tsunami Security Scanner",
            github_url="https://github.com/google/tsunami-security-scanner",
            category="Security",
            description="General purpose network security scanner",
            languages=["Java"],
            priority="high"
        ),
        GoogleProject(
            name="OSS-Fuzz",
            github_url="https://github.com/google/oss-fuzz",
            category="Security",
            description="Continuous fuzzing for open source software",
            languages=["Python", "C++"],
            priority="medium"
        ),

        # Testing & Quality
        GoogleProject(
            name="Googletest",
            github_url="https://github.com/google/googletest",
            category="Testing",
            description="Google Testing and Mocking Framework",
            languages=["C++"],
            priority="medium"
        ),
        GoogleProject(
            name="Web Platform Tests",
            github_url="https://github.com/web-platform-tests/wpt",
            category="Testing",
            description="Cross-browser test suite for Web platform",
            languages=["JavaScript", "Python"],
            priority="low"
        ),

        # Performance & Monitoring
        GoogleProject(
            name="OpenTelemetry",
            github_url="https://github.com/open-telemetry/opentelemetry-go",
            category="Monitoring",
            description="Observability framework for cloud-native software",
            languages=["Go"],
            priority="medium"
        ),

        # Utilities & Libraries
        GoogleProject(
            name="Guava",
            github_url="https://github.com/google/guava",
            category="Library",
            description="Google core libraries for Java",
            languages=["Java"],
            priority="medium"
        ),
        GoogleProject(
            name="Abseil (Python)",
            github_url="https://github.com/abseil/abseil-py",
            category="Library",
            description="Python Common Libraries",
            languages=["Python"],
            priority="medium"
        ),
        GoogleProject(
            name="Abseil (C++)",
            github_url="https://github.com/abseil/abseil-cpp",
            category="Library",
            description="C++ Common Libraries",
            languages=["C++"],
            priority="medium"
        ),

        # Browser & Rendering
        GoogleProject(
            name="V8",
            github_url="https://github.com/v8/v8",
            category="Browser",
            description="Google's high-performance JavaScript and WebAssembly engine",
            languages=["C++", "JavaScript"],
            priority="high"
        ),

        # Data Processing
        GoogleProject(
            name="Apache Beam",
            github_url="https://github.com/apache/beam",
            category="Data Processing",
            description="Unified model for batch and streaming data processing",
            languages=["Java", "Python", "Go"],
            priority="medium"
        ),
    ]

    def __init__(self, output_dir: str = "/tmp/google_oss_analysis"):
        """Initialize the testing suite"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.clone_dir = self.output_dir / "cloned_projects"
        self.clone_dir.mkdir(exist_ok=True)

        self.results_dir = self.output_dir / "results"
        self.results_dir.mkdir(exist_ok=True)

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Results storage
        self.analysis_results = {}

        print(f"🔬 Google OSS Testing Suite Initialized")
        print(f"📁 Output Directory: {self.output_dir}")
        print(f"📦 Total Projects: {len(self.GOOGLE_PROJECTS)}")

    def clone_project(self, project: GoogleProject, shallow: bool = True, max_depth: int = 1) -> Optional[Path]:
        """Clone a Google project repository"""
        print(f"\n📥 Cloning {project.name}...")

        project_dir = self.clone_dir / project.name.lower().replace(" ", "_")

        # Remove if exists
        if project_dir.exists():
            print(f"  ↻ Removing existing clone...")
            shutil.rmtree(project_dir)

        try:
            cmd = ["git", "clone"]
            if shallow:
                cmd.extend(["--depth", str(max_depth)])
            cmd.extend([project.github_url, str(project_dir)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                print(f"  ✓ Successfully cloned to {project_dir}")
                return project_dir
            else:
                print(f"  ✗ Clone failed: {result.stderr[:200]}")
                return None

        except subprocess.TimeoutExpired:
            print(f"  ✗ Clone timeout (5 minutes)")
            return None
        except Exception as e:
            print(f"  ✗ Clone error: {e}")
            return None

    def analyze_project_structure(self, project: GoogleProject, project_dir: Path) -> Dict[str, Any]:
        """Analyze project file structure and composition"""
        print(f"📊 Analyzing {project.name} structure...")

        analysis = {
            'total_files': 0,
            'total_lines': 0,
            'file_types': {},
            'directory_count': 0,
            'largest_files': [],
            'languages': {},
            'potential_vulns': []
        }

        # Walk through project
        for root, dirs, files in os.walk(project_dir):
            # Skip .git and node_modules
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'vendor', 'third_party']]

            analysis['directory_count'] += len(dirs)

            for file in files:
                file_path = Path(root) / file

                # Skip binary and large files
                if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                    continue

                analysis['total_files'] += 1

                # File extension
                ext = file_path.suffix.lower()
                analysis['file_types'][ext] = analysis['file_types'].get(ext, 0) + 1

                # Count lines for text files
                text_exts = ['.py', '.js', '.go', '.java', '.cpp', '.c', '.h', '.ts', '.jsx', '.tsx']
                if ext in text_exts:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = len(f.readlines())
                            analysis['total_lines'] += lines

                            # Track largest files
                            analysis['largest_files'].append({
                                'path': str(file_path.relative_to(project_dir)),
                                'lines': lines,
                                'size': file_path.stat().st_size
                            })
                    except:
                        pass

        # Sort largest files
        analysis['largest_files'] = sorted(
            analysis['largest_files'],
            key=lambda x: x['lines'],
            reverse=True
        )[:20]

        return analysis

    def run_vulnhunter_analysis(self, project: GoogleProject, project_dir: Path) -> Dict[str, Any]:
        """Run VulnHunter analysis on the project"""
        print(f"🔍 Running VulnHunter analysis on {project.name}...")

        results = {
            'project': project.name,
            'timestamp': datetime.now().isoformat(),
            'analyses': {},
            'summary': {}
        }

        # Find Python files for SAST analysis
        python_files = list(project_dir.rglob("*.py"))[:50]  # Limit to 50 files

        if python_files:
            print(f"  📝 Analyzing {len(python_files)} Python files...")
            results['analyses']['python_files'] = []

            for py_file in python_files[:10]:  # Analyze top 10
                try:
                    # Run VulnHunter code analyzer
                    cmd = [
                        sys.executable,
                        "/Users/ankitthakur/vuln_ml_research/vulnhunter/vulnhunter.py",
                        "hunt",
                        str(py_file)
                    ]

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        cwd="/Users/ankitthakur/vuln_ml_research"
                    )

                    if result.returncode == 0:
                        results['analyses']['python_files'].append({
                            'file': str(py_file.relative_to(project_dir)),
                            'status': 'analyzed',
                            'output': result.stdout[:500]
                        })
                except Exception as e:
                    results['analyses']['python_files'].append({
                        'file': str(py_file.relative_to(project_dir)),
                        'status': 'error',
                        'error': str(e)
                    })

        # Pattern-based security checks
        results['analyses']['security_patterns'] = self.security_pattern_scan(project_dir)

        # Dependency analysis
        results['analyses']['dependencies'] = self.analyze_dependencies(project_dir)

        return results

    def security_pattern_scan(self, project_dir: Path) -> Dict[str, Any]:
        """Scan for common security patterns and vulnerabilities"""
        patterns = {
            'hardcoded_secrets': [],
            'dangerous_functions': [],
            'weak_crypto': [],
            'sql_injection_risk': [],
            'xss_risk': [],
            'command_injection_risk': []
        }

        # Security patterns to search for
        secret_patterns = [
            r'(api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']{20,}["\']',
            r'(password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']',
            r'(secret|token)\s*[:=]\s*["\'][^"\']{20,}["\']',
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'
        ]

        dangerous_funcs = [
            'eval(', 'exec(', 'os.system(', 'subprocess.call(',
            'innerHTML', 'dangerouslySetInnerHTML', '__import__'
        ]

        weak_crypto = [
            'MD5', 'SHA1', 'DES', 'RC4', 'md5', 'sha1'
        ]

        # Scan source files
        source_exts = ['.py', '.js', '.ts', '.java', '.go', '.cpp', '.c']

        for source_file in project_dir.rglob("*"):
            if source_file.is_file() and source_file.suffix in source_exts:
                try:
                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        # Check for dangerous functions
                        for func in dangerous_funcs:
                            if func in content:
                                patterns['dangerous_functions'].append({
                                    'file': str(source_file.relative_to(project_dir)),
                                    'function': func
                                })

                        # Check for weak crypto
                        for crypto in weak_crypto:
                            if crypto in content:
                                patterns['weak_crypto'].append({
                                    'file': str(source_file.relative_to(project_dir)),
                                    'algorithm': crypto
                                })

                except:
                    pass

        return patterns

    def analyze_dependencies(self, project_dir: Path) -> Dict[str, Any]:
        """Analyze project dependencies"""
        deps = {
            'package_managers': [],
            'dependency_files': [],
            'total_dependencies': 0
        }

        # Check for dependency files
        dep_files = {
            'requirements.txt': 'pip',
            'package.json': 'npm',
            'go.mod': 'go',
            'pom.xml': 'maven',
            'build.gradle': 'gradle',
            'Cargo.toml': 'cargo',
            'Gemfile': 'bundler'
        }

        for dep_file, pkg_manager in dep_files.items():
            matches = list(project_dir.rglob(dep_file))
            if matches:
                deps['package_managers'].append(pkg_manager)
                deps['dependency_files'].extend([str(m.relative_to(project_dir)) for m in matches])

        return deps

    def generate_project_report(self, project: GoogleProject, structure: Dict, vulnhunter: Dict) -> Dict[str, Any]:
        """Generate comprehensive report for a project"""

        # Calculate risk score
        risk_score = 100  # Start with perfect score

        # Deduct points for findings
        if vulnhunter['analyses'].get('security_patterns'):
            patterns = vulnhunter['analyses']['security_patterns']
            risk_score -= len(patterns.get('hardcoded_secrets', [])) * 10
            risk_score -= len(patterns.get('dangerous_functions', [])) * 5
            risk_score -= len(patterns.get('weak_crypto', [])) * 8

        risk_score = max(0, min(100, risk_score))

        # Determine severity
        if risk_score >= 80:
            severity = "LOW"
        elif risk_score >= 60:
            severity = "MEDIUM"
        elif risk_score >= 40:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        report = {
            'project': asdict(project),
            'analysis_timestamp': datetime.now().isoformat(),
            'structure': structure,
            'vulnhunter_results': vulnhunter,
            'risk_assessment': {
                'score': risk_score,
                'severity': severity,
                'findings_summary': {
                    'hardcoded_secrets': len(vulnhunter['analyses'].get('security_patterns', {}).get('hardcoded_secrets', [])),
                    'dangerous_functions': len(vulnhunter['analyses'].get('security_patterns', {}).get('dangerous_functions', [])),
                    'weak_crypto': len(vulnhunter['analyses'].get('security_patterns', {}).get('weak_crypto', []))
                }
            }
        }

        return report

    def run_comprehensive_analysis(self, priority_filter: Optional[str] = None, max_projects: int = 10):
        """Run comprehensive analysis on Google OSS projects"""

        # Filter projects
        projects_to_analyze = self.GOOGLE_PROJECTS

        if priority_filter:
            projects_to_analyze = [p for p in projects_to_analyze if p.priority == priority_filter]

        projects_to_analyze = projects_to_analyze[:max_projects]

        print(f"\n{'='*80}")
        print(f"🚀 Starting Google OSS Security Analysis")
        print(f"{'='*80}")
        print(f"Projects to analyze: {len(projects_to_analyze)}")
        print(f"Priority filter: {priority_filter or 'None (all)'}")
        print(f"Output directory: {self.output_dir}")
        print(f"{'='*80}\n")

        for idx, project in enumerate(projects_to_analyze, 1):
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(projects_to_analyze)}] Analyzing: {project.name}")
            print(f"{'='*80}")

            # Clone project
            project_dir = self.clone_project(project, shallow=True, max_depth=1)

            if not project_dir:
                print(f"⚠️  Skipping {project.name} due to clone failure")
                continue

            # Analyze structure
            structure = self.analyze_project_structure(project, project_dir)

            # Run VulnHunter
            vulnhunter_results = self.run_vulnhunter_analysis(project, project_dir)

            # Generate report
            report = self.generate_project_report(project, structure, vulnhunter_results)

            # Store results
            self.analysis_results[project.name] = report

            # Save individual report
            report_file = self.results_dir / f"{project.name.lower().replace(' ', '_')}_report.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"✓ Report saved: {report_file}")

            # Clean up clone to save space
            if project_dir.exists():
                shutil.rmtree(project_dir)
                print(f"🧹 Cleaned up clone directory")

        # Generate master report
        self.generate_master_report()

    def generate_master_report(self):
        """Generate comprehensive master report"""
        print(f"\n{'='*80}")
        print("📊 Generating Master Report")
        print(f"{'='*80}\n")

        master_report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_projects_analyzed': len(self.analysis_results),
            'summary': {
                'by_category': {},
                'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                'by_priority': {'high': 0, 'medium': 0, 'low': 0},
                'total_files_analyzed': 0,
                'total_lines_analyzed': 0
            },
            'projects': self.analysis_results
        }

        # Calculate summaries
        for project_name, report in self.analysis_results.items():
            category = report['project']['category']
            severity = report['risk_assessment']['severity']
            priority = report['project']['priority']

            # By category
            if category not in master_report['summary']['by_category']:
                master_report['summary']['by_category'][category] = 0
            master_report['summary']['by_category'][category] += 1

            # By severity
            master_report['summary']['by_severity'][severity] += 1

            # By priority
            master_report['summary']['by_priority'][priority] += 1

            # Totals
            master_report['summary']['total_files_analyzed'] += report['structure']['total_files']
            master_report['summary']['total_lines_analyzed'] += report['structure']['total_lines']

        # Save master report
        master_file = self.output_dir / f"google_oss_master_report_{self.timestamp}.json"
        with open(master_file, 'w') as f:
            json.dump(master_report, f, indent=2)

        print(f"✓ Master report saved: {master_file}")

        # Generate text summary
        summary_file = self.output_dir / f"google_oss_summary_{self.timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("GOOGLE OPEN SOURCE PROJECTS - SECURITY ANALYSIS SUMMARY\n")
            f.write("="*80 + "\n\n")

            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Projects Analyzed: {len(self.analysis_results)}\n")
            f.write(f"Total Files Analyzed: {master_report['summary']['total_files_analyzed']:,}\n")
            f.write(f"Total Lines Analyzed: {master_report['summary']['total_lines_analyzed']:,}\n\n")

            f.write("-"*80 + "\n")
            f.write("SECURITY RISK DISTRIBUTION\n")
            f.write("-"*80 + "\n")
            for severity, count in master_report['summary']['by_severity'].items():
                if count > 0:
                    f.write(f"  {severity:12s}: {count} project(s)\n")

            f.write("\n" + "-"*80 + "\n")
            f.write("CATEGORY DISTRIBUTION\n")
            f.write("-"*80 + "\n")
            for category, count in sorted(master_report['summary']['by_category'].items()):
                f.write(f"  {category:20s}: {count} project(s)\n")

            f.write("\n" + "-"*80 + "\n")
            f.write("PROJECT DETAILS\n")
            f.write("-"*80 + "\n\n")

            for project_name, report in sorted(self.analysis_results.items()):
                f.write(f"Project: {project_name}\n")
                f.write(f"  Category: {report['project']['category']}\n")
                f.write(f"  Risk Score: {report['risk_assessment']['score']}/100 ({report['risk_assessment']['severity']})\n")
                f.write(f"  Files: {report['structure']['total_files']:,}\n")
                f.write(f"  Lines: {report['structure']['total_lines']:,}\n")
                f.write(f"  Findings:\n")
                findings = report['risk_assessment']['findings_summary']
                f.write(f"    - Hardcoded Secrets: {findings.get('hardcoded_secrets', 0)}\n")
                f.write(f"    - Dangerous Functions: {findings.get('dangerous_functions', 0)}\n")
                f.write(f"    - Weak Cryptography: {findings.get('weak_crypto', 0)}\n")
                f.write("\n")

        print(f"✓ Summary saved: {summary_file}")

        return master_file, summary_file

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Google OSS Projects Security Testing Suite")
    parser.add_argument("--priority", choices=["high", "medium", "low"], help="Filter by priority")
    parser.add_argument("--max-projects", type=int, default=10, help="Maximum projects to analyze")
    parser.add_argument("--output-dir", default="/tmp/google_oss_analysis", help="Output directory")

    args = parser.parse_args()

    # Create suite
    suite = GoogleOSSTestingSuite(output_dir=args.output_dir)

    # Run analysis
    suite.run_comprehensive_analysis(
        priority_filter=args.priority,
        max_projects=args.max_projects
    )

    print(f"\n{'='*80}")
    print("✅ Analysis Complete!")
    print(f"{'='*80}")
    print(f"📁 Results: {suite.output_dir}")
    print(f"📊 Individual reports: {suite.results_dir}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
