"""
VulnHunter PoC: Command Line Interface
Advanced AI-powered vulnerability detection CLI
"""

import click
import torch
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import time
from datetime import datetime
import colorama
from colorama import Fore, Style, Back

# Initialize colorama for cross-platform colored output
colorama.init()

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from src.models.vulnhunter_fusion import VulnHunterComplete
    from src.models.vulnhunter_nfv import VulnHunterNFV
    from src.models.solidity_fusion import SolidityFusionModel
    from src.parser.code_to_graph import CodeToGraphParser
    from src.parser.languages.solidity_parser import SolidityParser
except ImportError as e:
    print(f"Error importing VulnHunter modules: {e}")
    print("Please ensure all dependencies are installed and the project structure is correct.")
    sys.exit(1)

class VulnHunterCLI:
    """Command Line Interface for VulnHunter"""

    def __init__(self):
        self.model = None
        self.nfv_model = None
        self.solidity_model = None
        self.parser = CodeToGraphParser()
        self.solidity_parser = SolidityParser()
        self.scan_history = []

    def load_model(self, model_path: Optional[str] = None, language: str = "python", use_nfv: bool = False) -> bool:
        """Load the VulnHunter model"""
        try:
            model_type = "NFV" if use_nfv else "Standard"
            print(f"{Fore.CYAN}🔄 Loading VulnHunter {model_type} AI model for {language}...{Style.RESET_ALL}")

            if use_nfv:
                print(f"{Fore.MAGENTA}🧮 Initializing Neural-Formal Verification Layer...{Style.RESET_ALL}")
                self.nfv_model = VulnHunterNFV()

                if model_path and os.path.exists(model_path):
                    print(f"{Fore.GREEN}📂 Loading trained NFV model from {model_path}{Style.RESET_ALL}")
                    state_dict = torch.load(model_path, map_location='cpu')
                    self.nfv_model.load_state_dict(state_dict)
                else:
                    print(f"{Fore.YELLOW}⚠️  Using untrained NFV model (demo mode){Style.RESET_ALL}")

                self.nfv_model.eval()
            elif language == "solidity":
                self.solidity_model = SolidityFusionModel()

                if model_path and os.path.exists(model_path):
                    print(f"{Fore.GREEN}📂 Loading trained Solidity model from {model_path}{Style.RESET_ALL}")
                    state_dict = torch.load(model_path, map_location='cpu')
                    self.solidity_model.load_state_dict(state_dict)
                else:
                    print(f"{Fore.YELLOW}⚠️  Using untrained Solidity model (demo mode){Style.RESET_ALL}")

                self.solidity_model.eval()
            else:
                self.model = VulnHunterComplete()

                if model_path and os.path.exists(model_path):
                    print(f"{Fore.GREEN}📂 Loading trained model from {model_path}{Style.RESET_ALL}")
                    state_dict = torch.load(model_path, map_location='cpu')
                    self.model.load_state_dict(state_dict)
                else:
                    print(f"{Fore.YELLOW}⚠️  Using untrained model (demo mode){Style.RESET_ALL}")

                self.model.eval()

            print(f"{Fore.GREEN}✅ Model loaded successfully{Style.RESET_ALL}")
            return True

        except Exception as e:
            print(f"{Fore.RED}❌ Error loading model: {e}{Style.RESET_ALL}")
            return False

    def scan_file(self, file_path: str, detailed: bool = True, language: str = "auto", use_nfv: bool = False) -> Dict[str, Any]:
        """Scan a single file for vulnerabilities"""
        try:
            # Read file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            if not code.strip():
                return {
                    'error': 'File is empty or could not be read',
                    'file_path': file_path
                }

            # Auto-detect language if not specified
            if language == "auto":
                if file_path.endswith('.sol'):
                    language = "solidity"
                elif file_path.endswith(('.py', '.pyw')):
                    language = "python"
                else:
                    language = "python"  # Default

            # Scan with appropriate model
            start_time = time.time()

            if use_nfv:
                if self.nfv_model is None:
                    self.load_model(language=language, use_nfv=True)

                results = self.nfv_model.predict_vulnerability(code, return_explanation=detailed)
                # Convert NFV results to standard format
                results = self._convert_nfv_results(results)
            elif language == "solidity":
                if self.solidity_model is None:
                    self.load_model(language="solidity")

                results = self.solidity_model.analyze_solidity_contract(code)
                # Convert to standard format for CLI
                results = self._convert_solidity_results(results)
            else:
                if self.model is None:
                    self.load_model(language="python")

                results = self.model.scan_code(code, include_details=detailed)

            scan_time = time.time() - start_time

            # Add metadata
            results.update({
                'file_path': file_path,
                'language': language,
                'scan_time_seconds': scan_time,
                'file_size_bytes': len(code),
                'lines_of_code': len(code.split('\n')),
                'timestamp': datetime.now().isoformat()
            })

            return results

        except Exception as e:
            return {
                'error': str(e),
                'file_path': file_path,
                'language': language
            }

    def scan_directory(self, directory: str, extensions: List[str] = None, detailed: bool = True) -> List[Dict[str, Any]]:
        """Scan all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.php', '.java', '.cpp', '.c']

        results = []
        directory_path = Path(directory)

        if not directory_path.exists():
            return [{'error': f'Directory does not exist: {directory}'}]

        # Find all relevant files
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(directory_path.rglob(f'*{ext}'))

        print(f"{Fore.CYAN}📁 Found {len(files_to_scan)} files to scan{Style.RESET_ALL}")

        # Scan each file
        for i, file_path in enumerate(files_to_scan):
            print(f"{Fore.BLUE}🔍 Scanning ({i+1}/{len(files_to_scan)}): {file_path.name}{Style.RESET_ALL}")

            result = self.scan_file(str(file_path), detailed)
            results.append(result)

        return results

    def print_scan_result(self, result: Dict[str, Any], detailed: bool = True):
        """Print formatted scan results"""
        if 'error' in result:
            print(f"{Fore.RED}❌ Error: {result['error']}{Style.RESET_ALL}")
            return

        file_path = result.get('file_path', 'Unknown')
        is_vulnerable = result.get('is_vulnerable', False)
        risk_level = result.get('risk_level', 'UNKNOWN')
        probability = result.get('vulnerability_probability', 0.0)

        # Header
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📄 File: {Path(file_path).name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        # Main result
        if is_vulnerable:
            print(f"{Back.RED}{Fore.WHITE} ⚠️  VULNERABLE {Style.RESET_ALL}")
            print(f"{Fore.RED}Risk Level: {risk_level}{Style.RESET_ALL}")
            print(f"{Fore.RED}Probability: {probability:.1%}{Style.RESET_ALL}")
        else:
            print(f"{Back.GREEN}{Fore.WHITE} ✅ SAFE {Style.RESET_ALL}")
            print(f"{Fore.GREEN}Risk Level: {risk_level}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Probability: {probability:.1%}{Style.RESET_ALL}")

        # Vulnerability types
        if 'top_issues' in result and result['top_issues']:
            print(f"\n{Fore.YELLOW}🎯 Detected Issues:{Style.RESET_ALL}")
            for issue in result['top_issues']:
                issue_type = issue['type'].replace('_', ' ').title()
                score = issue['score']
                severity_color = Fore.RED if score > 0.7 else Fore.YELLOW if score > 0.4 else Fore.CYAN
                print(f"  {severity_color}• {issue_type}: {score:.1%}{Style.RESET_ALL}")

        # NFV-specific proof information
        if 'nfv_analysis' in result:
            nfv = result['nfv_analysis']
            print(f"\n{Fore.MAGENTA}🧮 Neural-Formal Verification Results:{Style.RESET_ALL}")

            if nfv['proven_vulnerable']:
                print(f"  {Back.RED}{Fore.WHITE} MATHEMATICALLY PROVEN VULNERABLE {Style.RESET_ALL}")
            else:
                print(f"  Decision Basis: {nfv['decision_reason']}")

            print(f"  Neural Prediction: {nfv['neural_prediction']:.1%}")
            print(f"  Paths Analyzed: {nfv['num_paths_analyzed']}")
            print(f"  Formal Analysis: {'✅ Successful' if nfv['analysis_successful'] else '❌ Failed'}")

            if nfv['proof_info']:
                print(f"\n{Fore.YELLOW}🔬 Proof Information:{Style.RESET_ALL}")
                for info in nfv['proof_info']:
                    print(f"  {info}")

        # Detailed information
        if detailed and 'vulnerability_types' in result:
            print(f"\n{Fore.CYAN}📊 Detailed Analysis:{Style.RESET_ALL}")

            # Severity and confidence
            severity = result.get('severity_score', 0)
            confidence = result.get('confidence_score', 0)
            print(f"  Severity: {severity:.1%}")
            print(f"  Confidence: {confidence:.1%}")

            # Graph statistics
            if 'graph_statistics' in result:
                stats = result['graph_statistics']
                print(f"  AST Nodes: {stats.get('num_nodes', 0)}")
                print(f"  Function Calls: {stats.get('call_nodes', 0)}")
                print(f"  Max Depth: {stats.get('max_depth', 0)}")

            # Recommendations
            if 'recommendations' in result and result['recommendations']:
                print(f"\n{Fore.GREEN}💡 Recommendations:{Style.RESET_ALL}")
                for i, rec in enumerate(result['recommendations'], 1):
                    print(f"  {i}. {rec}")

        # Performance info
        scan_time = result.get('scan_time_seconds', 0)
        file_size = result.get('file_size_bytes', 0)
        print(f"\n{Fore.CYAN}⏱️  Scan completed in {scan_time:.2f}s ({file_size:,} bytes){Style.RESET_ALL}")

    def print_summary(self, results: List[Dict[str, Any]]):
        """Print summary of multiple scan results"""
        if not results:
            return

        total_files = len(results)
        vulnerable_files = sum(1 for r in results if r.get('is_vulnerable', False))
        error_files = sum(1 for r in results if 'error' in r)

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📋 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        print(f"Total Files Scanned: {total_files}")
        print(f"Vulnerable Files: {Fore.RED}{vulnerable_files}{Style.RESET_ALL}")
        print(f"Safe Files: {Fore.GREEN}{total_files - vulnerable_files - error_files}{Style.RESET_ALL}")

        if error_files > 0:
            print(f"Files with Errors: {Fore.YELLOW}{error_files}{Style.RESET_ALL}")

        # Risk distribution
        risk_levels = {}
        for result in results:
            if 'error' not in result:
                risk = result.get('risk_level', 'UNKNOWN')
                risk_levels[risk] = risk_levels.get(risk, 0) + 1

        if risk_levels:
            print(f"\n{Fore.CYAN}Risk Distribution:{Style.RESET_ALL}")
            for risk, count in sorted(risk_levels.items()):
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN,
                    'MINIMAL': Fore.GREEN
                }.get(risk, Fore.WHITE)
                print(f"  {color}{risk}: {count} files{Style.RESET_ALL}")

    def _convert_solidity_results(self, solidity_results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Solidity analysis results to standard CLI format"""
        overall = solidity_results['overall_assessment']
        vuln_details = solidity_results['vulnerability_details']

        # Convert to standard format
        results = {
            'is_vulnerable': overall['is_vulnerable'],
            'vulnerability_probability': overall['vulnerability_probability'],
            'risk_level': overall['risk_level'],
            'confidence_score': overall['confidence_score'],
            'severity_score': self._severity_to_numeric(overall['predicted_severity']),
            'vulnerability_types': [],
            'top_issues': [],
            'recommendations': solidity_results['recommendations'],
            'contract_analysis': solidity_results['contract_analysis'],
            'technical_details': solidity_results['technical_details']
        }

        # Convert vulnerability types
        for vuln in vuln_details['detected_vulnerabilities']:
            results['vulnerability_types'].append(vuln['type'])
            results['top_issues'].append({
                'type': vuln['type'],
                'score': vuln['score']
            })

        return results

    def _severity_to_numeric(self, severity: str) -> float:
        """Convert severity string to numeric score"""
        severity_map = {
            'Critical': 0.0,
            'High': 0.25,
            'Medium': 0.5,
            'Low': 0.75,
            'Safe': 1.0
        }
        return severity_map.get(severity, 0.5)

    def _convert_nfv_results(self, nfv_results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert NFV analysis results to standard CLI format"""

        # Extract core prediction info
        is_vulnerable = nfv_results.get('vulnerable', False)
        probability = nfv_results.get('probability', 0.0)
        confidence = nfv_results.get('confidence', 0.0)
        proven_vulnerable = nfv_results.get('proven_vulnerable', False)
        decision_reason = nfv_results.get('decision_reason', 'UNKNOWN')

        # Risk level based on probability and proof status
        if proven_vulnerable:
            risk_level = "CRITICAL"
        elif probability > 0.8:
            risk_level = "HIGH"
        elif probability > 0.6:
            risk_level = "MEDIUM"
        elif probability > 0.3:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        # Build vulnerability types list
        vulnerability_types = []
        top_issues = []

        if 'vulnerability_types' in nfv_results:
            vuln_types = nfv_results['vulnerability_types']
            if isinstance(vuln_types, list):
                for i, score in enumerate(vuln_types):
                    if score > 0.5:  # Threshold for reporting
                        vuln_name = f"vulnerability_type_{i}"
                        vulnerability_types.append(vuln_name)
                        top_issues.append({
                            'type': vuln_name,
                            'score': score
                        })

        # Add proof-specific information
        proof_info = []
        if proven_vulnerable:
            proof_info.append("🧮 MATHEMATICALLY PROVEN VULNERABLE")
            if 'proof_witnesses' in nfv_results and nfv_results['proof_witnesses']:
                proof_info.append("💡 Exploit witness generated")

        # Recommendations based on NFV analysis
        recommendations = []
        if proven_vulnerable:
            recommendations.append("CRITICAL: Vulnerability formally proven - immediate action required")
            recommendations.append("Review mathematical proof and exploit witness provided")
        elif decision_reason == "NEURAL_HIGH_UNPROVEN":
            recommendations.append("HIGH: Neural model confident but unproven - manual review recommended")
        elif decision_reason == "LIKELY_SAFE":
            recommendations.append("Code appears safe based on formal analysis")
        else:
            recommendations.append("Standard vulnerability analysis - review flagged patterns")

        return {
            'is_vulnerable': is_vulnerable,
            'vulnerability_probability': probability,
            'risk_level': risk_level,
            'confidence_score': confidence,
            'severity_score': 1.0 - probability,  # Invert for severity
            'vulnerability_types': vulnerability_types,
            'top_issues': top_issues,
            'recommendations': recommendations,
            'nfv_analysis': {
                'proven_vulnerable': proven_vulnerable,
                'decision_reason': decision_reason,
                'neural_prediction': nfv_results.get('neural_prediction', 0.0),
                'analysis_successful': nfv_results.get('analysis_successful', False),
                'num_paths_analyzed': nfv_results.get('num_paths_analyzed', 0),
                'proof_info': proof_info
            }
        }

@click.group()
@click.version_option(version='1.0.0-poc', prog_name='VulnHunter')
def cli():
    """
    🛡️  VulnHunter AI - Advanced Vulnerability Detection

    AI-powered static analysis using Graph Neural Networks + Transformers
    """
    pass

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--detailed', '-d', is_flag=True, help='Show detailed analysis')
@click.option('--model', '-m', type=click.Path(exists=True), help='Path to trained model')
@click.option('--output', '-o', type=click.Path(), help='Save results to JSON file')
@click.option('--language', '-l', type=click.Choice(['auto', 'python', 'solidity']), default='auto', help='Programming language')
@click.option('--prove', '-p', is_flag=True, help='Use Neural-Formal Verification for mathematical proofs')
def scan(file_path: str, detailed: bool, model: Optional[str], output: Optional[str], language: str, prove: bool):
    """Scan a single file for vulnerabilities"""

    mode = "Neural-Formal Verification" if prove else "Standard AI Analysis"
    print(f"{Fore.CYAN}🛡️  VulnHunter AI - Vulnerability Scanner ({mode}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Version: 1.0.0-poc{Style.RESET_ALL}\n")

    if prove:
        print(f"{Fore.MAGENTA}🧮 Mathematical Proof Mode Enabled{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}    - Neural prediction + Formal verification{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}    - Z3 SMT solver for mathematical proofs{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}    - Exploit witness generation{Style.RESET_ALL}\n")

    # Initialize CLI
    vulnhunter_cli = VulnHunterCLI()

    # Auto-detect language if needed
    if language == 'auto':
        if file_path.endswith('.sol'):
            detected_language = 'solidity'
        else:
            detected_language = 'python'
    else:
        detected_language = language

    # Load model
    if not vulnhunter_cli.load_model(model, detected_language, use_nfv=prove):
        sys.exit(1)

    # Scan file
    analysis_type = "with mathematical proofs" if prove else ""
    print(f"{Fore.CYAN}🔍 Scanning {detected_language.title()} file: {file_path} {analysis_type}{Style.RESET_ALL}")
    result = vulnhunter_cli.scan_file(file_path, detailed, detected_language, use_nfv=prove)

    # Print results
    vulnhunter_cli.print_scan_result(result, detailed)

    # Save to file if requested
    if output:
        try:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}💾 Results saved to: {output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error saving results: {e}{Style.RESET_ALL}")

@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--extensions', '-e', multiple=True, default=['.py'], help='File extensions to scan')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed analysis')
@click.option('--model', '-m', type=click.Path(exists=True), help='Path to trained model')
@click.option('--output', '-o', type=click.Path(), help='Save results to JSON file')
def scan_dir(directory: str, extensions: tuple, detailed: bool, model: Optional[str], output: Optional[str]):
    """Scan all files in a directory"""

    print(f"{Fore.CYAN}🛡️  VulnHunter AI - Directory Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Version: 1.0.0-poc{Style.RESET_ALL}\n")

    # Initialize CLI
    vulnhunter_cli = VulnHunterCLI()

    # Load model
    if not vulnhunter_cli.load_model(model):
        sys.exit(1)

    # Scan directory
    print(f"{Fore.CYAN}📁 Scanning directory: {directory}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Extensions: {', '.join(extensions)}{Style.RESET_ALL}\n")

    results = vulnhunter_cli.scan_directory(directory, list(extensions), detailed)

    # Print individual results
    for result in results:
        vulnhunter_cli.print_scan_result(result, detailed)

    # Print summary
    vulnhunter_cli.print_summary(results)

    # Save to file if requested
    if output:
        try:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}💾 Results saved to: {output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error saving results: {e}{Style.RESET_ALL}")

@cli.command()
def demo():
    """Run a demonstration of VulnHunter capabilities"""

    print(f"{Fore.CYAN}🛡️  VulnHunter AI - Live Demo{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Version: 1.0.0-poc{Style.RESET_ALL}\n")

    # Create demo files
    demo_codes = {
        'vulnerable_sql.py': '''
def login(username, password):
    # Vulnerable: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
''',
        'safe_sql.py': '''
def login(username, password):
    # Safe: Parameterized query
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
''',
        'command_injection.py': '''
import os

def convert_image(filename):
    # Vulnerable: Command injection
    command = "convert " + filename + " output.pdf"
    os.system(command)
'''
    }

    # Initialize CLI
    vulnhunter_cli = VulnHunterCLI()

    # Load model
    if not vulnhunter_cli.load_model():
        sys.exit(1)

    # Create temporary demo directory
    demo_dir = Path('demo_files')
    demo_dir.mkdir(exist_ok=True)

    try:
        # Create demo files
        for filename, code in demo_codes.items():
            demo_file = demo_dir / filename
            with open(demo_file, 'w') as f:
                f.write(code)

        # Scan each demo file
        for filename in demo_codes.keys():
            demo_file = demo_dir / filename
            print(f"\n{Fore.CYAN}🔍 Demo: Scanning {filename}{Style.RESET_ALL}")
            result = vulnhunter_cli.scan_file(str(demo_file), detailed=True)
            vulnhunter_cli.print_scan_result(result, detailed=True)

    finally:
        # Cleanup demo files
        for filename in demo_codes.keys():
            demo_file = demo_dir / filename
            if demo_file.exists():
                demo_file.unlink()

        if demo_dir.exists():
            demo_dir.rmdir()

@cli.command()
def info():
    """Show information about VulnHunter"""

    print(f"{Fore.CYAN}🛡️  VulnHunter AI - Information{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"Version: 1.0.0-poc")
    print(f"Architecture: GNN + Transformer Fusion")
    print(f"Supported Languages: Python, JavaScript, Java, C/C++, PHP")
    print(f"Vulnerability Types: SQL Injection, Command Injection, XSS, Path Traversal, and more")
    print(f"Model: CodeBERT + Graph Neural Networks")
    print(f"License: MIT")
    print(f"Author: Rudra2018")
    print(f"\n{Fore.GREEN}🚀 AI-powered static analysis for modern security{Style.RESET_ALL}")

if __name__ == '__main__':
    cli()