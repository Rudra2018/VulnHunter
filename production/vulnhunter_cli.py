#!/usr/bin/env python3
"""
🛡️ VulnHunter V7 CLI - Easy Vulnerability Detection
==================================================

Simple command-line interface for VulnHunter V7 vulnerability detection.

Usage:
    python vulnhunter_cli.py --file <code_file>
    python vulnhunter_cli.py --text "code snippet"
    python vulnhunter_cli.py --batch <directory>
    python vulnhunter_cli.py --demo

Examples:
    python vulnhunter_cli.py --file vulnerable_contract.sol
    python vulnhunter_cli.py --text "strcpy(buffer, user_input);" --lang c
    python vulnhunter_cli.py --batch ./code_samples/
    python vulnhunter_cli.py --demo
"""

import argparse
import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Any
import time

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from vulnhunter_v7_unified_model import VulnHunterV7
except ImportError as e:
    print(f"❌ Error importing VulnHunter V7: {e}")
    print("Please ensure vulnhunter_v7_unified_model.py is in the same directory")
    sys.exit(1)

class VulnHunterCLI:
    """Command-line interface for VulnHunter V7."""

    def __init__(self):
        self.detector = VulnHunterV7()
        self.supported_extensions = {
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cxx': 'cpp',
            '.cc': 'cpp',
            '.hpp': 'cpp',
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.sol': 'solidity'
        }

    def detect_language(self, filename: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(filename).suffix.lower()
        return self.supported_extensions.get(ext, 'auto')

    def analyze_file(self, filepath: str, language: str = 'auto') -> Dict[str, Any]:
        """Analyze a single file for vulnerabilities."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            if language == 'auto':
                language = self.detect_language(filepath)

            result = self.detector.predict(code_content, language)
            result['file_path'] = filepath
            result['file_size'] = len(code_content)
            result['lines_of_code'] = len(code_content.split('\n'))

            return result

        except Exception as e:
            return {
                'file_path': filepath,
                'error': str(e),
                'vulnerable': False,
                'confidence': 0.0
            }

    def analyze_text(self, code_text: str, language: str = 'auto') -> Dict[str, Any]:
        """Analyze code text for vulnerabilities."""
        try:
            result = self.detector.predict(code_text, language)
            return result
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'confidence': 0.0
            }

    def analyze_batch(self, directory: str) -> List[Dict[str, Any]]:
        """Analyze all supported files in a directory."""
        results = []
        directory_path = Path(directory)

        if not directory_path.exists():
            print(f"❌ Directory not found: {directory}")
            return results

        print(f"🔍 Scanning directory: {directory}")

        supported_files = []
        for ext in self.supported_extensions.keys():
            supported_files.extend(directory_path.rglob(f"*{ext}"))

        if not supported_files:
            print("⚠️  No supported code files found")
            return results

        print(f"📁 Found {len(supported_files)} code files")

        for filepath in supported_files:
            print(f"📄 Analyzing: {filepath.name}")
            result = self.analyze_file(str(filepath))
            results.append(result)

        return results

    def print_result(self, result: Dict[str, Any], detailed: bool = False):
        """Print analysis result in a formatted way."""
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            return

        # Basic result
        status = "🚨 VULNERABLE" if result['vulnerable'] else "✅ SAFE"
        confidence = result['confidence']
        risk_level = result.get('risk_level', 'Unknown')

        print(f"\n{status}")
        print(f"🎯 Confidence: {confidence:.4f} ({confidence*100:.2f}%)")
        print(f"⚠️  Risk Level: {risk_level}")

        if 'file_path' in result:
            print(f"📄 File: {result['file_path']}")
            print(f"📏 Size: {result.get('file_size', 0)} chars, {result.get('lines_of_code', 0)} lines")

        if 'detected_language' in result:
            print(f"💻 Language: {result['detected_language']}")

        # Security features
        if 'security_features' in result and detailed:
            features = result['security_features']
            print(f"\n🔍 Security Analysis:")
            print(f"   • Dangerous functions: {features.get('dangerous_functions', 0)}")
            print(f"   • Security keywords: {features.get('security_keywords', 0)}")
            print(f"   • Buffer operations: {features.get('buffer_operations', 0)}")
            print(f"   • Crypto operations: {features.get('crypto_operations', 0)}")
            print(f"   • Complexity score: {features.get('complexity_score', 0)}")

        # Model predictions
        if 'model_predictions' in result and detailed:
            print(f"\n🧠 Model Ensemble:")
            for model_name, prediction in result['model_predictions'].items():
                emoji = "🚨" if prediction else "✅"
                print(f"   {emoji} {model_name}: {'Vulnerable' if prediction else 'Safe'}")

            if result.get('champion_model'):
                print(f"🏆 Champion: {result['champion_model']}")

    def run_demo(self):
        """Run demonstration with sample vulnerable code."""
        print("🚀 VulnHunter V7 Demo")
        print("=" * 50)

        demo_cases = [
            {
                'name': 'Buffer Overflow (C)',
                'code': '''
                #include <string.h>
                void vulnerable_function(char* user_input) {
                    char buffer[10];
                    strcpy(buffer, user_input);  // No bounds checking!
                    printf("Buffer: %s\\n", buffer);
                }
                ''',
                'language': 'c'
            },
            {
                'name': 'Integer Underflow (Solidity)',
                'code': '''
                function withdraw(uint amount) public {
                    require(balances[msg.sender] >= amount);
                    balances[msg.sender] -= amount;  // Potential underflow
                    msg.sender.transfer(amount);
                }
                ''',
                'language': 'solidity'
            },
            {
                'name': 'SQL Injection (Python)',
                'code': '''
                def get_user(user_id):
                    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
                    return db.execute(query)  # SQL injection vulnerability
                ''',
                'language': 'python'
            },
            {
                'name': 'Safe Function (Python)',
                'code': '''
                def safe_process(user_input):
                    if validate_input(user_input):
                        sanitized = escape_html(user_input)
                        return process_data(sanitized)
                    return None
                ''',
                'language': 'python'
            }
        ]

        for i, case in enumerate(demo_cases, 1):
            print(f"\n📝 Demo {i}: {case['name']}")
            print("-" * 40)
            print("Code snippet:")
            print(case['code'].strip())
            print("\n🔍 Analysis:")

            result = self.analyze_text(case['code'], case['language'])
            self.print_result(result, detailed=True)

            if i < len(demo_cases):
                input("\nPress Enter to continue...")

    def print_summary(self, results: List[Dict[str, Any]]):
        """Print summary of batch analysis."""
        if not results:
            return

        total_files = len(results)
        vulnerable_files = sum(1 for r in results if r.get('vulnerable', False))
        safe_files = total_files - vulnerable_files
        avg_confidence = sum(r.get('confidence', 0) for r in results) / total_files

        print(f"\n📊 Analysis Summary:")
        print(f"   📁 Total files: {total_files}")
        print(f"   🚨 Vulnerable: {vulnerable_files}")
        print(f"   ✅ Safe: {safe_files}")
        print(f"   🎯 Avg confidence: {avg_confidence:.4f}")

        # Show vulnerable files
        if vulnerable_files > 0:
            print(f"\n🚨 Vulnerable Files:")
            for result in results:
                if result.get('vulnerable', False):
                    filepath = result.get('file_path', 'Unknown')
                    confidence = result.get('confidence', 0)
                    risk = result.get('risk_level', 'Unknown')
                    print(f"   • {Path(filepath).name} - {confidence:.3f} ({risk})")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="🛡️ VulnHunter V7 - Advanced Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnhunter_cli.py --file contract.sol
  python vulnhunter_cli.py --text "strcpy(buf, input);" --lang c
  python vulnhunter_cli.py --batch ./src/
  python vulnhunter_cli.py --demo
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', '-f', help='Analyze a single file')
    group.add_argument('--text', '-t', help='Analyze code text directly')
    group.add_argument('--batch', '-b', help='Analyze all files in directory')
    group.add_argument('--demo', '-d', action='store_true', help='Run demo with sample code')

    parser.add_argument('--lang', '-l', default='auto',
                       choices=['auto', 'c', 'cpp', 'java', 'python', 'javascript', 'solidity'],
                       help='Programming language (default: auto-detect)')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed analysis results')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress non-essential output')

    args = parser.parse_args()

    try:
        cli = VulnHunterCLI()

        if not args.quiet:
            model_info = cli.detector.get_model_info()
            print(f"🚀 VulnHunter V7 v{model_info['version']}")
            print(f"🧠 Models: {', '.join(model_info['models_loaded'])}")
            print(f"🎯 Training Performance: {model_info['performance_stats']['f1_score']:.6f} F1 Score")
            print("=" * 60)

        start_time = time.time()
        results = []

        if args.demo:
            cli.run_demo()

        elif args.file:
            if not os.path.exists(args.file):
                print(f"❌ File not found: {args.file}")
                sys.exit(1)

            result = cli.analyze_file(args.file, args.lang)
            cli.print_result(result, args.detailed)
            results = [result]

        elif args.text:
            result = cli.analyze_text(args.text, args.lang)
            cli.print_result(result, args.detailed)
            results = [result]

        elif args.batch:
            results = cli.analyze_batch(args.batch)
            for result in results:
                cli.print_result(result, args.detailed)
                if args.detailed and len(results) > 1:
                    print("-" * 50)

            cli.print_summary(results)

        # Save results to file if requested
        if args.output and results:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {args.output}")

        elapsed_time = time.time() - start_time
        if not args.quiet:
            print(f"\n⏱️  Analysis completed in {elapsed_time:.2f} seconds")

    except KeyboardInterrupt:
        print("\n\n🛑 Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()