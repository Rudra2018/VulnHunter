#!/usr/bin/env python3
"""
VulnHunter Ωmega - Main Entry Point
Advanced AI-Powered Vulnerability Detection System
"""

import sys
import os
import argparse

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.vulnhunter_best_model_integration import VulnHunterBestModelIntegration

def main():
    parser = argparse.ArgumentParser(description='VulnHunter Ωmega - Advanced AI Vulnerability Hunter')
    parser.add_argument('--target', '-t', required=True, help='Target file or directory to analyze')
    parser.add_argument('--model', '-m', default='models/vulnhunter_best_model.pth', help='Model path')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--validation', action='store_true', default=True, help='Enable enhanced validation (default)')
    parser.add_argument('--confidence-threshold', type=float, default=0.5, help='Confidence threshold for detection')

    args = parser.parse_args()

    if args.verbose:
        print(f"🚀 VulnHunter Ωmega - Advanced AI Vulnerability Hunter (Best Model)")
        print(f"📁 Target: {args.target}")
        print(f"🤖 Model: Enhanced Pattern-Based ML Engine")
        print(f"✅ Validation: {'Enabled' if args.validation else 'Disabled'}")
        print(f"🎯 Confidence Threshold: {args.confidence_threshold}")

    try:
        # Initialize VulnHunter Best Model
        vulnhunter = VulnHunterBestModelIntegration(model_path=args.model)
        print("✅ VulnHunter Ωmega Best Model Initialized")

        # Analyze target
        if os.path.isfile(args.target):
            with open(args.target, 'r') as f:
                code = f.read()

            # Use best model analysis
            result = vulnhunter.analyze_code_comprehensive(code, enable_validation=args.validation)

            # Filter by confidence threshold
            if result.vulnerable and result.confidence < args.confidence_threshold:
                result.vulnerable = False
                result.description = f"Low confidence detection (below {args.confidence_threshold} threshold)"

            results = {
                'vulnerabilities': [
                    {
                        'vulnerable': result.vulnerable,
                        'type': result.vulnerability_type,
                        'severity': result.severity,
                        'confidence': result.confidence,
                        'cwe_id': result.cwe_id,
                        'description': result.description,
                        'risk_score': result.risk_score,
                        'remediation': result.remediation,
                        'line': result.location.get('primary_location', {}).get('line_number', 'unknown'),
                        'validation_status': result.validation_status,
                        'performance': result.performance_metrics
                    }
                ] if result.vulnerable else [],
                'analysis_metadata': {
                    'model_type': 'vulnhunter_omega_best',
                    'model_size_mb': 544.6,
                    'inference_time_ms': result.performance_metrics['inference_time_ms'],
                    'validation_enabled': args.validation,
                    'confidence_threshold': args.confidence_threshold
                }
            }

        elif os.path.isdir(args.target):
            # Directory analysis with best model
            results = {'vulnerabilities': [], 'files_analyzed': 0}
            for root, dirs, files in os.walk(args.target):
                for file in files:
                    if file.endswith(('.py', '.js', '.php', '.java', '.c', '.cpp', '.sol')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                code = f.read()
                            result = vulnhunter.analyze_code_comprehensive(code, enable_validation=args.validation)

                            # Apply confidence threshold
                            if result.vulnerable and result.confidence >= args.confidence_threshold:
                                results['vulnerabilities'].append({
                                    'file': file_path,
                                    'type': result.vulnerability_type,
                                    'severity': result.severity,
                                    'confidence': result.confidence,
                                    'description': result.description,
                                    'risk_score': result.risk_score,
                                    'cwe_id': result.cwe_id,
                                    'validation_status': result.validation_status
                                })
                            results['files_analyzed'] += 1
                        except Exception as e:
                            if args.verbose:
                                print(f"⚠️ Error analyzing {file_path}: {e}")

            results['analysis_metadata'] = {
                'model_type': 'vulnhunter_omega_best',
                'files_analyzed': results['files_analyzed'],
                'validation_enabled': args.validation,
                'confidence_threshold': args.confidence_threshold
            }
        else:
            print(f"❌ Error: {args.target} not found")
            return 1

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                import json
                json.dump(results, f, indent=2)
            print(f"📄 Results saved to {args.output}")
        else:
            print("\n🔍 Vulnerability Analysis Results:")
            vulnerabilities = results.get('vulnerabilities', [])

            if not vulnerabilities:
                print("  ✅ No vulnerabilities detected")
            else:
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity = vuln.get('severity', 'unknown')
                    vuln_type = vuln.get('type', 'unknown')
                    confidence = vuln.get('confidence', 0.0)
                    risk_score = vuln.get('risk_score', 0.0)
                    line = vuln.get('line', 'unknown')
                    cwe_id = vuln.get('cwe_id', 'Unknown')

                    print(f"  🚨 #{i} {severity.upper()}: {vuln_type.replace('_', ' ').title()} at line {line}")
                    print(f"     📊 Confidence: {confidence:.3f} | 🎯 Risk Score: {risk_score:.1f}")
                    print(f"     📍 CWE ID: {cwe_id}")

                    if 'validation_status' in vuln:
                        print(f"     ✅ Validation: {vuln['validation_status']}")

                    if args.verbose and 'description' in vuln:
                        print(f"     💡 {vuln['description']}")
                        if 'remediation' in vuln:
                            print(f"     🔧 {vuln['remediation']}")

            # Show analysis metadata
            metadata = results.get('analysis_metadata', {})
            if metadata:
                print(f"\n📊 Analysis Metadata:")
                print(f"   🤖 Model: VulnHunter Ωmega Best Model")
                print(f"   💾 Engine: Enhanced Pattern-Based ML")
                if 'inference_time_ms' in metadata:
                    print(f"   ⚡ Analysis Time: {metadata['inference_time_ms']:.1f}ms")
                if 'validation_enabled' in metadata:
                    print(f"   ✅ Validation: {'Enabled' if metadata['validation_enabled'] else 'Disabled'}")
                if 'confidence_threshold' in metadata:
                    print(f"   🎯 Confidence Threshold: {metadata['confidence_threshold']}")
                if 'files_analyzed' in metadata:
                    print(f"   📁 Files Analyzed: {metadata['files_analyzed']}")

        return 0

    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())