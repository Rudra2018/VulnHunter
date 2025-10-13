#!/usr/bin/env python3
"""
VulnHunter Command Line Interface

Production-ready CLI for the VulnHunter vulnerability analysis validation system.
Supports single file validation, batch processing, and various output formats.

Usage:
    vulnhunter validate analysis.json
    vulnhunter batch-validate analyses/
    vulnhunter stats
    vulnhunter train
"""

import argparse
import json
import sys
import os
import datetime
import glob
from typing import Dict, Any, List
import logging
from pathlib import Path

# Add the model path
sys.path.append('/Users/ankitthakur/vuln_ml_research')
from comprehensive_vulnhunter_final import ComprehensiveVulnHunter

class VulnHunterCLI:
    """Command Line Interface for VulnHunter."""

    def __init__(self):
        self.vulnhunter = None
        self.setup_logging()

    def setup_logging(self):
        """Setup logging for CLI operations."""

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/Users/ankitthakur/vuln_ml_research/logs/vulnhunter_cli.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('VulnHunterCLI')

        # Create logs directory
        os.makedirs('/Users/ankitthakur/vuln_ml_research/logs', exist_ok=True)

    def initialize_model(self) -> bool:
        """Initialize the VulnHunter model."""

        try:
            if self.vulnhunter is None:
                print("🔄 Initializing VulnHunter model...")
                self.vulnhunter = ComprehensiveVulnHunter()

                if not self.vulnhunter.is_trained:
                    print("🔄 Training model...")
                    self.vulnhunter.train_model()
                    print("✅ Model training completed")
                else:
                    print("✅ Model already trained and ready")

            return True

        except Exception as e:
            print(f"❌ Failed to initialize model: {e}")
            self.logger.error(f"Model initialization failed: {e}")
            return False

    def validate_single(self, analysis_file: str, output_format: str = 'json') -> bool:
        """Validate a single analysis file."""

        try:
            # Load analysis file
            if not os.path.exists(analysis_file):
                print(f"❌ File not found: {analysis_file}")
                return False

            with open(analysis_file, 'r') as f:
                analysis_data = json.load(f)

            print(f"🔍 Validating: {analysis_file}")

            # Perform validation
            result = self.vulnhunter.validate_analysis(analysis_data)

            # Output results
            if output_format == 'json':
                print(json.dumps(result, indent=2))
            elif output_format == 'summary':
                self._print_summary(result)
            elif output_format == 'detailed':
                self._print_detailed(result)

            # Log result
            classification = result['overall_assessment']['primary_classification']
            confidence = result['historical_context']['validation_confidence']
            self.logger.info(f"Validated {analysis_file}: {classification} (confidence: {confidence:.3f})")

            return True

        except Exception as e:
            print(f"❌ Validation failed: {e}")
            self.logger.error(f"Validation failed for {analysis_file}: {e}")
            return False

    def validate_batch(self, input_path: str, output_dir: str = None, output_format: str = 'json') -> bool:
        """Validate multiple analysis files."""

        try:
            # Find analysis files
            if os.path.isdir(input_path):
                pattern = os.path.join(input_path, '*.json')
                analysis_files = glob.glob(pattern)
            elif '*' in input_path:
                analysis_files = glob.glob(input_path)
            else:
                analysis_files = [input_path]

            if not analysis_files:
                print(f"❌ No analysis files found in: {input_path}")
                return False

            print(f"🔍 Found {len(analysis_files)} analysis files to validate")

            # Create output directory if needed
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Process each file
            results = []
            successful = 0
            failed = 0

            for i, analysis_file in enumerate(analysis_files, 1):
                try:
                    print(f"[{i}/{len(analysis_files)}] Processing: {os.path.basename(analysis_file)}")

                    with open(analysis_file, 'r') as f:
                        analysis_data = json.load(f)

                    result = self.vulnhunter.validate_analysis(analysis_data)
                    result['source_file'] = analysis_file
                    result['batch_index'] = i - 1

                    results.append(result)
                    successful += 1

                    # Save individual result if output directory specified
                    if output_dir:
                        output_file = os.path.join(
                            output_dir,
                            f"{os.path.splitext(os.path.basename(analysis_file))[0]}_validation.json"
                        )
                        with open(output_file, 'w') as f:
                            json.dump(result, f, indent=2)

                except Exception as e:
                    print(f"  ❌ Failed: {e}")
                    failed += 1
                    results.append({
                        'source_file': analysis_file,
                        'batch_index': i - 1,
                        'error': str(e),
                        'status': 'failed'
                    })

            # Generate batch summary
            batch_summary = {
                'batch_timestamp': datetime.datetime.now().isoformat(),
                'input_path': input_path,
                'total_files': len(analysis_files),
                'successful': successful,
                'failed': failed,
                'results_summary': self._generate_batch_summary(results),
                'results': results if output_format != 'summary' else None
            }

            # Output batch results
            if output_format == 'json':
                print(json.dumps(batch_summary, indent=2))
            else:
                self._print_batch_summary(batch_summary)

            # Save batch summary if output directory specified
            if output_dir:
                summary_file = os.path.join(output_dir, 'batch_validation_summary.json')
                with open(summary_file, 'w') as f:
                    json.dump(batch_summary, f, indent=2)
                print(f"📋 Batch summary saved to: {summary_file}")

            print(f"\n✅ Batch validation completed: {successful}/{len(analysis_files)} successful")
            return True

        except Exception as e:
            print(f"❌ Batch validation failed: {e}")
            self.logger.error(f"Batch validation failed: {e}")
            return False

    def _print_summary(self, result: Dict[str, Any]):
        """Print validation result summary."""

        assessment = result['overall_assessment']
        probabilities = result['probabilities']

        print("\n" + "="*60)
        print("🎯 VULNHUNTER VALIDATION SUMMARY")
        print("="*60)

        print(f"Classification: {assessment['primary_classification']}")
        print(f"Recommendation: {assessment['recommendation']}")
        print(f"Credibility Score: {assessment['credibility_score']:.2f}/1.00")
        print(f"Confidence: {assessment['confidence']:.2f}")

        print(f"\nProbabilities:")
        print(f"  • Fabrication: {probabilities['fabrication_probability']:.3f}")
        print(f"  • Overly Optimistic: {probabilities['optimism_probability']:.3f}")
        print(f"  • Market Unrealistic: {probabilities['market_unrealistic_probability']:.3f}")

        if result['actionable_recommendations']:
            print(f"\nRecommendations:")
            for i, rec in enumerate(result['actionable_recommendations'], 1):
                print(f"  {i}. {rec}")

        print("="*60)

    def _print_detailed(self, result: Dict[str, Any]):
        """Print detailed validation results."""

        self._print_summary(result)

        print(f"\nDetailed Analysis:")
        print(f"Model Version: {result['model_version']}")
        print(f"Validation Timestamp: {result['validation_timestamp']}")

        # Feature analysis
        if 'feature_analysis' in result:
            features = result['feature_analysis']
            print(f"\nFeature Analysis:")
            print(f"  • Total Features: {features['total_features_analyzed']}")

            if 'key_indicators' in features:
                print(f"  • Key Indicators:")
                for indicator in features['key_indicators']:
                    print(f"    - {indicator}")

        # Historical context
        context = result['historical_context']
        print(f"\nHistorical Context:")
        print(f"  • Similar to OpenAI Codex case: {context['similar_to_openai_codex_case']}")
        print(f"  • Similar to Microsoft bounty case: {context['similar_to_microsoft_bounty_case']}")
        print(f"  • Validation Confidence: {context['validation_confidence']:.3f}")

    def _generate_batch_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for batch results."""

        successful_results = [r for r in results if 'error' not in r]

        if not successful_results:
            return {'error': 'No successful validations'}

        # Count classifications
        classifications = {}
        for result in successful_results:
            if 'overall_assessment' in result:
                classification = result['overall_assessment']['primary_classification']
                classifications[classification] = classifications.get(classification, 0) + 1

        # Average probabilities
        avg_fabrication = sum(r['probabilities']['fabrication_probability'] for r in successful_results) / len(successful_results)
        avg_optimism = sum(r['probabilities']['optimism_probability'] for r in successful_results) / len(successful_results)
        avg_unrealistic = sum(r['probabilities']['market_unrealistic_probability'] for r in successful_results) / len(successful_results)

        return {
            'classification_counts': classifications,
            'average_probabilities': {
                'fabrication': avg_fabrication,
                'optimism': avg_optimism,
                'market_unrealistic': avg_unrealistic
            },
            'high_risk_analyses': len([r for r in successful_results
                                    if r['probabilities']['fabrication_probability'] > 0.7 or
                                       r['probabilities']['optimism_probability'] > 0.7])
        }

    def _print_batch_summary(self, batch_summary: Dict[str, Any]):
        """Print batch validation summary."""

        print("\n" + "="*60)
        print("📊 BATCH VALIDATION SUMMARY")
        print("="*60)

        print(f"Input Path: {batch_summary['input_path']}")
        print(f"Total Files: {batch_summary['total_files']}")
        print(f"Successful: {batch_summary['successful']}")
        print(f"Failed: {batch_summary['failed']}")

        if 'results_summary' in batch_summary and batch_summary['results_summary']:
            summary = batch_summary['results_summary']

            if 'classification_counts' in summary:
                print(f"\nClassification Breakdown:")
                for classification, count in summary['classification_counts'].items():
                    print(f"  • {classification}: {count}")

            if 'average_probabilities' in summary:
                probs = summary['average_probabilities']
                print(f"\nAverage Probabilities:")
                print(f"  • Fabrication: {probs['fabrication']:.3f}")
                print(f"  • Optimism: {probs['optimism']:.3f}")
                print(f"  • Market Unrealistic: {probs['market_unrealistic']:.3f}")

            if 'high_risk_analyses' in summary:
                print(f"\nHigh-Risk Analyses: {summary['high_risk_analyses']}")

        print("="*60)

    def show_stats(self):
        """Show model statistics."""

        if not self.initialize_model():
            return False

        stats = {
            'model_info': {
                'name': 'Comprehensive VulnHunter Final',
                'version': '1.0.0',
                'training_date': '2025-10-13',
                'is_trained': self.vulnhunter.is_trained
            },
            'validation_history': {
                'total_claims_validated': 4089,
                'openai_codex_case': {
                    'claimed_vulnerabilities': 2964,
                    'actual_valid': 0,
                    'classification': 'COMPLETE_FABRICATION'
                },
                'microsoft_bounty_case': {
                    'claimed_vulnerabilities': 1125,
                    'actual_valid': 0,
                    'classification': 'OVERLY_OPTIMISTIC'
                }
            },
            'capabilities': [
                'Fabrication Detection (OpenAI Codex pattern)',
                'Optimism Detection (Microsoft bounty pattern)',
                'Market Reality Validation',
                'Multi-Pattern Classification'
            ]
        }

        print("\n" + "="*60)
        print("📈 VULNHUNTER MODEL STATISTICS")
        print("="*60)

        print(f"Model: {stats['model_info']['name']}")
        print(f"Version: {stats['model_info']['version']}")
        print(f"Training Date: {stats['model_info']['training_date']}")
        print(f"Status: {'✅ Trained' if stats['model_info']['is_trained'] else '❌ Not Trained'}")

        print(f"\nValidation History:")
        print(f"  • Total Claims Validated: {stats['validation_history']['total_claims_validated']}")
        print(f"  • OpenAI Codex Case: {stats['validation_history']['openai_codex_case']['claimed_vulnerabilities']} claims → 0 valid")
        print(f"  • Microsoft Bounty Case: {stats['validation_history']['microsoft_bounty_case']['claimed_vulnerabilities']} claims → 0 valid")
        print(f"  • Overall False Positive Rate: 100%")

        print(f"\nCapabilities:")
        for capability in stats['capabilities']:
            print(f"  • {capability}")

        print("="*60)
        return True

    def train_model(self):
        """Train or retrain the model."""

        print("🔄 Initializing and training VulnHunter model...")

        try:
            self.vulnhunter = ComprehensiveVulnHunter()
            metrics = self.vulnhunter.train_model()

            print("✅ Model training completed successfully!")
            print(f"Model saved to: /Users/ankitthakur/vuln_ml_research/models/")

            return True

        except Exception as e:
            print(f"❌ Training failed: {e}")
            self.logger.error(f"Training failed: {e}")
            return False


def main():
    """Main CLI entry point."""

    parser = argparse.ArgumentParser(
        description='VulnHunter - Vulnerability Analysis Validation System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  vulnhunter validate analysis.json
  vulnhunter validate analysis.json --format summary
  vulnhunter batch-validate analyses/ --output results/
  vulnhunter stats
  vulnhunter train

For more information, visit: ~/vuln_ml_research/README_VULNHUNTER_FINAL.md
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate a single analysis file')
    validate_parser.add_argument('file', help='Analysis file to validate')
    validate_parser.add_argument('--format', choices=['json', 'summary', 'detailed'],
                               default='summary', help='Output format')

    # Batch validate command
    batch_parser = subparsers.add_parser('batch-validate', help='Validate multiple analysis files')
    batch_parser.add_argument('input', help='Input directory or file pattern')
    batch_parser.add_argument('--output', '-o', help='Output directory for results')
    batch_parser.add_argument('--format', choices=['json', 'summary'],
                            default='summary', help='Output format')

    # Stats command
    subparsers.add_parser('stats', help='Show model statistics')

    # Train command
    subparsers.add_parser('train', help='Train or retrain the model')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize CLI
    cli = VulnHunterCLI()

    # Execute command
    if args.command == 'validate':
        if not cli.initialize_model():
            return 1
        success = cli.validate_single(args.file, args.format)
        return 0 if success else 1

    elif args.command == 'batch-validate':
        if not cli.initialize_model():
            return 1
        success = cli.validate_batch(args.input, args.output, args.format)
        return 0 if success else 1

    elif args.command == 'stats':
        success = cli.show_stats()
        return 0 if success else 1

    elif args.command == 'train':
        success = cli.train_model()
        return 0 if success else 1

    return 0


if __name__ == '__main__':
    sys.exit(main())