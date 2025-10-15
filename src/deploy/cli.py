"""
Command Line Interface for VulnHunter V5
Provides CLI commands for vulnerability analysis, training, and model management
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import click
import pandas as pd
import torch
import structlog

# Import VulnHunter components
from ..models.v5_hybrid import VulnHunterV5Model
from ..verifiers.dynamic import DynamicVerifier
from ..data.dataset_loader import VulnDatasetLoader
from ..data.feature_extractor import StaticFeatureExtractor, DynamicFeatureExtractor
from ..pipelines.train_azure import AzureTrainingPipeline

logger = structlog.get_logger(__name__)


class VulnHunterCLI:
    """
    VulnHunter V5 Command Line Interface
    """

    def __init__(self):
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.static_extractor = StaticFeatureExtractor()
        self.dynamic_extractor = DynamicFeatureExtractor()
        self.dynamic_verifier = DynamicVerifier()

    def load_model(self, model_path: str):
        """Load a trained VulnHunter V5 model"""
        try:
            if not Path(model_path).exists():
                click.echo(f"Error: Model file not found: {model_path}", err=True)
                return False

            checkpoint = torch.load(model_path, map_location=self.device)
            model_config = checkpoint.get('model_config', {
                'static_feature_dim': 38,
                'dynamic_feature_dim': 10,
                'hidden_dim': 512,
                'num_classes': 2,
                'dropout': 0.1
            })

            self.model = VulnHunterV5Model(**model_config)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()

            click.echo(f"Model loaded successfully from {model_path}")
            return True

        except Exception as e:
            click.echo(f"Error loading model: {e}", err=True)
            return False

    def analyze_code(self,
                    code: str,
                    language: str = "solidity",
                    include_dynamic: bool = True,
                    explain: bool = False,
                    output_format: str = "json") -> Dict[str, Any]:
        """Analyze code for vulnerabilities"""

        if self.model is None:
            raise click.ClickException("No model loaded. Use --model-path to specify a model.")

        try:
            # Extract features
            static_features = self.static_extractor.extract_all_features(code, language)
            dynamic_features = self.dynamic_extractor.extract_all_features(code, language)

            # Prepare tensors
            static_tensor = torch.tensor([list(static_features.values())], dtype=torch.float32).to(self.device)
            dynamic_tensor = torch.tensor([list(dynamic_features.values())], dtype=torch.float32).to(self.device)

            # Pad/truncate features
            if static_tensor.shape[1] < 38:
                padding = torch.zeros(1, 38 - static_tensor.shape[1]).to(self.device)
                static_tensor = torch.cat([static_tensor, padding], dim=1)
            elif static_tensor.shape[1] > 38:
                static_tensor = static_tensor[:, :38]

            if dynamic_tensor.shape[1] < 10:
                padding = torch.zeros(1, 10 - dynamic_tensor.shape[1]).to(self.device)
                dynamic_tensor = torch.cat([dynamic_tensor, padding], dim=1)
            elif dynamic_tensor.shape[1] > 10:
                dynamic_tensor = dynamic_tensor[:, :10]

            # ML prediction
            with torch.no_grad():
                logits = self.model([code], static_tensor, dynamic_tensor)
                probabilities = torch.softmax(logits, dim=1)
                prediction = torch.argmax(logits, dim=1)
                confidence = probabilities[0][prediction[0]].item()
                is_vulnerable = bool(prediction[0].item())

            # Determine vulnerability type
            vuln_type = self._determine_vulnerability_type(code, static_features)

            result = {
                "ml_prediction": {
                    "is_vulnerable": is_vulnerable,
                    "confidence": confidence,
                    "vulnerability_type": vuln_type if is_vulnerable else None,
                    "severity": self._determine_severity(confidence, vuln_type)
                }
            }

            # Dynamic verification
            if include_dynamic and is_vulnerable:
                dynamic_result = self.dynamic_verifier.verify(code, vuln_type, language)
                result["dynamic_verification"] = dynamic_result

            # Explanations
            if explain and is_vulnerable:
                try:
                    explanation = self.model.explain_prediction([code], static_tensor, dynamic_tensor)
                    result["explanation"] = explanation
                except Exception as e:
                    result["explanation"] = {"error": f"Explanation failed: {e}"}

            return result

        except Exception as e:
            raise click.ClickException(f"Analysis failed: {e}")

    def _determine_vulnerability_type(self, code: str, features: Dict[str, Any]) -> str:
        """Determine vulnerability type based on code patterns"""
        code_lower = code.lower()

        if 'strcpy' in code_lower or 'strcat' in code_lower:
            return 'buffer_overflow'
        elif '++' in code or '--' in code or '+=' in code:
            return 'integer_overflow'
        elif 'select' in code_lower and '+' in code:
            return 'sql_injection'
        elif 'innerhtml' in code_lower:
            return 'xss'
        elif 'system(' in code_lower or 'exec(' in code_lower:
            return 'command_injection'
        elif 'require(' in code_lower or 'assert(' in code_lower:
            return 'access_control'
        elif '.call(' in code_lower:
            return 'reentrancy'
        else:
            return 'unknown'

    def _determine_severity(self, confidence: float, vuln_type: str) -> str:
        """Determine severity based on confidence and type"""
        high_severity_types = ['buffer_overflow', 'command_injection', 'reentrancy']

        if vuln_type in high_severity_types:
            return 'critical' if confidence > 0.8 else 'high'
        elif confidence > 0.9:
            return 'high'
        elif confidence > 0.7:
            return 'medium'
        else:
            return 'low'


# CLI Commands using Click
@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(verbose):
    """VulnHunter V5 - Advanced Vulnerability Detection"""
    if verbose:
        logger.info("VulnHunter V5 CLI started")


@cli.command()
@click.option('--model-path', '-m', required=True, help='Path to trained model')
@click.option('--code', '-c', help='Code string to analyze')
@click.option('--file', '-f', type=click.Path(exists=True), help='File containing code to analyze')
@click.option('--language', '-l', default='solidity', help='Programming language')
@click.option('--dynamic/--no-dynamic', default=True, help='Include dynamic verification')
@click.option('--explain/--no-explain', default=False, help='Include explanations')
@click.option('--output', '-o', type=click.Choice(['json', 'table', 'summary']), default='json', help='Output format')
def analyze(model_path, code, file, language, dynamic, explain, output):
    """Analyze code for vulnerabilities"""

    vulnhunter = VulnHunterCLI()

    # Load model
    if not vulnhunter.load_model(model_path):
        sys.exit(1)

    # Get code content
    if code:
        code_content = code
    elif file:
        with open(file, 'r') as f:
            code_content = f.read()
    else:
        click.echo("Error: Either --code or --file must be specified", err=True)
        sys.exit(1)

    try:
        # Analyze code
        result = vulnhunter.analyze_code(
            code_content,
            language=language,
            include_dynamic=dynamic,
            explain=explain,
            output_format=output
        )

        # Output results
        if output == 'json':
            click.echo(json.dumps(result, indent=2))

        elif output == 'table':
            ml_pred = result['ml_prediction']
            click.echo("\n=== VulnHunter V5 Analysis Results ===")
            click.echo(f"Vulnerable: {ml_pred['is_vulnerable']}")
            click.echo(f"Confidence: {ml_pred['confidence']:.3f}")
            if ml_pred['vulnerability_type']:
                click.echo(f"Type: {ml_pred['vulnerability_type']}")
            click.echo(f"Severity: {ml_pred['severity']}")

            if 'dynamic_verification' in result:
                dyn = result['dynamic_verification']
                click.echo(f"\nDynamic Verification:")
                click.echo(f"  Confirmed: {dyn['confirmed']}")
                click.echo(f"  Exploit Paths: {dyn['exploit_paths']}")
                click.echo(f"  Tool: {dyn['tool_used']}")

        elif output == 'summary':
            ml_pred = result['ml_prediction']
            status = "VULNERABLE" if ml_pred['is_vulnerable'] else "SAFE"
            click.echo(f"{status} ({ml_pred['confidence']:.1%} confidence)")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--input-dir', '-i', required=True, type=click.Path(exists=True), help='Directory containing code files')
@click.option('--model-path', '-m', required=True, help='Path to trained model')
@click.option('--output-file', '-o', help='Output file for results')
@click.option('--language', '-l', default='solidity', help='Programming language')
@click.option('--dynamic/--no-dynamic', default=True, help='Include dynamic verification')
def batch(input_dir, model_path, output_file, language, dynamic):
    """Batch analyze multiple files"""

    vulnhunter = VulnHunterCLI()

    # Load model
    if not vulnhunter.load_model(model_path):
        sys.exit(1)

    input_path = Path(input_dir)
    results = []

    # Find all code files
    extensions = {
        'solidity': ['*.sol'],
        'c': ['*.c', '*.h'],
        'python': ['*.py'],
        'javascript': ['*.js']
    }

    file_patterns = extensions.get(language, ['*'])
    files = []
    for pattern in file_patterns:
        files.extend(input_path.glob(pattern))

    if not files:
        click.echo(f"No {language} files found in {input_dir}")
        sys.exit(1)

    click.echo(f"Found {len(files)} files to analyze")

    # Process each file
    with click.progressbar(files, label='Analyzing files') as file_list:
        for file_path in file_list:
            try:
                with open(file_path, 'r') as f:
                    code_content = f.read()

                result = vulnhunter.analyze_code(
                    code_content,
                    language=language,
                    include_dynamic=dynamic,
                    explain=False
                )

                result['file_path'] = str(file_path)
                results.append(result)

            except Exception as e:
                click.echo(f"\nError processing {file_path}: {e}", err=True)
                results.append({
                    'file_path': str(file_path),
                    'error': str(e)
                })

    # Output results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\nResults saved to {output_file}")
    else:
        click.echo(json.dumps(results, indent=2))

    # Summary
    vulnerable_count = sum(1 for r in results if r.get('ml_prediction', {}).get('is_vulnerable', False))
    click.echo(f"\nSummary: {vulnerable_count}/{len(results)} files flagged as vulnerable")


@cli.command()
@click.option('--output-dir', '-o', default='./data/processed', help='Output directory for dataset')
@click.option('--format', type=click.Choice(['parquet', 'csv']), default='parquet', help='Output format')
def prepare_dataset(output_dir, format):
    """Prepare unified vulnerability detection dataset"""

    click.echo("Preparing VulnHunter V5 dataset...")

    try:
        loader = VulnDatasetLoader()
        dataset_path = loader.prepare_azure_dataset(
            output_path=f"{output_dir}/vulnhunter_v5_dataset.{format}"
        )

        click.echo(f"Dataset prepared successfully: {dataset_path}")

        # Show dataset statistics
        if format == 'parquet':
            df = pd.read_parquet(dataset_path)
        else:
            df = pd.read_csv(dataset_path)

        click.echo(f"\nDataset Statistics:")
        click.echo(f"  Total samples: {len(df)}")
        click.echo(f"  Vulnerable: {sum(df['is_vulnerable'])}")
        click.echo(f"  Non-vulnerable: {len(df) - sum(df['is_vulnerable'])}")
        click.echo(f"  Features: {len(df.columns)}")

    except Exception as e:
        click.echo(f"Error preparing dataset: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--dataset-path', '-d', required=True, help='Path to training dataset')
@click.option('--workspace-name', required=True, help='Azure ML workspace name')
@click.option('--resource-group', required=True, help='Azure resource group')
@click.option('--subscription-id', required=True, help='Azure subscription ID')
@click.option('--tune/--no-tune', default=True, help='Perform hyperparameter tuning')
@click.option('--max-trials', default=20, help='Maximum trials for hyperparameter tuning')
def train(dataset_path, workspace_name, resource_group, subscription_id, tune, max_trials):
    """Train VulnHunter V5 model on Azure ML"""

    click.echo("Starting VulnHunter V5 training...")

    try:
        # Initialize training pipeline
        pipeline = AzureTrainingPipeline(
            workspace_name=workspace_name,
            resource_group=resource_group,
            subscription_id=subscription_id
        )

        # Hyperparameter tuning
        best_config = None
        if tune:
            click.echo(f"Running hyperparameter tuning with {max_trials} trials...")
            best_config = pipeline.hyperparameter_tuning(dataset_path, max_trials)
            click.echo(f"Best configuration: {best_config}")

        # Train model
        click.echo("Training final model...")
        model, metrics = pipeline.train_model(dataset_path, best_config)

        # Evaluate on benchmarks
        click.echo("Evaluating on benchmarks...")
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        benchmark_results = pipeline.evaluate_on_benchmarks(model, device)

        # Save model
        model_path = "./models/vulnhunter_v5_final.pt"
        pipeline.save_model(model, model_path, metrics)

        click.echo("\nTraining completed successfully!")
        click.echo(f"Model saved to: {model_path}")
        click.echo(f"Final metrics: {metrics}")
        click.echo(f"Benchmark results: {benchmark_results}")

    except Exception as e:
        click.echo(f"Training failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--model-path', '-m', required=True, help='Path to trained model')
def info(model_path):
    """Show model information"""

    try:
        if not Path(model_path).exists():
            click.echo(f"Model file not found: {model_path}", err=True)
            sys.exit(1)

        checkpoint = torch.load(model_path, map_location='cpu')

        click.echo("=== VulnHunter V5 Model Information ===")
        click.echo(f"Model file: {model_path}")

        if 'model_config' in checkpoint:
            config = checkpoint['model_config']
            click.echo(f"Model configuration:")
            for key, value in config.items():
                click.echo(f"  {key}: {value}")

        if 'metrics' in checkpoint:
            metrics = checkpoint['metrics']
            click.echo(f"Training metrics:")
            for key, value in metrics.items():
                if isinstance(value, float):
                    click.echo(f"  {key}: {value:.4f}")
                else:
                    click.echo(f"  {key}: {value}")

        # Model size
        model_size = Path(model_path).stat().st_size / (1024 * 1024)
        click.echo(f"Model size: {model_size:.2f} MB")

    except Exception as e:
        click.echo(f"Error reading model info: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--model-path', '-m', required=True, help='Path to trained model')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
def serve(model_path, host, port):
    """Start API server"""

    try:
        from .api import create_app
        import uvicorn

        app = create_app(model_path=model_path)

        click.echo(f"Starting VulnHunter V5 API server on {host}:{port}")
        click.echo(f"API documentation available at http://{host}:{port}/docs")

        uvicorn.run(app, host=host, port=port, log_level="info")

    except ImportError:
        click.echo("Error: FastAPI dependencies not installed. Install with: pip install fastapi uvicorn", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Server failed to start: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()