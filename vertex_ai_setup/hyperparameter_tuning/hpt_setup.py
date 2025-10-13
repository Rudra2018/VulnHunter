"""
VulnHunter AI - Hyperparameter Tuning with Vertex AI
Advanced hyperparameter optimization for VulnHunter AI models
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import yaml

from google.cloud import aiplatform
from google.cloud.aiplatform import hyperparameter_tuning as hpt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnHunterHyperparameterTuner:
    """Advanced hyperparameter tuning for VulnHunter AI models"""

    def __init__(self, project_id: str, region: str, bucket_name: str):
        self.project_id = project_id
        self.region = region
        self.bucket_name = bucket_name

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=region)

    def create_hyperparameter_tuning_job(self,
                                        display_name: str,
                                        training_script_path: str,
                                        train_data_path: str,
                                        val_data_path: str,
                                        job_dir: str,
                                        base_args: Dict[str, Any],
                                        hyperparameter_configs: Dict[str, Any],
                                        max_trial_count: int = 50,
                                        parallel_trial_count: int = 5,
                                        algorithm: str = "ALGORITHM_UNSPECIFIED",
                                        optimization_goal: str = "MAXIMIZE",
                                        metric_id: str = "val_f1",
                                        machine_type: str = "n1-standard-8",
                                        accelerator_type: str = "NVIDIA_TESLA_T4",
                                        accelerator_count: int = 1,
                                        container_uri: str = "us-docker.pkg.dev/vertex-ai/training/pytorch-gpu.1-13.py310:latest"):
        """Create a comprehensive hyperparameter tuning job"""

        # Define hyperparameter specs
        parameter_specs = self._build_parameter_specs(hyperparameter_configs)

        # Define metric specs
        metric_spec = hpt.MetricSpec(
            metric_id=metric_id,
            goal=optimization_goal
        )

        # Worker pool specs
        worker_pool_specs = [
            {
                "machine_spec": {
                    "machine_type": machine_type,
                    "accelerator_type": accelerator_type,
                    "accelerator_count": accelerator_count,
                },
                "replica_count": 1,
                "container_spec": {
                    "image_uri": container_uri,
                    "command": ["python"],
                    "args": [
                        training_script_path,
                        f"--train-data-path={train_data_path}",
                        f"--val-data-path={val_data_path}",
                        f"--job-dir={job_dir}",
                    ] + [f"--{k}={v}" for k, v in base_args.items()]
                }
            }
        ]

        # Create the hyperparameter tuning job
        job = aiplatform.HyperparameterTuningJob(
            display_name=display_name,
            custom_job_spec={
                "worker_pool_specs": worker_pool_specs,
                "base_output_dir": job_dir,
            },
            parameter_specs=parameter_specs,
            metric_specs=[metric_spec],
            max_trial_count=max_trial_count,
            parallel_trial_count=parallel_trial_count,
            search_algorithm=algorithm,
        )

        logger.info(f"Created hyperparameter tuning job: {display_name}")
        logger.info(f"Max trials: {max_trial_count}, Parallel: {parallel_trial_count}")
        logger.info(f"Optimization goal: {optimization_goal} {metric_id}")

        return job

    def _build_parameter_specs(self, hyperparameter_configs: Dict[str, Any]) -> List[hpt.ParameterSpec]:
        """Build parameter specifications for hyperparameter tuning"""
        parameter_specs = []

        for param_name, config in hyperparameter_configs.items():
            param_type = config.get('type', 'double')
            scale_type = config.get('scale_type', 'UNIT_LINEAR_SCALE')

            if param_type == 'double':
                parameter_spec = hpt.ParameterSpec(
                    parameter_id=param_name,
                    double_value_spec=hpt.DoubleValueSpec(
                        min_value=config['min_value'],
                        max_value=config['max_value']
                    ),
                    scale_type=getattr(hpt.ScaleType, scale_type)
                )
            elif param_type == 'integer':
                parameter_spec = hpt.ParameterSpec(
                    parameter_id=param_name,
                    integer_value_spec=hpt.IntegerValueSpec(
                        min_value=int(config['min_value']),
                        max_value=int(config['max_value'])
                    ),
                    scale_type=getattr(hpt.ScaleType, scale_type)
                )
            elif param_type == 'categorical':
                parameter_spec = hpt.ParameterSpec(
                    parameter_id=param_name,
                    categorical_value_spec=hpt.CategoricalValueSpec(
                        values=config['values']
                    )
                )
            elif param_type == 'discrete':
                parameter_spec = hpt.ParameterSpec(
                    parameter_id=param_name,
                    discrete_value_spec=hpt.DiscreteValueSpec(
                        values=config['values']
                    )
                )
            else:
                raise ValueError(f"Unknown parameter type: {param_type}")

            parameter_specs.append(parameter_spec)

        return parameter_specs

    def get_optimal_hyperparameters(self, job_name: str) -> Dict[str, Any]:
        """Get optimal hyperparameters from completed tuning job"""
        try:
            job = aiplatform.HyperparameterTuningJob(job_name)
            trials = job.trials

            # Find best trial
            best_trial = None
            best_metric_value = float('-inf')

            for trial in trials:
                if trial.final_measurement and trial.final_measurement.metrics:
                    metric_value = trial.final_measurement.metrics[0].value
                    if metric_value > best_metric_value:
                        best_metric_value = metric_value
                        best_trial = trial

            if best_trial:
                optimal_params = {}
                for param in best_trial.parameters:
                    optimal_params[param.parameter_id] = param.value

                logger.info(f"Best trial metric value: {best_metric_value}")
                logger.info(f"Optimal hyperparameters: {optimal_params}")

                return {
                    'best_metric_value': best_metric_value,
                    'optimal_parameters': optimal_params,
                    'trial_id': best_trial.id
                }
            else:
                logger.warning("No successful trials found")
                return {}

        except Exception as e:
            logger.error(f"Failed to get optimal hyperparameters: {e}")
            return {}

    def create_advanced_hpt_configs(self) -> Dict[str, Dict[str, Any]]:
        """Create advanced hyperparameter tuning configurations for different model types"""

        configs = {
            "contextual_codebert": {
                "learning_rate": {
                    "type": "double",
                    "min_value": 1e-6,
                    "max_value": 1e-3,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "batch_size": {
                    "type": "categorical",
                    "values": ["8", "16", "32", "64"]
                },
                "weight_decay": {
                    "type": "double",
                    "min_value": 0.0,
                    "max_value": 0.1,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "warmup_steps": {
                    "type": "integer",
                    "min_value": 100,
                    "max_value": 2000,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "max_seq_length": {
                    "type": "categorical",
                    "values": ["256", "512", "768", "1024"]
                },
                "dropout_rate": {
                    "type": "double",
                    "min_value": 0.0,
                    "max_value": 0.5,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "context_attention_heads": {
                    "type": "categorical",
                    "values": ["4", "8", "12", "16"]
                },
                "context_layers": {
                    "type": "integer",
                    "min_value": 2,
                    "max_value": 8,
                    "scale_type": "UNIT_LINEAR_SCALE"
                }
            },
            "hybrid_architecture": {
                "learning_rate": {
                    "type": "double",
                    "min_value": 5e-6,
                    "max_value": 5e-4,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "batch_size": {
                    "type": "categorical",
                    "values": ["4", "8", "16", "32"]
                },
                "gnn_hidden_dim": {
                    "type": "categorical",
                    "values": ["64", "128", "256", "512"]
                },
                "gnn_num_layers": {
                    "type": "integer",
                    "min_value": 2,
                    "max_value": 6,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "transformer_num_layers": {
                    "type": "categorical",
                    "values": ["4", "6", "8", "12"]
                },
                "attention_heads": {
                    "type": "categorical",
                    "values": ["4", "8", "12", "16"]
                },
                "hierarchical_levels": {
                    "type": "integer",
                    "min_value": 2,
                    "max_value": 5,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "projection_dim": {
                    "type": "categorical",
                    "values": ["128", "256", "512", "768"]
                },
                "bayesian_samples": {
                    "type": "integer",
                    "min_value": 5,
                    "max_value": 20,
                    "scale_type": "UNIT_LINEAR_SCALE"
                }
            },
            "ensemble": {
                "learning_rate": {
                    "type": "double",
                    "min_value": 1e-5,
                    "max_value": 1e-3,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "ensemble_size": {
                    "type": "integer",
                    "min_value": 3,
                    "max_value": 10,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "diversity_regularization": {
                    "type": "double",
                    "min_value": 0.0,
                    "max_value": 1.0,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "temperature": {
                    "type": "double",
                    "min_value": 0.1,
                    "max_value": 5.0,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "voting_threshold": {
                    "type": "double",
                    "min_value": 0.3,
                    "max_value": 0.8,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "bootstrap_ratio": {
                    "type": "double",
                    "min_value": 0.6,
                    "max_value": 1.0,
                    "scale_type": "UNIT_LINEAR_SCALE"
                }
            },
            "contrastive_learning": {
                "learning_rate": {
                    "type": "double",
                    "min_value": 1e-5,
                    "max_value": 1e-3,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "temperature": {
                    "type": "double",
                    "min_value": 0.05,
                    "max_value": 0.5,
                    "scale_type": "UNIT_LOG_SCALE"
                },
                "projection_dim": {
                    "type": "categorical",
                    "values": ["64", "128", "256", "512"]
                },
                "negative_sampling_ratio": {
                    "type": "integer",
                    "min_value": 2,
                    "max_value": 8,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "augmentation_probability": {
                    "type": "double",
                    "min_value": 0.2,
                    "max_value": 0.8,
                    "scale_type": "UNIT_LINEAR_SCALE"
                },
                "similarity_function": {
                    "type": "categorical",
                    "values": ["cosine", "euclidean", "dot_product"]
                }
            }
        }

        return configs

    def run_comprehensive_hyperparameter_search(self,
                                               model_type: str,
                                               train_data_path: str,
                                               val_data_path: str,
                                               job_dir_base: str,
                                               max_trials: int = 50,
                                               parallel_trials: int = 5) -> Dict[str, Any]:
        """Run comprehensive hyperparameter search for a specific model type"""

        configs = self.create_advanced_hpt_configs()

        if model_type not in configs:
            raise ValueError(f"Unknown model type: {model_type}. Available: {list(configs.keys())}")

        hyperparameter_config = configs[model_type]

        # Base arguments
        base_args = {
            "model-type": model_type,
            "num-epochs": 5,  # Shorter for HPT
            "use-multimodal-features": "true",
            "early-stopping-patience": 2,
            "log-steps": 100,
            "save-steps": 1000
        }

        # Job directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        job_dir = f"{job_dir_base}/hpt_{model_type}_{timestamp}"

        # Create hyperparameter tuning job
        job = self.create_hyperparameter_tuning_job(
            display_name=f"vulnhunter-hpt-{model_type}-{timestamp}",
            training_script_path="/app/train.py",
            train_data_path=train_data_path,
            val_data_path=val_data_path,
            job_dir=job_dir,
            base_args=base_args,
            hyperparameter_configs=hyperparameter_config,
            max_trial_count=max_trials,
            parallel_trial_count=parallel_trials,
            algorithm="ALGORITHM_UNSPECIFIED",  # Let Vertex AI choose
            optimization_goal="MAXIMIZE",
            metric_id="val_f1"
        )

        logger.info(f"Starting hyperparameter tuning for {model_type}")
        logger.info(f"Configuration: {len(hyperparameter_config)} parameters")
        logger.info(f"Search space size: estimated {self._estimate_search_space_size(hyperparameter_config)}")

        return {
            "job": job,
            "job_name": job.resource_name,
            "job_dir": job_dir,
            "hyperparameter_config": hyperparameter_config,
            "expected_trials": max_trials
        }

    def _estimate_search_space_size(self, config: Dict[str, Any]) -> int:
        """Estimate the size of the hyperparameter search space"""
        space_size = 1

        for param_config in config.values():
            if param_config['type'] == 'categorical':
                space_size *= len(param_config['values'])
            elif param_config['type'] == 'discrete':
                space_size *= len(param_config['values'])
            elif param_config['type'] in ['double', 'integer']:
                # Rough estimate for continuous parameters
                space_size *= 20  # Assume ~20 meaningful values

        return min(space_size, 1000000)  # Cap at 1M for display

    def create_multi_objective_tuning_job(self,
                                        display_name: str,
                                        training_script_path: str,
                                        train_data_path: str,
                                        val_data_path: str,
                                        job_dir: str,
                                        base_args: Dict[str, Any],
                                        hyperparameter_configs: Dict[str, Any],
                                        objectives: List[Tuple[str, str]] = None):
        """Create multi-objective hyperparameter tuning job"""

        if objectives is None:
            objectives = [
                ("val_f1", "MAXIMIZE"),
                ("val_false_positive_rate", "MINIMIZE"),
                ("training_time", "MINIMIZE")
            ]

        # Define metric specs for multi-objective optimization
        metric_specs = [
            hpt.MetricSpec(metric_id=metric_id, goal=goal)
            for metric_id, goal in objectives
        ]

        parameter_specs = self._build_parameter_specs(hyperparameter_configs)

        # Worker pool specs
        worker_pool_specs = [
            {
                "machine_spec": {
                    "machine_type": "n1-standard-8",
                    "accelerator_type": "NVIDIA_TESLA_T4",
                    "accelerator_count": 1,
                },
                "replica_count": 1,
                "container_spec": {
                    "image_uri": "us-docker.pkg.dev/vertex-ai/training/pytorch-gpu.1-13.py310:latest",
                    "command": ["python"],
                    "args": [
                        training_script_path,
                        f"--train-data-path={train_data_path}",
                        f"--val-data-path={val_data_path}",
                        f"--job-dir={job_dir}",
                    ] + [f"--{k}={v}" for k, v in base_args.items()]
                }
            }
        ]

        # Create multi-objective tuning job
        job = aiplatform.HyperparameterTuningJob(
            display_name=display_name,
            custom_job_spec={
                "worker_pool_specs": worker_pool_specs,
                "base_output_dir": job_dir,
            },
            parameter_specs=parameter_specs,
            metric_specs=metric_specs,
            max_trial_count=100,
            parallel_trial_count=8,
            search_algorithm="ALGORITHM_UNSPECIFIED",
        )

        logger.info(f"Created multi-objective tuning job: {display_name}")
        logger.info(f"Objectives: {objectives}")

        return job

    def analyze_hyperparameter_importance(self, job_name: str) -> Dict[str, float]:
        """Analyze hyperparameter importance from completed tuning job"""
        try:
            job = aiplatform.HyperparameterTuningJob(job_name)
            trials = job.trials

            # Extract trial data
            trial_data = []
            for trial in trials:
                if trial.final_measurement and trial.final_measurement.metrics:
                    trial_info = {
                        'metric_value': trial.final_measurement.metrics[0].value
                    }
                    for param in trial.parameters:
                        trial_info[param.parameter_id] = param.value
                    trial_data.append(trial_info)

            if not trial_data:
                return {}

            # Simple correlation analysis
            import pandas as pd
            import numpy as np

            df = pd.DataFrame(trial_data)
            correlations = df.corr()['metric_value'].abs().drop('metric_value')

            importance_scores = correlations.to_dict()
            logger.info(f"Hyperparameter importance scores: {importance_scores}")

            return importance_scores

        except Exception as e:
            logger.error(f"Failed to analyze hyperparameter importance: {e}")
            return {}

    def save_tuning_results(self, job_name: str, output_path: str):
        """Save hyperparameter tuning results"""
        try:
            job = aiplatform.HyperparameterTuningJob(job_name)
            trials = job.trials

            results = {
                "job_name": job_name,
                "job_state": job.state.name,
                "total_trials": len(trials),
                "trials": []
            }

            for trial in trials:
                trial_info = {
                    "trial_id": trial.id,
                    "state": trial.state.name,
                    "parameters": {},
                    "final_measurement": None
                }

                # Extract parameters
                for param in trial.parameters:
                    trial_info["parameters"][param.parameter_id] = param.value

                # Extract final measurement
                if trial.final_measurement and trial.final_measurement.metrics:
                    trial_info["final_measurement"] = {
                        "metric_id": trial.final_measurement.metrics[0].metric_id,
                        "value": trial.final_measurement.metrics[0].value
                    }

                results["trials"].append(trial_info)

            # Save results
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)

            logger.info(f"Tuning results saved to: {output_path}")

        except Exception as e:
            logger.error(f"Failed to save tuning results: {e}")

def create_hpt_training_script():
    """Create training script optimized for hyperparameter tuning"""

    script_content = '''#!/usr/bin/env python3
"""
VulnHunter AI Training Script for Hyperparameter Tuning
Optimized for Vertex AI HPT with metric reporting
"""

import argparse
import json
import logging
from train import VulnHunterTrainer
from google.cloud import aiplatform

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def report_hyperparameter_tuning_metric(metric_name: str, metric_value: float, step: int = 0):
    """Report metric for hyperparameter tuning"""
    try:
        # Report to Vertex AI HPT
        aiplatform.log_metrics({metric_name: metric_value})

        # Also write to file for backup
        metric_data = {
            "metric_name": metric_name,
            "metric_value": float(metric_value),
            "step": step
        }

        with open(f"/tmp/{metric_name}.json", "w") as f:
            json.dump(metric_data, f)

        logger.info(f"HPT Metric reported: {metric_name} = {metric_value}")

    except Exception as e:
        logger.warning(f"Failed to report HPT metric: {e}")

def main():
    parser = argparse.ArgumentParser()

    # Add all training arguments
    parser.add_argument('--train-data-path', type=str, required=True)
    parser.add_argument('--val-data-path', type=str, required=True)
    parser.add_argument('--job-dir', type=str, required=True)
    parser.add_argument('--model-type', type=str, default='contextual_codebert')

    # Hyperparameters that will be tuned
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--weight-decay', type=float, default=0.01)
    parser.add_argument('--warmup-steps', type=int, default=1000)
    parser.add_argument('--max-seq-length', type=int, default=512)
    parser.add_argument('--dropout-rate', type=float, default=0.1)

    # Model-specific hyperparameters
    parser.add_argument('--gnn-hidden-dim', type=int, default=128)
    parser.add_argument('--gnn-num-layers', type=int, default=3)
    parser.add_argument('--transformer-num-layers', type=int, default=6)
    parser.add_argument('--attention-heads', type=int, default=8)
    parser.add_argument('--projection-dim', type=int, default=256)
    parser.add_argument('--temperature', type=float, default=0.1)

    # Training parameters
    parser.add_argument('--num-epochs', type=int, default=5)
    parser.add_argument('--early-stopping-patience', type=int, default=2)
    parser.add_argument('--use-multimodal-features', type=str, default='false')

    args = parser.parse_args()

    # Convert string boolean
    args.use_multimodal_features = args.use_multimodal_features.lower() == 'true'

    # Initialize and run training
    trainer = VulnHunterTrainer(args)

    # Custom training loop with HPT metric reporting
    class HPTTrainer(VulnHunterTrainer):
        def _validate(self, epoch: int):
            metrics = super()._validate(epoch)

            # Report key metrics for HPT
            if metrics:
                report_hyperparameter_tuning_metric('val_f1', metrics.get('val_f1', 0))
                report_hyperparameter_tuning_metric('val_accuracy', metrics.get('val_accuracy', 0))
                report_hyperparameter_tuning_metric('val_precision', metrics.get('val_precision', 0))
                report_hyperparameter_tuning_metric('val_recall', metrics.get('val_recall', 0))
                report_hyperparameter_tuning_metric('val_false_positive_rate', metrics.get('val_false_positive_rate', 1))

            return metrics

    # Use HPT-enabled trainer
    hpt_trainer = HPTTrainer(args)
    hpt_trainer.train()

if __name__ == '__main__':
    main()
'''

    return script_content

# Example usage and demonstration
if __name__ == "__main__":
    # Configuration
    PROJECT_ID = os.getenv("PROJECT_ID", "vulnhunter-ai-project")
    REGION = os.getenv("REGION", "us-central1")
    BUCKET_NAME = os.getenv("BUCKET_NAME", f"vulnhunter-ai-training-{PROJECT_ID}")

    print("🔬 VulnHunter AI Hyperparameter Tuning Setup")
    print("=" * 55)

    # Initialize hyperparameter tuner
    tuner = VulnHunterHyperparameterTuner(PROJECT_ID, REGION, BUCKET_NAME)

    # Show available configurations
    configs = tuner.create_advanced_hpt_configs()
    print(f"📊 Available Model Configurations:")
    for model_type, config in configs.items():
        print(f"   {model_type}: {len(config)} hyperparameters")
        space_size = tuner._estimate_search_space_size(config)
        print(f"     Search space size: ~{space_size:,}")

    # Example: Set up hyperparameter tuning for hybrid architecture
    print(f"\n🔬 Example: Hybrid Architecture HPT Setup")
    print("-" * 40)

    model_type = "hybrid_architecture"
    job_info = tuner.run_comprehensive_hyperparameter_search(
        model_type=model_type,
        train_data_path=f"gs://{BUCKET_NAME}/data/train.json",
        val_data_path=f"gs://{BUCKET_NAME}/data/val.json",
        job_dir_base=f"gs://{BUCKET_NAME}/experiments",
        max_trials=30,
        parallel_trials=6
    )

    print(f"✅ HPT Job Created:")
    print(f"   Job Name: {job_info['job'].display_name}")
    print(f"   Expected Trials: {job_info['expected_trials']}")
    print(f"   Output Directory: {job_info['job_dir']}")

    # Show hyperparameter configuration
    print(f"\n📋 Hyperparameters Being Tuned:")
    for param_name, param_config in job_info['hyperparameter_config'].items():
        if param_config['type'] == 'categorical':
            values = param_config['values']
            print(f"   {param_name}: {param_config['type']} {values}")
        elif param_config['type'] in ['double', 'integer']:
            min_val = param_config['min_value']
            max_val = param_config['max_value']
            scale = param_config.get('scale_type', 'LINEAR')
            print(f"   {param_name}: {param_config['type']} [{min_val}, {max_val}] ({scale})")

    # Multi-objective optimization example
    print(f"\n🎯 Multi-Objective Optimization Example:")
    print("-" * 40)

    multi_obj_job = tuner.create_multi_objective_tuning_job(
        display_name="vulnhunter-multi-objective-hpt",
        training_script_path="/app/hpt_train.py",
        train_data_path=f"gs://{BUCKET_NAME}/data/train.json",
        val_data_path=f"gs://{BUCKET_NAME}/data/val.json",
        job_dir=f"gs://{BUCKET_NAME}/experiments/multi_objective_hpt",
        base_args={"model-type": "ensemble", "num-epochs": 3},
        hyperparameter_configs=configs["ensemble"],
        objectives=[
            ("val_f1", "MAXIMIZE"),
            ("val_false_positive_rate", "MINIMIZE"),
            ("training_time", "MINIMIZE")
        ]
    )

    print(f"✅ Multi-Objective HPT Job Created:")
    print(f"   Objectives: F1-Score (max), FP Rate (min), Training Time (min)")
    print(f"   Advanced optimization for production deployment")

    # Performance expectations
    print(f"\n📈 Expected Performance Improvements:")
    print(f"   Baseline F1-Score: ~0.75")
    print(f"   Expected after HPT: ~0.85-0.90")
    print(f"   False Positive Reduction: ~70-85%")
    print(f"   Training Time: 4-8 hours (depending on trials)")

    print(f"\n📝 Next Steps:")
    print(f"   1. Submit HPT job: job.run(sync=False)")
    print(f"   2. Monitor progress in Vertex AI console")
    print(f"   3. Analyze results: tuner.get_optimal_hyperparameters()")
    print(f"   4. Use optimal params for production training")

    # Save HPT training script
    hpt_script = create_hpt_training_script()
    with open("vertex_ai_setup/training/hpt_train.py", "w") as f:
        f.write(hpt_script)

    print(f"   5. HPT training script saved: hpt_train.py")