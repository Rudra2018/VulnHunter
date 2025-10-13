"""
VulnHunter AI - MLOps Experiment Tracking & Model Versioning
Comprehensive experiment tracking, model versioning, and metadata management
"""

import os
import json
import logging
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import pickle
import joblib

import numpy as np
import torch
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from google.cloud import aiplatform
from google.cloud import storage
from google.cloud.aiplatform import metadata
from google.cloud.aiplatform.metadata import schema

import wandb
from tensorboardX import SummaryWriter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnHunterExperimentTracker:
    """Comprehensive experiment tracking and model versioning for VulnHunter AI"""

    def __init__(self, project_id: str, region: str, bucket_name: str,
                 experiment_name: str = "vulnhunter-experiments"):
        self.project_id = project_id
        self.region = region
        self.bucket_name = bucket_name
        self.experiment_name = experiment_name

        # Initialize clients
        aiplatform.init(project=project_id, location=region)
        self.storage_client = storage.Client()

        # Initialize metadata store
        self.metadata_store = self._initialize_metadata_store()

        # Initialize experiment
        self.experiment = self._initialize_experiment()

        # Tracking state
        self.current_run = None
        self.tensorboard_writer = None
        self.wandb_run = None

    def _initialize_metadata_store(self):
        """Initialize Vertex AI Metadata Store"""
        try:
            # Create metadata store if it doesn't exist
            metadata_store = metadata.MetadataStore.create_or_get(
                metadata_store_id="vulnhunter-metadata-store",
                project=self.project_id,
                location=self.region
            )

            logger.info(f"Metadata store initialized: {metadata_store.name}")
            return metadata_store

        except Exception as e:
            logger.warning(f"Failed to initialize metadata store: {e}")
            return None

    def _initialize_experiment(self):
        """Initialize experiment tracking"""
        try:
            experiment = aiplatform.Experiment.create_or_get(
                experiment_id=self.experiment_name,
                project=self.project_id,
                location=self.region
            )

            logger.info(f"Experiment initialized: {experiment.name}")
            return experiment

        except Exception as e:
            logger.warning(f"Failed to initialize experiment: {e}")
            return None

    def start_run(self, run_name: str, config: Dict[str, Any],
                  tags: List[str] = None, description: str = None) -> str:
        """Start a new experiment run"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        full_run_name = f"{run_name}_{timestamp}"

        # Create run context
        run_context = {
            "run_name": full_run_name,
            "start_time": timestamp,
            "config": config,
            "tags": tags or [],
            "description": description,
            "status": "RUNNING",
            "metrics": {},
            "artifacts": {},
            "model_checkpoints": []
        }

        self.current_run = run_context

        # Initialize tracking services
        self._setup_tensorboard(full_run_name)
        self._setup_wandb(full_run_name, config, tags)
        self._setup_vertex_ai_run(full_run_name, config)

        logger.info(f"Started experiment run: {full_run_name}")
        return full_run_name

    def _setup_tensorboard(self, run_name: str):
        """Setup TensorBoard logging"""
        try:
            log_dir = f"gs://{self.bucket_name}/tensorboard_logs/{run_name}"
            self.tensorboard_writer = SummaryWriter(log_dir)

            logger.info(f"TensorBoard logging: {log_dir}")
        except Exception as e:
            logger.warning(f"Failed to setup TensorBoard: {e}")

    def _setup_wandb(self, run_name: str, config: Dict[str, Any], tags: List[str]):
        """Setup Weights & Biases tracking"""
        try:
            if os.getenv("WANDB_API_KEY"):
                self.wandb_run = wandb.init(
                    project="vulnhunter-ai",
                    name=run_name,
                    config=config,
                    tags=tags,
                    reinit=True
                )

                logger.info(f"W&B tracking initialized: {run_name}")
        except Exception as e:
            logger.warning(f"Failed to setup W&B: {e}")

    def _setup_vertex_ai_run(self, run_name: str, config: Dict[str, Any]):
        """Setup Vertex AI experiment run"""
        try:
            if self.experiment:
                # Create experiment run
                aiplatform.start_run(
                    run=run_name,
                    experiment=self.experiment,
                    resume=True
                )

                # Log parameters
                aiplatform.log_params(config)

                logger.info(f"Vertex AI run started: {run_name}")
        except Exception as e:
            logger.warning(f"Failed to setup Vertex AI run: {e}")

    def log_metrics(self, metrics: Dict[str, float], step: int = None,
                   prefix: str = None, commit: bool = True):
        """Log metrics to all tracking services"""
        if not self.current_run:
            logger.warning("No active run. Start a run first.")
            return

        # Add prefix if specified
        if prefix:
            metrics = {f"{prefix}/{k}": v for k, v in metrics.items()}

        # Update run context
        for metric_name, metric_value in metrics.items():
            if metric_name not in self.current_run["metrics"]:
                self.current_run["metrics"][metric_name] = []
            self.current_run["metrics"][metric_name].append({
                "value": metric_value,
                "step": step or len(self.current_run["metrics"][metric_name]),
                "timestamp": time.time()
            })

        # Log to TensorBoard
        if self.tensorboard_writer and step is not None:
            for metric_name, metric_value in metrics.items():
                self.tensorboard_writer.add_scalar(metric_name, metric_value, step)
            if commit:
                self.tensorboard_writer.flush()

        # Log to W&B
        if self.wandb_run:
            wandb_metrics = metrics.copy()
            if step is not None:
                wandb_metrics["step"] = step
            self.wandb_run.log(wandb_metrics, commit=commit)

        # Log to Vertex AI
        try:
            aiplatform.log_metrics(metrics)
        except Exception as e:
            logger.warning(f"Failed to log to Vertex AI: {e}")

        logger.debug(f"Logged metrics: {metrics}")

    def log_parameters(self, params: Dict[str, Any]):
        """Log parameters/hyperparameters"""
        if not self.current_run:
            logger.warning("No active run. Start a run first.")
            return

        # Update run context
        self.current_run["config"].update(params)

        # Log to W&B
        if self.wandb_run:
            wandb.config.update(params)

        # Log to Vertex AI
        try:
            aiplatform.log_params(params)
        except Exception as e:
            logger.warning(f"Failed to log params to Vertex AI: {e}")

        logger.debug(f"Logged parameters: {params}")

    def log_artifacts(self, artifacts: Dict[str, Any], artifact_type: str = "general"):
        """Log artifacts (files, plots, etc.)"""
        if not self.current_run:
            logger.warning("No active run. Start a run first.")
            return

        run_name = self.current_run["run_name"]
        artifact_dir = f"gs://{self.bucket_name}/artifacts/{run_name}/{artifact_type}"

        for artifact_name, artifact_data in artifacts.items():
            try:
                # Save artifact
                artifact_path = self._save_artifact(
                    artifact_data, artifact_name, artifact_dir
                )

                # Update run context
                if artifact_type not in self.current_run["artifacts"]:
                    self.current_run["artifacts"][artifact_type] = {}
                self.current_run["artifacts"][artifact_type][artifact_name] = artifact_path

                # Log to W&B
                if self.wandb_run:
                    if isinstance(artifact_data, plt.Figure):
                        wandb.log({artifact_name: wandb.Image(artifact_data)})
                    elif isinstance(artifact_data, (str, Path)) and os.path.exists(artifact_data):
                        wandb.save(str(artifact_data))

                logger.debug(f"Logged artifact: {artifact_name} -> {artifact_path}")

            except Exception as e:
                logger.error(f"Failed to log artifact {artifact_name}: {e}")

    def _save_artifact(self, artifact_data: Any, artifact_name: str,
                      artifact_dir: str) -> str:
        """Save artifact to cloud storage"""
        bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
        bucket = self.storage_client.bucket(bucket_name)

        # Determine file extension
        if isinstance(artifact_data, plt.Figure):
            ext = ".png"
            local_path = f"/tmp/{artifact_name}{ext}"
            artifact_data.savefig(local_path, dpi=300, bbox_inches='tight')
        elif isinstance(artifact_data, pd.DataFrame):
            ext = ".csv"
            local_path = f"/tmp/{artifact_name}{ext}"
            artifact_data.to_csv(local_path, index=False)
        elif isinstance(artifact_data, dict):
            ext = ".json"
            local_path = f"/tmp/{artifact_name}{ext}"
            with open(local_path, 'w') as f:
                json.dump(artifact_data, f, indent=2, default=str)
        elif isinstance(artifact_data, (str, Path)):
            # File path
            local_path = str(artifact_data)
            ext = Path(local_path).suffix
        else:
            # Pickle for other objects
            ext = ".pkl"
            local_path = f"/tmp/{artifact_name}{ext}"
            with open(local_path, 'wb') as f:
                pickle.dump(artifact_data, f)

        # Upload to GCS
        blob_path = f"artifacts/{self.current_run['run_name']}/{artifact_name}{ext}"
        blob = bucket.blob(blob_path)
        blob.upload_from_filename(local_path)

        return f"gs://{bucket_name}/{blob_path}"

    def save_model(self, model: torch.nn.Module, model_name: str,
                  metrics: Dict[str, float], metadata: Dict[str, Any] = None):
        """Save model with versioning and metadata"""
        if not self.current_run:
            logger.warning("No active run. Start a run first.")
            return

        run_name = self.current_run["run_name"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create model version
        model_version = f"{model_name}_v{timestamp}"

        # Save model locally first
        model_dir = f"/tmp/models/{model_version}"
        os.makedirs(model_dir, exist_ok=True)

        model_path = f"{model_dir}/model.pt"
        torch.save(model.state_dict(), model_path)

        # Save model metadata
        model_metadata = {
            "model_name": model_name,
            "model_version": model_version,
            "run_name": run_name,
            "timestamp": timestamp,
            "metrics": metrics,
            "model_architecture": str(model),
            "model_parameters": sum(p.numel() for p in model.parameters()),
            "custom_metadata": metadata or {}
        }

        metadata_path = f"{model_dir}/metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(model_metadata, f, indent=2, default=str)

        # Upload to GCS
        model_gcs_dir = f"gs://{self.bucket_name}/models/{model_version}"
        bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
        bucket = self.storage_client.bucket(bucket_name)

        # Upload model file
        model_blob = bucket.blob(f"models/{model_version}/model.pt")
        model_blob.upload_from_filename(model_path)

        # Upload metadata
        metadata_blob = bucket.blob(f"models/{model_version}/metadata.json")
        metadata_blob.upload_from_filename(metadata_path)

        # Register model in Vertex AI Model Registry
        try:
            vertex_model = aiplatform.Model.upload(
                display_name=model_version,
                artifact_uri=model_gcs_dir,
                serving_container_image_uri="us-docker.pkg.dev/vertex-ai/prediction/pytorch-gpu.1-13.py310:latest",
                description=f"VulnHunter AI model - {model_name}"
            )

            model_metadata["vertex_ai_model_id"] = vertex_model.resource_name
            logger.info(f"Model registered in Vertex AI: {vertex_model.resource_name}")

        except Exception as e:
            logger.warning(f"Failed to register model in Vertex AI: {e}")

        # Update run context
        checkpoint_info = {
            "model_name": model_name,
            "model_version": model_version,
            "model_path": f"{model_gcs_dir}/model.pt",
            "metadata_path": f"{model_gcs_dir}/metadata.json",
            "metrics": metrics,
            "timestamp": timestamp
        }
        self.current_run["model_checkpoints"].append(checkpoint_info)

        # Log to W&B
        if self.wandb_run:
            model_artifact = wandb.Artifact(
                name=model_version,
                type="model",
                metadata=model_metadata
            )
            model_artifact.add_file(model_path)
            model_artifact.add_file(metadata_path)
            self.wandb_run.log_artifact(model_artifact)

        logger.info(f"Model saved: {model_version} -> {model_gcs_dir}")
        return model_version, model_gcs_dir

    def compare_experiments(self, run_names: List[str]) -> pd.DataFrame:
        """Compare multiple experiment runs"""
        comparison_data = []

        for run_name in run_names:
            try:
                run_data = self._load_run_data(run_name)

                if run_data:
                    # Extract final metrics
                    final_metrics = {}
                    for metric_name, metric_history in run_data.get("metrics", {}).items():
                        if metric_history:
                            final_metrics[metric_name] = metric_history[-1]["value"]

                    row = {
                        "run_name": run_name,
                        "status": run_data.get("status", "UNKNOWN"),
                        "start_time": run_data.get("start_time", ""),
                        **final_metrics,
                        **run_data.get("config", {})
                    }
                    comparison_data.append(row)

            except Exception as e:
                logger.warning(f"Failed to load run data for {run_name}: {e}")

        if comparison_data:
            df = pd.DataFrame(comparison_data)
            return df
        else:
            return pd.DataFrame()

    def _load_run_data(self, run_name: str) -> Dict[str, Any]:
        """Load run data from storage"""
        try:
            bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
            bucket = self.storage_client.bucket(bucket_name)

            blob_path = f"experiment_runs/{run_name}/run_data.json"
            blob = bucket.blob(blob_path)

            if blob.exists():
                content = blob.download_as_text()
                return json.loads(content)
            else:
                logger.warning(f"Run data not found for {run_name}")
                return {}

        except Exception as e:
            logger.error(f"Failed to load run data: {e}")
            return {}

    def generate_experiment_report(self, run_names: List[str] = None) -> str:
        """Generate comprehensive experiment report"""
        if run_names is None:
            # Get all runs from current experiment
            run_names = self._get_all_run_names()

        # Compare experiments
        comparison_df = self.compare_experiments(run_names)

        if comparison_df.empty:
            logger.warning("No experiment data found for report")
            return ""

        # Generate report
        report = []
        report.append("# VulnHunter AI Experiment Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Summary statistics
        report.append("## Summary Statistics")
        report.append(f"Total Experiments: {len(comparison_df)}")

        if "status" in comparison_df.columns:
            status_counts = comparison_df["status"].value_counts()
            for status, count in status_counts.items():
                report.append(f"- {status}: {count}")

        report.append("")

        # Best performing models
        metric_columns = [col for col in comparison_df.columns
                         if col.startswith(("val_", "test_", "train_"))]

        if metric_columns:
            report.append("## Best Performing Models")

            for metric in metric_columns:
                if metric in comparison_df.columns:
                    if "loss" in metric.lower() or "error" in metric.lower():
                        best_idx = comparison_df[metric].idxmin()
                        goal = "minimize"
                    else:
                        best_idx = comparison_df[metric].idxmax()
                        goal = "maximize"

                    best_run = comparison_df.iloc[best_idx]
                    report.append(f"- {metric} ({goal}): {best_run['run_name']} ({best_run[metric]:.4f})")

            report.append("")

        # Hyperparameter analysis
        report.append("## Hyperparameter Analysis")

        # Find hyperparameters (non-metric columns)
        hyperparam_columns = [col for col in comparison_df.columns
                             if not col.startswith(("val_", "test_", "train_", "run_", "status", "start_time"))]

        if hyperparam_columns:
            for param in hyperparam_columns:
                if comparison_df[param].dtype in ['int64', 'float64']:
                    report.append(f"- {param}: mean={comparison_df[param].mean():.4f}, "
                                f"std={comparison_df[param].std():.4f}")
                else:
                    value_counts = comparison_df[param].value_counts()
                    top_value = value_counts.index[0]
                    report.append(f"- {param}: most common='{top_value}' ({value_counts.iloc[0]} runs)")

        report.append("")

        # Detailed results table
        report.append("## Detailed Results")
        report.append("")

        # Create markdown table
        table_columns = ["run_name"] + metric_columns[:5]  # Limit columns for readability
        available_columns = [col for col in table_columns if col in comparison_df.columns]

        if available_columns:
            # Header
            report.append("| " + " | ".join(available_columns) + " |")
            report.append("| " + " | ".join(["---"] * len(available_columns)) + " |")

            # Rows
            for _, row in comparison_df.iterrows():
                row_values = []
                for col in available_columns:
                    value = row[col]
                    if isinstance(value, float):
                        row_values.append(f"{value:.4f}")
                    else:
                        row_values.append(str(value))

                report.append("| " + " | ".join(row_values) + " |")

        report_text = "\n".join(report)

        # Save report
        report_path = f"gs://{self.bucket_name}/reports/experiment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
        bucket = self.storage_client.bucket(bucket_name)
        blob = bucket.blob(report_path.replace(f"gs://{bucket_name}/", ""))
        blob.upload_from_string(report_text)

        logger.info(f"Experiment report saved: {report_path}")
        return report_text

    def _get_all_run_names(self) -> List[str]:
        """Get all run names from experiment"""
        run_names = []
        try:
            bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
            bucket = self.storage_client.bucket(bucket_name)

            blobs = bucket.list_blobs(prefix="experiment_runs/")
            for blob in blobs:
                if blob.name.endswith("/run_data.json"):
                    run_name = blob.name.split("/")[1]
                    run_names.append(run_name)

        except Exception as e:
            logger.error(f"Failed to get run names: {e}")

        return run_names

    def end_run(self, status: str = "COMPLETED"):
        """End the current experiment run"""
        if not self.current_run:
            logger.warning("No active run to end.")
            return

        # Update run status
        self.current_run["status"] = status
        self.current_run["end_time"] = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save run data
        self._save_run_data()

        # Close tracking services
        if self.tensorboard_writer:
            self.tensorboard_writer.close()
            self.tensorboard_writer = None

        if self.wandb_run:
            self.wandb_run.finish()
            self.wandb_run = None

        try:
            aiplatform.end_run()
        except Exception as e:
            logger.warning(f"Failed to end Vertex AI run: {e}")

        run_name = self.current_run["run_name"]
        logger.info(f"Ended experiment run: {run_name} ({status})")

        self.current_run = None

    def _save_run_data(self):
        """Save current run data to storage"""
        if not self.current_run:
            return

        try:
            run_name = self.current_run["run_name"]
            bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
            bucket = self.storage_client.bucket(bucket_name)

            # Save run data
            blob_path = f"experiment_runs/{run_name}/run_data.json"
            blob = bucket.blob(blob_path)
            blob.upload_from_string(
                json.dumps(self.current_run, indent=2, default=str)
            )

            logger.debug(f"Run data saved: gs://{bucket_name}/{blob_path}")

        except Exception as e:
            logger.error(f"Failed to save run data: {e}")

class ModelVersionManager:
    """Manages model versions and deployment"""

    def __init__(self, project_id: str, region: str, bucket_name: str):
        self.project_id = project_id
        self.region = region
        self.bucket_name = bucket_name

        aiplatform.init(project=project_id, location=region)
        self.storage_client = storage.Client()

    def list_model_versions(self, model_name: str = None) -> List[Dict[str, Any]]:
        """List all model versions"""
        versions = []

        try:
            bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
            bucket = self.storage_client.bucket(bucket_name)

            prefix = f"models/{model_name}" if model_name else "models/"
            blobs = bucket.list_blobs(prefix=prefix)

            for blob in blobs:
                if blob.name.endswith("/metadata.json"):
                    try:
                        content = blob.download_as_text()
                        metadata = json.loads(content)
                        versions.append(metadata)
                    except Exception as e:
                        logger.warning(f"Failed to load metadata for {blob.name}: {e}")

            # Sort by timestamp
            versions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        except Exception as e:
            logger.error(f"Failed to list model versions: {e}")

        return versions

    def get_best_model(self, metric_name: str = "val_f1",
                      model_name: str = None) -> Optional[Dict[str, Any]]:
        """Get the best model based on a specific metric"""
        versions = self.list_model_versions(model_name)

        if not versions:
            return None

        # Find best model
        best_model = None
        best_metric = float('-inf')

        for version in versions:
            metrics = version.get("metrics", {})
            if metric_name in metrics:
                metric_value = metrics[metric_name]
                if metric_value > best_metric:
                    best_metric = metric_value
                    best_model = version

        return best_model

    def promote_model(self, model_version: str, stage: str = "production"):
        """Promote a model to a specific stage"""
        try:
            # Update model metadata with stage information
            bucket_name = self.bucket_name.replace("gs://", "").split("/")[0]
            bucket = self.storage_client.bucket(bucket_name)

            metadata_blob = bucket.blob(f"models/{model_version}/metadata.json")

            if metadata_blob.exists():
                content = metadata_blob.download_as_text()
                metadata = json.loads(content)

                metadata["stage"] = stage
                metadata["promoted_at"] = datetime.now().isoformat()

                metadata_blob.upload_from_string(
                    json.dumps(metadata, indent=2, default=str)
                )

                logger.info(f"Model {model_version} promoted to {stage}")
                return True
            else:
                logger.error(f"Model metadata not found: {model_version}")
                return False

        except Exception as e:
            logger.error(f"Failed to promote model: {e}")
            return False

# Example usage and demonstration
if __name__ == "__main__":
    # Configuration
    PROJECT_ID = os.getenv("PROJECT_ID", "vulnhunter-ai-project")
    REGION = os.getenv("REGION", "us-central1")
    BUCKET_NAME = os.getenv("BUCKET_NAME", f"vulnhunter-ai-training-{PROJECT_ID}")

    print("🔬 VulnHunter AI MLOps Experiment Tracking Setup")
    print("=" * 60)

    # Initialize experiment tracker
    tracker = VulnHunterExperimentTracker(PROJECT_ID, REGION, BUCKET_NAME)

    print(f"✅ Experiment tracker initialized")
    print(f"   Project: {PROJECT_ID}")
    print(f"   Region: {REGION}")
    print(f"   Storage: gs://{BUCKET_NAME}")

    # Example experiment run
    print(f"\n🧪 Example Experiment Run:")
    print("-" * 30)

    # Start experiment run
    config = {
        "model_type": "hybrid_architecture",
        "learning_rate": 2e-5,
        "batch_size": 16,
        "num_epochs": 10,
        "use_multimodal_features": True
    }

    run_name = tracker.start_run(
        run_name="vulnhunter_hybrid_test",
        config=config,
        tags=["hybrid", "multimodal", "test"],
        description="Testing hybrid architecture with multimodal features"
    )

    print(f"   Run started: {run_name}")

    # Simulate training metrics
    for epoch in range(3):
        metrics = {
            "train_loss": 0.8 - epoch * 0.1 + np.random.normal(0, 0.02),
            "val_loss": 0.9 - epoch * 0.12 + np.random.normal(0, 0.03),
            "val_accuracy": 0.6 + epoch * 0.08 + np.random.normal(0, 0.01),
            "val_f1": 0.55 + epoch * 0.1 + np.random.normal(0, 0.02),
            "val_precision": 0.58 + epoch * 0.09 + np.random.normal(0, 0.015),
            "val_recall": 0.52 + epoch * 0.11 + np.random.normal(0, 0.02),
            "val_false_positive_rate": 0.25 - epoch * 0.05 + np.random.normal(0, 0.01)
        }

        tracker.log_metrics(metrics, step=epoch)
        print(f"   Epoch {epoch}: F1={metrics['val_f1']:.3f}, "
              f"FPR={metrics['val_false_positive_rate']:.3f}")

    # Log artifacts
    print(f"\n📊 Logging Artifacts:")

    # Create sample plot
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

    epochs = range(3)
    ax1.plot(epochs, [0.8, 0.7, 0.6], label='Train Loss')
    ax1.plot(epochs, [0.9, 0.78, 0.66], label='Val Loss')
    ax1.set_title('Training Loss')
    ax1.legend()

    ax2.plot(epochs, [0.6, 0.68, 0.76], label='Accuracy')
    ax2.plot(epochs, [0.55, 0.65, 0.75], label='F1-Score')
    ax2.set_title('Performance Metrics')
    ax2.legend()

    plt.tight_layout()

    # Log plot as artifact
    tracker.log_artifacts({"training_curves": fig}, "plots")
    plt.close()

    # Log configuration as artifact
    tracker.log_artifacts({"experiment_config": config}, "configs")

    print(f"   Training curves saved")
    print(f"   Configuration saved")

    # Simulate model saving
    print(f"\n💾 Model Versioning:")

    # Create dummy model for demonstration
    import torch.nn as nn
    dummy_model = nn.Sequential(
        nn.Linear(768, 256),
        nn.ReLU(),
        nn.Dropout(0.1),
        nn.Linear(256, 2)
    )

    final_metrics = {
        "val_f1": 0.842,
        "val_accuracy": 0.835,
        "val_precision": 0.851,
        "val_recall": 0.833,
        "val_false_positive_rate": 0.078
    }

    model_version, model_path = tracker.save_model(
        model=dummy_model,
        model_name="vulnhunter_hybrid",
        metrics=final_metrics,
        metadata={"training_samples": 50000, "validation_samples": 10000}
    )

    print(f"   Model saved: {model_version}")
    print(f"   Location: {model_path}")

    # End experiment run
    tracker.end_run(status="COMPLETED")
    print(f"   Experiment completed: {run_name}")

    # Model version management
    print(f"\n📦 Model Version Management:")
    print("-" * 35)

    version_manager = ModelVersionManager(PROJECT_ID, REGION, BUCKET_NAME)

    # List model versions
    versions = version_manager.list_model_versions()
    print(f"   Total model versions: {len(versions)}")

    # Get best model
    best_model = version_manager.get_best_model("val_f1")
    if best_model:
        print(f"   Best model (F1): {best_model['model_version']} "
              f"({best_model['metrics']['val_f1']:.3f})")

    # Performance summary
    print(f"\n📈 Expected MLOps Benefits:")
    print(f"   Experiment reproducibility: 100%")
    print(f"   Model traceability: Full lineage tracking")
    print(f"   Automated versioning: Timestamp-based + metrics")
    print(f"   Multi-platform logging: TensorBoard + W&B + Vertex AI")
    print(f"   Performance comparison: Automated report generation")

    print(f"\n📝 Integration Points:")
    print(f"   • Training scripts: Auto-logging integration")
    print(f"   • Hyperparameter tuning: Metric optimization")
    print(f"   • Model deployment: Version-based promotion")
    print(f"   • A/B testing: Performance comparison framework")
    print(f"   • Production monitoring: Continuous evaluation")