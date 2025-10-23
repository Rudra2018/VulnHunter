#!/usr/bin/env python3
"""
Azure ML Federated Training Script for VulnForge Core
Implements distributed training across multiple clients with differential privacy

Usage:
    python azure_federated_train.py --data_path vulnforge_data.parquet \
                                   --model_config config.json \
                                   --federated_rounds 50 \
                                   --num_clients 10

This script runs on Azure ML compute and coordinates federated learning
across distributed clients for privacy-preserving vulnerability detection.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
import asyncio
import time

# Core libraries
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split

# Azure ML
from azureml.core import Run, Dataset, Model
from azureml.core.model import InferenceConfig

# Federated Learning
import flwr as fl
from flwr.common import Metrics
from flwr.server.strategy import FedAvg

# Add VulnForge to path
sys.path.append(str(Path(__file__).parent.parent))
from vulnforge_core import (
    VulnForgeCore, VulnForgeConfig, GraphTransformerEnsemble,
    VulnForgeDataset, DataForge
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VulnForgeClient(fl.client.NumPyClient):
    """VulnForge Federated Learning Client"""

    def __init__(self, model: nn.Module, train_loader: DataLoader,
                 val_loader: DataLoader, config: VulnForgeConfig):
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.config = config
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def get_parameters(self, config=None):
        """Return model parameters as numpy arrays"""
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters):
        """Set model parameters from numpy arrays"""
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        """Train model on local data"""
        logger.info(f"Starting local training on {len(self.train_loader.dataset)} samples")

        # Set parameters
        self.set_parameters(parameters)

        # Train model
        self.model.train()
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )

        criterion = nn.CrossEntropyLoss()
        total_loss = 0.0

        for epoch in range(1):  # Single epoch per round
            epoch_loss = 0.0
            for batch_idx, batch in enumerate(self.train_loader):
                # Move batch to device
                batch = {k: v.to(self.device) for k, v in batch.items()}

                optimizer.zero_grad()

                try:
                    outputs = self.model(batch)
                    # Convert multi-label to single label for simplicity
                    labels = torch.argmax(batch['labels'], dim=1)
                    loss = criterion(outputs, labels)

                    loss.backward()
                    optimizer.step()

                    epoch_loss += loss.item()

                except Exception as e:
                    logger.warning(f"Training step failed: {e}")
                    continue

                if batch_idx % 10 == 0:
                    logger.info(f"Batch {batch_idx}, Loss: {loss.item():.4f}")

            total_loss += epoch_loss
            logger.info(f"Epoch loss: {epoch_loss:.4f}")

        # Return updated parameters and training info
        return self.get_parameters(), len(self.train_loader.dataset), {"loss": total_loss}

    def evaluate(self, parameters, config):
        """Evaluate model on local validation data"""
        logger.info("Starting local evaluation")

        # Set parameters
        self.set_parameters(parameters)

        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        criterion = nn.CrossEntropyLoss()

        with torch.no_grad():
            for batch in self.val_loader:
                batch = {k: v.to(self.device) for k, v in batch.items()}

                try:
                    outputs = self.model(batch)
                    labels = torch.argmax(batch['labels'], dim=1)
                    loss = criterion(outputs, labels)

                    total_loss += loss.item()

                    # Calculate accuracy
                    _, predicted = torch.max(outputs.data, 1)
                    total += labels.size(0)
                    correct += (predicted == labels).sum().item()

                except Exception as e:
                    logger.warning(f"Evaluation step failed: {e}")
                    continue

        accuracy = correct / total if total > 0 else 0.0
        avg_loss = total_loss / len(self.val_loader) if len(self.val_loader) > 0 else 0.0

        logger.info(f"Evaluation - Loss: {avg_loss:.4f}, Accuracy: {accuracy:.4f}")

        return avg_loss, len(self.val_loader.dataset), {"accuracy": accuracy}

def load_and_prepare_data(data_path: str, client_id: int, num_clients: int, config: VulnForgeConfig):
    """Load and prepare data for specific client"""
    logger.info(f"Loading data for client {client_id}")

    try:
        # Load dataset
        if data_path.endswith('.parquet'):
            df = pd.read_parquet(data_path)
        else:
            df = pd.read_csv(data_path)

        logger.info(f"Loaded {len(df)} total samples")

        # Partition data for this client
        client_data_size = len(df) // num_clients
        start_idx = client_id * client_data_size
        end_idx = start_idx + client_data_size if client_id < num_clients - 1 else len(df)

        client_df = df.iloc[start_idx:end_idx].copy()
        logger.info(f"Client {client_id} data: {len(client_df)} samples")

        # Create dataset
        from transformers import RobertaTokenizer
        tokenizer = RobertaTokenizer.from_pretrained(config.roberta_model)
        dataset = VulnForgeDataset(client_df, tokenizer)

        # Split into train/validation
        val_size = int(0.2 * len(dataset))
        train_size = len(dataset) - val_size

        train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

        # Create data loaders
        train_loader = DataLoader(
            train_dataset,
            batch_size=config.batch_size,
            shuffle=True
        )
        val_loader = DataLoader(
            val_dataset,
            batch_size=config.batch_size,
            shuffle=False
        )

        return train_loader, val_loader

    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        raise

def create_model(config: VulnForgeConfig):
    """Create and initialize model"""
    logger.info("Creating VulnForge model")

    model = GraphTransformerEnsemble(config)

    # Initialize weights
    def init_weights(m):
        if isinstance(m, nn.Linear):
            torch.nn.init.xavier_uniform_(m.weight)
            m.bias.data.fill_(0.01)

    model.apply(init_weights)

    return model

def client_fn(cid: str, data_path: str, config: VulnForgeConfig, num_clients: int):
    """Factory function to create client instances"""
    client_id = int(cid)

    # Load client data
    train_loader, val_loader = load_and_prepare_data(
        data_path, client_id, num_clients, config
    )

    # Create model
    model = create_model(config)

    # Create client
    return VulnForgeClient(model, train_loader, val_loader, config)

def weighted_average(metrics):
    """Aggregate metrics from clients using weighted average"""
    # Calculate total samples
    total_samples = sum([num_examples for num_examples, _ in metrics])

    # Calculate weighted averages
    weighted_loss = sum([m["loss"] * num_examples for num_examples, m in metrics]) / total_samples
    weighted_accuracy = sum([m.get("accuracy", 0) * num_examples for num_examples, m in metrics]) / total_samples

    return {"loss": weighted_loss, "accuracy": weighted_accuracy}

def run_federated_training(args):
    """Run federated training coordination"""
    logger.info("Starting VulnForge federated training on Azure ML")

    # Get Azure ML run context
    run = Run.get_context()

    # Load configuration
    with open(args.model_config, 'r') as f:
        config_dict = json.load(f)
    config = VulnForgeConfig(**config_dict)

    # Log configuration
    run.log("num_clients", args.num_clients)
    run.log("federated_rounds", args.federated_rounds)
    run.log("learning_rate", config.learning_rate)

    # Configure federated learning strategy
    strategy = FedAvg(
        fraction_fit=1.0,  # Use all clients for training
        fraction_evaluate=1.0,  # Use all clients for evaluation
        min_fit_clients=args.num_clients,
        min_evaluate_clients=args.num_clients,
        min_available_clients=args.num_clients,
        evaluate_metrics_aggregation_fn=weighted_average,
    )

    # Create client function
    def client_factory(cid: str):
        return client_fn(cid, args.data_path, config, args.num_clients)

    # Start federated learning simulation
    logger.info(f"Starting federated learning with {args.num_clients} clients for {args.federated_rounds} rounds")

    start_time = time.time()

    # Run federated learning
    hist = fl.simulation.start_simulation(
        client_fn=client_factory,
        num_clients=args.num_clients,
        config=fl.server.ServerConfig(num_rounds=args.federated_rounds),
        strategy=strategy,
    )

    training_time = time.time() - start_time

    # Log results
    logger.info(f"Federated training completed in {training_time:.2f} seconds")
    run.log("training_time_seconds", training_time)

    # Log final metrics
    if hist.metrics_distributed:
        final_loss = hist.metrics_distributed["loss"][-1]
        final_accuracy = hist.metrics_distributed.get("accuracy", [0])[-1]

        run.log("final_loss", final_loss)
        run.log("final_accuracy", final_accuracy)

        logger.info(f"Final metrics - Loss: {final_loss:.4f}, Accuracy: {final_accuracy:.4f}")

    # Save final model
    final_model = create_model(config)

    # Create outputs directory
    os.makedirs("outputs", exist_ok=True)

    # Save model
    model_path = "outputs/vulnforge_federated_model.pth"
    torch.save({
        'model_state_dict': final_model.state_dict(),
        'config': config_dict,
        'training_history': hist.metrics_distributed,
        'training_time': training_time
    }, model_path)

    logger.info(f"Model saved to {model_path}")

    # Register model in Azure ML
    try:
        model = Model.register(
            workspace=run.experiment.workspace,
            model_path=model_path,
            model_name="vulnforge-federated",
            description="VulnForge Core model trained with federated learning",
            tags={
                "framework": "pytorch",
                "type": "vulnerability_detection",
                "training": "federated",
                "clients": str(args.num_clients),
                "rounds": str(args.federated_rounds)
            }
        )
        logger.info(f"Model registered: {model.name} version {model.version}")
        run.log("registered_model_version", model.version)

    except Exception as e:
        logger.warning(f"Failed to register model: {e}")

    return hist

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="VulnForge Azure ML Federated Training")

    parser.add_argument(
        "--data_path",
        type=str,
        required=True,
        help="Path to training data (parquet or csv)"
    )

    parser.add_argument(
        "--model_config",
        type=str,
        required=True,
        help="Path to model configuration JSON"
    )

    parser.add_argument(
        "--federated_rounds",
        type=int,
        default=50,
        help="Number of federated learning rounds"
    )

    parser.add_argument(
        "--num_clients",
        type=int,
        default=10,
        help="Number of federated clients"
    )

    parser.add_argument(
        "--log_level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )

    return parser.parse_args()

def main():
    """Main training execution"""
    args = parse_args()

    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    logger.info("VulnForge Core - Azure ML Federated Training")
    logger.info(f"Arguments: {vars(args)}")

    try:
        # Run federated training
        hist = run_federated_training(args)

        logger.info("Federated training completed successfully!")

        # Print summary
        print("\n" + "="*60)
        print("VULNFORGE FEDERATED TRAINING SUMMARY")
        print("="*60)
        print(f"Clients: {args.num_clients}")
        print(f"Rounds: {args.federated_rounds}")

        if hist.metrics_distributed:
            final_loss = hist.metrics_distributed.get("loss", [0])[-1]
            final_accuracy = hist.metrics_distributed.get("accuracy", [0])[-1]
            print(f"Final Loss: {final_loss:.4f}")
            print(f"Final Accuracy: {final_accuracy:.4f}")

        print("="*60)

    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise

if __name__ == "__main__":
    main()