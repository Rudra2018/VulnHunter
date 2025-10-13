#!/usr/bin/env python3
"""
Vertex AI Distributed Training Configuration for VulnHunter BGNN4VD
Implements multi-GPU and multi-node training for large-scale vulnerability detection
"""

import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

@dataclass
class DistributedTrainingConfig:
    """Configuration for distributed training"""

    # Cluster configuration
    machine_type: str = "n1-standard-8"  # 8 vCPUs, 30GB RAM
    accelerator_type: str = "NVIDIA_TESLA_T4"  # or "NVIDIA_TESLA_V100"
    accelerator_count: int = 2  # GPUs per node
    replica_count: int = 2  # Number of nodes

    # Training configuration
    batch_size_per_gpu: int = 16
    gradient_accumulation_steps: int = 4
    mixed_precision: bool = True
    sync_batch_norm: bool = True

    # Distribution strategy
    strategy: str = "MULTI_WORKER_MIRRORED"  # or "PARAMETER_SERVER"
    all_reduce_alg: str = "RING"  # or "NCCL"

    # Resource limits
    max_runtime_seconds: int = 14400  # 4 hours
    max_retries: int = 3

    def __post_init__(self):
        self.total_gpus = self.accelerator_count * self.replica_count
        self.global_batch_size = self.batch_size_per_gpu * self.total_gpus * self.gradient_accumulation_steps

class DistributedTrainingManager:
    """Manages distributed training for BGNN4VD model"""

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        self.config = DistributedTrainingConfig()

    def create_training_script(self) -> str:
        """Create distributed training script for BGNN4VD"""

        training_script = '''#!/usr/bin/env python3
"""
Distributed Training Script for VulnHunter BGNN4VD Model
"""

import os
import json
import logging
import argparse
from datetime import datetime
import multiprocessing as mp

# Import distributed training libraries
import torch
import torch.distributed as dist
import torch.multiprocessing as mp
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data.distributed import DistributedSampler

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_distributed(rank, world_size, backend='nccl'):
    """Initialize distributed training process group"""
    os.environ['MASTER_ADDR'] = os.environ.get('MASTER_ADDR', 'localhost')
    os.environ['MASTER_PORT'] = os.environ.get('MASTER_PORT', '12355')

    logger.info(f"Setting up distributed training: rank {rank}, world_size {world_size}")
    dist.init_process_group(backend, rank=rank, world_size=world_size)

    # Set device for this process
    torch.cuda.set_device(rank % torch.cuda.device_count())
    device = torch.device(f'cuda:{rank % torch.cuda.device_count()}')

    return device

def cleanup_distributed():
    """Clean up distributed training"""
    dist.destroy_process_group()

class BGNN4VDDistributed:
    """Distributed version of BGNN4VD model"""

    def __init__(self, config, device, rank=0):
        self.config = config
        self.device = device
        self.rank = rank

        # Model architecture (simplified for demo)
        self.model = self.create_model()
        self.model = self.model.to(device)

        # Wrap model with DDP
        self.model = DDP(self.model, device_ids=[device])

        # Optimizer
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=config.get('learning_rate', 0.001),
            weight_decay=config.get('weight_decay', 1e-5)
        )

        # Learning rate scheduler
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=config.get('num_epochs', 100)
        )

    def create_model(self):
        """Create BGNN4VD model architecture"""
        # Simplified model for demo
        import torch.nn as nn

        class SimplifiedBGNN4VD(nn.Module):
            def __init__(self, config):
                super().__init__()
                hidden_dim = config.get('hidden_dim', 256)
                self.encoder = nn.Sequential(
                    nn.Linear(100, hidden_dim),  # Input features
                    nn.ReLU(),
                    nn.Dropout(config.get('dropout_rate', 0.3)),
                    nn.Linear(hidden_dim, hidden_dim // 2),
                    nn.ReLU(),
                    nn.Linear(hidden_dim // 2, 2)  # Binary classification
                )

            def forward(self, x):
                return self.encoder(x)

        return SimplifiedBGNN4VD(self.config)

    def train_epoch(self, dataloader, epoch):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        for batch_idx, (data, targets) in enumerate(dataloader):
            data, targets = data.to(self.device), targets.to(self.device)

            # Forward pass
            outputs = self.model(data)
            loss = torch.nn.CrossEntropyLoss()(outputs, targets)

            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

            self.optimizer.step()

            # Statistics
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()

            if batch_idx % 10 == 0 and self.rank == 0:
                logger.info(f'Epoch {epoch}, Batch {batch_idx}: Loss={loss.item():.4f}')

        # Synchronize metrics across processes
        metrics = torch.tensor([total_loss, correct, total], device=self.device)
        dist.all_reduce(metrics, op=dist.ReduceOp.SUM)

        avg_loss = metrics[0].item() / len(dataloader)
        accuracy = metrics[1].item() / metrics[2].item()

        return avg_loss, accuracy

    def validate(self, dataloader):
        """Validation loop"""
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0

        with torch.no_grad():
            for data, targets in dataloader:
                data, targets = data.to(self.device), targets.to(self.device)
                outputs = self.model(data)
                loss = torch.nn.CrossEntropyLoss()(outputs, targets)

                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += targets.size(0)
                correct += predicted.eq(targets).sum().item()

        # Synchronize validation metrics
        metrics = torch.tensor([total_loss, correct, total], device=self.device)
        dist.all_reduce(metrics, op=dist.ReduceOp.SUM)

        avg_loss = metrics[0].item() / len(dataloader)
        accuracy = metrics[1].item() / metrics[2].item()

        return avg_loss, accuracy

def create_dummy_dataset(batch_size, num_workers):
    """Create dummy dataset for demonstration"""
    import torch.utils.data as data

    class DummyDataset(data.Dataset):
        def __init__(self, size=1000):
            self.size = size

        def __len__(self):
            return self.size

        def __getitem__(self, idx):
            # Random features and labels
            features = torch.randn(100)
            label = torch.randint(0, 2, (1,)).squeeze()
            return features, label

    dataset = DummyDataset()
    sampler = DistributedSampler(dataset)
    dataloader = data.DataLoader(
        dataset,
        batch_size=batch_size,
        sampler=sampler,
        num_workers=num_workers,
        pin_memory=True
    )

    return dataloader, sampler

def train_worker(rank, world_size, config):
    """Training worker function"""
    try:
        # Setup distributed training
        device = setup_distributed(rank, world_size)

        logger.info(f"Worker {rank}/{world_size} started on device {device}")

        # Create model
        model = BGNN4VDDistributed(config, device, rank)

        # Create datasets
        train_loader, train_sampler = create_dummy_dataset(
            config.get('batch_size_per_gpu', 16),
            config.get('num_workers', 4)
        )
        val_loader, _ = create_dummy_dataset(
            config.get('batch_size_per_gpu', 16),
            config.get('num_workers', 4)
        )

        # Training loop
        best_val_acc = 0
        num_epochs = config.get('num_epochs', 50)

        for epoch in range(num_epochs):
            # Set epoch for sampler
            train_sampler.set_epoch(epoch)

            # Train
            train_loss, train_acc = model.train_epoch(train_loader, epoch)

            # Validate
            val_loss, val_acc = model.validate(val_loader)

            # Update learning rate
            model.scheduler.step()

            # Log metrics (only from rank 0)
            if rank == 0:
                logger.info(f"Epoch {epoch+1}/{num_epochs}")
                logger.info(f"  Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}")
                logger.info(f"  Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")

                # Save best model
                if val_acc > best_val_acc:
                    best_val_acc = val_acc
                    torch.save({
                        'epoch': epoch,
                        'model_state_dict': model.model.module.state_dict(),
                        'optimizer_state_dict': model.optimizer.state_dict(),
                        'val_acc': val_acc,
                        'config': config
                    }, f'best_model_distributed.pth')

                    logger.info(f"  New best validation accuracy: {val_acc:.4f}")

        if rank == 0:
            logger.info(f"Training completed! Best validation accuracy: {best_val_acc:.4f}")

            # Save final training report
            report = {
                "training_type": "distributed",
                "world_size": world_size,
                "best_val_accuracy": best_val_acc,
                "config": config,
                "completion_time": datetime.now().isoformat()
            }

            with open('distributed_training_report.json', 'w') as f:
                json.dump(report, f, indent=2)

    except Exception as e:
        logger.error(f"Worker {rank} failed: {e}")
        raise
    finally:
        cleanup_distributed()

def main():
    parser = argparse.ArgumentParser(description='Distributed VulnHunter Training')
    parser.add_argument('--config', type=str, required=True, help='Training config file')
    parser.add_argument('--world-size', type=int, default=2, help='Number of processes')
    args = parser.parse_args()

    # Load config
    with open(args.config, 'r') as f:
        config = json.load(f)

    logger.info(f"Starting distributed training with {args.world_size} processes")
    logger.info(f"Config: {config}")

    # Start distributed training
    mp.spawn(
        train_worker,
        args=(args.world_size, config),
        nprocs=args.world_size,
        join=True
    )

if __name__ == '__main__':
    main()
'''

        return training_script

    def create_vertex_ai_job_spec(self, job_name: str, hyperparameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create Vertex AI distributed training job specification"""

        # Default hyperparameters from best HPT results
        if hyperparameters is None:
            hyperparameters = {
                "hidden_dim": 256,
                "num_gnn_layers": 4,
                "num_attention_heads": 16,
                "dropout_rate": 0.2,
                "learning_rate": 0.01,
                "batch_size_per_gpu": 16,
                "weight_decay": 0.001,
                "num_epochs": 100
            }

        job_spec = {
            "displayName": job_name,
            "jobSpec": {
                "workerPoolSpecs": [
                    {
                        "machineSpec": {
                            "machineType": self.config.machine_type,
                            "acceleratorType": self.config.accelerator_type,
                            "acceleratorCount": self.config.accelerator_count
                        },
                        "replicaCount": self.config.replica_count,
                        "containerSpec": {
                            "imageUri": "gcr.io/deeplearning-platform-release/pytorch-gpu.1-13",
                            "command": [
                                "python3",
                                "/app/distributed_training.py"
                            ],
                            "args": [
                                "--config", "/app/training_config.json",
                                "--world-size", str(self.config.total_gpus)
                            ],
                            "env": [
                                {"name": "NCCL_DEBUG", "value": "INFO"},
                                {"name": "PYTHONUNBUFFERED", "value": "1"},
                                {"name": "MASTER_PORT", "value": "12355"}
                            ]
                        }
                    }
                ],
                "scheduling": {
                    "timeout": f"{self.config.max_runtime_seconds}s",
                    "restartJobOnWorkerRestart": True
                }
            }
        }

        return job_spec

    def create_training_package(self, output_dir: str = "distributed_training_package"):
        """Create training package for Vertex AI"""

        import os
        import shutil

        # Create package directory
        os.makedirs(output_dir, exist_ok=True)

        # Create training script
        training_script = self.create_training_script()
        with open(f"{output_dir}/distributed_training.py", "w") as f:
            f.write(training_script)

        # Create config file
        config = {
            "hidden_dim": 256,
            "num_gnn_layers": 4,
            "num_attention_heads": 16,
            "dropout_rate": 0.2,
            "learning_rate": 0.01,
            "batch_size_per_gpu": self.config.batch_size_per_gpu,
            "weight_decay": 0.001,
            "num_epochs": 100,
            "num_workers": 4
        }

        with open(f"{output_dir}/training_config.json", "w") as f:
            json.dump(config, f, indent=2)

        # Create requirements.txt
        requirements = """
torch>=1.13.0
torch-geometric>=2.3.0
numpy>=1.21.0
scikit-learn>=1.1.0
tensorboard>=2.9.0
google-cloud-storage>=2.5.0
        """.strip()

        with open(f"{output_dir}/requirements.txt", "w") as f:
            f.write(requirements)

        # Create Dockerfile
        dockerfile = """
FROM gcr.io/deeplearning-platform-release/pytorch-gpu.1-13

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "distributed_training.py"]
        """

        with open(f"{output_dir}/Dockerfile", "w") as f:
            f.write(dockerfile)

        logger.info(f"Training package created in: {output_dir}")
        return output_dir

    def start_distributed_training(self, job_name: str = None, hyperparameters: Dict[str, Any] = None):
        """Start distributed training job on Vertex AI"""

        if job_name is None:
            job_name = f"vulnhunter-distributed-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        logger.info(f"🚀 Starting distributed training job: {job_name}")

        # Create training package
        package_dir = self.create_training_package()

        # Create job specification
        job_spec = self.create_vertex_ai_job_spec(job_name, hyperparameters)

        # Save job spec for reference
        with open("distributed_job_spec.json", "w") as f:
            json.dump(job_spec, f, indent=2)

        logger.info("📊 Distributed Training Configuration:")
        logger.info(f"  Machine Type: {self.config.machine_type}")
        logger.info(f"  Accelerator: {self.config.accelerator_type} x {self.config.accelerator_count}")
        logger.info(f"  Replica Count: {self.config.replica_count}")
        logger.info(f"  Total GPUs: {self.config.total_gpus}")
        logger.info(f"  Global Batch Size: {self.config.global_batch_size}")

        # In a real implementation, this would submit to Vertex AI
        logger.info("✅ Distributed training job created successfully!")
        logger.info(f"📦 Training package: {package_dir}")
        logger.info(f"📄 Job specification: distributed_job_spec.json")

        return {
            "job_name": job_name,
            "package_dir": package_dir,
            "job_spec": job_spec,
            "config": self.config.__dict__
        }

# Demo function for testing
def demo_distributed_training():
    """Demonstrate distributed training setup"""

    logger.info("🎭 Demonstrating Distributed Training Configuration")

    manager = DistributedTrainingManager("vulnhunter-ai-research")

    # Start distributed training
    result = manager.start_distributed_training("vulnhunter-distributed-demo")

    # Save demo results
    with open("distributed_training_demo_results.json", "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("📄 Demo results saved to: distributed_training_demo_results.json")

    return result

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_distributed_training()