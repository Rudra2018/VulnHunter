#!/bin/bash
# Setup script for reproducible environment

set -e

echo "Setting up Security Intelligence Framework environment..."

# Set reproducibility environment variables
export PYTHONHASHSEED=42
export CUDA_LAUNCH_BLOCKING=1
export CUBLAS_WORKSPACE_CONFIG=:4096:8

# Create necessary directories
mkdir -p data/{raw,processed,metadata}
mkdir -p models/saved_models
mkdir -p results/baselines
mkdir -p cache
mkdir -p logs

echo "Environment setup complete!"
echo "Run 'python smoke_test.py' to verify installation"
