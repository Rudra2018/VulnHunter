# Docker Setup Guide

This document explains how to use Docker with the Security Intelligence Framework.

## Prerequisites

- Docker 20.10 or later
- Docker Compose 1.29 or later (optional)
- NVIDIA Docker runtime (optional, for GPU support)

## Quick Start

### Build the Docker Image

```bash
docker build -t security-intelligence-framework .
```

### Run the Container

```bash
# Run smoke test
docker run -it security-intelligence-framework

# Run with interactive shell
docker run -it security-intelligence-framework bash

# Run with mounted volumes (for development)
docker run -it \
  -v $(pwd)/core:/app/core \
  -v $(pwd)/results:/app/results \
  security-intelligence-framework bash
```

## Using Docker Compose

### Build and Run

```bash
# Build the image
docker-compose build

# Run the default service
docker-compose up vuln-research

# Run with shell access
docker-compose run vuln-research bash
```

### Available Services

1. **vuln-research** - Main research environment with PyTorch
2. **vuln-research-vertex** - Optimized for Vertex AI training

## Dockerfiles

### Dockerfile

The main Dockerfile (`Dockerfile`) is designed for:
- Development and research
- Running experiments locally
- Model training with PyTorch and CUDA support
- Includes full framework with all dependencies

Key features:
- Based on `pytorch/pytorch:2.1.0-cuda12.1-cudnn8-devel`
- Includes security analysis tools
- Sandboxed execution with SecureRunner
- Non-root user for security
- Health checks included

### Dockerfile.vertex

The Vertex AI Dockerfile (`Dockerfile.vertex`) is optimized for:
- Cloud training on Google Cloud Vertex AI
- GPU-accelerated training
- PyTorch Geometric for graph neural networks

Key features:
- Based on `nvidia/cuda:11.8.0-cudnn8-runtime-ubuntu22.04`
- Lightweight runtime image
- PyTorch with CUDA 11.8 support
- PyTorch Geometric for GNN support
- Google Cloud integration

## GPU Support

### Enable NVIDIA GPU Support

```bash
# Check if NVIDIA runtime is available
docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi

# Run with GPU support
docker run --gpus all -it security-intelligence-framework bash
```

### Using Docker Compose with GPU

Uncomment the GPU section in `docker-compose.yml`:

```yaml
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

Then run:

```bash
docker-compose up vuln-research
```

## Common Tasks

### Run Smoke Test

```bash
docker run security-intelligence-framework python3 smoke_test.py
```

### Run Training

```bash
docker run -it security-intelligence-framework python3 train_enhanced_vulnhunter.py
```

### Run Tests

```bash
docker run -it security-intelligence-framework python3 -m pytest tests/
```

### Interactive Development

```bash
# Mount local code for live editing
docker run -it \
  -v $(pwd)/core:/app/core \
  -v $(pwd)/experiments:/app/experiments \
  security-intelligence-framework bash
```

## Volume Mounts

Recommended volume mounts for development:

```bash
docker run -it \
  -v $(pwd)/core:/app/core \
  -v $(pwd)/models:/app/models \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/experiments:/app/experiments \
  security-intelligence-framework bash
```

## Environment Variables

Key environment variables:

- `PYTHONHASHSEED=42` - For reproducibility
- `CUDA_LAUNCH_BLOCKING=1` - For CUDA debugging
- `CUBLAS_WORKSPACE_CONFIG=:4096:8` - For deterministic CUDA operations
- `PYTHONPATH=/app` - Python import path

## Troubleshooting

### Build Fails

1. **Check Docker version**:
   ```bash
   docker --version
   ```

2. **Clean build cache**:
   ```bash
   docker build --no-cache -t security-intelligence-framework .
   ```

3. **Check disk space**:
   ```bash
   docker system df
   docker system prune  # Clean up unused resources
   ```

### Container Exits Immediately

Check logs:
```bash
docker logs <container_id>
```

### GPU Not Detected

1. Install NVIDIA Docker runtime:
   ```bash
   distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
   curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
   curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
   sudo apt-get update && sudo apt-get install -y nvidia-docker2
   sudo systemctl restart docker
   ```

2. Test GPU access:
   ```bash
   docker run --gpus all nvidia/cuda:11.8.0-base nvidia-smi
   ```

## Best Practices

1. **Use .dockerignore**: Exclude unnecessary files from the build context
2. **Layer caching**: Order Dockerfile commands from least to most frequently changing
3. **Multi-stage builds**: Consider multi-stage builds for smaller production images
4. **Security**: Always run containers as non-root user (already configured)
5. **Volumes**: Use volumes for persistent data and development

## Building for Production

For production deployment:

```bash
# Build optimized image
docker build \
  --target production \
  -t security-intelligence-framework:prod \
  .

# Tag for registry
docker tag security-intelligence-framework:prod \
  your-registry.com/security-intelligence-framework:latest

# Push to registry
docker push your-registry.com/security-intelligence-framework:latest
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [NVIDIA Docker](https://github.com/NVIDIA/nvidia-docker)
- [Docker Compose](https://docs.docker.com/compose/)
- [PyTorch Docker Images](https://hub.docker.com/r/pytorch/pytorch)

## Support

For issues related to Docker setup, please check:
1. Docker logs: `docker logs <container_id>`
2. Build logs: Save build output with `docker build . 2>&1 | tee build.log`
3. System resources: `docker system df`

## License

See main project LICENSE file.
