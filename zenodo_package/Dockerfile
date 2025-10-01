# Dockerfile for Security Intelligence Framework
# Production-ready containerized environment for vulnerability detection research

FROM pytorch/pytorch:2.1.0-cuda12.1-cudnn8-devel

# Set maintainer and labels
LABEL maintainer="ankit.thakur@halodoc.com"
LABEL description="Security Intelligence Framework - Unified Vulnerability Detection"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    cmake \
    libssl-dev \
    vim \
    tree \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY requirements-lock.txt /app/
COPY environment.yml /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-lock.txt

# Create necessary directories
RUN mkdir -p data/{raw,processed,metadata} \
    && mkdir -p models/saved_models \
    && mkdir -p results/baselines \
    && mkdir -p cache \
    && mkdir -p sandbox_runs \
    && mkdir -p tools/bin \
    && mkdir -p logs

# Copy source code
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY config/ /app/config/
COPY case_studies/ /app/case_studies/
COPY tools/ /app/tools/

# Copy documentation and scripts
COPY *.md /app/
COPY *.py /app/
COPY setup_reproduction_environment.sh /app/

# Set environment variables for reproducibility
ENV PYTHONHASHSEED=42
ENV CUDA_LAUNCH_BLOCKING=1
ENV CUBLAS_WORKSPACE_CONFIG=:4096:8
ENV PYTHONPATH=/app

# Set permissions
RUN chmod +x /app/setup_reproduction_environment.sh \
    && chmod +x /app/tools/bin/* 2>/dev/null || true

# Create non-root user for security
RUN useradd -m -u 1000 researcher && \
    chown -R researcher:researcher /app
USER researcher

# Verify installation
RUN python3 -c "import torch; print(f'PyTorch {torch.__version__} ready')" \
    && python3 -c "import transformers; print(f'Transformers {transformers.__version__} ready')" \
    && python3 -c "from src.utils.secure_runner import SecureRunner; print('SecureRunner ready')"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from src.utils.secure_runner import secure_run; print('Framework healthy')" || exit 1

# Default command
CMD ["python3", "smoke_test.py"]

# Build instructions for reviewers:
# docker build -t security-intelligence-framework .
# docker run -it security-intelligence-framework

# For development with mounted volumes:
# docker run -it -v $(pwd):/app security-intelligence-framework bash