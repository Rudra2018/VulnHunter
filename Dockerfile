# VulnHunter V5 Docker Image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install fuzzing tools (optional - for dynamic verification)
RUN wget https://github.com/AFLplusplus/AFLplusplus/archive/4.08c.tar.gz \
    && tar -xzf 4.08c.tar.gz \
    && cd AFLplusplus-4.08c \
    && make \
    && make install \
    && cd .. \
    && rm -rf AFLplusplus-4.08c 4.08c.tar.gz || true

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install additional dependencies for production
RUN pip install --no-cache-dir \
    click>=8.1.0 \
    pyyaml>=6.0 \
    gunicorn>=20.1.0

# Copy the application code
COPY src/ ./src/
COPY setup.py .

# Install the package
RUN pip install -e .

# Create directories for models and data
RUN mkdir -p /app/models /app/data/cache /app/logs

# Set environment variables
ENV PYTHONPATH="/app"
ENV VULNHUNTER_MODEL_PATH="/app/models/vulnhunter_v5_final.pt"
ENV VULNHUNTER_CACHE_DIR="/app/data/cache"
ENV VULNHUNTER_LOG_LEVEL="INFO"

# Expose the API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash vulnhunter
RUN chown -R vulnhunter:vulnhunter /app
USER vulnhunter

# Default command (can be overridden)
CMD ["python", "-m", "src.deploy.cli", "serve", "--model-path", "/app/models/vulnhunter_v5_final.pt", "--host", "0.0.0.0", "--port", "8000"]