# VulnHunter - Production Docker Image
# ====================================
#
# Multi-stage Docker build for VulnHunter vulnerability detection platform
# Optimized for production deployment with minimal attack surface

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements first for better caching
COPY requirements.txt requirements-prod.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-prod.txt

# Production stage
FROM python:3.11-slim as production

# Set production arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG VULNHUNTER_VERSION="2.0.0"
ARG BUILD_DATE
ARG VCS_REF

# Add labels
LABEL maintainer="VulnHunter Team <security@vulnhunter.ai>" \
      org.label-schema.name="vulnhunter" \
      org.label-schema.description="Enterprise-Grade Vulnerability Detection Platform" \
      org.label-schema.version="${VULNHUNTER_VERSION}" \
      org.label-schema.build-date="${BUILD_DATE}" \
      org.label-schema.vcs-ref="${VCS_REF}" \
      org.label-schema.schema-version="1.0"

# Create non-root user for security
RUN groupadd -r vulnhunter && \
    useradd -r -g vulnhunter -d /app -s /bin/bash vulnhunter

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p \
    /app/logs \
    /app/data \
    /app/config \
    /app/enhanced_models \
    /app/tmp \
    && chown -R vulnhunter:vulnhunter /app

# Copy application code
COPY --chown=vulnhunter:vulnhunter vulnhunter/ ./vulnhunter/
COPY --chown=vulnhunter:vulnhunter enhanced_models/ ./enhanced_models/
COPY --chown=vulnhunter:vulnhunter config/ ./config/

# Copy additional files
COPY --chown=vulnhunter:vulnhunter scripts/docker-entrypoint.sh ./entrypoint.sh
COPY --chown=vulnhunter:vulnhunter scripts/healthcheck.py ./healthcheck.py

# Make scripts executable
RUN chmod +x ./entrypoint.sh ./healthcheck.py

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULNHUNTER_CONFIG_PATH=/app/config/vulnhunter.yaml \
    VULNHUNTER_LOG_LEVEL=INFO \
    VULNHUNTER_HOST=0.0.0.0 \
    VULNHUNTER_PORT=8000 \
    VULNHUNTER_WORKERS=4

# Switch to non-root user
USER vulnhunter

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python /app/healthcheck.py

# Default command
ENTRYPOINT ["./entrypoint.sh"]
CMD ["api"]

# Multi-service support via build targets

# Development image
FROM production as development

USER root

# Install development dependencies
COPY --chown=vulnhunter:vulnhunter requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# Install additional development tools
RUN apt-get update && apt-get install -y \
    git \
    vim \
    htop \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy test files
COPY --chown=vulnhunter:vulnhunter tests/ ./tests/

USER vulnhunter

ENV VULNHUNTER_DEBUG=true

# Testing image
FROM development as testing

USER root

# Install testing dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-xdist \
    pytest-mock

USER vulnhunter

# Default to running tests
CMD ["pytest", "tests/", "-v", "--cov=vulnhunter"]

# Model training image
FROM production as training

USER root

# Install training dependencies
RUN pip install --no-cache-dir \
    scikit-learn \
    pandas \
    numpy \
    matplotlib \
    seaborn \
    jupyter

# Copy training scripts
COPY --chown=vulnhunter:vulnhunter training/ ./training/

USER vulnhunter

CMD ["python", "-m", "vulnhunter.training.train"]