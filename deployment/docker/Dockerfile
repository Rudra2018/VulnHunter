# VulnHunter Ω Production Docker Image
# Multi-stage build for optimized production deployment

# Stage 1: Build environment
FROM python:3.12-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production environment
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV VULNHUNTER_ENV=production

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash vulnhunter

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/vulnhunter/.local

# Copy application code
COPY scripts/ ./scripts/
COPY models/ ./models/
COPY configs/ ./configs/
COPY docs/ ./docs/

# Set ownership and permissions
RUN chown -R vulnhunter:vulnhunter /app
RUN chmod +x scripts/*.py

# Switch to non-root user
USER vulnhunter

# Add local bin to PATH
ENV PATH=/home/vulnhunter/.local/bin:$PATH

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8765

# Default command
CMD ["python", "scripts/vulnhunter_production_platform.py", "--server", "--port", "8080"]