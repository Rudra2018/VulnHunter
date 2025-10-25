FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY vulnforge_api.py .
COPY vulnforge_production_ensemble.py .
COPY vulnforge_production_ensemble.pkl .
COPY vulnforge_500k_aggregated_results.json .

# Create demo requests file at runtime
RUN touch api_demo_requests.json

# Expose port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5001/health || exit 1

# Run the application
CMD ["python", "vulnforge_api.py"]