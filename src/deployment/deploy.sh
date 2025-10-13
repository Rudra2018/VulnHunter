#!/bin/bash
# VulnHunter Deployment Script

set -e

echo "🚀 VulnHunter Deployment Script"
echo "================================"

# Configuration
CONTAINER_NAME="vulnhunter-api"
IMAGE_NAME="vulnhunter"
PORT="${VULNHUNTER_PORT:-5000}"

# Check dependencies
check_dependencies() {
    echo "📋 Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        echo "❌ Docker Compose is not installed"
        exit 1
    fi

    echo "✅ Dependencies OK"
}

# Build container
build_container() {
    echo "🔨 Building VulnHunter container..."
    docker build -f Dockerfile.vulnhunter -t $IMAGE_NAME .
    echo "✅ Container built successfully"
}

# Deploy with docker-compose
deploy_compose() {
    echo "🚀 Deploying with Docker Compose..."

    # Create logs directory
    mkdir -p logs

    # Start services
    docker-compose up -d vulnhunter-api

    echo "✅ VulnHunter API deployed on port $PORT"
    echo "🔗 Health check: http://localhost:$PORT/health"
}

# Deploy standalone
deploy_standalone() {
    echo "🚀 Deploying standalone container..."

    # Stop existing container
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true

    # Create logs directory
    mkdir -p logs
    mkdir -p models

    # Run container
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:5000 \
        -v $(pwd)/logs:/app/logs \
        -v $(pwd)/models:/app/models \
        -e VULNHUNTER_API_KEY="${VULNHUNTER_API_KEY:-production-change-this-key}" \
        -e VULNHUNTER_REQUIRE_AUTH="${VULNHUNTER_REQUIRE_AUTH:-true}" \
        $IMAGE_NAME

    echo "✅ VulnHunter API deployed on port $PORT"
    echo "🔗 Health check: http://localhost:$PORT/health"
}

# Health check
health_check() {
    echo "🏥 Running health check..."

    sleep 5  # Wait for startup

    if curl -f "http://localhost:$PORT/health" &>/dev/null; then
        echo "✅ VulnHunter API is healthy"
        curl -s "http://localhost:$PORT/health" | jq '.'
    else
        echo "❌ Health check failed"
        echo "📋 Container logs:"
        docker logs $CONTAINER_NAME --tail 20
        exit 1
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build     - Build container image"
    echo "  deploy    - Deploy with docker-compose"
    echo "  standalone - Deploy standalone container"
    echo "  health    - Run health check"
    echo "  logs      - Show container logs"
    echo "  stop      - Stop services"
    echo "  clean     - Clean up containers and images"
    echo ""
}

# Show logs
show_logs() {
    if command -v docker-compose &> /dev/null && [ -f docker-compose.yml ]; then
        docker-compose logs -f vulnhunter-api
    else
        docker logs -f $CONTAINER_NAME
    fi
}

# Stop services
stop_services() {
    echo "🛑 Stopping VulnHunter services..."

    if [ -f docker-compose.yml ]; then
        docker-compose down
    fi

    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true

    echo "✅ Services stopped"
}

# Clean up
cleanup() {
    echo "🧹 Cleaning up..."

    stop_services
    docker rmi $IMAGE_NAME 2>/dev/null || true

    echo "✅ Cleanup complete"
}

# Main execution
case "${1:-deploy}" in
    build)
        check_dependencies
        build_container
        ;;
    deploy)
        check_dependencies
        build_container
        deploy_compose
        health_check
        ;;
    standalone)
        check_dependencies
        build_container
        deploy_standalone
        health_check
        ;;
    health)
        health_check
        ;;
    logs)
        show_logs
        ;;
    stop)
        stop_services
        ;;
    clean)
        cleanup
        ;;
    *)
        show_usage
        ;;
esac