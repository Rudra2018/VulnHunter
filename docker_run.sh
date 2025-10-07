#!/bin/bash
# Convenience script for running Docker containers

set -e

IMAGE_NAME="security-intelligence-framework"
CONTAINER_NAME="vuln_ml_research"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build       - Build the Docker image"
    echo "  run         - Run smoke test"
    echo "  shell       - Start interactive shell"
    echo "  dev         - Start development shell with mounted volumes"
    echo "  test        - Run tests"
    echo "  train       - Run training"
    echo "  gpu         - Start shell with GPU support"
    echo "  clean       - Remove container and image"
    echo "  help        - Show this help message"
    echo ""
}

build_image() {
    echo -e "${GREEN}Building Docker image...${NC}"
    docker build -t $IMAGE_NAME .
    echo -e "${GREEN}✓ Build complete${NC}"
}

run_smoke_test() {
    echo -e "${GREEN}Running smoke test...${NC}"
    docker run --rm $IMAGE_NAME python3 smoke_test.py
}

start_shell() {
    echo -e "${GREEN}Starting interactive shell...${NC}"
    docker run --rm -it $IMAGE_NAME bash
}

start_dev_shell() {
    echo -e "${GREEN}Starting development shell with mounted volumes...${NC}"
    docker run --rm -it \
        -v "$(pwd)/core:/app/core" \
        -v "$(pwd)/experiments:/app/experiments" \
        -v "$(pwd)/results:/app/results" \
        -v "$(pwd)/models:/app/models" \
        $IMAGE_NAME bash
}

run_tests() {
    echo -e "${GREEN}Running tests...${NC}"
    docker run --rm $IMAGE_NAME python3 -m pytest tests/ -v
}

run_training() {
    echo -e "${GREEN}Starting training...${NC}"
    docker run --rm -it \
        -v "$(pwd)/results:/app/results" \
        -v "$(pwd)/models:/app/models" \
        $IMAGE_NAME python3 train_enhanced_vulnhunter.py
}

start_gpu_shell() {
    echo -e "${GREEN}Starting shell with GPU support...${NC}"
    if ! docker run --rm --gpus all nvidia/cuda:11.8.0-base nvidia-smi > /dev/null 2>&1; then
        echo -e "${RED}✗ GPU not available or nvidia-docker not installed${NC}"
        exit 1
    fi
    docker run --rm -it --gpus all \
        -v "$(pwd)/core:/app/core" \
        -v "$(pwd)/experiments:/app/experiments" \
        -v "$(pwd)/results:/app/results" \
        $IMAGE_NAME bash
}

clean() {
    echo -e "${YELLOW}Cleaning up Docker resources...${NC}"
    docker ps -a | grep $CONTAINER_NAME && docker rm -f $CONTAINER_NAME || true
    docker images | grep $IMAGE_NAME && docker rmi $IMAGE_NAME || true
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main script
case "${1:-}" in
    build)
        build_image
        ;;
    run)
        run_smoke_test
        ;;
    shell)
        start_shell
        ;;
    dev)
        start_dev_shell
        ;;
    test)
        run_tests
        ;;
    train)
        run_training
        ;;
    gpu)
        start_gpu_shell
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        print_usage
        ;;
    *)
        echo -e "${RED}Error: Unknown command '${1}'${NC}"
        echo ""
        print_usage
        exit 1
        ;;
esac
