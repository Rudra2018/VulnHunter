#!/bin/bash
# VulnHunter Monitoring Stack Startup Script

set -e

echo "🔍 Starting VulnHunter Monitoring Stack"
echo "======================================="

# Configuration
MONITORING_DIR="/Users/ankitthakur/vuln_ml_research/monitoring"
COMPOSE_FILE="docker-compose.monitoring.yml"

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

# Create necessary directories
create_directories() {
    echo "📁 Creating directories..."

    mkdir -p "$MONITORING_DIR/data/prometheus"
    mkdir -p "$MONITORING_DIR/data/grafana"
    mkdir -p "$MONITORING_DIR/data/alertmanager"

    echo "✅ Directories created"
}

# Start monitoring stack
start_stack() {
    echo "🚀 Starting monitoring stack..."

    cd "$MONITORING_DIR"

    # Set API key for demo
    export VULNHUNTER_API_KEY="monitoring-demo-key-$(date +%s)"

    # Start all services
    docker-compose -f "$COMPOSE_FILE" up -d

    echo "✅ Monitoring stack started"
}

# Wait for services
wait_for_services() {
    echo "⏳ Waiting for services to start..."

    services=("vulnhunter-api:5000" "prometheus:9090" "grafana:3000" "alertmanager:9093")

    for service in "${services[@]}"; do
        name=$(echo $service | cut -d: -f1)
        port=$(echo $service | cut -d: -f2)

        echo "  Waiting for $name on port $port..."

        timeout=60
        count=0

        while [ $count -lt $timeout ]; do
            if nc -z localhost $port 2>/dev/null; then
                echo "  ✅ $name is ready"
                break
            fi

            sleep 1
            ((count++))
        done

        if [ $count -eq $timeout ]; then
            echo "  ❌ $name failed to start within $timeout seconds"
            return 1
        fi
    done

    echo "✅ All services are ready"
}

# Setup Grafana datasource
setup_grafana() {
    echo "⚙️  Setting up Grafana..."

    # Wait a bit more for Grafana to fully initialize
    sleep 10

    # Add Prometheus datasource
    curl -X POST \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Prometheus",
            "type": "prometheus",
            "url": "http://prometheus:9090",
            "access": "proxy",
            "isDefault": true
        }' \
        "http://admin:vulnhunter123@localhost:3000/api/datasources" \
        2>/dev/null || echo "Datasource may already exist"

    echo "✅ Grafana configured"
}

# Show service URLs
show_urls() {
    echo ""
    echo "🌐 Service URLs"
    echo "==============="
    echo "VulnHunter API:     http://localhost:5000"
    echo "  Health Check:     http://localhost:5000/health"
    echo "  Metrics:          http://localhost:5000/metrics"
    echo ""
    echo "Prometheus:         http://localhost:9090"
    echo "Grafana:            http://localhost:3000 (admin/vulnhunter123)"
    echo "Alertmanager:       http://localhost:9093"
    echo "Node Exporter:      http://localhost:9100"
    echo ""
    echo "📊 Grafana Dashboard: http://localhost:3000/d/vulnhunter/vulnhunter-monitoring-dashboard"
    echo ""
}

# Show monitoring commands
show_commands() {
    echo "🔧 Monitoring Commands"
    echo "====================="
    echo "View logs:          docker-compose -f $COMPOSE_FILE logs -f [service]"
    echo "Stop stack:         docker-compose -f $COMPOSE_FILE down"
    echo "Restart service:    docker-compose -f $COMPOSE_FILE restart [service]"
    echo "Check status:       docker-compose -f $COMPOSE_FILE ps"
    echo ""
    echo "Test VulnHunter:    curl http://localhost:5000/health"
    echo "Query Prometheus:   curl 'http://localhost:9090/api/v1/query?query=up'"
    echo ""
}

# Test monitoring setup
test_monitoring() {
    echo "🧪 Testing monitoring setup..."

    # Test VulnHunter API
    if curl -f "http://localhost:5000/health" &>/dev/null; then
        echo "✅ VulnHunter API responding"
    else
        echo "❌ VulnHunter API not responding"
        return 1
    fi

    # Test Prometheus
    if curl -f "http://localhost:9090/-/healthy" &>/dev/null; then
        echo "✅ Prometheus responding"
    else
        echo "❌ Prometheus not responding"
        return 1
    fi

    # Test Grafana
    if curl -f "http://localhost:3000/api/health" &>/dev/null; then
        echo "✅ Grafana responding"
    else
        echo "❌ Grafana not responding"
        return 1
    fi

    # Test metrics collection
    if curl -s "http://localhost:9090/api/v1/query?query=up{job=\"vulnhunter-api\"}" | grep -q '"value":\[.*,"1"\]'; then
        echo "✅ Metrics collection working"
    else
        echo "⚠️  Metrics collection may need time to start"
    fi

    echo "✅ Monitoring tests completed"
}

# Main execution
main() {
    case "${1:-start}" in
        start)
            check_dependencies
            create_directories
            start_stack
            wait_for_services
            setup_grafana
            show_urls
            show_commands
            test_monitoring
            ;;
        stop)
            echo "🛑 Stopping monitoring stack..."
            cd "$MONITORING_DIR"
            docker-compose -f "$COMPOSE_FILE" down
            echo "✅ Monitoring stack stopped"
            ;;
        restart)
            echo "🔄 Restarting monitoring stack..."
            cd "$MONITORING_DIR"
            docker-compose -f "$COMPOSE_FILE" restart
            echo "✅ Monitoring stack restarted"
            ;;
        test)
            test_monitoring
            ;;
        urls)
            show_urls
            ;;
        *)
            echo "Usage: $0 [start|stop|restart|test|urls]"
            echo ""
            echo "Commands:"
            echo "  start    - Start the monitoring stack (default)"
            echo "  stop     - Stop the monitoring stack"
            echo "  restart  - Restart all services"
            echo "  test     - Test monitoring setup"
            echo "  urls     - Show service URLs"
            ;;
    esac
}

main "$@"