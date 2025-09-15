#!/bin/bash

# Kong Guard AI - Unified Stack Management
# Manages everything in one location: Kong, AI Services, Grafana, Prometheus

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to check if service is healthy
check_health() {
    local service=$1
    local url=$2
    if curl -s "$url" > /dev/null 2>&1; then
        print_status "$service is healthy"
        return 0
    else
        print_error "$service is not responding"
        return 1
    fi
}

# Main menu
case "$1" in
    start)
        echo "🚀 Starting Kong Guard AI Stack..."
        echo "=================================="
        
        # Stop any running standalone services first
        print_info "Stopping standalone services if running..."
        pkill -f "python.*18002" 2>/dev/null || true
        pkill -f "python.*18003" 2>/dev/null || true
        pkill -f "grafana-server" 2>/dev/null || true
        pkill -f "prometheus" 2>/dev/null || true
        
        # Start the complete stack
        print_info "Starting Docker Compose stack..."
        docker-compose up -d
        
        echo ""
        print_info "Waiting for services to be ready..."
        sleep 10
        
        # Health checks
        echo ""
        echo "Health Checks:"
        echo "--------------"
        check_health "Kong Gateway" "http://localhost:18001"
        check_health "Konga Admin UI" "http://localhost:1337"
        check_health "Cloud AI Service" "http://localhost:18002/health"
        check_health "Ollama AI Service" "http://localhost:18003/health"
        check_health "Web Dashboard" "http://localhost:8080"
        check_health "Grafana" "http://localhost:3000/api/health"
        check_health "Prometheus" "http://localhost:9090/-/healthy"
        
        echo ""
        echo "📊 Access Points:"
        echo "=================="
        echo "• Kong Gateway:     http://localhost:18000"
        echo "• Kong Admin API:   http://localhost:18001"
        echo "• Konga Admin UI:   http://localhost:1337"
        echo "• Web Dashboard:    http://localhost:8080"
        echo "• Grafana:          http://localhost:3000 (admin/KongGuard2024!)"
        echo "• Prometheus:       http://localhost:9090"
        echo "• Cloud AI API:     http://localhost:18002"
        echo "• Ollama AI API:    http://localhost:18003"
        ;;
        
    stop)
        echo "🛑 Stopping Kong Guard AI Stack..."
        docker-compose down
        print_status "Stack stopped"
        ;;
        
    restart)
        echo "🔄 Restarting Kong Guard AI Stack..."
        docker-compose restart
        print_status "Stack restarted"
        ;;
        
    status)
        echo "📊 Kong Guard AI Stack Status"
        echo "=============================="
        docker-compose ps
        
        echo ""
        echo "Service Health:"
        echo "--------------"
        check_health "Kong Gateway" "http://localhost:18001" || true
        check_health "Cloud AI Service" "http://localhost:18002/health" || true
        check_health "Ollama AI Service" "http://localhost:18003/health" || true
        check_health "Grafana" "http://localhost:3000/api/health" || true
        check_health "Prometheus" "http://localhost:9090/-/healthy" || true
        ;;
        
    logs)
        if [ -z "$2" ]; then
            docker-compose logs -f --tail=100
        else
            docker-compose logs -f --tail=100 "$2"
        fi
        ;;
        
    metrics)
        echo "📈 Current Metrics"
        echo "=================="
        
        echo ""
        echo "Cloud AI Service Metrics:"
        curl -s http://localhost:18002/metrics | grep -E "^kong_guard" | head -10
        
        echo ""
        echo "Ollama AI Service Metrics:"
        curl -s http://localhost:18003/metrics | grep -E "^kong_guard" | head -10
        ;;
        
    clean)
        echo "🧹 Cleaning Kong Guard AI Stack..."
        docker-compose down -v
        rm -rf ./grafana-data ./prometheus-data ./logs
        print_status "Stack cleaned"
        ;;
        
    build)
        echo "🔨 Building AI Service Images..."
        docker-compose build ai-service-cloud ai-service-ollama
        print_status "Images built"
        ;;
        
    *)
        echo "Kong Guard AI Stack Manager"
        echo "==========================="
        echo ""
        echo "Usage: $0 {start|stop|restart|status|logs|metrics|clean|build}"
        echo ""
        echo "Commands:"
        echo "  start    - Start the complete stack"
        echo "  stop     - Stop the complete stack"
        echo "  restart  - Restart all services"
        echo "  status   - Show stack status and health"
        echo "  logs     - Show logs (optional: service name)"
        echo "  metrics  - Display current metrics"
        echo "  clean    - Stop and remove all data"
        echo "  build    - Rebuild AI service images"
        echo ""
        echo "Examples:"
        echo "  $0 start              # Start everything"
        echo "  $0 logs grafana       # Show Grafana logs"
        echo "  $0 status             # Check all services"
        exit 1
        ;;
esac