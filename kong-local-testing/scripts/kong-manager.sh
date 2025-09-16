#!/bin/bash

# Kong Local Testing Manager Script
# Usage: ./kong-manager.sh [command] [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
KONG_ADMIN_URL="http://localhost:8001"
KONG_DBLESS_ADMIN_URL="http://localhost:9001"

# Functions
print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}     Kong Local Testing Environment${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    print_success "Docker is running"
}

# Commands
cmd_start() {
    print_header
    print_info "Starting Kong Testing Environment..."
    check_docker

    local profile="${1:-default}"

    case $profile in
        "full")
            print_info "Starting with all services (DB mode + monitoring + tools)..."
            docker-compose --profile monitoring --profile tools up -d
            ;;
        "dbless")
            print_info "Starting DB-less mode..."
            docker-compose --profile dbless up -d kong-dbless httpbin echo-server mockbin redis
            ;;
        "monitoring")
            print_info "Starting with monitoring stack..."
            docker-compose --profile monitoring up -d
            ;;
        "minimal")
            print_info "Starting minimal setup (DB mode only)..."
            docker-compose up -d kong-database kong-migration kong-db httpbin
            ;;
        *)
            print_info "Starting default setup (DB mode + services)..."
            docker-compose up -d
            ;;
    esac

    print_info "Waiting for Kong to be ready..."
    sleep 10

    if curl -s $KONG_ADMIN_URL > /dev/null 2>&1; then
        print_success "Kong DB mode is ready at $KONG_ADMIN_URL"
    fi

    if [ "$profile" == "dbless" ] && curl -s $KONG_DBLESS_ADMIN_URL > /dev/null 2>&1; then
        print_success "Kong DB-less mode is ready at $KONG_DBLESS_ADMIN_URL"
    fi

    print_info "Services available:"
    echo "  • Kong Admin API (DB):     http://localhost:8001"
    echo "  • Kong Proxy (DB):         http://localhost:8000"
    echo "  • Kong Manager GUI:        http://localhost:8002"
    [ "$profile" == "dbless" ] && echo "  • Kong Admin API (DBless): http://localhost:9001"
    [ "$profile" == "dbless" ] && echo "  • Kong Proxy (DBless):     http://localhost:9000"
    echo "  • HTTPBin Service:         http://localhost:8080"
    echo "  • Echo Server:             http://localhost:8081"
    echo "  • MockBin Service:         http://localhost:8082"
    [ "$profile" == "monitoring" ] || [ "$profile" == "full" ] && echo "  • Prometheus:              http://localhost:9090"
    [ "$profile" == "monitoring" ] || [ "$profile" == "full" ] && echo "  • Grafana:                 http://localhost:3000 (admin/admin123)"
    [ "$profile" == "tools" ] || [ "$profile" == "full" ] && echo "  • pgAdmin:                 http://localhost:5050 (admin@kong.local/admin123)"
    [ "$profile" == "tools" ] || [ "$profile" == "full" ] && echo "  • Redis Commander:         http://localhost:8083"
}

cmd_stop() {
    print_header
    print_info "Stopping Kong Testing Environment..."
    docker-compose --profile monitoring --profile tools --profile dbless down
    print_success "All services stopped"
}

cmd_clean() {
    print_header
    print_info "Cleaning Kong Testing Environment..."
    docker-compose --profile monitoring --profile tools --profile dbless down -v
    print_success "All services stopped and volumes removed"
}

cmd_status() {
    print_header
    print_info "Service Status:"
    docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

    echo ""
    print_info "Kong Status:"
    if curl -s $KONG_ADMIN_URL > /dev/null 2>&1; then
        local version=$(curl -s $KONG_ADMIN_URL | jq -r .version 2>/dev/null || echo "unknown")
        print_success "Kong DB mode is running (version: $version)"

        local services=$(curl -s $KONG_ADMIN_URL/services | jq -r '.data | length' 2>/dev/null || echo "0")
        local routes=$(curl -s $KONG_ADMIN_URL/routes | jq -r '.data | length' 2>/dev/null || echo "0")
        local plugins=$(curl -s $KONG_ADMIN_URL/plugins | jq -r '.data | length' 2>/dev/null || echo "0")

        echo "  • Services: $services"
        echo "  • Routes:   $routes"
        echo "  • Plugins:  $plugins"
    else
        print_error "Kong DB mode is not responding"
    fi

    if curl -s $KONG_DBLESS_ADMIN_URL > /dev/null 2>&1; then
        local version=$(curl -s $KONG_DBLESS_ADMIN_URL | jq -r .version 2>/dev/null || echo "unknown")
        print_success "Kong DB-less mode is running (version: $version)"
    fi
}

cmd_logs() {
    local service="${1:-kong-db}"
    print_header
    print_info "Showing logs for $service..."
    docker-compose logs -f $service
}

cmd_test() {
    print_header
    print_info "Running Kong API Tests..."

    # Test Kong Admin API
    print_info "Testing Kong Admin API..."
    if curl -s $KONG_ADMIN_URL > /dev/null 2>&1; then
        print_success "Admin API is responsive"
    else
        print_error "Admin API is not responding"
        return 1
    fi

    # Test HTTPBin through Kong
    print_info "Testing HTTPBin service through Kong..."
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/httpbin/get)
    if [ "$response" == "200" ]; then
        print_success "HTTPBin service is accessible (HTTP $response)"
    else
        print_error "HTTPBin service test failed (HTTP $response)"
    fi

    # Test Echo Server through Kong
    print_info "Testing Echo service through Kong..."
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/echo)
    if [ "$response" == "200" ]; then
        print_success "Echo service is accessible (HTTP $response)"
    else
        print_error "Echo service test failed (HTTP $response)"
    fi

    # Test Rate Limiting
    print_info "Testing rate limiting..."
    for i in {1..5}; do
        response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/httpbin/get)
        echo -n "  Request $i: HTTP $response"
        if [ "$response" == "429" ]; then
            echo " (Rate limited)"
        else
            echo ""
        fi
    done
}

cmd_configure() {
    print_header
    print_info "Configuring Kong services and routes..."

    # Add a test service
    print_info "Adding test service..."
    curl -s -X POST $KONG_ADMIN_URL/services \
        -H "Content-Type: application/json" \
        -d '{
            "name": "test-service",
            "url": "http://httpbin:80"
        }' > /dev/null

    print_success "Test service added"

    # Add a route
    print_info "Adding test route..."
    curl -s -X POST $KONG_ADMIN_URL/services/test-service/routes \
        -H "Content-Type: application/json" \
        -d '{
            "name": "test-route",
            "paths": ["/test"]
        }' > /dev/null

    print_success "Test route added"

    # Add rate limiting plugin
    print_info "Adding rate limiting plugin..."
    curl -s -X POST $KONG_ADMIN_URL/services/test-service/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "rate-limiting",
            "config": {
                "minute": 10,
                "policy": "local"
            }
        }' > /dev/null

    print_success "Rate limiting plugin added"

    print_info "Configuration complete!"
    echo "  Test your service at: http://localhost:8000/test"
}

cmd_help() {
    print_header
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  start [profile]    Start Kong environment (profiles: default, full, dbless, monitoring, minimal)"
    echo "  stop              Stop all services"
    echo "  clean             Stop all services and remove volumes"
    echo "  status            Show service status"
    echo "  logs [service]    Show logs for a service (default: kong-db)"
    echo "  test              Run basic API tests"
    echo "  configure         Configure sample services and routes"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start              # Start default setup"
    echo "  $0 start full         # Start with all features"
    echo "  $0 start dbless       # Start DB-less mode"
    echo "  $0 logs kong-db       # View Kong logs"
    echo "  $0 test               # Run API tests"
}

# Main script
case "${1:-help}" in
    start)
        cmd_start "${2:-default}"
        ;;
    stop)
        cmd_stop
        ;;
    clean)
        cmd_clean
        ;;
    status)
        cmd_status
        ;;
    logs)
        cmd_logs "$2"
        ;;
    test)
        cmd_test
        ;;
    configure)
        cmd_configure
        ;;
    help|*)
        cmd_help
        ;;
esac
