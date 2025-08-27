#!/bin/bash

# Kong Guard AI Health Check Script
# Comprehensive health monitoring for all services

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
KONG_URL="${KONG_URL:-http://localhost:8000}"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
FASTAPI_URL="${FASTAPI_URL:-http://localhost:8080}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"

# Thresholds
ERROR_RATE_THRESHOLD=0.01  # 1% error rate
LATENCY_P95_THRESHOLD=1000  # 1000ms
MEMORY_USAGE_THRESHOLD=80   # 80% memory usage
CPU_USAGE_THRESHOLD=80      # 80% CPU usage

# Status tracking
OVERALL_STATUS=0
SERVICES_CHECKED=0
SERVICES_HEALTHY=0

# Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

# Check service health
check_service() {
    local service_name=$1
    local health_url=$2
    local expected_status=${3:-200}
    
    SERVICES_CHECKED=$((SERVICES_CHECKED + 1))
    
    if response=$(curl -s -o /dev/null -w "%{http_code}" "$health_url" 2>/dev/null); then
        if [ "$response" = "$expected_status" ]; then
            log_success "$service_name is healthy (HTTP $response)"
            SERVICES_HEALTHY=$((SERVICES_HEALTHY + 1))
            return 0
        else
            log_error "$service_name returned unexpected status (HTTP $response)"
            OVERALL_STATUS=1
            return 1
        fi
    else
        log_error "$service_name is not responding"
        OVERALL_STATUS=1
        return 1
    fi
}

# Check Kong Gateway
check_kong() {
    log_info "Checking Kong Gateway..."
    
    # Check proxy health
    check_service "Kong Proxy" "$KONG_URL/health"
    
    # Check admin API
    check_service "Kong Admin API" "$KONG_ADMIN_URL/status"
    
    # Check plugin status
    if plugins=$(curl -s "$KONG_ADMIN_URL/plugins/enabled" 2>/dev/null); then
        if echo "$plugins" | grep -q "kong-guard-ai"; then
            log_success "Kong Guard AI plugin is enabled"
        else
            log_warning "Kong Guard AI plugin is not enabled"
        fi
    fi
    
    # Check routes and services
    routes_count=$(curl -s "$KONG_ADMIN_URL/routes" 2>/dev/null | jq '.data | length' 2>/dev/null || echo 0)
    services_count=$(curl -s "$KONG_ADMIN_URL/services" 2>/dev/null | jq '.data | length' 2>/dev/null || echo 0)
    log_info "Kong has $services_count services and $routes_count routes configured"
}

# Check FastAPI
check_fastapi() {
    log_info "Checking FastAPI Management API..."
    
    # Check health endpoint
    check_service "FastAPI Health" "$FASTAPI_URL/health"
    
    # Check API endpoints
    check_service "FastAPI Docs" "$FASTAPI_URL/docs"
    check_service "FastAPI OpenAPI" "$FASTAPI_URL/openapi.json"
    
    # Check specific endpoints
    if config=$(curl -s "$FASTAPI_URL/v1/config" -H "Authorization: Bearer test" 2>/dev/null); then
        if echo "$config" | jq -e '.dry_run_mode' >/dev/null 2>&1; then
            dry_run=$(echo "$config" | jq -r '.dry_run_mode')
            log_info "Kong Guard AI is in dry_run_mode: $dry_run"
        fi
    fi
}

# Check Database
check_database() {
    log_info "Checking Database connections..."
    
    # Check Kong database
    if docker exec kong-database pg_isready -U kong >/dev/null 2>&1; then
        log_success "Kong database is ready"
        SERVICES_HEALTHY=$((SERVICES_HEALTHY + 1))
    else
        log_error "Kong database is not ready"
        OVERALL_STATUS=1
    fi
    SERVICES_CHECKED=$((SERVICES_CHECKED + 1))
    
    # Check API database
    if docker exec api-database pg_isready -U kongguard >/dev/null 2>&1; then
        log_success "API database is ready"
        SERVICES_HEALTHY=$((SERVICES_HEALTHY + 1))
    else
        log_error "API database is not ready"
        OVERALL_STATUS=1
    fi
    SERVICES_CHECKED=$((SERVICES_CHECKED + 1))
}

# Check Redis
check_redis() {
    log_info "Checking Redis..."
    
    SERVICES_CHECKED=$((SERVICES_CHECKED + 1))
    
    if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
        log_success "Redis is responding"
        SERVICES_HEALTHY=$((SERVICES_HEALTHY + 1))
        
        # Check memory usage
        memory_usage=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" INFO memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
        log_info "Redis memory usage: $memory_usage"
    else
        log_error "Redis is not responding"
        OVERALL_STATUS=1
    fi
}

# Check Monitoring Stack
check_monitoring() {
    log_info "Checking Monitoring Stack..."
    
    # Check Prometheus
    check_service "Prometheus" "$PROMETHEUS_URL/-/healthy"
    
    if [ $? -eq 0 ]; then
        # Query metrics
        if metrics=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=up" 2>/dev/null); then
            up_count=$(echo "$metrics" | jq '[.data.result[] | select(.value[1] == "1")] | length' 2>/dev/null || echo 0)
            down_count=$(echo "$metrics" | jq '[.data.result[] | select(.value[1] == "0")] | length' 2>/dev/null || echo 0)
            log_info "Prometheus: $up_count targets up, $down_count targets down"
        fi
    fi
    
    # Check Grafana
    check_service "Grafana" "$GRAFANA_URL/api/health"
}

# Check Performance Metrics
check_performance() {
    log_info "Checking Performance Metrics..."
    
    if ! command -v curl >/dev/null 2>&1; then
        log_warning "curl not found, skipping performance checks"
        return
    fi
    
    # Check error rate
    if error_rate=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=rate(kong_http_requests_total{status=~'5..'}[5m])" 2>/dev/null | jq -r '.data.result[0].value[1]' 2>/dev/null); then
        if [ "$error_rate" != "null" ] && [ "$error_rate" != "" ]; then
            if (( $(echo "$error_rate > $ERROR_RATE_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
                log_warning "High error rate detected: ${error_rate}"
            else
                log_success "Error rate is normal: ${error_rate}"
            fi
        fi
    fi
    
    # Check latency
    if latency_p95=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=histogram_quantile(0.95,kong_latency_bucket)" 2>/dev/null | jq -r '.data.result[0].value[1]' 2>/dev/null); then
        if [ "$latency_p95" != "null" ] && [ "$latency_p95" != "" ]; then
            if (( $(echo "$latency_p95 > $LATENCY_P95_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
                log_warning "High latency detected: ${latency_p95}ms (P95)"
            else
                log_success "Latency is normal: ${latency_p95}ms (P95)"
            fi
        fi
    fi
}

# Check Docker containers
check_containers() {
    log_info "Checking Docker containers..."
    
    local containers=("kong" "fastapi" "kong-database" "api-database" "redis" "prometheus" "grafana")
    
    for container in "${containers[@]}"; do
        SERVICES_CHECKED=$((SERVICES_CHECKED + 1))
        
        if docker ps --format "table {{.Names}}" | grep -q "^${container}$"; then
            status=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")
            if [ "$status" = "running" ]; then
                health=$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
                if [ "$health" = "healthy" ] || [ "$health" = "none" ]; then
                    log_success "Container $container is running${health:+ (health: $health)}"
                    SERVICES_HEALTHY=$((SERVICES_HEALTHY + 1))
                else
                    log_warning "Container $container is running but unhealthy (health: $health)"
                    OVERALL_STATUS=1
                fi
            else
                log_error "Container $container is not running (status: $status)"
                OVERALL_STATUS=1
            fi
        else
            log_error "Container $container not found"
            OVERALL_STATUS=1
        fi
    done
}

# Check disk usage
check_disk_usage() {
    log_info "Checking disk usage..."
    
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    
    if [ "$disk_usage" -gt 90 ]; then
        log_error "Critical disk usage: ${disk_usage}%"
        OVERALL_STATUS=1
    elif [ "$disk_usage" -gt 80 ]; then
        log_warning "High disk usage: ${disk_usage}%"
    else
        log_success "Disk usage is normal: ${disk_usage}%"
    fi
}

# Generate health report
generate_report() {
    echo ""
    echo "=========================================="
    echo "Kong Guard AI Health Check Report"
    echo "=========================================="
    echo "Timestamp: $(date)"
    echo "Services Checked: $SERVICES_CHECKED"
    echo "Services Healthy: $SERVICES_HEALTHY"
    echo "Overall Status: $([ $OVERALL_STATUS -eq 0 ] && echo "HEALTHY" || echo "UNHEALTHY")"
    echo "=========================================="
    
    if [ $OVERALL_STATUS -ne 0 ]; then
        echo ""
        echo "⚠️  Some services are experiencing issues."
        echo "Please check the logs for more details:"
        echo "  docker-compose logs -f"
    else
        echo ""
        echo "✅ All systems operational!"
    fi
}

# Main execution
main() {
    log_info "Starting Kong Guard AI Health Check..."
    echo ""
    
    check_containers
    echo ""
    
    check_kong
    echo ""
    
    check_fastapi
    echo ""
    
    check_database
    echo ""
    
    check_redis
    echo ""
    
    check_monitoring
    echo ""
    
    check_performance
    echo ""
    
    check_disk_usage
    echo ""
    
    generate_report
    
    exit $OVERALL_STATUS
}

# Run main function
main "$@"