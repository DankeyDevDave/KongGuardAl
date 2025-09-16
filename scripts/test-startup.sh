#!/bin/bash

# Kong Guard AI Startup Test Script
# Tests the complete Docker stack startup process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() {
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..50})${NC}"
}

log_info() {
    echo -e "${BLUE}[STARTUP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_header "Checking Prerequisites"

    local failed=0

    # Check Docker
    if ! command -v docker > /dev/null 2>&1; then
        log_error "Docker is not installed"
        ((failed++))
    else
        if ! docker info > /dev/null 2>&1; then
            log_error "Docker daemon is not running"
            ((failed++))
        else
            log_success "Docker is ready"
        fi
    fi

    # Check Docker Compose
    if ! command -v docker-compose > /dev/null 2>&1 && ! docker compose version > /dev/null 2>&1; then
        log_error "Docker Compose is not available"
        ((failed++))
    else
        log_success "Docker Compose is ready"
    fi

    # Check compose file
    if [ ! -f "docker-compose.yml" ]; then
        log_error "docker-compose.yml not found"
        ((failed++))
    else
        log_success "docker-compose.yml found"
    fi

    # Check plugin files
    if [ ! -d "plugins" ]; then
        log_error "plugins directory not found"
        ((failed++))
    elif [ ! -f "plugins/kong-guard-ai/handler.lua" ]; then
        log_error "Kong Guard AI plugin handler not found"
        ((failed++))
    else
        log_success "Kong Guard AI plugin files found"
    fi

    return $failed
}

# Stop existing containers
cleanup_existing() {
    log_header "Cleaning Up Existing Containers"

    # Stop and remove containers
    if docker-compose ps -q 2>/dev/null | grep -q .; then
        log_info "Stopping existing containers..."
        docker-compose down --remove-orphans || true
        log_success "Existing containers stopped"
    else
        log_info "No existing containers to stop"
    fi

    # Remove any dangling kong containers
    local kong_containers=$(docker ps -a --filter "name=kong" --format "{{.ID}}" || true)
    if [ -n "$kong_containers" ]; then
        log_info "Removing orphaned Kong containers..."
        echo "$kong_containers" | xargs docker rm -f > /dev/null 2>&1 || true
    fi
}

# Start the stack
start_stack() {
    log_header "Starting Docker Stack"

    log_info "Starting services in the background..."

    # Start with verbose output
    if docker-compose up -d --build; then
        log_success "Docker stack started successfully"
        return 0
    else
        log_error "Failed to start Docker stack"
        return 1
    fi
}

# Wait for services to be healthy
wait_for_services() {
    log_header "Waiting for Services to be Healthy"

    local max_wait=180  # 3 minutes
    local wait_count=0
    local check_interval=5

    local services=("kong-database" "kong-gateway" "demo-api" "redis")

    for service in "${services[@]}"; do
        log_info "Waiting for $service to be healthy..."

        wait_count=0
        while [ $wait_count -lt $max_wait ]; do
            local health_status=$(docker inspect --format='{{.State.Health.Status}}' "$service" 2>/dev/null || echo "unknown")

            case "$health_status" in
                "healthy")
                    log_success "$service is healthy"
                    break
                    ;;
                "unhealthy")
                    log_error "$service is unhealthy"
                    docker logs "$service" --tail 20
                    return 1
                    ;;
                "starting"|"unknown")
                    if [ $((wait_count % 15)) -eq 0 ]; then
                        log_info "$service status: $health_status (waiting ${wait_count}s)"
                    fi
                    ;;
            esac

            sleep $check_interval
            ((wait_count += check_interval))
        done

        if [ $wait_count -ge $max_wait ]; then
            log_error "Timeout waiting for $service to be healthy"
            return 1
        fi
    done

    return 0
}

# Test Kong connectivity
test_kong_connectivity() {
    log_header "Testing Kong Connectivity"

    local kong_admin="http://localhost:8001"
    local kong_proxy="http://localhost:8000"
    local max_retries=12
    local retry_count=0

    # Test Admin API
    log_info "Testing Kong Admin API..."
    while [ $retry_count -lt $max_retries ]; do
        if curl -s --connect-timeout 5 "$kong_admin/status" > /dev/null 2>&1; then
            log_success "Kong Admin API is accessible"
            break
        else
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                log_info "Retry $retry_count/$max_retries - Admin API not ready yet..."
                sleep 5
            else
                log_error "Kong Admin API is not accessible after $max_retries retries"
                return 1
            fi
        fi
    done

    # Test Proxy
    retry_count=0
    log_info "Testing Kong Proxy..."
    while [ $retry_count -lt $max_retries ]; do
        if curl -s --connect-timeout 5 "$kong_proxy" > /dev/null 2>&1; then
            log_success "Kong Proxy is accessible"
            break
        else
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                log_info "Retry $retry_count/$max_retries - Proxy not ready yet..."
                sleep 5
            else
                log_error "Kong Proxy is not accessible after $max_retries retries"
                return 1
            fi
        fi
    done

    return 0
}

# Test plugin loading
test_plugin_loading() {
    log_header "Testing Plugin Loading"

    local kong_admin="http://localhost:8001"

    # Check if plugin is available
    log_info "Checking if kong-guard-ai plugin is available..."

    local available_plugins=$(curl -s "$kong_admin/plugins/available" 2>/dev/null)

    if echo "$available_plugins" | jq -r '.available_plugins[]?' 2>/dev/null | grep -q "kong-guard-ai"; then
        log_success "kong-guard-ai plugin is available"
    else
        log_warning "kong-guard-ai plugin not found in available plugins"
        log_info "Available plugins:"
        echo "$available_plugins" | jq -r '.available_plugins[]?' 2>/dev/null | head -10
        return 1
    fi

    # Check plugin schema
    log_info "Checking plugin schema..."
    local schema_response=$(curl -s "$kong_admin/plugins/schema/kong-guard-ai" 2>/dev/null)

    if [ -n "$schema_response" ] && [ "$schema_response" != "null" ]; then
        log_success "Plugin schema is accessible"
    else
        log_error "Plugin schema is not accessible"
        return 1
    fi

    return 0
}

# Create test service and enable plugin
test_plugin_enablement() {
    log_header "Testing Plugin Enablement"

    local kong_admin="http://localhost:8001"

    # Create test service
    log_info "Creating test service..."
    local service_data='{
        "name": "startup-test-service",
        "url": "http://demo-api:80"
    }'

    local service_response=$(curl -s -X POST "$kong_admin/services" \
        -H "Content-Type: application/json" \
        -d "$service_data" 2>/dev/null)

    local service_id=$(echo "$service_response" | jq -r '.id' 2>/dev/null)

    if [ -z "$service_id" ] || [ "$service_id" = "null" ]; then
        log_error "Failed to create test service"
        echo "Response: $service_response"
        return 1
    fi

    log_success "Test service created with ID: $service_id"

    # Create test route
    log_info "Creating test route..."
    local route_data='{
        "paths": ["/startup-test"],
        "methods": ["GET", "POST"]
    }'

    local route_response=$(curl -s -X POST "$kong_admin/services/$service_id/routes" \
        -H "Content-Type: application/json" \
        -d "$route_data" 2>/dev/null)

    local route_id=$(echo "$route_response" | jq -r '.id' 2>/dev/null)

    if [ -z "$route_id" ] || [ "$route_id" = "null" ]; then
        log_error "Failed to create test route"
        return 1
    fi

    log_success "Test route created with ID: $route_id"

    # Enable plugin on service
    log_info "Enabling kong-guard-ai plugin on test service..."
    local plugin_data='{
        "name": "kong-guard-ai",
        "config": {
            "dry_run": true,
            "log_level": "debug",
            "rate_limit_enabled": true,
            "rate_limit_threshold": 10
        }
    }'

    local plugin_response=$(curl -s -X POST "$kong_admin/services/$service_id/plugins" \
        -H "Content-Type: application/json" \
        -d "$plugin_data" 2>/dev/null)

    local plugin_id=$(echo "$plugin_response" | jq -r '.id' 2>/dev/null)

    if [ -z "$plugin_id" ] || [ "$plugin_id" = "null" ]; then
        log_error "Failed to enable plugin on service"
        echo "Response: $plugin_response"
        return 1
    fi

    log_success "Plugin enabled with ID: $plugin_id"

    # Test request through Kong
    log_info "Testing request through Kong with plugin..."
    local test_response=$(curl -s -w "%{http_code}" "http://localhost:8000/startup-test/get" -o /dev/null 2>/dev/null)

    if [ "$test_response" = "200" ]; then
        log_success "Test request successful (HTTP $test_response)"
    else
        log_warning "Test request returned HTTP $test_response"
    fi

    # Store IDs for cleanup
    echo "$service_id" > /tmp/startup-test-service-id
    echo "$route_id" > /tmp/startup-test-route-id
    echo "$plugin_id" > /tmp/startup-test-plugin-id

    return 0
}

# Check Kong logs for plugin activity
check_plugin_logs() {
    log_header "Checking Plugin Logs"

    log_info "Checking Kong logs for plugin activity..."

    # Get recent Kong logs
    local kong_logs=$(docker logs kong-gateway --tail 50 2>&1 | grep -i "kong-guard-ai\|guard.*ai" || true)

    if [ -n "$kong_logs" ]; then
        log_success "Plugin activity found in logs:"
        echo "$kong_logs" | head -10
    else
        log_warning "No specific plugin activity found in recent logs"
        log_info "Recent Kong logs (last 10 lines):"
        docker logs kong-gateway --tail 10 2>&1
    fi
}

# Cleanup test resources
cleanup_test_resources() {
    log_header "Cleaning Up Test Resources"

    local kong_admin="http://localhost:8001"

    # Remove plugin
    if [ -f /tmp/startup-test-plugin-id ]; then
        local plugin_id=$(cat /tmp/startup-test-plugin-id)
        curl -s -X DELETE "$kong_admin/plugins/$plugin_id" > /dev/null 2>&1
        rm -f /tmp/startup-test-plugin-id
        log_info "Test plugin removed"
    fi

    # Remove route
    if [ -f /tmp/startup-test-route-id ]; then
        local route_id=$(cat /tmp/startup-test-route-id)
        curl -s -X DELETE "$kong_admin/routes/$route_id" > /dev/null 2>&1
        rm -f /tmp/startup-test-route-id
        log_info "Test route removed"
    fi

    # Remove service
    if [ -f /tmp/startup-test-service-id ]; then
        local service_id=$(cat /tmp/startup-test-service-id)
        curl -s -X DELETE "$kong_admin/services/$service_id" > /dev/null 2>&1
        rm -f /tmp/startup-test-service-id
        log_info "Test service removed"
    fi

    log_success "Test resources cleaned up"
}

# Generate startup report
generate_startup_report() {
    log_header "Generating Startup Report"

    local report_file="startup-test-report-$(date +%Y%m%d-%H%M%S).md"

    cat > "$report_file" << EOF
# Kong Guard AI Startup Test Report

**Generated:** $(date)
**Test Duration:** $(date -u -d @$(($(date +%s) - start_time)) +%H:%M:%S 2>/dev/null || echo "N/A")

## Test Results Summary

### Infrastructure
- Docker daemon: $(docker info > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Failed")
- Docker Compose: $(command -v docker-compose > /dev/null 2>&1 || docker compose version > /dev/null 2>&1 && echo "✅ Available" || echo "❌ Failed")
- Kong containers: $(docker ps --filter "name=kong" --format "{{.Names}}" | wc -l) running

### Service Health
- Kong Gateway: $(curl -s --connect-timeout 5 "http://localhost:8001/status" > /dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Unhealthy")
- Kong Proxy: $(curl -s --connect-timeout 5 "http://localhost:8000" > /dev/null 2>&1 && echo "✅ Accessible" || echo "❌ Inaccessible")
- PostgreSQL: $(docker inspect --format='{{.State.Health.Status}}' kong-database 2>/dev/null || echo "Unknown")
- Redis: $(docker inspect --format='{{.State.Health.Status}}' kong-redis 2>/dev/null || echo "Unknown")
- Demo API: $(docker inspect --format='{{.State.Health.Status}}' demo-api 2>/dev/null || echo "Unknown")

### Plugin Status
- Plugin available: $(curl -s "http://localhost:8001/plugins/available" 2>/dev/null | jq -r '.available_plugins[]?' | grep -q "kong-guard-ai" && echo "✅ Yes" || echo "❌ No")
- Plugin schema: $(curl -s "http://localhost:8001/plugins/schema/kong-guard-ai" 2>/dev/null | jq -e '.fields' > /dev/null 2>&1 && echo "✅ Valid" || echo "❌ Invalid")

### Container Status
\`\`\`
$(docker ps --filter "name=kong" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}")
\`\`\`

### Kong Configuration
\`\`\`
$(curl -s "http://localhost:8001/status" 2>/dev/null | jq '.' || echo "Kong status not available")
\`\`\`

### Recent Kong Logs
\`\`\`
$(docker logs kong-gateway --tail 20 2>&1 | tail -20)
\`\`\`

## Next Steps

1. Run full integration tests: \`./scripts/validate-integration.sh\`
2. Test plugin functionality: \`./scripts/validate-plugin-lifecycle.sh\`
3. Monitor logs: \`docker-compose logs -f kong\`
4. Access Kong Admin UI: http://localhost:8001
5. Test API through Kong: http://localhost:8000

## Troubleshooting

If any tests failed:

1. Check container logs: \`docker-compose logs kong\`
2. Verify plugin files: \`ls -la plugins/kong-guard-ai/\`
3. Check Kong configuration: \`docker exec kong-gateway kong config\`
4. Restart services: \`docker-compose restart kong\`

---
*Report generated by Kong Guard AI Startup Test*
EOF

    log_success "Startup report generated: $report_file"
    echo "$report_file"
}

# Main startup test function
main() {
    local start_time=$(date +%s)

    log_header "Kong Guard AI Startup Test"
    echo -e "${CYAN}Testing complete Docker stack startup and plugin integration...${NC}"
    echo

    local failed_tests=0
    local total_tests=0

    # Prerequisites
    ((total_tests++))
    if ! check_prerequisites; then
        ((failed_tests++))
        log_error "Prerequisites failed, aborting startup test"
        exit 1
    fi

    # Cleanup existing
    cleanup_existing

    # Start stack
    ((total_tests++))
    if ! start_stack; then
        ((failed_tests++))
        log_error "Failed to start Docker stack"
        exit 1
    fi

    # Wait for services
    ((total_tests++))
    if ! wait_for_services; then
        ((failed_tests++))
        log_error "Services failed to become healthy"
    fi

    # Test connectivity
    ((total_tests++))
    if ! test_kong_connectivity; then
        ((failed_tests++))
    fi

    # Test plugin loading
    ((total_tests++))
    if ! test_plugin_loading; then
        ((failed_tests++))
    fi

    # Test plugin enablement
    ((total_tests++))
    if ! test_plugin_enablement; then
        ((failed_tests++))
    fi

    # Check logs
    check_plugin_logs

    # Generate report
    local report_file=$(generate_startup_report)

    # Cleanup test resources
    cleanup_test_resources

    # Final summary
    log_header "Startup Test Summary"

    echo -e "${BOLD}Total Tests:${NC} $total_tests"
    echo -e "${BOLD}Passed:${NC} $((total_tests - failed_tests))"
    echo -e "${BOLD}Failed:${NC} $failed_tests"
    echo

    if [ $failed_tests -eq 0 ]; then
        log_success "🎉 All startup tests passed!"
        log_info "Kong Guard AI is ready for development"
    elif [ $failed_tests -lt $total_tests ]; then
        log_warning "⚠️  Partial startup success ($((total_tests - failed_tests))/$total_tests tests passed)"
        log_info "Some components may need attention"
    else
        log_error "❌ Startup tests failed"
        log_info "Check the report for troubleshooting steps"
    fi

    echo
    log_info "📄 Detailed report: $report_file"
    log_info "🌐 Kong Admin API: http://localhost:8001"
    log_info "🚀 Kong Proxy: http://localhost:8000"

    exit $failed_tests
}

# Script options
case "${1:-}" in
    --cleanup-only)
        cleanup_existing
        exit 0
        ;;
    --no-cleanup)
        # Skip cleanup and start directly
        start_stack
        wait_for_services
        test_kong_connectivity
        test_plugin_loading
        test_plugin_enablement
        check_plugin_logs
        generate_startup_report
        exit $?
        ;;
    --help)
        echo "Kong Guard AI Startup Test Script"
        echo
        echo "Usage: $0 [option]"
        echo
        echo "Options:"
        echo "  --cleanup-only  Only cleanup existing containers"
        echo "  --no-cleanup    Skip cleanup, start with existing setup"
        echo "  --help          Show this help message"
        echo
        echo "Without options, runs complete startup test with cleanup"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
