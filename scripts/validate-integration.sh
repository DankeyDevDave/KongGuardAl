#!/bin/bash

# Kong Guard AI Integration Validation Script
# This script validates the complete Kong plugin integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KONG_ADMIN_URL="http://localhost:8001"
KONG_PROXY_URL="http://localhost:8000"
PLUGIN_NAME="kong-guard-ai"
TIMEOUT=30

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
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

# Validation functions
check_kong_admin() {
    log_info "Checking Kong Admin API connectivity..."
    
    if curl -s --connect-timeout $TIMEOUT "$KONG_ADMIN_URL" > /dev/null; then
        log_success "Kong Admin API is accessible"
        return 0
    else
        log_error "Kong Admin API is not accessible at $KONG_ADMIN_URL"
        return 1
    fi
}

check_kong_proxy() {
    log_info "Checking Kong Proxy connectivity..."
    
    if curl -s --connect-timeout $TIMEOUT "$KONG_PROXY_URL" > /dev/null; then
        log_success "Kong Proxy is accessible"
        return 0
    else
        log_error "Kong Proxy is not accessible at $KONG_PROXY_URL"
        return 1
    fi
}

check_plugin_available() {
    log_info "Checking if $PLUGIN_NAME plugin is available..."
    
    local plugins=$(curl -s "$KONG_ADMIN_URL/plugins/available" | jq -r '.available_plugins[]' 2>/dev/null)
    
    if echo "$plugins" | grep -q "$PLUGIN_NAME"; then
        log_success "$PLUGIN_NAME plugin is available"
        return 0
    else
        log_warning "$PLUGIN_NAME plugin is not in available plugins list"
        log_info "Available plugins: $plugins"
        return 1
    fi
}

check_plugin_schema() {
    log_info "Checking plugin schema..."
    
    local schema=$(curl -s "$KONG_ADMIN_URL/plugins/schema/$PLUGIN_NAME" 2>/dev/null)
    
    if [ -n "$schema" ] && [ "$schema" != "null" ]; then
        log_success "$PLUGIN_NAME schema is accessible"
        echo "$schema" | jq . > /tmp/plugin-schema.json 2>/dev/null || true
        return 0
    else
        log_error "Could not retrieve plugin schema"
        return 1
    fi
}

create_test_service() {
    log_info "Creating test service..."
    
    local service_data='{
        "name": "test-service-guardai",
        "url": "http://httpbin.org"
    }'
    
    local response=$(curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d "$service_data" 2>/dev/null)
    
    if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        log_success "Test service created successfully"
        echo "$response" | jq -r '.id' > /tmp/test-service-id
        return 0
    else
        log_error "Failed to create test service: $response"
        return 1
    fi
}

create_test_route() {
    log_info "Creating test route..."
    
    local service_id=$(cat /tmp/test-service-id 2>/dev/null)
    
    if [ -z "$service_id" ]; then
        log_error "No service ID found"
        return 1
    fi
    
    local route_data='{
        "paths": ["/test-guardai"],
        "methods": ["GET", "POST"]
    }'
    
    local response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/routes" \
        -H "Content-Type: application/json" \
        -d "$route_data" 2>/dev/null)
    
    if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        log_success "Test route created successfully"
        echo "$response" | jq -r '.id' > /tmp/test-route-id
        return 0
    else
        log_error "Failed to create test route: $response"
        return 1
    fi
}

enable_plugin_on_service() {
    log_info "Enabling $PLUGIN_NAME plugin on test service..."
    
    local service_id=$(cat /tmp/test-service-id 2>/dev/null)
    
    if [ -z "$service_id" ]; then
        log_error "No service ID found"
        return 1
    fi
    
    local plugin_data='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": true,
            "threat_detection": {
                "rate_limit_threshold": 100,
                "anomaly_detection": true
            },
            "notifications": {
                "enabled": false
            }
        }
    }'
    
    local response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/plugins" \
        -H "Content-Type: application/json" \
        -d "$plugin_data" 2>/dev/null)
    
    if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        log_success "Plugin enabled on service successfully"
        echo "$response" | jq -r '.id' > /tmp/test-plugin-id
        return 0
    else
        log_error "Failed to enable plugin: $response"
        return 1
    fi
}

test_plugin_execution() {
    log_info "Testing plugin execution..."
    
    # Test normal request
    local response=$(curl -s -w "%{http_code}" "$KONG_PROXY_URL/test-guardai/get" -o /tmp/test-response.json 2>/dev/null)
    
    if [ "$response" = "200" ]; then
        log_success "Plugin allows normal requests"
    else
        log_warning "Unexpected response code: $response"
    fi
    
    # Test multiple requests to trigger rate detection
    log_info "Testing threat detection with rapid requests..."
    for i in {1..10}; do
        curl -s "$KONG_PROXY_URL/test-guardai/get" > /dev/null 2>&1 &
    done
    wait
    
    sleep 2
    log_success "Rapid request test completed"
}

check_kong_logs() {
    log_info "Checking Kong logs for plugin activity..."
    
    # This assumes Kong is running in Docker
    if command -v docker > /dev/null && docker ps | grep -q kong; then
        local container_id=$(docker ps | grep kong | awk '{print $1}' | head -1)
        log_info "Kong container: $container_id"
        
        # Check for plugin-related log entries
        local plugin_logs=$(docker logs "$container_id" 2>&1 | grep -i "$PLUGIN_NAME" | tail -5)
        
        if [ -n "$plugin_logs" ]; then
            log_success "Plugin activity found in logs:"
            echo "$plugin_logs"
        else
            log_warning "No plugin activity found in recent logs"
        fi
    else
        log_warning "Kong container not found, skipping log check"
    fi
}

cleanup_test_resources() {
    log_info "Cleaning up test resources..."
    
    # Remove plugin
    if [ -f /tmp/test-plugin-id ]; then
        local plugin_id=$(cat /tmp/test-plugin-id)
        curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" > /dev/null 2>&1
        rm -f /tmp/test-plugin-id
    fi
    
    # Remove route
    if [ -f /tmp/test-route-id ]; then
        local route_id=$(cat /tmp/test-route-id)
        curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" > /dev/null 2>&1
        rm -f /tmp/test-route-id
    fi
    
    # Remove service
    if [ -f /tmp/test-service-id ]; then
        local service_id=$(cat /tmp/test-service-id)
        curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" > /dev/null 2>&1
        rm -f /tmp/test-service-id
    fi
    
    # Clean temporary files
    rm -f /tmp/test-response.json /tmp/plugin-schema.json
    
    log_success "Cleanup completed"
}

# Performance test
performance_test() {
    log_info "Running basic performance test..."
    
    if command -v ab > /dev/null; then
        log_info "Using Apache Bench for performance testing..."
        ab -n 1000 -c 10 "$KONG_PROXY_URL/test-guardai/get" > /tmp/ab-results.txt 2>&1
        
        local avg_time=$(grep "Time per request" /tmp/ab-results.txt | head -1 | awk '{print $4}')
        log_info "Average response time: ${avg_time}ms"
        
        if [ -n "$avg_time" ] && [ "${avg_time%.*}" -lt 20 ]; then
            log_success "Performance test passed (< 20ms average)"
        else
            log_warning "Performance test shows high latency: ${avg_time}ms"
        fi
    else
        log_warning "Apache Bench not available, skipping performance test"
    fi
}

# Main validation workflow
main() {
    echo "============================================="
    echo "Kong Guard AI Integration Validation"
    echo "============================================="
    
    local failed_tests=0
    
    # Basic connectivity tests
    check_kong_admin || ((failed_tests++))
    check_kong_proxy || ((failed_tests++))
    
    # Plugin availability tests
    check_plugin_available || ((failed_tests++))
    check_plugin_schema || ((failed_tests++))
    
    # Integration tests
    create_test_service || ((failed_tests++))
    create_test_route || ((failed_tests++))
    enable_plugin_on_service || ((failed_tests++))
    
    # Functional tests
    test_plugin_execution || ((failed_tests++))
    check_kong_logs
    
    # Performance test
    performance_test
    
    # Cleanup
    cleanup_test_resources
    
    echo "============================================="
    if [ $failed_tests -eq 0 ]; then
        log_success "All validation tests passed!"
        exit 0
    else
        log_error "$failed_tests test(s) failed"
        exit 1
    fi
}

# Handle script termination
trap cleanup_test_resources EXIT

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi