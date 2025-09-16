#!/bin/bash

# Kong Plugin Lifecycle Validation Script
# Tests all phases of the Kong plugin lifecycle

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
KONG_ADMIN_URL="http://localhost:8001"
KONG_PROXY_URL="http://localhost:8000"
PLUGIN_NAME="kong-guard-ai"

log_info() {
    echo -e "${BLUE}[LIFECYCLE]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test init_worker phase
test_init_worker_phase() {
    log_info "Testing init_worker phase..."

    # Check if Kong has loaded the plugin
    local kong_status=$(curl -s "$KONG_ADMIN_URL/status" | jq -r '.configuration.loaded_plugins[]' 2>/dev/null | grep -c "$PLUGIN_NAME" || echo "0")

    if [ "$kong_status" -gt 0 ]; then
        log_success "Plugin loaded in init_worker phase"
        return 0
    else
        log_error "Plugin not found in loaded plugins"
        return 1
    fi
}

# Test access phase
test_access_phase() {
    log_info "Testing access phase..."

    # Create a test service and route
    local service_data='{
        "name": "lifecycle-test-service",
        "url": "http://httpbin.org"
    }'

    local service_response=$(curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d "$service_data")

    local service_id=$(echo "$service_response" | jq -r '.id' 2>/dev/null)

    if [ -z "$service_id" ] || [ "$service_id" = "null" ]; then
        log_error "Failed to create test service for access phase test"
        return 1
    fi

    # Create route
    local route_data='{
        "paths": ["/lifecycle-test"],
        "methods": ["GET", "POST"]
    }'

    local route_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/routes" \
        -H "Content-Type: application/json" \
        -d "$route_data")

    local route_id=$(echo "$route_response" | jq -r '.id' 2>/dev/null)

    # Enable plugin with logging to capture access phase
    local plugin_data='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": true,
            "debug_logging": true,
            "threat_detection": {
                "enabled": true,
                "log_access_phase": true
            }
        }
    }'

    local plugin_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/plugins" \
        -H "Content-Type: application/json" \
        -d "$plugin_data")

    local plugin_id=$(echo "$plugin_response" | jq -r '.id' 2>/dev/null)

    if [ -z "$plugin_id" ] || [ "$plugin_id" = "null" ]; then
        log_error "Failed to enable plugin for access phase test"
        # Cleanup
        curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" > /dev/null 2>&1
        curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" > /dev/null 2>&1
        return 1
    fi

    # Make test request to trigger access phase
    local test_response=$(curl -s -w "%{http_code}" "$KONG_PROXY_URL/lifecycle-test/get" -o /dev/null)

    # Check if request was processed (indicating access phase executed)
    if [ "$test_response" = "200" ]; then
        log_success "Access phase executed successfully"
    else
        log_error "Access phase test failed with response code: $test_response"
    fi

    # Cleanup
    curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" > /dev/null 2>&1

    return 0
}

# Test log phase
test_log_phase() {
    log_info "Testing log phase..."

    # Similar setup as access phase but focused on log phase
    local service_data='{
        "name": "log-test-service",
        "url": "http://httpbin.org"
    }'

    local service_response=$(curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d "$service_data")

    local service_id=$(echo "$service_response" | jq -r '.id' 2>/dev/null)

    local route_data='{
        "paths": ["/log-test"],
        "methods": ["GET"]
    }'

    local route_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/routes" \
        -H "Content-Type: application/json" \
        -d "$route_data")

    local route_id=$(echo "$route_response" | jq -r '.id' 2>/dev/null)

    # Enable plugin with log phase focus
    local plugin_data='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": true,
            "logging": {
                "enabled": true,
                "log_level": "debug",
                "capture_request_body": true,
                "capture_response_body": true
            }
        }
    }'

    local plugin_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/plugins" \
        -H "Content-Type: application/json" \
        -d "$plugin_data")

    local plugin_id=$(echo "$plugin_response" | jq -r '.id' 2>/dev/null)

    if [ -n "$plugin_id" ] && [ "$plugin_id" != "null" ]; then
        # Make request to trigger log phase
        curl -s "$KONG_PROXY_URL/log-test/get" > /dev/null

        log_success "Log phase test completed"
    else
        log_error "Failed to enable plugin for log phase test"
    fi

    # Cleanup
    curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" > /dev/null 2>&1
}

# Test plugin configuration reload
test_config_reload() {
    log_info "Testing plugin configuration reload..."

    # Create service and route
    local service_data='{"name": "config-test-service", "url": "http://httpbin.org"}'
    local service_response=$(curl -s -X POST "$KONG_ADMIN_URL/services" -H "Content-Type: application/json" -d "$service_data")
    local service_id=$(echo "$service_response" | jq -r '.id' 2>/dev/null)

    local route_data='{"paths": ["/config-test"], "methods": ["GET"]}'
    local route_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/routes" -H "Content-Type: application/json" -d "$route_data")
    local route_id=$(echo "$route_response" | jq -r '.id' 2>/dev/null)

    # Enable plugin with initial config
    local initial_config='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": true,
            "threat_detection": {
                "rate_limit_threshold": 100
            }
        }
    }'

    local plugin_response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$service_id/plugins" -H "Content-Type: application/json" -d "$initial_config")
    local plugin_id=$(echo "$plugin_response" | jq -r '.id' 2>/dev/null)

    if [ -n "$plugin_id" ] && [ "$plugin_id" != "null" ]; then
        # Update plugin configuration
        local updated_config='{
            "config": {
                "dry_run": false,
                "threat_detection": {
                    "rate_limit_threshold": 50
                }
            }
        }'

        local update_response=$(curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" -H "Content-Type: application/json" -d "$updated_config")

        if echo "$update_response" | jq -e '.config.dry_run' | grep -q false; then
            log_success "Plugin configuration reload successful"
        else
            log_error "Plugin configuration reload failed"
        fi
    else
        log_error "Failed to create plugin for config reload test"
    fi

    # Cleanup
    curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" > /dev/null 2>&1
    curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" > /dev/null 2>&1
}

# Test plugin error handling
test_error_handling() {
    log_info "Testing plugin error handling..."

    # Try to create plugin with invalid configuration
    local invalid_config='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "invalid_field": "invalid_value",
            "threat_detection": {
                "rate_limit_threshold": "not_a_number"
            }
        }
    }'

    local error_response=$(curl -s -X POST "$KONG_ADMIN_URL/plugins" -H "Content-Type: application/json" -d "$invalid_config")

    if echo "$error_response" | jq -e '.message' | grep -q -i "error\|invalid"; then
        log_success "Plugin properly handles invalid configuration"
    else
        log_error "Plugin did not properly validate configuration"
    fi
}

# Test plugin metrics and status
test_plugin_status() {
    log_info "Testing plugin status and metrics..."

    # Check if plugin provides status endpoint
    local status_response=$(curl -s "$KONG_PROXY_URL/guard-ai/status" 2>/dev/null || echo "{}")

    if echo "$status_response" | jq -e '.plugin_status' > /dev/null 2>&1; then
        log_success "Plugin status endpoint accessible"
    else
        log_info "Plugin status endpoint not yet available (may be created later)"
    fi

    # Check plugin in Kong's plugin list
    local plugins_list=$(curl -s "$KONG_ADMIN_URL/plugins" | jq -r '.data[] | select(.name == "'$PLUGIN_NAME'") | .id' 2>/dev/null)

    if [ -n "$plugins_list" ]; then
        log_success "Plugin instances found in Kong"
    else
        log_info "No plugin instances currently active (expected in early testing)"
    fi
}

# Main lifecycle test function
main() {
    echo "============================================="
    echo "Kong Plugin Lifecycle Validation"
    echo "============================================="

    local failed_tests=0

    # Test each lifecycle phase
    test_init_worker_phase || ((failed_tests++))
    test_access_phase || ((failed_tests++))
    test_log_phase || ((failed_tests++))
    test_config_reload || ((failed_tests++))
    test_error_handling || ((failed_tests++))
    test_plugin_status || ((failed_tests++))

    echo "============================================="
    if [ $failed_tests -eq 0 ]; then
        log_success "All lifecycle tests passed!"
        exit 0
    else
        log_error "$failed_tests lifecycle test(s) failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
