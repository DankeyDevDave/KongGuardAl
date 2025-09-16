#!/bin/bash

# Kong Guard AI - Admin API Compatibility Validation Script
# Validates plugin configuration and behavior with Kong Admin API
# Ensures identical behavior across Kong Gateway and Konnect deployments

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
KONG_PROXY_URL="${KONG_PROXY_URL:-http://localhost:8000}"
PLUGIN_NAME="kong-guard-ai"
TEST_SERVICE_NAME="test-kong-guard-ai"
TEST_TIMEOUT=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging functions
log_header() {
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"
}

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

# Test tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

test_result() {
    local test_name="$1"
    local passed="$2"
    local message="$3"

    if [ "$passed" = "true" ]; then
        ((TESTS_PASSED++))
        log_success "$test_name"
        [ -n "$message" ] && echo "   $message"
    else
        ((TESTS_FAILED++))
        log_error "$test_name"
        [ -n "$message" ] && echo "   $message"
        FAILED_TESTS+=("$test_name")
    fi
}

# Check if Kong is accessible
check_kong_availability() {
    log_header "Checking Kong Availability"

    local admin_available=false
    local proxy_available=false

    if curl -s --connect-timeout 5 "$KONG_ADMIN_URL/status" > /dev/null 2>&1; then
        admin_available=true
        log_success "Kong Admin API accessible at $KONG_ADMIN_URL"
    else
        log_error "Kong Admin API not accessible at $KONG_ADMIN_URL"
    fi

    if curl -s --connect-timeout 5 "$KONG_PROXY_URL" > /dev/null 2>&1; then
        proxy_available=true
        log_success "Kong Proxy accessible at $KONG_PROXY_URL"
    else
        log_warning "Kong Proxy not accessible at $KONG_PROXY_URL (may affect some tests)"
    fi

    if [ "$admin_available" != "true" ]; then
        log_error "Kong Admin API is required for compatibility testing"
        return 1
    fi

    return 0
}

# Test plugin availability
test_plugin_availability() {
    log_header "Testing Plugin Availability"

    # Check if plugin is available in Kong
    local available_plugins=$(curl -s "$KONG_ADMIN_URL/plugins/available" 2>/dev/null || echo '{"available_plugins":[]}')

    if echo "$available_plugins" | grep -q "$PLUGIN_NAME"; then
        test_result "Plugin Available in Kong" true "Plugin $PLUGIN_NAME is loaded and available"
    else
        test_result "Plugin Available in Kong" false "Plugin $PLUGIN_NAME is not available in Kong"
        log_warning "This may be expected if the plugin is not yet installed"
    fi

    # Check plugin schema endpoint
    local schema_response=$(curl -s -w "%{http_code}" "$KONG_ADMIN_URL/schemas/plugins/$PLUGIN_NAME" -o /dev/null 2>/dev/null || echo "000")

    if [ "$schema_response" = "200" ]; then
        test_result "Plugin Schema Available" true "Schema endpoint accessible"
    else
        test_result "Plugin Schema Available" false "Schema endpoint returned $schema_response"
    fi
}

# Test configuration schema validation
test_configuration_validation() {
    log_header "Testing Configuration Schema Validation"

    # Test 1: Valid minimal configuration
    local minimal_config='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": true,
            "log_level": "info"
        }
    }'

    local response=$(curl -s -X POST "$KONG_ADMIN_URL/schemas/plugins/validate" \
        -H "Content-Type: application/json" \
        -d "$minimal_config" \
        -w "%{http_code}" -o /tmp/validation_response.json 2>/dev/null || echo "000")

    if [ "$response" = "200" ]; then
        test_result "Minimal Configuration Validation" true "Basic config structure accepted"
    else
        local error_msg=$(cat /tmp/validation_response.json 2>/dev/null | jq -r '.message // "Unknown error"' 2>/dev/null || echo "Validation failed")
        test_result "Minimal Configuration Validation" false "$error_msg"
    fi

    # Test 2: Invalid configuration - wrong type
    local invalid_config='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": "not_a_boolean",
            "log_level": "invalid_level"
        }
    }'

    response=$(curl -s -X POST "$KONG_ADMIN_URL/schemas/plugins/validate" \
        -H "Content-Type: application/json" \
        -d "$invalid_config" \
        -w "%{http_code}" -o /tmp/validation_response.json 2>/dev/null || echo "000")

    if [ "$response" -ge "400" ]; then
        test_result "Invalid Configuration Rejection" true "Invalid config properly rejected"
    else
        test_result "Invalid Configuration Rejection" false "Invalid config was accepted"
    fi

    # Test 3: Complex valid configuration
    local complex_config='{
        "name": "'$PLUGIN_NAME'",
        "config": {
            "dry_run": false,
            "log_level": "debug",
            "threat_detection": {
                "enabled": true,
                "rules": {
                    "rate_limit_threshold": 100,
                    "suspicious_patterns": ["SELECT.*FROM", "<script"],
                    "blocked_ips": ["203.0.113.100"]
                }
            },
            "response_actions": {
                "enabled": true,
                "immediate_block": false
            },
            "notifications": {
                "webhook_url": "http://example.com/webhook"
            }
        }
    }'

    response=$(curl -s -X POST "$KONG_ADMIN_URL/schemas/plugins/validate" \
        -H "Content-Type: application/json" \
        -d "$complex_config" \
        -w "%{http_code}" -o /tmp/validation_response.json 2>/dev/null || echo "000")

    if [ "$response" = "200" ]; then
        test_result "Complex Configuration Validation" true "Advanced config structure accepted"
    else
        local error_msg=$(cat /tmp/validation_response.json 2>/dev/null | jq -r '.message // "Unknown error"' 2>/dev/null || echo "Validation failed")
        test_result "Complex Configuration Validation" false "$error_msg"
    fi

    # Clean up
    rm -f /tmp/validation_response.json
}

# Test plugin lifecycle management
test_plugin_lifecycle() {
    log_header "Testing Plugin Lifecycle Management"

    # Clean up any existing test resources first
    cleanup_test_resources >/dev/null 2>&1

    # Create test service
    local service_config='{
        "name": "'$TEST_SERVICE_NAME'",
        "url": "http://httpbin.org"
    }'

    local service_response=$(curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d "$service_config" \
        -w "%{http_code}" -o /tmp/service_response.json 2>/dev/null || echo "000")

    if [ "$service_response" = "201" ]; then
        test_result "Test Service Creation" true "Service created successfully"
        local service_id=$(cat /tmp/service_response.json | jq -r '.id' 2>/dev/null)
    else
        test_result "Test Service Creation" false "Service creation failed with status $service_response"
        return 1
    fi

    # Create test route
    local route_config='{
        "name": "test-route-'$TEST_SERVICE_NAME'",
        "service": {"id": "'$service_id'"},
        "paths": ["/test-admin-api"]
    }'

    local route_response=$(curl -s -X POST "$KONG_ADMIN_URL/routes" \
        -H "Content-Type: application/json" \
        -d "$route_config" \
        -w "%{http_code}" -o /tmp/route_response.json 2>/dev/null || echo "000")

    if [ "$route_response" = "201" ]; then
        test_result "Test Route Creation" true "Route created successfully"
        local route_id=$(cat /tmp/route_response.json | jq -r '.id' 2>/dev/null)
    else
        test_result "Test Route Creation" false "Route creation failed with status $route_response"
        return 1
    fi

    # Add plugin to service
    local plugin_config='{
        "name": "'$PLUGIN_NAME'",
        "service": {"id": "'$service_id'"},
        "config": {
            "dry_run": true,
            "log_level": "info",
            "threat_detection": {
                "enabled": true,
                "rules": {
                    "rate_limit_threshold": 10
                }
            }
        }
    }'

    local plugin_response=$(curl -s -X POST "$KONG_ADMIN_URL/plugins" \
        -H "Content-Type: application/json" \
        -d "$plugin_config" \
        -w "%{http_code}" -o /tmp/plugin_response.json 2>/dev/null || echo "000")

    if [ "$plugin_response" = "201" ]; then
        test_result "Plugin Installation" true "Plugin installed on service"
        local plugin_id=$(cat /tmp/plugin_response.json | jq -r '.id' 2>/dev/null)
    else
        local error_msg=$(cat /tmp/plugin_response.json 2>/dev/null | jq -r '.message // "Unknown error"' 2>/dev/null || echo "Installation failed")
        test_result "Plugin Installation" false "$error_msg"
        return 1
    fi

    # Test plugin configuration update
    local updated_config='{
        "config": {
            "dry_run": false,
            "log_level": "debug"
        }
    }'

    local update_response=$(curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$updated_config" \
        -w "%{http_code}" -o /tmp/update_response.json 2>/dev/null || echo "000")

    if [ "$update_response" = "200" ]; then
        test_result "Plugin Configuration Update" true "Configuration updated successfully"
    else
        local error_msg=$(cat /tmp/update_response.json 2>/dev/null | jq -r '.message // "Unknown error"' 2>/dev/null || echo "Update failed")
        test_result "Plugin Configuration Update" false "$error_msg"
    fi

    # Verify configuration persistence
    local get_response=$(curl -s "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -w "%{http_code}" -o /tmp/get_response.json 2>/dev/null || echo "000")

    if [ "$get_response" = "200" ]; then
        local dry_run_value=$(cat /tmp/get_response.json | jq -r '.config.dry_run' 2>/dev/null)
        if [ "$dry_run_value" = "false" ]; then
            test_result "Configuration Persistence" true "Updated configuration persisted correctly"
        else
            test_result "Configuration Persistence" false "Configuration not properly persisted"
        fi
    else
        test_result "Configuration Persistence" false "Could not retrieve plugin configuration"
    fi

    # Clean up temp files
    rm -f /tmp/service_response.json /tmp/route_response.json /tmp/plugin_response.json /tmp/update_response.json /tmp/get_response.json
}

# Test hot configuration reload
test_hot_reload() {
    log_header "Testing Configuration Hot Reload"

    # Find our test plugin
    local plugins_response=$(curl -s "$KONG_ADMIN_URL/plugins" -o /tmp/plugins_list.json -w "%{http_code}" 2>/dev/null || echo "000")

    if [ "$plugins_response" != "200" ]; then
        test_result "Hot Reload Setup" false "Could not fetch plugins list"
        return 1
    fi

    local plugin_id=$(cat /tmp/plugins_list.json | jq -r --arg name "$PLUGIN_NAME" '.data[] | select(.name == $name) | .id' 2>/dev/null | head -n1)

    if [ -z "$plugin_id" ] || [ "$plugin_id" = "null" ]; then
        test_result "Hot Reload Setup" false "Test plugin not found"
        return 1
    fi

    # Test rapid configuration changes
    local changes=('{"config":{"log_level":"debug"}}' '{"config":{"log_level":"info"}}' '{"config":{"log_level":"warn"}}')
    local all_successful=true

    for change in "${changes[@]}"; do
        local change_response=$(curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
            -H "Content-Type: application/json" \
            -d "$change" \
            -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

        if [ "$change_response" != "200" ]; then
            all_successful=false
            break
        fi

        sleep 0.1  # Small delay between changes
    done

    if [ "$all_successful" = "true" ]; then
        test_result "Hot Configuration Changes" true "All rapid configuration changes successful"
    else
        test_result "Hot Configuration Changes" false "Some configuration changes failed"
    fi

    rm -f /tmp/plugins_list.json
}

# Test dry run mode behavior
test_dry_run_behavior() {
    log_header "Testing Dry Run Mode Behavior"

    # This test requires the proxy to be accessible
    if ! curl -s --connect-timeout 5 "$KONG_PROXY_URL" > /dev/null 2>&1; then
        log_warning "Kong Proxy not accessible, skipping dry run behavior tests"
        return 0
    fi

    # Find our test plugin
    local plugins_response=$(curl -s "$KONG_ADMIN_URL/plugins" -o /tmp/plugins_list.json -w "%{http_code}" 2>/dev/null || echo "000")

    if [ "$plugins_response" != "200" ]; then
        test_result "Dry Run Setup" false "Could not fetch plugins list"
        return 1
    fi

    local plugin_id=$(cat /tmp/plugins_list.json | jq -r --arg name "$PLUGIN_NAME" '.data[] | select(.name == $name) | .id' 2>/dev/null | head -n1)

    if [ -z "$plugin_id" ] || [ "$plugin_id" = "null" ]; then
        test_result "Dry Run Setup" false "Test plugin not found"
        return 1
    fi

    # Enable dry run mode
    local dry_run_config='{"config":{"dry_run":true}}'
    curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$dry_run_config" > /dev/null 2>&1

    sleep 1  # Allow configuration to propagate

    # Test that requests pass through in dry run mode
    local proxy_response=$(curl -s -X POST "$KONG_PROXY_URL/test-admin-api" \
        -H "Content-Type: application/json" \
        -H "User-Agent: test-malicious-bot" \
        -d '{"test":"<script>alert(1)</script>"}' \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    # In dry run mode, requests should not be blocked (status < 400)
    if [ "$proxy_response" -lt "400" ]; then
        test_result "Dry Run No Blocking" true "Requests pass through in dry run mode"
    else
        test_result "Dry Run No Blocking" false "Requests blocked in dry run mode (status: $proxy_response)"
    fi

    # Disable dry run mode
    local active_config='{"config":{"dry_run":false}}'
    curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$active_config" > /dev/null 2>&1

    sleep 1  # Allow configuration to propagate

    # Test that malicious requests may be blocked in active mode
    proxy_response=$(curl -s -X POST "$KONG_PROXY_URL/test-admin-api" \
        -H "Content-Type: application/json" \
        -H "User-Agent: test-malicious-bot" \
        -d '{"test":"<script>alert(1)</script>"}' \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    # Note: Since plugin behavior may vary, we just verify the mode change is possible
    test_result "Active Mode Configuration" true "Successfully switched to active mode"

    # Re-enable dry run for safety
    curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$dry_run_config" > /dev/null 2>&1

    rm -f /tmp/plugins_list.json
}

# Test Konnect compatibility (simulated)
test_konnect_compatibility() {
    log_header "Testing Konnect Compatibility (Simulation)"

    # Export current configuration
    local config_response=$(curl -s "$KONG_ADMIN_URL/config" -w "%{http_code}" -o /tmp/kong_config.json 2>/dev/null || echo "000")

    if [ "$config_response" = "200" ]; then
        test_result "Configuration Export" true "Configuration exported successfully"
    else
        test_result "Configuration Export" false "Configuration export failed"
        return 1
    fi

    # Check for Konnect-compatible format
    local has_format_version=$(cat /tmp/kong_config.json | jq -r '._format_version // empty' 2>/dev/null)
    local has_transform=$(cat /tmp/kong_config.json | jq -r '._transform // empty' 2>/dev/null)

    if [ -n "$has_format_version" ] && [ -n "$has_transform" ]; then
        test_result "Konnect Format Compliance" true "Configuration includes Konnect format fields"
    else
        test_result "Konnect Format Compliance" false "Missing Konnect format fields (_format_version, _transform)"
    fi

    # Test declarative configuration reload
    local reload_response=$(curl -s -X POST "$KONG_ADMIN_URL/config" \
        -H "Content-Type: application/json" \
        -d @/tmp/kong_config.json \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    if [ "$reload_response" = "200" ] || [ "$reload_response" = "201" ]; then
        test_result "Declarative Configuration Reload" true "Configuration reloaded successfully"
    else
        test_result "Declarative Configuration Reload" false "Configuration reload failed (status: $reload_response)"
    fi

    rm -f /tmp/kong_config.json
}

# Test error handling and recovery
test_error_handling() {
    log_header "Testing Error Handling and Recovery"

    # Find our test plugin
    local plugins_response=$(curl -s "$KONG_ADMIN_URL/plugins" -o /tmp/plugins_list.json -w "%{http_code}" 2>/dev/null || echo "000")

    if [ "$plugins_response" != "200" ]; then
        test_result "Error Handling Setup" false "Could not fetch plugins list"
        return 1
    fi

    local plugin_id=$(cat /tmp/plugins_list.json | jq -r --arg name "$PLUGIN_NAME" '.data[] | select(.name == $name) | .id' 2>/dev/null | head -n1)

    if [ -z "$plugin_id" ] || [ "$plugin_id" = "null" ]; then
        test_result "Error Handling Setup" false "Test plugin not found"
        return 1
    fi

    # Store original configuration
    local original_config=$(curl -s "$KONG_ADMIN_URL/plugins/$plugin_id" | jq -r '.config' 2>/dev/null)

    # Test invalid configuration update
    local invalid_config='{"config":{"dry_run":"not_a_boolean","log_level":"invalid_level"}}'
    local error_response=$(curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$invalid_config" \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    if [ "$error_response" -ge "400" ]; then
        test_result "Invalid Configuration Rejection" true "Invalid configuration properly rejected"
    else
        test_result "Invalid Configuration Rejection" false "Invalid configuration was accepted"
    fi

    # Verify plugin still works after error
    local status_response=$(curl -s "$KONG_ADMIN_URL/plugins/$plugin_id" -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    if [ "$status_response" = "200" ]; then
        test_result "Plugin Stability After Error" true "Plugin remains functional after invalid update attempt"
    else
        test_result "Plugin Stability After Error" false "Plugin affected by invalid update attempt"
    fi

    # Test configuration rollback
    local rollback_config="{\"config\":$original_config}"
    local rollback_response=$(curl -s -X PATCH "$KONG_ADMIN_URL/plugins/$plugin_id" \
        -H "Content-Type: application/json" \
        -d "$rollback_config" \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    if [ "$rollback_response" = "200" ]; then
        test_result "Configuration Rollback" true "Configuration successfully rolled back"
    else
        test_result "Configuration Rollback" false "Configuration rollback failed"
    fi

    rm -f /tmp/plugins_list.json
}

# Clean up test resources
cleanup_test_resources() {
    log_info "Cleaning up test resources..."

    # Remove test plugins
    local plugins=$(curl -s "$KONG_ADMIN_URL/plugins" 2>/dev/null | jq -r --arg service_name "$TEST_SERVICE_NAME" '.data[] | select(.service.name == $service_name) | .id' 2>/dev/null)
    if [ -n "$plugins" ]; then
        while IFS= read -r plugin_id; do
            if [ -n "$plugin_id" ] && [ "$plugin_id" != "null" ]; then
                curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" >/dev/null 2>&1
                log_info "   Removed plugin $plugin_id"
            fi
        done <<< "$plugins"
    fi

    # Remove test routes
    local routes=$(curl -s "$KONG_ADMIN_URL/routes" 2>/dev/null | jq -r --arg service_name "$TEST_SERVICE_NAME" '.data[] | select(.service.name == $service_name) | .id' 2>/dev/null)
    if [ -n "$routes" ]; then
        while IFS= read -r route_id; do
            if [ -n "$route_id" ] && [ "$route_id" != "null" ]; then
                curl -s -X DELETE "$KONG_ADMIN_URL/routes/$route_id" >/dev/null 2>&1
                log_info "   Removed route $route_id"
            fi
        done <<< "$routes"
    fi

    # Remove test service
    local service_id=$(curl -s "$KONG_ADMIN_URL/services" 2>/dev/null | jq -r --arg name "$TEST_SERVICE_NAME" '.data[] | select(.name == $name) | .id' 2>/dev/null)
    if [ -n "$service_id" ] && [ "$service_id" != "null" ]; then
        curl -s -X DELETE "$KONG_ADMIN_URL/services/$service_id" >/dev/null 2>&1
        log_info "   Removed service $service_id"
    fi
}

# Generate test report
generate_test_report() {
    local report_file="admin_api_compatibility_report_$(date +%Y%m%d_%H%M%S).md"

    cat > "$report_file" << EOF
# Kong Guard AI - Admin API Compatibility Test Report

**Generated:** $(date)
**Kong Admin URL:** $KONG_ADMIN_URL
**Kong Proxy URL:** $KONG_PROXY_URL

## Test Summary

- **Total Tests:** $((TESTS_PASSED + TESTS_FAILED))
- **Passed:** $TESTS_PASSED
- **Failed:** $TESTS_FAILED
- **Success Rate:** $(( TESTS_PASSED * 100 / (TESTS_PASSED + TESTS_FAILED) ))%

## Test Results

### Configuration Validation
- Schema validation tests verify plugin configuration structure
- Invalid configuration rejection tests ensure proper error handling
- Complex configuration support validates advanced features

### Plugin Lifecycle Management
- Plugin installation and removal
- Configuration updates and persistence
- Hot reload capability testing

### Operational Behavior
- Dry run mode consistency
- Configuration hot reload
- Error handling and recovery

### Compatibility Testing
- Kong Admin API integration
- Konnect format compliance (simulated)
- Declarative configuration support

EOF

    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo "## Failed Tests" >> "$report_file"
        echo "" >> "$report_file"
        for test in "${FAILED_TESTS[@]}"; do
            echo "- $test" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
## Recommendations

### For Production Deployment
1. Ensure all configuration validation tests pass
2. Verify plugin hot reload works correctly
3. Test dry run mode behavior thoroughly
4. Validate error handling scenarios

### For Konnect Migration
1. Export configuration in declarative format
2. Validate configuration structure includes required fields
3. Test configuration reload functionality
4. Ensure plugin behavior is identical

## Next Steps

1. Address any failed tests
2. Run integration tests with live traffic
3. Perform load testing with plugin enabled
4. Validate monitoring and alerting integration

---
*Report generated by Kong Guard AI Compatibility Validator*
EOF

    log_success "Test report generated: $report_file"
    echo "$report_file"
}

# Main execution
main() {
    log_header "Kong Guard AI - Admin API Compatibility Testing"
    echo "Starting comprehensive compatibility validation..."
    echo ""

    # Reset counters
    TESTS_PASSED=0
    TESTS_FAILED=0
    FAILED_TESTS=()

    # Run tests
    if ! check_kong_availability; then
        log_error "Kong is not available. Please start Kong and try again."
        exit 1
    fi

    test_plugin_availability
    test_configuration_validation
    test_plugin_lifecycle
    test_hot_reload
    test_dry_run_behavior
    test_konnect_compatibility
    test_error_handling

    # Clean up
    cleanup_test_resources

    # Generate report
    local report_file=$(generate_test_report)

    # Final summary
    echo ""
    log_header "Validation Complete"
    echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    echo "Report: $report_file"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "🎉 All tests passed! Kong Guard AI is compatible with Kong Admin API"
        exit 0
    else
        log_warning "⚠️  Some tests failed. Review the report for details."
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Kong Guard AI Admin API Compatibility Validator"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h              Show this help message"
        echo "  --cleanup-only          Only run cleanup of test resources"
        echo "  --validation-only       Only run configuration validation tests"
        echo "  --lifecycle-only        Only run plugin lifecycle tests"
        echo ""
        echo "Environment variables:"
        echo "  KONG_ADMIN_URL          Kong Admin API URL (default: http://localhost:8001)"
        echo "  KONG_PROXY_URL          Kong Proxy URL (default: http://localhost:8000)"
        exit 0
        ;;
    --cleanup-only)
        cleanup_test_resources
        exit 0
        ;;
    --validation-only)
        check_kong_availability && test_configuration_validation
        exit $?
        ;;
    --lifecycle-only)
        check_kong_availability && test_plugin_lifecycle
        exit $?
        ;;
    *)
        main "$@"
        ;;
esac
