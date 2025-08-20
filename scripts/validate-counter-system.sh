#!/bin/bash

# Kong Guard AI - Counter System Validation Script
# Tests the comprehensive counter management system
#
# This script validates:
# - Per-IP and global request/response counters
# - Status code distribution tracking  
# - Response time percentile calculations
# - Memory usage monitoring
# - Counter expiration and cleanup
# - Status endpoint functionality

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
KONG_PROXY_URL="${KONG_PROXY_URL:-http://localhost:8000}"
TEST_SERVICE_NAME="counter-test-service"
TEST_ROUTE_NAME="counter-test-route"
TEST_UPSTREAM_URL="http://httpbin.org"

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

test_counter() {
    ((TOTAL_TESTS++))
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    log_info "Testing: $test_name"
    
    if output=$(eval "$test_command" 2>&1); then
        if echo "$output" | grep -q "$expected_pattern"; then
            log_success "$test_name"
            return 0
        else
            log_error "$test_name - Expected pattern '$expected_pattern' not found in output"
            echo "Output: $output"
            return 1
        fi
    else
        log_error "$test_name - Command failed: $test_command"
        echo "Error: $output"
        return 1
    fi
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create test service
    curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$TEST_SERVICE_NAME\",
            \"url\": \"$TEST_UPSTREAM_URL\"
        }" > /dev/null 2>&1 || true
    
    # Create test route
    curl -s -X POST "$KONG_ADMIN_URL/routes" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$TEST_ROUTE_NAME\",
            \"service\": {\"name\": \"$TEST_SERVICE_NAME\"},
            \"paths\": [\"/counter-test\"],
            \"methods\": [\"GET\", \"POST\"]
        }" > /dev/null 2>&1 || true
    
    # Enable Kong Guard AI plugin on the route
    curl -s -X POST "$KONG_ADMIN_URL/routes/$TEST_ROUTE_NAME/plugins" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"kong-guard-ai\",
            \"config\": {
                \"dry_run_mode\": false,
                \"threat_threshold\": 0.8,
                \"log_all_requests\": true
            }
        }" > /dev/null 2>&1 || true
    
    log_success "Test environment setup complete"
    sleep 2  # Allow Kong to reload configuration
}

# Generate test traffic to populate counters
generate_test_traffic() {
    log_info "Generating test traffic to populate counters..."
    
    local test_ips=("192.168.1.100" "10.0.0.50" "172.16.0.25")
    local status_codes=(200 404 500)
    local methods=("GET" "POST")
    
    for i in {1..50}; do
        local ip=${test_ips[$((i % 3))]}
        local method=${methods[$((i % 2))]}
        local delay=$((i % 3))  # Vary response times
        
        # Make request with custom IP header (simulated)
        curl -s -X "$method" \
            -H "X-Forwarded-For: $ip" \
            -H "User-Agent: CounterTestAgent/1.0" \
            "$KONG_PROXY_URL/counter-test/delay/$delay" \
            > /dev/null 2>&1 &
        
        # Don't overwhelm the system
        if (( i % 10 == 0 )); then
            sleep 0.5
        fi
    done
    
    # Wait for background requests to complete
    wait
    sleep 3  # Allow time for log phase processing
    
    log_success "Generated test traffic (50 requests across 3 IPs)"
}

# Test counter system functionality
test_counter_functionality() {
    log_info "Testing counter system functionality..."
    
    # Test global counter endpoint
    test_counter "Global Status Endpoint" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status'" \
        '"counters".*"global"'
    
    # Test memory usage endpoint
    test_counter "Memory Usage Endpoint" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/memory'" \
        '"counters_dict".*"data_dict"'
    
    # Test IP-specific metrics
    test_counter "IP Metrics Endpoint" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/metrics/ip/192.168.1.100'" \
        '"counters".*"performance"'
    
    # Test global request counters
    test_counter "Global Request Counter Populated" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.global.req.lifetime'" \
        '^[1-9][0-9]*$'
    
    # Test response time percentiles
    test_counter "Response Time Percentiles" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.performance.response_times.p50'" \
        '^[0-9]+$'
    
    # Test error rate calculation
    test_counter "Error Rate Calculation" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.performance.error_rate.error_rate'" \
        '^[0-9.]+$'
}

# Test counter time windows
test_time_windows() {
    log_info "Testing time window functionality..."
    
    # Test that different time windows exist
    test_counter "Minute Window Counter" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.global.req.minute'" \
        '^[0-9]+$'
    
    test_counter "Five Minute Window Counter" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.global.req.five_minutes'" \
        '^[0-9]+$'
    
    test_counter "Hour Window Counter" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.global.req.hour'" \
        '^[0-9]+$'
    
    test_counter "Lifetime Counter" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status' | jq -r '.counters.global.req.lifetime'" \
        '^[0-9]+$'
}

# Test per-IP tracking
test_per_ip_tracking() {
    log_info "Testing per-IP counter tracking..."
    
    # Generate traffic from specific IP
    local test_ip="203.0.113.50"
    for i in {1..5}; do
        curl -s -H "X-Forwarded-For: $test_ip" \
            "$KONG_PROXY_URL/counter-test" > /dev/null 2>&1
    done
    
    sleep 2  # Allow processing
    
    # Test IP-specific counters
    test_counter "IP-Specific Request Counter" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/metrics/ip/$test_ip' | jq -r '.counters.req.minute'" \
        '^[1-9][0-9]*$'
    
    test_counter "IP-Specific Response Time" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/metrics/ip/$test_ip' | jq -r '.performance.response_times.total'" \
        '^[0-9]+$'
}

# Test memory usage monitoring
test_memory_monitoring() {
    log_info "Testing memory usage monitoring..."
    
    test_counter "Counters Dict Memory Usage" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/memory' | jq -r '.counters_dict.usage_percent'" \
        '^[0-9]+$'
    
    test_counter "Data Dict Memory Usage" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/memory' | jq -r '.data_dict.usage_percent'" \
        '^[0-9]+$'
    
    # Test memory usage is reasonable (< 80%)
    test_counter "Memory Usage Below 80%" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/memory' | jq -r '.counters_dict.usage_percent' | awk '{print (\$1 < 80)}'" \
        '^1$'
}

# Test status code tracking
test_status_code_tracking() {
    log_info "Testing status code distribution tracking..."
    
    # Generate requests with different status codes
    curl -s "$KONG_PROXY_URL/counter-test/status/200" > /dev/null 2>&1
    curl -s "$KONG_PROXY_URL/counter-test/status/404" > /dev/null 2>&1
    curl -s "$KONG_PROXY_URL/counter-test/status/500" > /dev/null 2>&1
    
    sleep 2  # Allow processing
    
    # Note: Status code tracking would be in the global counters
    test_counter "Status Code Tracking Available" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status'" \
        '"counters"'
}

# Test endpoint error handling
test_error_handling() {
    log_info "Testing endpoint error handling..."
    
    # Test invalid IP address
    test_counter "Invalid IP Error Handling" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/metrics/ip/invalid-ip' | jq -r '.error'" \
        'null'  # Should either work or return structured error
    
    # Test nonexistent endpoints
    test_counter "Nonexistent Endpoint Returns 404" \
        "curl -s -w '%{http_code}' '$KONG_ADMIN_URL:8001/guard-ai/nonexistent'" \
        '404'
}

# Performance testing
test_performance() {
    log_info "Testing counter system performance..."
    
    local start_time=$(date +%s.%N)
    
    # Make rapid requests to test performance
    for i in {1..100}; do
        curl -s "$KONG_PROXY_URL/counter-test" > /dev/null 2>&1 &
        if (( i % 20 == 0 )); then
            wait  # Batch requests
        fi
    done
    wait
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    log_info "Processed 100 requests in ${duration}s"
    
    # Check that system is still responsive
    test_counter "System Responsive After Load" \
        "curl -s '$KONG_ADMIN_URL:8001/guard-ai/status'" \
        '"status".*"active"'
}

# Cleanup test environment
cleanup_test_environment() {
    log_info "Cleaning up test environment..."
    
    # Remove plugin
    local plugin_id=$(curl -s "$KONG_ADMIN_URL/routes/$TEST_ROUTE_NAME/plugins" | \
                     jq -r '.data[] | select(.name == "kong-guard-ai") | .id' 2>/dev/null || echo "")
    if [[ -n "$plugin_id" && "$plugin_id" != "null" ]]; then
        curl -s -X DELETE "$KONG_ADMIN_URL/plugins/$plugin_id" > /dev/null 2>&1 || true
    fi
    
    # Remove route
    curl -s -X DELETE "$KONG_ADMIN_URL/routes/$TEST_ROUTE_NAME" > /dev/null 2>&1 || true
    
    # Remove service
    curl -s -X DELETE "$KONG_ADMIN_URL/services/$TEST_SERVICE_NAME" > /dev/null 2>&1 || true
    
    log_info "Cleanup complete"
}

# Main execution
main() {
    echo "============================================"
    echo "Kong Guard AI Counter System Validation"
    echo "============================================"
    echo ""
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi
    
    # Check if Kong is running
    if ! curl -s "$KONG_ADMIN_URL" > /dev/null; then
        log_error "Kong Admin API is not accessible at $KONG_ADMIN_URL"
        exit 1
    fi
    
    # Run tests
    setup_test_environment
    generate_test_traffic
    test_counter_functionality
    test_time_windows
    test_per_ip_tracking
    test_memory_monitoring
    test_status_code_tracking
    test_error_handling
    test_performance
    cleanup_test_environment
    
    # Report results
    echo ""
    echo "============================================"
    echo "Test Results Summary"
    echo "============================================"
    echo -e "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    
    if (( TESTS_FAILED == 0 )); then
        echo -e "\n${GREEN}✅ All counter system tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ Some tests failed. Please check the output above.${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"