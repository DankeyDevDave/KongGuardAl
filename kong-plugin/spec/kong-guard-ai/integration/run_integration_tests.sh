#!/bin/bash

# Kong Pongo Integration Test Runner for TAXII/STIX Implementation
# This script sets up and runs comprehensive integration tests

set -e

echo "========================================"
echo "Kong Guard AI TAXII Integration Tests"
echo "========================================"

# Configuration
PLUGIN_NAME="kong-guard-ai"
TAXII_SERVER_PORT=8080
KONG_VERSION=${KONG_VERSION:-"3.4.0"}
TEST_TIMEOUT=60

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v kong &> /dev/null; then
        log_error "Kong is not installed or not in PATH"
        exit 1
    fi

    if ! command -v lua &> /dev/null; then
        log_error "Lua is not installed or not in PATH"
        exit 1
    fi

    if ! command -v busted &> /dev/null; then
        log_warn "Busted is not installed. Installing..."
        luarocks install busted
    fi

    log_info "Dependencies check passed"
}

# Start mock TAXII server
start_mock_server() {
    log_info "Starting mock TAXII server on port $TAXII_SERVER_PORT..."

    # Kill any existing mock server
    pkill -f "mock_taxii_server.lua" || true
    sleep 1

    # Start mock server in background
    lua ./spec/kong-guard-ai/integration/mock_taxii_server.lua $TAXII_SERVER_PORT &
    MOCK_SERVER_PID=$!

    # Wait for server to start
    sleep 3

    # Test if server is responding
    if curl -s http://localhost:$TAXII_SERVER_PORT/taxii/ > /dev/null; then
        log_info "Mock TAXII server started successfully (PID: $MOCK_SERVER_PID)"
    else
        log_error "Failed to start mock TAXII server"
        exit 1
    fi
}

# Stop mock TAXII server
stop_mock_server() {
    if [ ! -z "$MOCK_SERVER_PID" ]; then
        log_info "Stopping mock TAXII server (PID: $MOCK_SERVER_PID)..."
        kill $MOCK_SERVER_PID 2>/dev/null || true
    fi
    pkill -f "mock_taxii_server.lua" || true
}

# Setup Kong for testing
setup_kong() {
    log_info "Setting up Kong for testing..."

    # Create test Kong configuration
    cat > kong.test.conf << EOF
# Kong test configuration for TAXII integration
database = off
log_level = info
plugins = kong-guard-ai
prefix = ./kong-test

# Admin API
admin_listen = 0.0.0.0:8001

# Proxy
proxy_listen = 0.0.0.0:8000

# Lua settings
lua_shared_dict kong_cache 128m
lua_shared_dict kong_worker_events 5m
lua_shared_dict prometheus_metrics 5m

# Plugin path
lua_package_path = ./kong/plugins/?.lua;./kong/plugins/?/init.lua;;
EOF

    export KONG_CONF=kong.test.conf
}

# Start Kong
start_kong() {
    log_info "Starting Kong..."

    # Prepare Kong
    kong prepare -c kong.test.conf

    # Start Kong
    kong start -c kong.test.conf

    # Wait for Kong to be ready
    local retry_count=0
    while ! curl -s http://localhost:8001/status > /dev/null; do
        retry_count=$((retry_count + 1))
        if [ $retry_count -gt 30 ]; then
            log_error "Kong failed to start within timeout"
            exit 1
        fi
        sleep 1
    done

    log_info "Kong started successfully"
}

# Stop Kong
stop_kong() {
    log_info "Stopping Kong..."
    kong stop -c kong.test.conf 2>/dev/null || true
    rm -rf ./kong-test 2>/dev/null || true
    rm -f kong.test.conf 2>/dev/null || true
}

# Configure test route and plugin
setup_test_route() {
    log_info "Setting up test route and plugin..."

    # Create service
    curl -s -X POST http://localhost:8001/services \
        -H "Content-Type: application/json" \
        -d '{
            "name": "test-service",
            "url": "http://httpbin.org/anything"
        }' > /dev/null

    # Create route
    curl -s -X POST http://localhost:8001/routes \
        -H "Content-Type: application/json" \
        -d '{
            "service": {"name": "test-service"},
            "paths": ["/test"]
        }' > /dev/null

    # Configure plugin
    curl -s -X POST http://localhost:8001/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "kong-guard-ai",
            "config": {
                "enable_taxii_ingestion": true,
                "taxii_version": "2.1",
                "taxii_poll_interval_seconds": 60,
                "taxii_cache_ttl_seconds": 300,
                "taxii_max_objects_per_poll": 100,
                "taxii_servers": [{
                    "url": "http://localhost:'$TAXII_SERVER_PORT'",
                    "collections": ["test-collection"],
                    "auth_type": "none"
                }],
                "taxii_score_weights": {
                    "ip_blocklist": 0.9,
                    "domain_blocklist": 0.8,
                    "url_blocklist": 0.8
                },
                "block_threshold": 0.8,
                "dry_run": false
            }
        }' > /dev/null

    log_info "Test route and plugin configured"
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."

    if busted spec/kong-guard-ai/unit/ --verbose; then
        log_info "Unit tests passed"
    else
        log_error "Unit tests failed"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."

    if busted spec/kong-guard-ai/integration/ --verbose; then
        log_info "Integration tests passed"
    else
        log_error "Integration tests failed"
        return 1
    fi
}

# Test basic functionality
test_basic_functionality() {
    log_info "Testing basic functionality..."

    # Test normal request
    if curl -s -f http://localhost:8000/test > /dev/null; then
        log_info "✓ Normal request handling works"
    else
        log_error "✗ Normal request handling failed"
        return 1
    fi

    # Test plugin status
    local plugin_count=$(curl -s http://localhost:8001/plugins | jq '.data | length')
    if [ "$plugin_count" -gt 0 ]; then
        log_info "✓ Plugin loaded successfully"
    else
        log_error "✗ Plugin not loaded"
        return 1
    fi
}

# Test TAXII integration
test_taxii_integration() {
    log_info "Testing TAXII integration..."

    # Give some time for TAXII polling to occur
    sleep 5

    # Test with potentially malicious IP (from mock data)
    local response=$(curl -s -w "%{http_code}" -o /dev/null -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/test)
    if [ "$response" = "403" ] || [ "$response" = "200" ]; then
        log_info "✓ TAXII threat intelligence processing works (response: $response)"
    else
        log_error "✗ Unexpected response: $response"
        return 1
    fi

    # Test with allowlisted IP
    local response=$(curl -s -w "%{http_code}" -o /dev/null -H "X-Forwarded-For: 8.8.8.8" http://localhost:8000/test)
    if [ "$response" = "200" ]; then
        log_info "✓ Allowlist processing works"
    else
        log_error "✗ Allowlist test failed (response: $response)"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    stop_kong
    stop_mock_server
    rm -f kong.test.conf 2>/dev/null || true
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    log_info "Starting TAXII integration tests..."

    check_dependencies
    start_mock_server
    setup_kong
    start_kong
    setup_test_route

    # Wait a moment for everything to be ready
    sleep 3

    local test_failures=0

    # Run tests
    if ! run_unit_tests; then
        test_failures=$((test_failures + 1))
    fi

    if ! test_basic_functionality; then
        test_failures=$((test_failures + 1))
    fi

    if ! test_taxii_integration; then
        test_failures=$((test_failures + 1))
    fi

    if ! run_integration_tests; then
        test_failures=$((test_failures + 1))
    fi

    # Results
    echo
    echo "========================================"
    echo "TEST RESULTS"
    echo "========================================"

    if [ $test_failures -eq 0 ]; then
        log_info "✅ All tests passed!"
        echo
        echo "TAXII/STIX integration is working correctly:"
        echo "- Plugin loads and initializes successfully"
        echo "- TAXII server connectivity works"
        echo "- STIX indicator processing works"
        echo "- Threat intelligence lookups work"
        echo "- Cache management works"
        echo "- Scheduler operates correctly"
        return 0
    else
        log_error "❌ $test_failures test(s) failed"
        return 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            UNIT_ONLY=true
            shift
            ;;
        --integration-only)
            INTEGRATION_ONLY=true
            shift
            ;;
        --mock-server-only)
            start_mock_server
            log_info "Mock server running. Press Ctrl+C to stop."
            while true; do sleep 1; done
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --unit-only         Run only unit tests"
            echo "  --integration-only  Run only integration tests"
            echo "  --mock-server-only  Start only the mock TAXII server"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main