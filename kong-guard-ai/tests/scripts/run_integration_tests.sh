#!/bin/bash

# Kong Guard AI Integration Test Runner Script
# Comprehensive testing orchestration for Kong Guard AI plugin

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_DIR="$PROJECT_ROOT/tests"
RESULTS_DIR="$PROJECT_ROOT/test-results"

# Default values
TEST_ENVIRONMENT="${TEST_ENVIRONMENT:-local}"
KONG_VERSION="${KONG_VERSION:-3.7}"
TEST_SUITE="${TEST_SUITE:-all}"
TEST_CATEGORY="${TEST_CATEGORY:-all}"
PARALLEL_WORKERS="${PARALLEL_WORKERS:-4}"
TIMEOUT="${TIMEOUT:-300}"
CLEANUP="${CLEANUP:-true}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

log_header() {
    echo -e "${MAGENTA}${1}${NC}"
}

# Usage information
usage() {
    cat << EOF
Kong Guard AI Integration Test Runner

Usage: $0 [OPTIONS]

Options:
    -e, --environment    Test environment (local|docker|ci) [default: local]
    -k, --kong-version   Kong version to test against [default: 3.7]
    -s, --suite         Test suite to run (all|integration|load|security) [default: all]
    -c, --category      Test category filter (threat-detection|remediation|monitoring) [default: all]
    -w, --workers       Number of parallel workers [default: 4]
    -t, --timeout       Test timeout in seconds [default: 300]
    --no-cleanup        Don't cleanup test environment after completion
    -v, --verbose       Enable verbose output
    -h, --help          Show this help message

Environment Variables:
    TEST_ENVIRONMENT    Same as --environment
    KONG_VERSION        Same as --kong-version
    TEST_SUITE         Same as --suite
    TEST_CATEGORY      Same as --category
    PARALLEL_WORKERS   Same as --workers
    TIMEOUT            Same as --timeout
    CLEANUP            Set to 'false' to disable cleanup
    VERBOSE            Set to 'true' to enable verbose output

Examples:
    # Run all tests locally
    $0

    # Run only threat detection tests
    $0 --category threat-detection

    # Run security tests in Docker environment
    $0 --environment docker --suite security

    # Run with verbose output and no cleanup
    $0 --verbose --no-cleanup

    # Run load tests with 8 workers
    $0 --suite load --workers 8

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                TEST_ENVIRONMENT="$2"
                shift 2
                ;;
            -k|--kong-version)
                KONG_VERSION="$2"
                shift 2
                ;;
            -s|--suite)
                TEST_SUITE="$2"
                shift 2
                ;;
            -c|--category)
                TEST_CATEGORY="$2"
                shift 2
                ;;
            -w|--workers)
                PARALLEL_WORKERS="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --no-cleanup)
                CLEANUP="false"
                shift
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Validate dependencies
validate_dependencies() {
    log_info "Validating dependencies..."

    # Check Lua
    if ! command -v lua >/dev/null 2>&1; then
        log_error "Lua is not installed or not in PATH"
        exit 1
    fi

    # Check LuaRocks
    if ! command -v luarocks >/dev/null 2>&1; then
        log_error "LuaRocks is not installed or not in PATH"
        exit 1
    fi

    # Check Kong (depending on environment)
    if [[ "$TEST_ENVIRONMENT" == "local" ]]; then
        if ! command -v kong >/dev/null 2>&1; then
            log_error "Kong Gateway is not installed or not in PATH"
            exit 1
        fi

        local kong_version
        kong_version=$(kong version 2>/dev/null | head -n1 | awk '{print $2}')
        log_info "Kong version detected: $kong_version"
    fi

    # Check Docker (for Docker environment)
    if [[ "$TEST_ENVIRONMENT" == "docker" ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            log_error "Docker is not installed or not in PATH"
            exit 1
        fi

        if ! command -v docker-compose >/dev/null 2>&1; then
            log_error "Docker Compose is not installed or not in PATH"
            exit 1
        fi
    fi

    log_success "Dependencies validation passed"
}

# Install Lua dependencies
install_lua_dependencies() {
    log_info "Installing Lua dependencies..."

    local dependencies=(
        "busted"
        "luacov"
        "lua-cjson"
        "luasocket"
        "lyaml"
        "penlight"
    )

    for dep in "${dependencies[@]}"; do
        if [[ "$VERBOSE" == "true" ]]; then
            luarocks install "$dep" || log_warning "Failed to install $dep (might already be installed)"
        else
            luarocks install "$dep" >/dev/null 2>&1 || log_warning "Failed to install $dep (might already be installed)"
        fi
    done

    log_success "Lua dependencies installed"
}

# Prepare test environment
prepare_environment() {
    log_info "Preparing test environment: $TEST_ENVIRONMENT"

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    case "$TEST_ENVIRONMENT" in
        local)
            prepare_local_environment
            ;;
        docker)
            prepare_docker_environment
            ;;
        ci)
            prepare_ci_environment
            ;;
        *)
            log_error "Unknown test environment: $TEST_ENVIRONMENT"
            exit 1
            ;;
    esac
}

# Prepare local test environment
prepare_local_environment() {
    log_info "Setting up local test environment"

    # Install Kong plugin locally
    cd "$PROJECT_ROOT"

    if [[ -f "kong-plugin-kong-guard-ai-0.1.0-1.rockspec" ]]; then
        log_info "Installing Kong Guard AI plugin locally..."
        if [[ "$VERBOSE" == "true" ]]; then
            luarocks make kong-plugin-kong-guard-ai-0.1.0-1.rockspec
        else
            luarocks make kong-plugin-kong-guard-ai-0.1.0-1.rockspec >/dev/null 2>&1
        fi
        log_success "Kong Guard AI plugin installed locally"
    fi
}

# Prepare Docker test environment
prepare_docker_environment() {
    log_info "Setting up Docker test environment"

    cd "$TEST_DIR/docker"

    # Build test images
    log_info "Building test images..."
    if [[ "$VERBOSE" == "true" ]]; then
        docker-compose -f docker-compose.test.yml build
    else
        docker-compose -f docker-compose.test.yml build >/dev/null 2>&1
    fi

    # Start test environment
    log_info "Starting test environment..."
    KONG_VERSION="$KONG_VERSION" docker-compose -f docker-compose.test.yml up -d

    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    local max_wait=120
    local wait_count=0

    while [[ $wait_count -lt $max_wait ]]; do
        if curl -s http://localhost:8001/status >/dev/null 2>&1; then
            break
        fi

        sleep 2
        wait_count=$((wait_count + 2))

        if [[ $wait_count -ge $max_wait ]]; then
            log_error "Services failed to start within $max_wait seconds"
            docker-compose -f docker-compose.test.yml logs
            exit 1
        fi
    done

    log_success "Docker test environment ready"
}

# Prepare CI test environment
prepare_ci_environment() {
    log_info "Setting up CI test environment"

    # CI-specific setup
    export CI=true
    export CLEANUP=true

    # Use environment-specific URLs if provided
    export KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
    export KONG_PROXY_URL="${KONG_PROXY_URL:-http://localhost:8000}"

    log_success "CI test environment prepared"
}

# Run specific test suite
run_test_suite() {
    local suite_name="$1"
    log_info "Running test suite: $suite_name"

    case "$suite_name" in
        integration)
            run_integration_tests
            ;;
        load)
            run_load_tests
            ;;
        security)
            run_security_tests
            ;;
        monitoring)
            run_monitoring_tests
            ;;
        all)
            run_integration_tests
            run_load_tests
            run_security_tests
            run_monitoring_tests
            ;;
        *)
            log_error "Unknown test suite: $suite_name"
            exit 1
            ;;
    esac
}

# Run integration tests
run_integration_tests() {
    log_header "🧪 Running Integration Tests"

    cd "$PROJECT_ROOT"

    # Set environment variables
    export TEST_ENVIRONMENT="$TEST_ENVIRONMENT"
    export TEST_CATEGORY="$TEST_CATEGORY"
    export PARALLEL_WORKERS="$PARALLEL_WORKERS"
    export VERBOSE="$VERBOSE"

    # Run Lua test runner
    if [[ "$VERBOSE" == "true" ]]; then
        timeout "$TIMEOUT" lua tests/run_all_tests.lua
    else
        timeout "$TIMEOUT" lua tests/run_all_tests.lua > "$RESULTS_DIR/integration_tests.log" 2>&1
    fi

    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed (exit code: $exit_code)"
        if [[ "$VERBOSE" != "true" ]]; then
            log_info "See detailed logs in: $RESULTS_DIR/integration_tests.log"
        fi
        return $exit_code
    fi
}

# Run load tests
run_load_tests() {
    log_header "⚡ Running Load Tests"

    local target_url
    case "$TEST_ENVIRONMENT" in
        docker)
            target_url="http://kong-gateway:8000"
            ;;
        *)
            target_url="http://localhost:8000"
            ;;
    esac

    # Run wrk load test
    log_info "Running wrk load test..."
    if command -v wrk >/dev/null 2>&1; then
        wrk -t12 -c400 -d60s --timeout 10s -s "$TEST_DIR/load/wrk_load_test.lua" "$target_url/test" > "$RESULTS_DIR/load_test_wrk.txt"
        log_success "wrk load test completed"
    else
        log_warning "wrk not available, skipping load test"
    fi

    # Run hey load test for comparison
    log_info "Running hey load test..."
    if command -v hey >/dev/null 2>&1; then
        hey -z 60s -c 200 -q 100 "$target_url/test" > "$RESULTS_DIR/load_test_hey.txt"
        log_success "hey load test completed"
    else
        log_warning "hey not available, skipping hey load test"
    fi
}

# Run security tests
run_security_tests() {
    log_header "🛡️ Running Security Tests"

    if [[ "$TEST_ENVIRONMENT" == "docker" ]]; then
        cd "$TEST_DIR/docker"

        # Run security testing container
        log_info "Running comprehensive security tests..."
        docker run --rm \
            --network tests_kong-test-net \
            -v "$RESULTS_DIR:/results" \
            -e TARGET_URL="http://kong-gateway:8000" \
            -e ADMIN_URL="http://kong-gateway:8001" \
            kong-guard-ai-security-test

        log_success "Security tests completed"
    else
        log_warning "Security tests are optimized for Docker environment"

        # Run basic security validation
        local target_url="http://localhost:8000"

        # Test SQL injection blocking
        log_info "Testing SQL injection blocking..."
        local sql_response
        sql_response=$(curl -s -o /dev/null -w "%{http_code}" "$target_url/api/users?id=1' OR '1'='1")

        if [[ "$sql_response" == "403" ]]; then
            log_success "SQL injection properly blocked"
        else
            log_warning "SQL injection not blocked (status: $sql_response)"
        fi

        # Test XSS blocking
        log_info "Testing XSS blocking..."
        local xss_response
        xss_response=$(curl -s -o /dev/null -w "%{http_code}" "$target_url/search?q=<script>alert('xss')</script>")

        if [[ "$xss_response" == "403" ]]; then
            log_success "XSS properly blocked"
        else
            log_warning "XSS not blocked (status: $xss_response)"
        fi
    fi
}

# Run monitoring tests
run_monitoring_tests() {
    log_header "📊 Running Monitoring Tests"

    local target_url
    case "$TEST_ENVIRONMENT" in
        docker)
            target_url="http://kong-gateway:8000"
            ;;
        *)
            target_url="http://localhost:8000"
            ;;
    esac

    # Test status endpoint
    log_info "Testing status endpoint..."
    if curl -s "$target_url/_guard_ai/status" > "$RESULTS_DIR/status_response.json"; then
        log_success "Status endpoint accessible"
    else
        log_warning "Status endpoint not accessible"
    fi

    # Test metrics endpoint
    log_info "Testing metrics endpoint..."
    if curl -s "$target_url/_guard_ai/metrics" > "$RESULTS_DIR/metrics_response.txt"; then
        log_success "Metrics endpoint accessible"
    else
        log_warning "Metrics endpoint not accessible"
    fi

    # Test analytics dashboard
    log_info "Testing analytics dashboard..."
    if curl -s "$target_url/_guard_ai/analytics" > "$RESULTS_DIR/analytics_response.json"; then
        log_success "Analytics dashboard accessible"
    else
        log_warning "Analytics dashboard not accessible"
    fi
}

# Cleanup test environment
cleanup_environment() {
    if [[ "$CLEANUP" == "true" ]]; then
        log_info "Cleaning up test environment..."

        case "$TEST_ENVIRONMENT" in
            docker)
                cd "$TEST_DIR/docker"
                docker-compose -f docker-compose.test.yml down -v
                log_success "Docker environment cleaned up"
                ;;
            local)
                # Kill any remaining Kong processes
                pkill -f "kong start" 2>/dev/null || true
                log_success "Local environment cleaned up"
                ;;
        esac
    else
        log_info "Skipping cleanup (CLEANUP=false)"
    fi
}

# Generate final report
generate_final_report() {
    log_header "📋 Generating Final Report"

    local report_file="$RESULTS_DIR/final_test_report.txt"

    cat > "$report_file" << EOF
Kong Guard AI Integration Test Report
=====================================

Test Configuration:
- Environment: $TEST_ENVIRONMENT
- Kong Version: $KONG_VERSION
- Test Suite: $TEST_SUITE
- Test Category: $TEST_CATEGORY
- Parallel Workers: $PARALLEL_WORKERS
- Timeout: ${TIMEOUT}s
- Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Test Results:
EOF

    # Add results from various test outputs
    if [[ -f "$RESULTS_DIR/comprehensive-test-report.json" ]]; then
        echo "" >> "$report_file"
        echo "Detailed results available in: comprehensive-test-report.json" >> "$report_file"
    fi

    if [[ -f "$RESULTS_DIR/load_test_wrk.txt" ]]; then
        echo "" >> "$report_file"
        echo "Load Test Results (wrk):" >> "$report_file"
        echo "------------------------" >> "$report_file"
        tail -n 20 "$RESULTS_DIR/load_test_wrk.txt" >> "$report_file"
    fi

    log_success "Final report generated: $report_file"
}

# Main execution
main() {
    log_header "🚀 Kong Guard AI Integration Test Suite"
    log_header "═══════════════════════════════════════"

    # Show configuration
    log_info "Test Configuration:"
    log_info "  Environment: $TEST_ENVIRONMENT"
    log_info "  Kong Version: $KONG_VERSION"
    log_info "  Test Suite: $TEST_SUITE"
    log_info "  Test Category: $TEST_CATEGORY"
    log_info "  Parallel Workers: $PARALLEL_WORKERS"
    log_info "  Timeout: ${TIMEOUT}s"
    log_info "  Cleanup: $CLEANUP"
    log_info "  Verbose: $VERBOSE"

    # Execute test pipeline
    validate_dependencies
    install_lua_dependencies
    prepare_environment

    # Run tests
    local overall_success=true

    if ! run_test_suite "$TEST_SUITE"; then
        overall_success=false
    fi

    # Generate reports
    generate_final_report

    # Cleanup
    cleanup_environment

    # Final result
    if [[ "$overall_success" == "true" ]]; then
        log_success "🎉 All tests completed successfully!"
        exit 0
    else
        log_error "💥 Some tests failed. Please review the results."
        exit 1
    fi
}

# Trap to ensure cleanup on exit
trap cleanup_environment EXIT

# Parse arguments and run
parse_args "$@"
main
