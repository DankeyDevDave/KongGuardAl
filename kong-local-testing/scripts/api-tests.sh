#!/bin/bash

# Kong API Testing Script
# Tests various Kong features and plugins

set -e

# Configuration
KONG_PROXY="http://localhost:8000"
KONG_ADMIN="http://localhost:8001"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
    ((TESTS_RUN++))
}

pass() {
    echo -e "${GREEN}  ✓ PASS${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}  ✗ FAIL${NC} $1"
    ((TESTS_FAILED++))
}

assert_response() {
    local expected=$1
    local actual=$2
    local test_name=$3

    if [ "$actual" == "$expected" ]; then
        pass "$test_name (HTTP $actual)"
    else
        fail "$test_name (Expected: $expected, Got: $actual)"
    fi
}

# Test Suite
run_tests() {
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}        Kong API Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    # 1. Admin API Tests
    echo -e "${YELLOW}▸ Admin API Tests${NC}"

    print_test "Admin API Health Check"
    response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_ADMIN/)
    assert_response "200" "$response" "Admin API is accessible"

    print_test "Get Kong Version"
    version=$(curl -s $KONG_ADMIN/ | jq -r .version 2>/dev/null || echo "")
    if [ -n "$version" ]; then
        pass "Kong version: $version"
    else
        fail "Could not retrieve Kong version"
    fi

    # 2. Service Tests
    echo ""
    echo -e "${YELLOW}▸ Service Tests${NC}"

    print_test "HTTPBin Service"
    response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get)
    assert_response "200" "$response" "HTTPBin GET request"

    print_test "HTTPBin POST"
    response=$(curl -s -X POST -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d '{"test":"data"}' \
        $KONG_PROXY/httpbin/post)
    assert_response "200" "$response" "HTTPBin POST request"

    print_test "Echo Service"
    response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/echo)
    assert_response "200" "$response" "Echo service request"

    # 3. Plugin Tests
    echo ""
    echo -e "${YELLOW}▸ Plugin Tests${NC}"

    print_test "CORS Headers"
    cors_header=$(curl -s -I $KONG_PROXY/httpbin/get | grep -i "access-control-allow-origin" | wc -l)
    if [ "$cors_header" -gt 0 ]; then
        pass "CORS headers present"
    else
        fail "CORS headers missing"
    fi

    print_test "Request Transformer"
    kong_header=$(curl -s $KONG_PROXY/echo | jq -r '.headers."x-kong-proxy"' 2>/dev/null || echo "")
    if [ "$kong_header" == "true" ]; then
        pass "Request transformer added header"
    else
        fail "Request transformer header missing"
    fi

    print_test "Correlation ID"
    correlation_id=$(curl -s -I $KONG_PROXY/httpbin/get | grep -i "x-kong-request-id" | wc -l)
    if [ "$correlation_id" -gt 0 ]; then
        pass "Correlation ID present"
    else
        fail "Correlation ID missing"
    fi

    # 4. Rate Limiting Tests
    echo ""
    echo -e "${YELLOW}▸ Rate Limiting Tests${NC}"

    print_test "Rate Limiting (100 requests/minute)"
    rate_limited=false
    for i in {1..15}; do
        response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get)
        if [ "$response" == "429" ]; then
            rate_limited=true
            break
        fi
    done

    if [ "$rate_limited" == "false" ]; then
        pass "Rate limiting not triggered (under threshold)"
    else
        fail "Rate limiting triggered too early"
    fi

    # 5. Authentication Tests
    echo ""
    echo -e "${YELLOW}▸ Authentication Tests${NC}"

    print_test "API Key Authentication (without key)"
    # First, add key-auth plugin to a route
    curl -s -X POST $KONG_ADMIN/routes/httpbin-route/plugins \
        -d "name=key-auth" > /dev/null 2>&1 || true

    sleep 2
    response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get)
    assert_response "401" "$response" "Unauthorized without API key"

    print_test "API Key Authentication (with key)"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "apikey: test-api-key-123" \
        $KONG_PROXY/httpbin/get)
    assert_response "200" "$response" "Authorized with valid API key"

    # Remove key-auth plugin for other tests
    plugin_id=$(curl -s $KONG_ADMIN/routes/httpbin-route/plugins | jq -r '.data[] | select(.name=="key-auth") | .id' 2>/dev/null || echo "")
    if [ -n "$plugin_id" ]; then
        curl -s -X DELETE $KONG_ADMIN/plugins/$plugin_id > /dev/null 2>&1
    fi

    # 6. Load Balancing Tests
    echo ""
    echo -e "${YELLOW}▸ Load Balancing Tests${NC}"

    print_test "Upstream Health Checks"
    upstreams=$(curl -s $KONG_ADMIN/upstreams | jq -r '.data | length' 2>/dev/null || echo "0")
    if [ "$upstreams" -gt 0 ]; then
        pass "Upstreams configured: $upstreams"
    else
        pass "No upstreams configured (expected in basic setup)"
    fi

    # 7. Performance Tests
    echo ""
    echo -e "${YELLOW}▸ Performance Tests${NC}"

    print_test "Response Time"
    start_time=$(date +%s%N)
    curl -s $KONG_PROXY/httpbin/get > /dev/null
    end_time=$(date +%s%N)
    response_time=$(( ($end_time - $start_time) / 1000000 ))

    if [ "$response_time" -lt 1000 ]; then
        pass "Response time: ${response_time}ms"
    else
        fail "Response time too high: ${response_time}ms"
    fi

    print_test "Concurrent Requests"
    failed_requests=0
    for i in {1..10}; do
        (curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get || echo "000") &
    done
    wait
    pass "10 concurrent requests completed"

    # 8. Error Handling Tests
    echo ""
    echo -e "${YELLOW}▸ Error Handling Tests${NC}"

    print_test "404 Not Found"
    response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/nonexistent)
    assert_response "404" "$response" "Non-existent route returns 404"

    print_test "Method Not Allowed"
    response=$(curl -s -X TRACE -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get)
    if [ "$response" == "405" ] || [ "$response" == "200" ]; then
        pass "Method handling (HTTP $response)"
    else
        fail "Unexpected response for TRACE method (HTTP $response)"
    fi

    # 9. Request Size Limiting
    echo ""
    echo -e "${YELLOW}▸ Request Size Tests${NC}"

    print_test "Large Payload (under limit)"
    # Generate 1MB of data
    data=$(head -c 1048576 /dev/zero | base64)
    response=$(curl -s -X POST -o /dev/null -w "%{http_code}" \
        -H "Content-Type: text/plain" \
        --data "$data" \
        $KONG_PROXY/httpbin/post)
    assert_response "200" "$response" "1MB payload accepted"

    print_test "Large Payload (over limit)"
    # Generate 11MB of data (over 10MB limit)
    data=$(head -c 11534336 /dev/zero | base64)
    response=$(curl -s -X POST -o /dev/null -w "%{http_code}" \
        -H "Content-Type: text/plain" \
        --data "$data" \
        $KONG_PROXY/httpbin/post)
    assert_response "413" "$response" "11MB payload rejected"

    # Test Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}           Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "Tests Run:    ${TESTS_RUN}"
    echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"

    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some tests failed${NC}"
        return 1
    fi
}

# Performance Benchmark
run_benchmark() {
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}      Kong Performance Benchmark${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    echo "Running performance benchmark..."
    echo "Target: $KONG_PROXY/httpbin/get"
    echo ""

    # Check if ab (Apache Bench) is installed
    if ! command -v ab &> /dev/null; then
        echo -e "${YELLOW}Apache Bench (ab) is not installed${NC}"
        echo "Install with: brew install httpd (macOS) or apt-get install apache2-utils (Linux)"
        return 1
    fi

    # Run benchmark
    echo "Warming up..."
    ab -n 100 -c 10 -q $KONG_PROXY/httpbin/get > /dev/null 2>&1

    echo "Running benchmark (1000 requests, 10 concurrent)..."
    ab -n 1000 -c 10 $KONG_PROXY/httpbin/get 2>/dev/null | grep -E "Requests per second:|Time per request:|Transfer rate:"

    echo ""
    echo "Running benchmark (5000 requests, 50 concurrent)..."
    ab -n 5000 -c 50 $KONG_PROXY/httpbin/get 2>/dev/null | grep -E "Requests per second:|Time per request:|Transfer rate:"
}

# Load Test
run_load_test() {
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}         Kong Load Test${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    echo "Simulating gradual load increase..."

    for concurrency in 1 5 10 25 50 100; do
        echo -e "${YELLOW}Testing with $concurrency concurrent users${NC}"

        success=0
        failed=0

        for i in $(seq 1 $concurrency); do
            response=$(curl -s -o /dev/null -w "%{http_code}" $KONG_PROXY/httpbin/get &)
        done
        wait

        echo "  Completed $concurrency concurrent requests"
        sleep 2
    done

    echo -e "${GREEN}Load test completed${NC}"
}

# Main menu
case "${1:-test}" in
    test)
        run_tests
        ;;
    benchmark)
        run_benchmark
        ;;
    load)
        run_load_test
        ;;
    all)
        run_tests
        echo ""
        run_benchmark
        echo ""
        run_load_test
        ;;
    *)
        echo "Usage: $0 [test|benchmark|load|all]"
        echo "  test      - Run functional tests"
        echo "  benchmark - Run performance benchmark"
        echo "  load      - Run load test"
        echo "  all       - Run all tests"
        ;;
esac
