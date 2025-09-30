# Kong Guard AI Integration Testing Guide

This guide provides comprehensive instructions for testing Kong Guard AI plugin functionality, performance, and security using the integrated testing framework.

## Table of Contents

- [Overview](#overview)
- [Test Architecture](#test-architecture)
- [Test Categories](#test-categories)
- [Quick Start](#quick-start)
- [Test Environments](#test-environments)
- [Running Tests](#running-tests)
- [Test Configuration](#test-configuration)
- [CI/CD Integration](#cicd-integration)
- [Performance Testing](#performance-testing)
- [Security Testing](#security-testing)
- [Monitoring & Observability](#monitoring--observability)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

The Kong Guard AI testing framework provides comprehensive validation of:

- **Threat Detection**: IP blacklisting, path filtering, rate limiting, method filtering
- **Remediation Actions**: Admin API integration, blocking, rollback procedures
- **Performance**: Sub-10ms latency validation, throughput testing (>1K RPS)
- **Security**: Attack simulation, penetration testing, bypass detection
- **Monitoring**: Metrics collection, dashboard functionality, alerting
- **Scalability**: Load testing up to 10K+ RPS with concurrent users

## Test Architecture

```
tests/
├── integration_test_framework.lua    # Core testing framework
├── run_all_tests.lua                # Main test orchestrator
├── integration/                     # Integration test suites
│   ├── threat-detection/           # Threat detection tests
│   │   ├── ip_blacklist_integration_test.lua
│   │   ├── path_filter_integration_test.lua
│   │   └── rate_limiting_integration_test.lua
│   └── remediation/                # Remediation action tests
│       └── admin_api_remediation_test.lua
├── load/                           # Load testing scripts
│   └── wrk_load_test.lua          # Advanced wrk load testing
├── security/                      # Security testing payloads
├── monitoring/                    # Observability tests
│   └── observability_test.lua    # Monitoring integration tests
├── docker/                        # Docker test environment
│   ├── docker-compose.test.yml   # Complete test environment
│   ├── Dockerfile.test-runner     # Test execution environment
│   └── Dockerfile.security-test   # Security testing tools
├── ci/                           # CI/CD pipeline configuration
│   └── github-actions.yml       # GitHub Actions workflow
└── scripts/                     # Utility scripts
    └── run-integration-tests.sh # Main test runner script
```

## Test Categories

### 1. Integration Tests
- **IP Blacklist**: CIDR support, O(1) lookup performance, Admin API integration
- **Path Filter**: Regex patterns, attack detection, false positive handling
- **Rate Limiting**: Sliding window, burst detection, progressive penalties
- **Method Filter**: HTTP method blocking, bypass prevention
- **Admin API**: Dynamic configuration, remediation actions

### 2. Performance Tests
- **Latency**: <10ms processing time under load
- **Throughput**: >1000 RPS sustained performance
- **Scalability**: 10K+ RPS peak load testing
- **Memory**: Efficient resource usage, leak detection

### 3. Security Tests
- **Attack Simulation**: SQL injection, XSS, path traversal, command injection
- **Penetration Testing**: OWASP Top 10, custom attack vectors
- **Bypass Detection**: Encoding attacks, method variations
- **Compliance**: Security standard validation

### 4. Monitoring Tests
- **Metrics Collection**: Prometheus format, real-time updates
- **Dashboard Functionality**: Status, analytics, performance dashboards
- **Alerting**: Incident notifications, escalation procedures
- **Log Analysis**: Structured logging, correlation tracking

## Quick Start

### Prerequisites

```bash
# Install dependencies
sudo apt-get install lua5.1 luarocks curl docker docker-compose

# Install Lua testing libraries
luarocks install busted luacov lua-cjson luasocket lyaml penlight

# Install load testing tools
# wrk
git clone https://github.com/wg/wrk.git && cd wrk && make && sudo cp wrk /usr/local/bin/

# hey
wget https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_amd64
chmod +x hey_linux_amd64 && sudo mv hey_linux_amd64 /usr/local/bin/hey
```

### Run All Tests (Local Environment)

```bash
# Clone and setup
cd kong-guard-ai/tests

# Run comprehensive test suite
./scripts/run-integration-tests.sh

# Run specific test category
./scripts/run-integration-tests.sh --category threat-detection

# Run with verbose output
./scripts/run-integration-tests.sh --verbose
```

### Run Tests in Docker

```bash
# Start Docker test environment
cd tests/docker
docker-compose -f docker-compose.test.yml up -d

# Run tests in container
docker run --rm \
  --network tests_kong-test-net \
  -v $(pwd)/../..:/workspace:ro \
  -v $(pwd)/test-results:/results \
  kong-guard-ai-test-runner

# View results
cat test-results/comprehensive-test-report.json
```

## Test Environments

### Local Environment
- **Use Case**: Development, quick validation
- **Requirements**: Kong Gateway, Lua, LuaRocks
- **Setup**: Automatic Kong instance management
- **Isolation**: Process-level separation

```bash
export TEST_ENVIRONMENT=local
./scripts/run-integration-tests.sh
```

### Docker Environment  
- **Use Case**: Isolated testing, CI/CD integration
- **Requirements**: Docker, Docker Compose
- **Setup**: Complete containerized environment
- **Isolation**: Container-level separation

```bash
export TEST_ENVIRONMENT=docker
./scripts/run-integration-tests.sh
```

### CI Environment
- **Use Case**: Automated testing, regression detection
- **Requirements**: GitHub Actions, container registry access
- **Setup**: Automated pipeline execution
- **Isolation**: Runner-level separation

```bash
# Triggered automatically on PR/push
# or manually via GitHub Actions
```

## Running Tests

### Command Line Options

```bash
./scripts/run-integration-tests.sh [OPTIONS]

Options:
  -e, --environment     Test environment (local|docker|ci)
  -k, --kong-version    Kong version (3.6|3.7|latest)
  -s, --suite          Test suite (all|integration|load|security)
  -c, --category       Test category filter
  -w, --workers        Parallel workers (default: 4)
  -t, --timeout        Test timeout seconds (default: 300)
  --no-cleanup         Preserve test environment
  -v, --verbose        Enable verbose output
  -h, --help           Show help
```

### Environment Variables

```bash
# Test configuration
export TEST_ENVIRONMENT=docker
export KONG_VERSION=3.7
export TEST_SUITE=integration
export TEST_CATEGORY=threat-detection
export PARALLEL_WORKERS=8
export TIMEOUT=600
export CLEANUP=false
export VERBOSE=true

# Kong URLs (for CI environments)
export KONG_ADMIN_URL=http://kong:8001
export KONG_PROXY_URL=http://kong:8000
```

### Test Selection Examples

```bash
# Run all tests
./scripts/run-integration-tests.sh

# Run only threat detection tests
./scripts/run-integration-tests.sh --category threat-detection

# Run security tests with 8 workers
./scripts/run-integration-tests.sh --suite security --workers 8

# Run load tests against Kong 3.6
./scripts/run-integration-tests.sh --suite load --kong-version 3.6

# Run in Docker with no cleanup for debugging
./scripts/run-integration-tests.sh --environment docker --no-cleanup --verbose
```

## Test Configuration

### Plugin Configuration for Testing

```lua
local plugin_config = {
    dry_run_mode = false,
    threat_threshold = 7.0,
    
    -- IP Blacklist
    enable_ip_blacklist = true,
    ip_blacklist = {"203.0.113.100", "198.51.100.0/24"},
    ip_blacklist_ttl_seconds = 300,
    
    -- Path Filtering  
    enable_path_filtering = true,
    path_filter_block_threshold = 7.0,
    custom_path_patterns = {
        {pattern = "/admin/.*", priority = 1, description = "Admin access"}
    },
    
    -- Rate Limiting
    enable_advanced_rate_limiting = true,
    rate_limit_per_minute = 60,
    enable_burst_detection = true,
    
    -- Monitoring
    status_endpoint_enabled = true,
    metrics_endpoint_enabled = true,
    analytics_dashboard_enabled = true,
    
    -- Remediation
    admin_api_enabled = true,
    enable_auto_blocking = true,
    enable_rate_limiting_response = true
}
```

### Test Framework Configuration

```lua
local test_config = {
    kong_mode = "dbless",            -- Kong configuration mode
    environment = "local",           -- Test environment
    timeout = 120,                   -- Test timeout seconds
    parallel_workers = 4,            -- Concurrent test workers
    enable_coverage = true,          -- Code coverage collection
    verbose = false,                 -- Verbose output
    cleanup_on_exit = true,         -- Cleanup after tests
    preserve_logs = false           -- Keep log files
}
```

## CI/CD Integration

### GitHub Actions Workflow

The provided GitHub Actions workflow (`.github/workflows/integration-tests.yml`) automatically:

1. **Triggers**: On push, PR, schedule, or manual dispatch
2. **Builds**: Test runner and security test containers
3. **Tests**: Runs comprehensive test matrix
4. **Reports**: Generates detailed test reports and PR comments
5. **Validates**: Performance requirements and security compliance

### Test Matrix

```yaml
strategy:
  matrix:
    kong_version: [3.6, 3.7]
    test_suite: [integration, load, security]
    include:
      - test_suite: integration
        tests: [ip_blacklist, path_filter, rate_limiting, admin_api]
      - test_suite: load  
        profiles: [light, medium, heavy]
      - test_suite: security
        scans: [owasp_top10, custom_attacks, penetration]
```

### Performance Requirements Validation

```yaml
# Automated validation of:
- Average latency < 10ms
- 99th percentile latency < 50ms  
- Throughput > 1000 RPS
- Threat block rate > 80%
- Memory usage < 512MB
```

## Performance Testing

### Load Testing with wrk

```bash
# Basic load test
wrk -t12 -c400 -d60s --timeout 10s \
    -s tests/load/wrk_load_test.lua \
    http://localhost:8000/test

# Custom attack simulation
wrk -t8 -c200 -d120s \
    -s tests/load/attack_simulation.lua \
    http://localhost:8000/
```

### Performance Metrics

The load test script automatically validates:

- **Latency**: Average <10ms, P99 <50ms
- **Throughput**: >1000 RPS sustained
- **Attack Block Rate**: >80% of attack requests blocked
- **Error Rate**: <1% server errors
- **Resource Usage**: Memory and CPU efficiency

### Load Test Profiles

```bash
# Light load (100 RPS, 60s)
./scripts/run-integration-tests.sh --suite load --workers 2

# Medium load (1000 RPS, 120s)  
./scripts/run-integration-tests.sh --suite load --workers 4

# Heavy load (5000 RPS, 300s)
./scripts/run-integration-tests.sh --suite load --workers 8
```

## Security Testing

### Attack Simulation

The security test suite simulates:

```bash
# SQL Injection
curl "http://localhost:8000/api/users?id=1' OR '1'='1"

# XSS Attacks
curl "http://localhost:8000/search?q=<script>alert('xss')</script>"

# Path Traversal
curl "http://localhost:8000/../../etc/passwd"

# Command Injection
curl -d "cmd=; cat /etc/passwd" "http://localhost:8000/exec"
```

### Security Testing Tools

- **OWASP ZAP**: Automated vulnerability scanning
- **Nuclei**: Template-based security testing
- **Nikto**: Web server scanner
- **Custom Scripts**: Kong Guard AI specific attack vectors

### Running Security Tests

```bash
# Full security suite
./scripts/run-integration-tests.sh --suite security

# Docker-based security testing (recommended)
cd tests/docker
docker run --rm \
  --network tests_kong-test-net \
  -v $(pwd)/test-results:/results \
  -e TARGET_URL=http://kong-gateway:8000 \
  kong-guard-ai-security-test
```

## Monitoring & Observability

### Dashboard Endpoints

```bash
# Plugin status
curl http://localhost:8000/_guard_ai/status

# Performance metrics  
curl http://localhost:8000/_guard_ai/metrics

# Analytics dashboard
curl http://localhost:8000/_guard_ai/analytics

# Incident reporting
curl http://localhost:8000/_guard_ai/incidents
```

### Metrics Validation

Tests verify:

- **Status Endpoint**: Health, uptime, configuration
- **Metrics Endpoint**: Counters, histograms, performance data
- **Analytics Dashboard**: Threat events, geographical data
- **Incident Analytics**: Alert generation, escalation
- **Log Correlation**: Request tracking, structured logging

### Prometheus Integration

```bash
# Prometheus-formatted metrics
curl http://localhost:8000/_guard_ai/metrics?format=prometheus

# Sample metrics:
# kong_guard_ai_requests_total{status="blocked"} 157
# kong_guard_ai_latency_histogram_bucket{le="10"} 0.95
# kong_guard_ai_threats_detected_total{type="sql_injection"} 23
```

## Troubleshooting

### Common Issues

#### Kong Startup Failures
```bash
# Check Kong configuration
kong check /path/to/kong.conf

# View Kong logs
tail -f /var/log/kong/error.log

# Verify plugin installation
luarocks list | grep kong-guard-ai
```

#### Test Framework Issues
```bash
# Verify Lua dependencies
luarocks list

# Check test framework initialization
lua -e "require('tests.integration_test_framework').initialize()"

# Debug verbose mode
./scripts/run-integration-tests.sh --verbose
```

#### Docker Environment Issues
```bash
# Check container status
docker-compose -f tests/docker/docker-compose.test.yml ps

# View container logs
docker-compose -f tests/docker/docker-compose.test.yml logs kong-gateway

# Rebuild containers
docker-compose -f tests/docker/docker-compose.test.yml build --no-cache
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats

# Check Kong worker processes
ps aux | grep kong

# Verify system limits
ulimit -n  # File descriptors
ulimit -u  # Processes
```

### Debug Mode

```bash
# Enable debug output
export LUA_PATH="./?.lua;./tests/?.lua;;"
export VERBOSE=true
export CLEANUP=false

# Run single test with debugging
lua -e "
local framework = require('tests.integration_test_framework')
framework.initialize({verbose = true})
local tests = require('tests.integration.threat-detection.ip_blacklist_integration_test')
print(require('cjson').encode(tests.run_tests(framework, {})))
"
```

### Log Analysis

```bash
# Kong access logs
tail -f /var/log/kong/access.log | grep "guard_ai"

# Kong error logs  
tail -f /var/log/kong/error.log | grep -i error

# Test framework logs
cat test-results/comprehensive-test-report.json | jq '.summary'

# Performance analysis
grep "processing_time" test-results/*.log
```

## Contributing

### Adding New Tests

1. **Create Test File**:
```lua
-- tests/integration/new-feature/my_test.lua
local function run_tests(framework, config)
    local tests = {}
    
    local test1 = framework.create_test("My Test", framework.TEST_MODES.INTEGRATION)
    -- Test implementation
    table.insert(tests, framework.complete_test(test1))
    
    return tests
end

return {
    run_tests = run_tests,
    description = "My Feature Tests",
    requires_kong = true,
    test_type = "integration"
}
```

2. **Register Test Suite**:
```lua
-- Add to tests/run_all_tests.lua
{
    name = "My Feature Tests",
    file = "tests/integration/new-feature/my_test.lua", 
    category = "new-feature",
    priority = 2
}
```

3. **Update CI Pipeline**:
```yaml
# Add to .github/workflows/integration-tests.yml
strategy:
  matrix:
    test_suite:
      - my_feature
```

### Test Guidelines

- **Isolation**: Each test should be independent
- **Cleanup**: Always cleanup resources in tests
- **Performance**: Validate <10ms latency requirement
- **Security**: Test both positive and negative cases
- **Documentation**: Include clear test descriptions
- **Assertions**: Use specific, meaningful assertions

### Code Coverage

```bash
# Enable coverage collection
export ENABLE_COVERAGE=true

# Run tests with coverage
luacov tests/run_all_tests.lua

# Generate coverage report
luacov -r html

# View coverage
open luacov-html/index.html
```

## Performance Benchmarks

### Expected Performance Metrics

| Metric | Requirement | Typical Performance |
|--------|-------------|-------------------|
| Average Latency | <10ms | 2-5ms |
| P99 Latency | <50ms | 15-25ms |
| Throughput | >1000 RPS | 3000-8000 RPS |
| Block Rate | >80% | 95-99% |
| Memory Usage | <512MB | 128-256MB |
| CPU Usage | <50% | 15-30% |

### Scaling Guidelines

- **1K RPS**: Single Kong worker, minimal configuration
- **5K RPS**: 2-4 Kong workers, optimized caching
- **10K RPS**: 4-8 Kong workers, Redis caching, load balancing
- **20K+ RPS**: Multiple Kong nodes, distributed caching

---

For additional support or questions, please refer to the main [Kong Guard AI documentation](../README.md) or open an issue in the repository.