#!/bin/bash

# Master Validation Script for Kong Guard AI
# Orchestrates all validation tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_header() {
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..50})${NC}"
}

log_info() {
    echo -e "${BLUE}[MASTER]${NC} $1"
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
    
    # Check if validation scripts exist
    local scripts=(
        "validate-docker-environment.sh"
        "validate-integration.sh"
        "validate-plugin-lifecycle.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [ -f "$SCRIPT_DIR/$script" ]; then
            log_success "$script found"
        else
            log_error "$script not found"
            ((failed++))
        fi
    done
    
    # Check for required tools
    local tools=("curl" "jq" "docker")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" > /dev/null 2>&1; then
            log_success "$tool is available"
        else
            log_warning "$tool is not installed (some tests may fail)"
        fi
    done
    
    return $failed
}

# Wait for development environment
wait_for_environment() {
    log_header "Waiting for Development Environment"
    
    local max_wait=300  # 5 minutes
    local wait_count=0
    local check_interval=10
    
    log_info "Waiting for other agents to complete environment setup..."
    
    while [ $wait_count -lt $max_wait ]; do
        # Check for key files that indicate environment is ready
        local ready_indicators=0
        
        # Check for Docker Compose file
        if [ -f "../docker-compose.yml" ] || [ -f "./docker-compose.yml" ]; then
            ((ready_indicators++))
        fi
        
        # Check for plugin files
        if [ -d "../kong" ] || [ -d "./kong" ] || [ -f "../kong-guard-ai.lua" ]; then
            ((ready_indicators++))
        fi
        
        # Check for configuration files
        if [ -f "../kong.yml" ] || [ -f "./kong.yml" ] || [ -f "../kong.conf" ]; then
            ((ready_indicators++))
        fi
        
        if [ $ready_indicators -ge 2 ]; then
            log_success "Development environment appears ready"
            return 0
        fi
        
        sleep $check_interval
        ((wait_count += check_interval))
        
        if [ $((wait_count % 30)) -eq 0 ]; then
            log_info "Still waiting... (${wait_count}s elapsed, ${ready_indicators}/3 indicators ready)"
        fi
    done
    
    log_warning "Timeout waiting for environment (proceeding with available validation)"
    return 1
}

# Run Docker environment validation
run_docker_validation() {
    log_header "Docker Environment Validation"
    
    if [ -f "$SCRIPT_DIR/validate-docker-environment.sh" ]; then
        if bash "$SCRIPT_DIR/validate-docker-environment.sh"; then
            log_success "Docker environment validation passed"
            return 0
        else
            log_warning "Docker environment validation had issues"
            return 1
        fi
    else
        log_error "Docker validation script not found"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_header "Integration Tests"
    
    # Check if Kong is running
    if curl -s --connect-timeout 5 "http://localhost:8001/status" > /dev/null 2>&1; then
        log_info "Kong Admin API is accessible, running integration tests..."
        
        if [ -f "$SCRIPT_DIR/validate-integration.sh" ]; then
            if bash "$SCRIPT_DIR/validate-integration.sh"; then
                log_success "Integration tests passed"
                return 0
            else
                log_warning "Integration tests had failures"
                return 1
            fi
        else
            log_error "Integration test script not found"
            return 1
        fi
    else
        log_warning "Kong is not running, skipping integration tests"
        log_info "Start Kong with: docker-compose up -d"
        return 1
    fi
}

# Run plugin lifecycle tests
run_lifecycle_tests() {
    log_header "Plugin Lifecycle Tests"
    
    # Check if Kong is running and plugin is available
    if curl -s --connect-timeout 5 "http://localhost:8001/status" > /dev/null 2>&1; then
        log_info "Kong is running, testing plugin lifecycle..."
        
        if [ -f "$SCRIPT_DIR/validate-plugin-lifecycle.sh" ]; then
            if bash "$SCRIPT_DIR/validate-plugin-lifecycle.sh"; then
                log_success "Plugin lifecycle tests passed"
                return 0
            else
                log_warning "Plugin lifecycle tests had failures"
                return 1
            fi
        else
            log_error "Plugin lifecycle test script not found"
            return 1
        fi
    else
        log_warning "Kong is not running, skipping plugin lifecycle tests"
        return 1
    fi
}

# Generate comprehensive report
generate_report() {
    log_header "Generating Validation Report"
    
    local report_file="validation-report-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$report_file" << EOF
# Kong Guard AI Validation Report

**Generated:** $(date)
**Environment:** $(uname -s) $(uname -r)

## Executive Summary

This report summarizes the validation results for the Kong Guard AI plugin development environment.

## Test Results

### Prerequisites Check
- Validation scripts: $([ -f "$SCRIPT_DIR/validate-docker-environment.sh" ] && echo "✅" || echo "❌") Present
- Required tools: $(command -v curl > /dev/null && command -v jq > /dev/null && command -v docker > /dev/null && echo "✅" || echo "⚠️") Available

### Docker Environment
- Docker daemon: $(docker info > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Not running")
- Docker Compose: $(command -v docker-compose > /dev/null 2>&1 || docker compose version > /dev/null 2>&1 && echo "✅ Available" || echo "❌ Not available")
- Port availability: 
  - 8000 (Kong Proxy): $(lsof -i :8000 > /dev/null 2>&1 && echo "🟡 In use" || echo "✅ Available")
  - 8001 (Kong Admin): $(lsof -i :8001 > /dev/null 2>&1 && echo "🟡 In use" || echo "✅ Available")
  - 5432 (PostgreSQL): $(lsof -i :5432 > /dev/null 2>&1 && echo "🟡 In use" || echo "✅ Available")

### Kong Status
- Admin API: $(curl -s --connect-timeout 5 "http://localhost:8001/status" > /dev/null 2>&1 && echo "✅ Accessible" || echo "❌ Not accessible")
- Proxy API: $(curl -s --connect-timeout 5 "http://localhost:8000" > /dev/null 2>&1 && echo "✅ Accessible" || echo "❌ Not accessible")

### Plugin Status
- Plugin files: $([ -f "../kong-guard-ai.lua" ] || [ -d "../kong" ] && echo "✅ Present" || echo "⏳ Pending")
- Plugin loaded: $(curl -s "http://localhost:8001/plugins/available" 2>/dev/null | grep -q "kong-guard-ai" && echo "✅ Loaded" || echo "⏳ Pending")

### Environment Files
- Docker Compose: $([ -f "../docker-compose.yml" ] || [ -f "./docker-compose.yml" ] && echo "✅ Present" || echo "⏳ Pending")
- Kong Config: $([ -f "../kong.yml" ] || [ -f "../kong.conf" ] && echo "✅ Present" || echo "⏳ Pending")

## Recommendations

### Immediate Actions Required
EOF

    # Add specific recommendations based on current state
    if ! docker info > /dev/null 2>&1; then
        echo "- 🔥 **CRITICAL**: Start Docker daemon" >> "$report_file"
    fi
    
    if ! curl -s --connect-timeout 5 "http://localhost:8001/status" > /dev/null 2>&1; then
        echo "- 🔧 **HIGH**: Start Kong Gateway (\`docker-compose up -d\`)" >> "$report_file"
    fi
    
    if [ ! -f "../docker-compose.yml" ] && [ ! -f "./docker-compose.yml" ]; then
        echo "- ⏳ **MEDIUM**: Wait for Docker environment setup by other agents" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

### Development Workflow
1. Start the development environment: \`docker-compose up -d\`
2. Verify Kong connectivity: \`curl http://localhost:8001/status\`
3. Run plugin integration tests: \`./scripts/validate-integration.sh\`
4. Monitor Kong logs: \`docker-compose logs -f kong\`

### Monitoring Commands
\`\`\`bash
# Check Kong status
curl http://localhost:8001/status

# List available plugins
curl http://localhost:8001/plugins/available

# Check plugin instances
curl http://localhost:8001/plugins

# Monitor logs
docker-compose logs -f kong
\`\`\`

## Validation Scripts

The following validation scripts are available:

1. **validate-all.sh** - Master validation orchestrator
2. **validate-docker-environment.sh** - Docker and system validation
3. **validate-integration.sh** - Kong Admin API integration tests
4. **validate-plugin-lifecycle.sh** - Plugin lifecycle phase testing

## Next Steps

1. Continue monitoring agent progress
2. Run full validation once environment is complete
3. Execute integration tests with live Kong instance
4. Verify plugin functionality with test scenarios

---
*Report generated by Kong Guard AI Integration Validator*
EOF

    log_success "Validation report generated: $report_file"
    echo "$report_file"
}

# Main validation orchestrator
main() {
    log_header "Kong Guard AI Master Validation"
    echo -e "${CYAN}Starting comprehensive validation suite...${NC}"
    echo
    
    local failed_tests=0
    local total_tests=0
    
    # Prerequisites
    ((total_tests++))
    if ! check_prerequisites; then
        ((failed_tests++))
        log_error "Prerequisites check failed, continuing with available tests"
    fi
    
    # Wait for environment (optional)
    wait_for_environment
    
    # Docker validation
    ((total_tests++))
    if ! run_docker_validation; then
        ((failed_tests++))
    fi
    
    # Integration tests (conditional)
    ((total_tests++))
    if ! run_integration_tests; then
        ((failed_tests++))
    fi
    
    # Lifecycle tests (conditional)
    ((total_tests++))
    if ! run_lifecycle_tests; then
        ((failed_tests++))
    fi
    
    # Generate report
    local report_file=$(generate_report)
    
    # Final summary
    log_header "Validation Summary"
    
    echo -e "${BOLD}Total Tests:${NC} $total_tests"
    echo -e "${BOLD}Passed:${NC} $((total_tests - failed_tests))"
    echo -e "${BOLD}Failed/Pending:${NC} $failed_tests"
    echo
    
    if [ $failed_tests -eq 0 ]; then
        log_success "🎉 All validation tests passed!"
        log_info "Kong Guard AI environment is fully operational"
    elif [ $failed_tests -lt $total_tests ]; then
        log_warning "⚠️  Partial validation success ($((total_tests - failed_tests))/$total_tests tests passed)"
        log_info "Some components may still be initializing"
    else
        log_error "❌ Validation incomplete - environment needs attention"
    fi
    
    echo
    log_info "📄 Detailed report: $report_file"
    log_info "🔄 Re-run this script as development progresses"
    
    exit $failed_tests
}

# Script options
case "${1:-}" in
    --docker-only)
        run_docker_validation
        exit $?
        ;;
    --integration-only)
        run_integration_tests
        exit $?
        ;;
    --lifecycle-only)
        run_lifecycle_tests
        exit $?
        ;;
    --report-only)
        generate_report
        exit 0
        ;;
    --help)
        echo "Kong Guard AI Master Validation Script"
        echo
        echo "Usage: $0 [option]"
        echo
        echo "Options:"
        echo "  --docker-only      Run only Docker environment validation"
        echo "  --integration-only Run only Kong integration tests"
        echo "  --lifecycle-only   Run only plugin lifecycle tests"
        echo "  --report-only      Generate validation report only"
        echo "  --help            Show this help message"
        echo
        echo "Without options, runs complete validation suite"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac