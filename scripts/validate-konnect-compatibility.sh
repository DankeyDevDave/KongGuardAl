#!/bin/bash

# Kong Guard AI - Konnect Compatibility Validation Script
# Validates plugin configuration and declarative workflows for Kong Konnect
# Ensures seamless deployment in Konnect cloud environment

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
PLUGIN_NAME="kong-guard-ai"
DECLARATIVE_CONFIG_PATH="${DECLARATIVE_CONFIG_PATH:-$PROJECT_ROOT/kong/config/kong.yml}"
TEMP_DIR="/tmp/konnect-validation"

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
KONNECT_ISSUES=()

test_result() {
    local test_name="$1"
    local passed="$2"
    local message="$3"
    local severity="${4:-error}"
    
    if [ "$passed" = "true" ]; then
        ((TESTS_PASSED++))
        log_success "$test_name"
        [ -n "$message" ] && echo "   $message"
    else
        ((TESTS_FAILED++))
        if [ "$severity" = "warning" ]; then
            log_warning "$test_name"
        else
            log_error "$test_name"
        fi
        [ -n "$message" ] && echo "   $message"
        FAILED_TESTS+=("$test_name")
        if [ "$severity" = "konnect" ]; then
            KONNECT_ISSUES+=("$test_name: $message")
        fi
    fi
}

# Setup temporary directory
setup_temp_dir() {
    mkdir -p "$TEMP_DIR"
}

# Cleanup temporary directory
cleanup_temp_dir() {
    rm -rf "$TEMP_DIR"
}

# Test declarative configuration format
test_declarative_format() {
    log_header "Testing Declarative Configuration Format"
    
    # Check if declarative config file exists
    if [ ! -f "$DECLARATIVE_CONFIG_PATH" ]; then
        test_result "Declarative Config File" false "File not found: $DECLARATIVE_CONFIG_PATH" "error"
        return 1
    fi
    
    test_result "Declarative Config File" true "Found at $DECLARATIVE_CONFIG_PATH"
    
    # Validate YAML syntax
    if command -v yq >/dev/null 2>&1; then
        if yq eval '.' "$DECLARATIVE_CONFIG_PATH" >/dev/null 2>&1; then
            test_result "YAML Syntax Validation" true "Valid YAML format"
        else
            test_result "YAML Syntax Validation" false "Invalid YAML syntax" "error"
            return 1
        fi
    else
        log_warning "yq not available, skipping YAML syntax validation"
    fi
    
    # Check for required Konnect fields
    local format_version=""
    local transform=""
    
    if command -v yq >/dev/null 2>&1; then
        format_version=$(yq eval '._format_version' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null)
        transform=$(yq eval '._transform' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null)
    else
        # Fallback to grep
        format_version=$(grep "_format_version" "$DECLARATIVE_CONFIG_PATH" | head -1 | cut -d'"' -f2 2>/dev/null || echo "null")
        transform=$(grep "_transform" "$DECLARATIVE_CONFIG_PATH" | head -1 | awk '{print $2}' 2>/dev/null || echo "null")
    fi
    
    if [ "$format_version" != "null" ] && [ -n "$format_version" ]; then
        test_result "Konnect Format Version" true "Found _format_version: $format_version"
    else
        test_result "Konnect Format Version" false "Missing _format_version field" "konnect"
    fi
    
    if [ "$transform" != "null" ] && [ -n "$transform" ]; then
        test_result "Konnect Transform Field" true "Found _transform: $transform"
    else
        test_result "Konnect Transform Field" false "Missing _transform field" "konnect"
    fi
    
    # Validate format version compatibility
    if [ "$format_version" != "null" ] && [ -n "$format_version" ]; then
        case "$format_version" in
            "3.0"|"2.1"|"1.1")
                test_result "Format Version Compatibility" true "Version $format_version is Konnect compatible"
                ;;
            *)
                test_result "Format Version Compatibility" false "Version $format_version may not be fully supported" "warning"
                ;;
        esac
    fi
}

# Test plugin configuration in declarative format
test_plugin_declarative_config() {
    log_header "Testing Plugin Configuration in Declarative Format"
    
    if [ ! -f "$DECLARATIVE_CONFIG_PATH" ]; then
        test_result "Plugin Config Setup" false "Declarative config file not available"
        return 1
    fi
    
    # Check if kong-guard-ai plugin is configured
    if grep -q "$PLUGIN_NAME" "$DECLARATIVE_CONFIG_PATH"; then
        test_result "Plugin in Declarative Config" true "Plugin found in configuration"
    else
        test_result "Plugin in Declarative Config" false "Plugin not found in declarative configuration" "warning"
        return 1
    fi
    
    # Extract plugin configuration to temporary file
    if command -v yq >/dev/null 2>&1; then
        yq eval '.services[].plugins[] | select(.name == "'$PLUGIN_NAME'")' "$DECLARATIVE_CONFIG_PATH" > "$TEMP_DIR/plugin_config.yml" 2>/dev/null
        
        if [ -s "$TEMP_DIR/plugin_config.yml" ]; then
            test_result "Plugin Config Extraction" true "Successfully extracted plugin configuration"
        else
            # Try checking global plugins
            yq eval '.plugins[] | select(.name == "'$PLUGIN_NAME'")' "$DECLARATIVE_CONFIG_PATH" > "$TEMP_DIR/plugin_config.yml" 2>/dev/null
            
            if [ -s "$TEMP_DIR/plugin_config.yml" ]; then
                test_result "Plugin Config Extraction" true "Found plugin in global configuration"
            else
                test_result "Plugin Config Extraction" false "Could not extract plugin configuration"
                return 1
            fi
        fi
    else
        # Fallback method without yq
        if grep -A 20 "$PLUGIN_NAME" "$DECLARATIVE_CONFIG_PATH" > "$TEMP_DIR/plugin_config.yml"; then
            test_result "Plugin Config Extraction" true "Extracted plugin configuration (fallback method)"
        else
            test_result "Plugin Config Extraction" false "Could not extract plugin configuration"
            return 1
        fi
    fi
    
    # Validate required configuration fields
    local has_dry_run=false
    local has_log_level=false
    local has_threat_detection=false
    
    if grep -q "dry_run" "$TEMP_DIR/plugin_config.yml"; then
        has_dry_run=true
    fi
    
    if grep -q "log_level" "$TEMP_DIR/plugin_config.yml"; then
        has_log_level=true
    fi
    
    if grep -q "threat_detection" "$TEMP_DIR/plugin_config.yml"; then
        has_threat_detection=true
    fi
    
    test_result "Plugin Config Fields" "$has_dry_run" "dry_run field present: $has_dry_run"
    test_result "Plugin Log Level" "$has_log_level" "log_level field present: $has_log_level"
    test_result "Plugin Threat Detection" "$has_threat_detection" "threat_detection config present: $has_threat_detection"
}

# Test Konnect-specific constraints
test_konnect_constraints() {
    log_header "Testing Konnect-Specific Constraints"
    
    # Check for unsupported plugins (common issues)
    local unsupported_patterns=("file-log" "syslog" "loggly")
    local unsupported_found=false
    
    for pattern in "${unsupported_patterns[@]}"; do
        if grep -q "$pattern" "$DECLARATIVE_CONFIG_PATH" 2>/dev/null; then
            test_result "Unsupported Plugin Check ($pattern)" false "Found potentially unsupported plugin: $pattern" "konnect"
            unsupported_found=true
        fi
    done
    
    if [ "$unsupported_found" = "false" ]; then
        test_result "Unsupported Plugin Check" true "No obviously unsupported plugins found"
    fi
    
    # Check for custom entities that might not be supported
    local custom_entities=("upstreams" "certificates" "ca_certificates")
    local custom_found=false
    
    for entity in "${custom_entities[@]}"; do
        if grep -q "^${entity}:" "$DECLARATIVE_CONFIG_PATH" 2>/dev/null; then
            log_info "Found custom entity: $entity (verify Konnect support)"
            custom_found=true
        fi
    done
    
    test_result "Custom Entities Check" true "Custom entities check completed"
    
    # Check for localhost references (common issue in Konnect)
    if grep -i "localhost\|127.0.0.1" "$DECLARATIVE_CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Localhost References" false "Found localhost references - may need updating for Konnect" "konnect"
    else
        test_result "Localhost References" true "No localhost references found"
    fi
    
    # Check for HTTP URLs (should be HTTPS in production)
    local http_urls=$(grep -o 'http://[^"]*' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null | wc -l)
    if [ "$http_urls" -gt 0 ]; then
        test_result "HTTP URLs Check" false "Found $http_urls HTTP URLs - consider HTTPS for production" "warning"
    else
        test_result "HTTP URLs Check" true "No insecure HTTP URLs found"
    fi
}

# Test configuration size limits
test_configuration_size() {
    log_header "Testing Configuration Size Limits"
    
    local config_size=$(stat -f%z "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || stat -c%s "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
    local size_mb=$((config_size / 1024 / 1024))
    
    log_info "Configuration file size: ${config_size} bytes (${size_mb} MB)"
    
    # Konnect has configuration size limits
    if [ "$config_size" -lt 10485760 ]; then  # 10MB
        test_result "Configuration Size" true "Size within Konnect limits"
    else
        test_result "Configuration Size" false "Configuration may be too large for Konnect (>10MB)" "konnect"
    fi
    
    # Count entities
    local service_count=0
    local route_count=0
    local plugin_count=0
    
    if command -v yq >/dev/null 2>&1; then
        service_count=$(yq eval '.services | length' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
        route_count=$(yq eval '.routes | length' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
        plugin_count=$(yq eval '[.plugins[], .services[].plugins[], .routes[].plugins[]] | length' "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
    else
        service_count=$(grep -c "^  - name:" "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
        route_count=$(grep -c "routes:" "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
        plugin_count=$(grep -c "- name: $PLUGIN_NAME" "$DECLARATIVE_CONFIG_PATH" 2>/dev/null || echo "0")
    fi
    
    log_info "Entity counts - Services: $service_count, Routes: $route_count, Plugins: $plugin_count"
    
    # Basic entity count validation
    if [ "$service_count" -lt 1000 ] && [ "$route_count" -lt 10000 ]; then
        test_result "Entity Count Limits" true "Entity counts within reasonable limits"
    else
        test_result "Entity Count Limits" false "High entity count may impact Konnect performance" "warning"
    fi
}

# Test schema compatibility with Kong versions
test_schema_compatibility() {
    log_header "Testing Schema Compatibility"
    
    # Create a test configuration for validation
    local test_config='{
        "_format_version": "3.0",
        "_transform": true,
        "services": [
            {
                "name": "test-service-konnect",
                "url": "https://httpbin.org",
                "plugins": [
                    {
                        "name": "'$PLUGIN_NAME'",
                        "config": {
                            "dry_run": true,
                            "log_level": "info",
                            "threat_detection": {
                                "enabled": true,
                                "rules": {
                                    "rate_limit_threshold": 100,
                                    "suspicious_patterns": ["test"],
                                    "blocked_ips": []
                                }
                            },
                            "response_actions": {
                                "enabled": true,
                                "immediate_block": false
                            },
                            "notifications": {
                                "webhook_url": "https://example.com/webhook"
                            }
                        }
                    }
                ]
            }
        ],
        "routes": [
            {
                "name": "test-route-konnect",
                "service": {"name": "test-service-konnect"},
                "paths": ["/test-konnect"]
            }
        ]
    }'
    
    echo "$test_config" > "$TEMP_DIR/test_konnect_config.json"
    
    # Validate against Kong if available
    if curl -s --connect-timeout 5 "$KONG_ADMIN_URL/status" >/dev/null 2>&1; then
        local validation_response=$(curl -s -X POST "$KONG_ADMIN_URL/config" \
            -H "Content-Type: application/json" \
            -d "$test_config" \
            -w "%{http_code}" -o "$TEMP_DIR/validation_result.json" 2>/dev/null || echo "000")
        
        if [ "$validation_response" = "200" ] || [ "$validation_response" = "201" ]; then
            test_result "Kong Schema Validation" true "Test configuration validates against Kong"
        else
            local error_msg=$(cat "$TEMP_DIR/validation_result.json" 2>/dev/null | jq -r '.message // "Unknown error"' 2>/dev/null || echo "Validation failed")
            test_result "Kong Schema Validation" false "$error_msg"
        fi
        
        # Clean up test configuration
        curl -s -X DELETE "$KONG_ADMIN_URL/services/test-service-konnect" >/dev/null 2>&1
    else
        test_result "Kong Schema Validation" false "Kong not available for validation" "warning"
    fi
}

# Test environment-specific configurations
test_environment_configurations() {
    log_header "Testing Environment-Specific Configurations"
    
    # Check for environment variables references
    if grep -E '\$\{[^}]+\}|\$[A-Z_]+' "$DECLARATIVE_CONFIG_PATH" >/dev/null 2>&1; then
        test_result "Environment Variables" true "Found environment variable references"
        log_info "Ensure all environment variables are properly set in Konnect"
    else
        test_result "Environment Variables" true "No environment variables found (hardcoded values)"
        log_warning "Consider using environment variables for secrets and endpoints"
    fi
    
    # Check for secrets management
    local secret_patterns=("password" "token" "key" "secret")
    local secrets_hardcoded=false
    
    for pattern in "${secret_patterns[@]}"; do
        if grep -i "$pattern.*:" "$DECLARATIVE_CONFIG_PATH" | grep -v "\${" >/dev/null 2>&1; then
            secrets_hardcoded=true
            break
        fi
    done
    
    if [ "$secrets_hardcoded" = "true" ]; then
        test_result "Secrets Management" false "Hardcoded secrets found - use environment variables or vault" "konnect"
    else
        test_result "Secrets Management" true "No hardcoded secrets detected"
    fi
    
    # Check for development-specific configurations
    local dev_patterns=("localhost" "dev-" "test-" "debug.*true")
    local dev_config_found=false
    
    for pattern in "${dev_patterns[@]}"; do
        if grep -i "$pattern" "$DECLARATIVE_CONFIG_PATH" >/dev/null 2>&1; then
            dev_config_found=true
            break
        fi
    done
    
    if [ "$dev_config_found" = "true" ]; then
        test_result "Development Configuration" false "Development configurations found - review for production" "warning"
    else
        test_result "Development Configuration" true "No obvious development configurations found"
    fi
}

# Generate Konnect deployment guide
generate_deployment_guide() {
    local guide_file="konnect_deployment_guide.md"
    
    cat > "$guide_file" << EOF
# Kong Guard AI - Konnect Deployment Guide

**Generated:** $(date)
**Plugin:** $PLUGIN_NAME
**Configuration:** $DECLARATIVE_CONFIG_PATH

## Pre-Deployment Checklist

### Configuration Validation
- [ ] Declarative configuration format is valid
- [ ] Required Konnect fields (_format_version, _transform) are present
- [ ] Plugin configuration is complete and valid
- [ ] No localhost references in configuration
- [ ] Secrets are managed via environment variables

### Konnect Compatibility
- [ ] Configuration size is under Konnect limits
- [ ] No unsupported plugins are used
- [ ] Entity counts are within reasonable limits
- [ ] HTTPS URLs are used for external services

## Deployment Steps

### 1. Prepare Configuration

\`\`\`bash
# Validate configuration locally
./scripts/validate-konnect-compatibility.sh

# Export environment-specific variables
export WEBHOOK_URL="https://your-webhook-endpoint.com"
export API_KEYS="your-production-api-keys"
\`\`\`

### 2. Deploy to Konnect

1. **Login to Kong Konnect**
   - Navigate to https://cloud.konghq.com
   - Select your organization and control plane

2. **Upload Configuration**
   - Go to Gateway Manager → Configuration
   - Upload your declarative configuration file
   - Review the configuration diff

3. **Configure Environment Variables**
   - Set up any required environment variables
   - Configure secrets in Konnect vault (if available)

4. **Deploy and Validate**
   - Deploy the configuration
   - Monitor deployment logs
   - Run connectivity tests

### 3. Post-Deployment Validation

\`\`\`bash
# Test plugin functionality
curl -X GET "https://your-konnect-proxy/test-endpoint" \\
  -H "Authorization: Bearer \$API_TOKEN"

# Check plugin metrics (if enabled)
curl -X GET "https://your-konnect-proxy/_guard_ai/metrics" \\
  -H "Authorization: Bearer \$API_TOKEN"
\`\`\`

## Configuration Differences from Kong Gateway

### Required Changes for Konnect

1. **Format Version**
   - Must include \`_format_version: "3.0"\`
   - Must include \`_transform: true\`

2. **Service URLs**
   - Replace localhost with actual hostnames
   - Use HTTPS for external services
   - Update internal service references

3. **Plugin Configuration**
   - Verify plugin is available in Konnect
   - Update any Konnect-specific configuration options
   - Use environment variables for secrets

### Kong Guard AI Specific Settings

\`\`\`yaml
plugins:
  - name: kong-guard-ai
    config:
      # Recommended Konnect settings
      dry_run: false  # Enable after testing
      log_level: "info"
      
      # Notification endpoints should use HTTPS
      notifications:
        webhook_url: "\$WEBHOOK_URL"  # Use environment variable
        
      # AI Gateway settings for Konnect
      ai_gateway:
        enabled: false  # Enable if AI Gateway is available
        model_endpoint: "\$AI_GATEWAY_ENDPOINT"
\`\`\`

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   - Check format version compatibility
   - Verify plugin name spelling
   - Validate YAML syntax

2. **Plugin Not Loading**
   - Confirm plugin availability in Konnect
   - Check plugin configuration syntax
   - Review Konnect deployment logs

3. **Service Connectivity Issues**
   - Verify service URLs are accessible from Konnect
   - Check network connectivity and DNS resolution
   - Validate SSL certificates

### Monitoring and Debugging

\`\`\`bash
# Check Konnect logs (via Konnect UI)
# Monitor proxy metrics
# Review plugin-specific logs
\`\`\`

## Best Practices

1. **Configuration Management**
   - Use version control for declarative configurations
   - Implement CI/CD for configuration deployments
   - Maintain separate configs for different environments

2. **Security**
   - Use environment variables for sensitive data
   - Regularly rotate API keys and secrets
   - Monitor for security events

3. **Performance**
   - Monitor plugin performance impact
   - Adjust rate limiting thresholds based on traffic
   - Use dry run mode for testing new configurations

---
*Generated by Kong Guard AI Konnect Compatibility Validator*
EOF

    log_success "Deployment guide generated: $guide_file"
    echo "$guide_file"
}

# Generate test report
generate_test_report() {
    local report_file="konnect_compatibility_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# Kong Guard AI - Konnect Compatibility Test Report

**Generated:** $(date)
**Plugin:** $PLUGIN_NAME
**Configuration File:** $DECLARATIVE_CONFIG_PATH
**Kong Admin URL:** $KONG_ADMIN_URL

## Test Summary

- **Total Tests:** $((TESTS_PASSED + TESTS_FAILED))
- **Passed:** $TESTS_PASSED
- **Failed:** $TESTS_FAILED
- **Success Rate:** $(( TESTS_PASSED * 100 / (TESTS_PASSED + TESTS_FAILED) ))%

## Compatibility Assessment

EOF

    if [ ${#KONNECT_ISSUES[@]} -eq 0 ]; then
        echo "✅ **KONNECT READY** - No Konnect-specific issues detected" >> "$report_file"
    else
        echo "⚠️ **REQUIRES ATTENTION** - ${#KONNECT_ISSUES[@]} Konnect-specific issue(s) found" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

## Test Results

### Declarative Configuration
- Format validation and Konnect field compliance
- Plugin configuration extraction and validation
- YAML syntax and structure verification

### Konnect Constraints
- Unsupported plugin detection
- Localhost reference checking
- HTTP/HTTPS URL validation

### Configuration Limits
- File size validation
- Entity count verification
- Performance impact assessment

### Environment Configuration
- Environment variable usage
- Secrets management validation
- Development configuration detection

EOF

    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo "## Failed Tests" >> "$report_file"
        echo "" >> "$report_file"
        for test in "${FAILED_TESTS[@]}"; do
            echo "- $test" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi

    if [ ${#KONNECT_ISSUES[@]} -gt 0 ]; then
        echo "## Konnect-Specific Issues" >> "$report_file"
        echo "" >> "$report_file"
        for issue in "${KONNECT_ISSUES[@]}"; do
            echo "- $issue" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
## Recommendations

### Before Konnect Deployment
1. Address all Konnect-specific issues
2. Update localhost references to actual hostnames
3. Configure environment variables for secrets
4. Test configuration with Kong Gateway locally

### Deployment Process
1. Use staging environment first
2. Monitor deployment logs carefully
3. Validate plugin functionality post-deployment
4. Set up monitoring and alerting

### Production Considerations
1. Use HTTPS for all external communications
2. Implement proper secrets management
3. Monitor plugin performance impact
4. Have rollback plan ready

---
*Report generated by Kong Guard AI Konnect Compatibility Validator*
EOF

    log_success "Compatibility report generated: $report_file"
    echo "$report_file"
}

# Main execution
main() {
    log_header "Kong Guard AI - Konnect Compatibility Validation"
    echo "Validating configuration for Kong Konnect deployment..."
    echo ""
    
    # Setup
    setup_temp_dir
    trap cleanup_temp_dir EXIT
    
    # Reset counters
    TESTS_PASSED=0
    TESTS_FAILED=0
    FAILED_TESTS=()
    KONNECT_ISSUES=()
    
    # Run tests
    test_declarative_format
    test_plugin_declarative_config
    test_konnect_constraints
    test_configuration_size
    test_schema_compatibility
    test_environment_configurations
    
    # Generate reports
    local report_file=$(generate_test_report)
    local guide_file=$(generate_deployment_guide)
    
    # Final summary
    echo ""
    log_header "Validation Complete"
    echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    echo "Konnect Issues: ${#KONNECT_ISSUES[@]}"
    echo ""
    echo "Reports Generated:"
    echo "  - Compatibility: $report_file"
    echo "  - Deployment Guide: $guide_file"
    
    if [ ${#KONNECT_ISSUES[@]} -eq 0 ] && [ $TESTS_FAILED -eq 0 ]; then
        log_success "🎉 Configuration is ready for Konnect deployment!"
        exit 0
    elif [ ${#KONNECT_ISSUES[@]} -gt 0 ]; then
        log_warning "⚠️  Konnect-specific issues found. Review and fix before deployment."
        exit 2
    else
        log_warning "⚠️  Some tests failed. Review the report for details."
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Kong Guard AI Konnect Compatibility Validator"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h                Show this help message"
        echo "  --config FILE             Use specific declarative config file"
        echo "  --format-only             Only validate declarative format"
        echo "  --constraints-only        Only check Konnect constraints"
        echo "  --generate-guide-only     Only generate deployment guide"
        echo ""
        echo "Environment variables:"
        echo "  DECLARATIVE_CONFIG_PATH   Path to kong.yml (default: kong/config/kong.yml)"
        echo "  KONG_ADMIN_URL            Kong Admin API URL for validation"
        exit 0
        ;;
    --config)
        DECLARATIVE_CONFIG_PATH="$2"
        shift 2
        ;;
    --format-only)
        setup_temp_dir
        test_declarative_format
        cleanup_temp_dir
        exit $?
        ;;
    --constraints-only)
        setup_temp_dir
        test_konnect_constraints
        cleanup_temp_dir
        exit $?
        ;;
    --generate-guide-only)
        generate_deployment_guide
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac