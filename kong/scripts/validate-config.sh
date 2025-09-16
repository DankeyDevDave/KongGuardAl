#!/bin/bash
# Kong Guard AI - Configuration Validation Script
# Validates Kong configuration files and plugin structure

set -e

echo "🔍 Kong Guard AI Configuration Validation"
echo "========================================"

# Configuration variables
KONG_CONFIG_DIR="${KONG_CONFIG_DIR:-$(pwd)/kong/config}"
KONG_PLUGINS_DIR="${KONG_PLUGINS_DIR:-$(pwd)/kong/plugins}"
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
    esac
}

# Function to check file exists
check_file() {
    local file=$1
    local description=$2

    if [ -f "$file" ]; then
        print_status "SUCCESS" "$description found: $file"
        return 0
    else
        print_status "ERROR" "$description not found: $file"
        return 1
    fi
}

# Function to validate YAML syntax
validate_yaml() {
    local file=$1
    local description=$2

    if command -v yq > /dev/null; then
        if yq eval '.' "$file" > /dev/null 2>&1; then
            print_status "SUCCESS" "$description YAML syntax is valid"
            return 0
        else
            print_status "ERROR" "$description YAML syntax is invalid"
            return 1
        fi
    else
        print_status "WARNING" "yq not found, skipping YAML validation for $description"
        return 0
    fi
}

# Function to validate Lua syntax
validate_lua() {
    local file=$1
    local description=$2

    if command -v lua > /dev/null; then
        if lua -l "$file" -e "print('OK')" > /dev/null 2>&1; then
            print_status "SUCCESS" "$description Lua syntax is valid"
            return 0
        else
            print_status "ERROR" "$description Lua syntax is invalid"
            return 1
        fi
    else
        print_status "WARNING" "lua not found, skipping Lua validation for $description"
        return 0
    fi
}

# Function to check Kong Admin API
check_kong_admin() {
    print_status "INFO" "Checking Kong Admin API availability..."

    if curl -s --fail "$KONG_ADMIN_URL/status" > /dev/null 2>&1; then
        print_status "SUCCESS" "Kong Admin API is accessible"

        # Check if kong-guard-ai plugin is available
        local available_plugins=$(curl -s "$KONG_ADMIN_URL/plugins/enabled" 2>/dev/null || echo '{"enabled_plugins":[]}')
        if echo "$available_plugins" | grep -q "kong-guard-ai"; then
            print_status "SUCCESS" "kong-guard-ai plugin is loaded in Kong"
        else
            print_status "WARNING" "kong-guard-ai plugin is not loaded in Kong"
        fi

        return 0
    else
        print_status "WARNING" "Kong Admin API is not accessible (Kong may not be running)"
        return 1
    fi
}

# Function to validate plugin structure
validate_plugin_structure() {
    print_status "INFO" "Validating plugin structure..."

    local plugin_dir="$KONG_PLUGINS_DIR/kong-guard-ai"
    local errors=0

    # Check required files
    if ! check_file "$plugin_dir/handler.lua" "Plugin handler"; then
        errors=$((errors + 1))
    fi

    if ! check_file "$plugin_dir/schema.lua" "Plugin schema"; then
        errors=$((errors + 1))
    fi

    check_file "$plugin_dir/README.md" "Plugin README"

    # Validate Lua files
    if [ -f "$plugin_dir/handler.lua" ]; then
        if ! validate_lua "$plugin_dir/handler.lua" "Plugin handler"; then
            errors=$((errors + 1))
        fi
    fi

    if [ -f "$plugin_dir/schema.lua" ]; then
        if ! validate_lua "$plugin_dir/schema.lua" "Plugin schema"; then
            errors=$((errors + 1))
        fi
    fi

    if [ $errors -eq 0 ]; then
        print_status "SUCCESS" "Plugin structure validation passed"
        return 0
    else
        print_status "ERROR" "Plugin structure validation failed with $errors errors"
        return 1
    fi
}

# Function to validate Kong configuration files
validate_kong_config() {
    print_status "INFO" "Validating Kong configuration files..."

    local errors=0

    # Check Kong configuration files
    if ! check_file "$KONG_CONFIG_DIR/kong.conf" "Kong configuration"; then
        errors=$((errors + 1))
    fi

    check_file "$KONG_CONFIG_DIR/kong-dev.conf" "Kong development configuration"

    # Check declarative configuration
    if check_file "$KONG_CONFIG_DIR/kong.yml" "Kong declarative configuration"; then
        if ! validate_yaml "$KONG_CONFIG_DIR/kong.yml" "Kong declarative configuration"; then
            errors=$((errors + 1))
        fi
    else
        errors=$((errors + 1))
    fi

    # Check nginx configuration
    check_file "$KONG_CONFIG_DIR/nginx-kong.conf" "Nginx Kong configuration"

    # Check scripts
    check_file "$(dirname "$KONG_CONFIG_DIR")/scripts/init-kong.sh" "Kong initialization script"

    if [ $errors -eq 0 ]; then
        print_status "SUCCESS" "Kong configuration validation passed"
        return 0
    else
        print_status "ERROR" "Kong configuration validation failed with $errors errors"
        return 1
    fi
}

# Function to validate declarative configuration content
validate_declarative_content() {
    print_status "INFO" "Validating declarative configuration content..."

    local config_file="$KONG_CONFIG_DIR/kong.yml"

    if [ ! -f "$config_file" ]; then
        print_status "ERROR" "Declarative configuration file not found"
        return 1
    fi

    # Check for required sections
    local required_sections=("services" "routes" "plugins")
    local warnings=0

    for section in "${required_sections[@]}"; do
        if grep -q "^${section}:" "$config_file"; then
            print_status "SUCCESS" "Found $section section in declarative config"
        else
            print_status "WARNING" "Missing $section section in declarative config"
            warnings=$((warnings + 1))
        fi
    done

    # Check for kong-guard-ai plugin configuration
    if grep -q "kong-guard-ai" "$config_file"; then
        print_status "SUCCESS" "kong-guard-ai plugin configured in declarative config"
    else
        print_status "WARNING" "kong-guard-ai plugin not found in declarative config"
        warnings=$((warnings + 1))
    fi

    # Check for demo services
    if grep -q "demo-api" "$config_file"; then
        print_status "SUCCESS" "Demo API service configured"
    else
        print_status "WARNING" "Demo API service not configured"
    fi

    if [ $warnings -eq 0 ]; then
        print_status "SUCCESS" "Declarative configuration content validation passed"
        return 0
    else
        print_status "WARNING" "Declarative configuration content validation completed with $warnings warnings"
        return 0
    fi
}

# Function to test plugin configuration schema
test_plugin_schema() {
    print_status "INFO" "Testing plugin configuration schema..."

    # Create a temporary test configuration
    local test_config='
{
  "dry_run": true,
  "log_level": "info",
  "threat_detection": {
    "enabled": true,
    "rules": {
      "rate_limit_threshold": 100,
      "suspicious_patterns": ["test"],
      "blocked_ips": ["127.0.0.1"],
      "blocked_user_agents": ["test-agent"]
    }
  },
  "response_actions": {
    "enabled": true,
    "immediate_block": false
  },
  "notifications": {
    "webhook_url": "http://localhost:3001/webhook"
  }
}'

    # Test configuration against Kong Admin API if available
    if curl -s --fail "$KONG_ADMIN_URL/status" > /dev/null 2>&1; then
        # Try to validate configuration through Kong
        local validation_result=$(curl -s -X POST "$KONG_ADMIN_URL/schemas/plugins/validate" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"kong-guard-ai\",\"config\":$test_config}" 2>/dev/null || echo "error")

        if echo "$validation_result" | grep -q "error"; then
            print_status "WARNING" "Could not validate plugin schema through Kong Admin API"
        else
            print_status "SUCCESS" "Plugin schema validation through Kong Admin API passed"
        fi
    else
        print_status "INFO" "Kong not running, skipping live schema validation"
    fi
}

# Function to check dependencies
check_dependencies() {
    print_status "INFO" "Checking dependencies..."

    # Check for optional tools
    local tools=("curl" "jq" "yq" "lua")

    for tool in "${tools[@]}"; do
        if command -v "$tool" > /dev/null; then
            print_status "SUCCESS" "$tool is available"
        else
            print_status "WARNING" "$tool is not available (some features may be limited)"
        fi
    done
}

# Function to generate summary report
generate_summary() {
    print_status "INFO" "Validation Summary"
    echo "=================="

    echo ""
    echo "Configuration Files:"
    echo "  - Kong configuration: $KONG_CONFIG_DIR/kong.conf"
    echo "  - Kong development config: $KONG_CONFIG_DIR/kong-dev.conf"
    echo "  - Declarative config: $KONG_CONFIG_DIR/kong.yml"
    echo "  - Nginx config: $KONG_CONFIG_DIR/nginx-kong.conf"
    echo ""
    echo "Plugin Files:"
    echo "  - Plugin handler: $KONG_PLUGINS_DIR/kong-guard-ai/handler.lua"
    echo "  - Plugin schema: $KONG_PLUGINS_DIR/kong-guard-ai/schema.lua"
    echo "  - Plugin README: $KONG_PLUGINS_DIR/kong-guard-ai/README.md"
    echo ""
    echo "Scripts:"
    echo "  - Initialization: $(dirname "$KONG_CONFIG_DIR")/scripts/init-kong.sh"
    echo "  - Validation: $(dirname "$KONG_CONFIG_DIR")/scripts/validate-config.sh"
    echo ""

    if curl -s --fail "$KONG_ADMIN_URL/status" > /dev/null 2>&1; then
        echo "Kong Status: Running (Admin API accessible)"
    else
        echo "Kong Status: Not running or not accessible"
    fi

    echo ""
    print_status "INFO" "Validation completed!"
}

# Main execution
main() {
    echo ""
    print_status "INFO" "Starting validation with the following paths:"
    print_status "INFO" "Config directory: $KONG_CONFIG_DIR"
    print_status "INFO" "Plugins directory: $KONG_PLUGINS_DIR"
    print_status "INFO" "Kong Admin URL: $KONG_ADMIN_URL"
    echo ""

    local total_errors=0

    # Run all validations
    check_dependencies
    echo ""

    if ! validate_kong_config; then
        total_errors=$((total_errors + 1))
    fi
    echo ""

    if ! validate_plugin_structure; then
        total_errors=$((total_errors + 1))
    fi
    echo ""

    validate_declarative_content
    echo ""

    test_plugin_schema
    echo ""

    check_kong_admin
    echo ""

    generate_summary

    if [ $total_errors -eq 0 ]; then
        print_status "SUCCESS" "All critical validations passed!"
        exit 0
    else
        print_status "ERROR" "Validation failed with $total_errors critical errors"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Kong Guard AI Configuration Validation Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h          Show this help message"
        echo "  --config-dir DIR    Set Kong config directory (default: ./kong/config)"
        echo "  --plugins-dir DIR   Set Kong plugins directory (default: ./kong/plugins)"
        echo "  --admin-url URL     Set Kong Admin API URL (default: http://localhost:8001)"
        echo ""
        echo "Environment variables:"
        echo "  KONG_CONFIG_DIR     Kong configuration directory"
        echo "  KONG_PLUGINS_DIR    Kong plugins directory"
        echo "  KONG_ADMIN_URL      Kong Admin API URL"
        exit 0
        ;;
    --config-dir)
        KONG_CONFIG_DIR="$2"
        shift 2
        ;;
    --plugins-dir)
        KONG_PLUGINS_DIR="$2"
        shift 2
        ;;
    --admin-url)
        KONG_ADMIN_URL="$2"
        shift 2
        ;;
esac

# Run main function
main "$@"
