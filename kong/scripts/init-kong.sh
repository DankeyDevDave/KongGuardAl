#!/bin/bash
# Kong Guard AI - Kong Initialization Script
# This script initializes Kong Gateway with the kong-guard-ai plugin

set -e

echo "🚀 Initializing Kong Gateway with Kong Guard AI plugin..."

# Configuration variables
KONG_ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"
KONG_CONFIG_PATH="${KONG_CONFIG_PATH:-/etc/kong/kong.yml}"
POSTGRES_HOST="${POSTGRES_HOST:-kong-database}"
POSTGRES_DB="${POSTGRES_DB:-kong}"
POSTGRES_USER="${POSTGRES_USER:-kong}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-kongpass}"

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s --fail "$url" > /dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        echo "⏸️  Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to become ready after $max_attempts attempts"
    exit 1
}

# Function to check if Kong database is initialized
check_database_status() {
    echo "🔍 Checking Kong database status..."
    
    # Check if Kong database is accessible
    PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1;" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "❌ Cannot connect to Kong database"
        exit 1
    fi
    
    # Check if Kong schema exists
    local table_count=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'kong_%';" 2>/dev/null | tr -d ' ')
    
    if [ "$table_count" -eq "0" ]; then
        echo "📋 Kong database schema not found, running migrations..."
        kong migrations bootstrap
        echo "✅ Kong database migrations completed"
    else
        echo "✅ Kong database schema already exists"
        echo "🔄 Running pending migrations..."
        kong migrations up
    fi
}

# Function to validate plugin loading
validate_plugin() {
    echo "🔍 Validating kong-guard-ai plugin..."
    
    # Check if plugin files exist
    if [ ! -f "/etc/kong/plugins/kong-guard-ai/handler.lua" ]; then
        echo "❌ Plugin handler not found at /etc/kong/plugins/kong-guard-ai/handler.lua"
        exit 1
    fi
    
    if [ ! -f "/etc/kong/plugins/kong-guard-ai/schema.lua" ]; then
        echo "❌ Plugin schema not found at /etc/kong/plugins/kong-guard-ai/schema.lua"
        exit 1
    fi
    
    echo "✅ Plugin files found"
    
    # Validate Lua syntax
    lua -l kong.plugins.kong-guard-ai.handler -e "print('Handler syntax OK')" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "❌ Plugin handler has syntax errors"
        exit 1
    fi
    
    lua -l kong.plugins.kong-guard-ai.schema -e "print('Schema syntax OK')" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "❌ Plugin schema has syntax errors"
        exit 1
    fi
    
    echo "✅ Plugin Lua syntax validation passed"
}

# Function to create required shared memory zones
setup_shared_memory() {
    echo "🧠 Setting up shared memory zones for kong-guard-ai..."
    
    # Check if nginx.conf includes the shared memory directives
    # This would typically be configured in the Kong configuration
    echo "ℹ️  Shared memory zones should be configured in kong.conf:"
    echo "   lua_shared_dict kong_guard_ai_data 10m"
    echo "   lua_shared_dict kong_guard_ai_counters 10m"
}

# Function to load declarative configuration
load_declarative_config() {
    if [ -f "$KONG_CONFIG_PATH" ]; then
        echo "📄 Loading declarative configuration from $KONG_CONFIG_PATH..."
        
        # Validate YAML syntax
        if command -v yq > /dev/null; then
            yq eval '.' "$KONG_CONFIG_PATH" > /dev/null
            if [ $? -eq 0 ]; then
                echo "✅ Declarative configuration syntax is valid"
            else
                echo "❌ Declarative configuration has syntax errors"
                exit 1
            fi
        else
            echo "⚠️  yq not found, skipping YAML validation"
        fi
        
        # Apply configuration via Admin API
        curl -X POST "$KONG_ADMIN_URL/config" \
             -F "config=@$KONG_CONFIG_PATH" \
             -H "Content-Type: multipart/form-data"
        
        if [ $? -eq 0 ]; then
            echo "✅ Declarative configuration loaded successfully"
        else
            echo "❌ Failed to load declarative configuration"
            exit 1
        fi
    else
        echo "⚠️  Declarative configuration file not found at $KONG_CONFIG_PATH"
        echo "   Kong will start with default configuration"
    fi
}

# Function to verify plugin is loaded
verify_plugin_loaded() {
    echo "🔍 Verifying kong-guard-ai plugin is loaded..."
    
    # Wait for Kong to be ready
    wait_for_service "Kong Admin API" "$KONG_ADMIN_URL/status"
    
    # Check available plugins
    local plugin_list=$(curl -s "$KONG_ADMIN_URL/plugins/enabled" | grep -o "kong-guard-ai" || echo "")
    
    if [ "$plugin_list" = "kong-guard-ai" ]; then
        echo "✅ kong-guard-ai plugin is loaded and available"
    else
        echo "❌ kong-guard-ai plugin is not loaded"
        echo "📋 Available plugins:"
        curl -s "$KONG_ADMIN_URL/plugins/enabled" | jq -r '.enabled_plugins[]' || echo "Could not fetch plugin list"
        exit 1
    fi
}

# Function to test plugin functionality
test_plugin_functionality() {
    echo "🧪 Testing kong-guard-ai plugin functionality..."
    
    # Create a test service and route if they don't exist
    local service_exists=$(curl -s "$KONG_ADMIN_URL/services/test-service" | jq -r '.name' 2>/dev/null || echo "null")
    
    if [ "$service_exists" = "null" ]; then
        echo "🔧 Creating test service..."
        curl -X POST "$KONG_ADMIN_URL/services" \
             -H "Content-Type: application/json" \
             -d '{
                 "name": "test-service",
                 "url": "http://httpbin.org"
             }'
    fi
    
    # Create test route
    local route_exists=$(curl -s "$KONG_ADMIN_URL/routes" | jq -r '.data[] | select(.paths[] == "/test") | .id' 2>/dev/null || echo "")
    
    if [ "$route_exists" = "" ]; then
        echo "🔧 Creating test route..."
        curl -X POST "$KONG_ADMIN_URL/routes" \
             -H "Content-Type: application/json" \
             -d '{
                 "service": {"name": "test-service"},
                 "paths": ["/test"]
             }'
    fi
    
    # Enable plugin on the test service
    echo "🔧 Enabling kong-guard-ai plugin on test service..."
    curl -X POST "$KONG_ADMIN_URL/services/test-service/plugins" \
         -H "Content-Type: application/json" \
         -d '{
             "name": "kong-guard-ai",
             "config": {
                 "dry_run": true,
                 "log_level": "info"
             }
         }'
    
    echo "✅ Plugin functionality test setup completed"
    echo "🧪 You can now test the plugin by making requests to http://localhost:8000/test"
}

# Main execution
main() {
    echo "🐣 Starting Kong Guard AI initialization..."
    
    # Step 1: Check database
    check_database_status
    
    # Step 2: Validate plugin
    validate_plugin
    
    # Step 3: Setup shared memory
    setup_shared_memory
    
    # Step 4: Wait for Kong to be ready (in case it's starting)
    wait_for_service "Kong Admin API" "$KONG_ADMIN_URL/status"
    
    # Step 5: Load declarative configuration
    load_declarative_config
    
    # Step 6: Verify plugin is loaded
    verify_plugin_loaded
    
    # Step 7: Test plugin functionality
    test_plugin_functionality
    
    echo "🎉 Kong Guard AI initialization completed successfully!"
    echo ""
    echo "📋 Next steps:"
    echo "   1. Make test requests to http://localhost:8000/test"
    echo "   2. Check Kong logs for kong-guard-ai plugin activity"
    echo "   3. Monitor the Admin API at $KONG_ADMIN_URL"
    echo "   4. Configure notifications and AI Gateway if needed"
    echo ""
    echo "🔧 Useful commands:"
    echo "   - View plugin status: curl $KONG_ADMIN_URL/plugins"
    echo "   - View logs: docker logs kong-gateway"
    echo "   - Test threats: curl -H 'User-Agent: sqlmap' http://localhost:8000/test"
}

# Run main function
main "$@"