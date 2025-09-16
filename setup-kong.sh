#!/bin/bash

# Kong Guard AI - Kong Configuration Setup Script

set -e

KONG_ADMIN_URL="http://localhost:8001"
DEMO_API_URL="http://demo-api:80"
MOCK_ATTACKER_URL="http://mock-attacker:80"

echo "🔧 Configuring Kong Gateway for Kong Guard AI..."

# Wait for Kong to be ready
echo "⏳ Waiting for Kong Admin API..."
until curl -s "$KONG_ADMIN_URL/status" >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ✅ Kong Admin API ready"

# Function to create service
create_service() {
    local name=$1
    local url=$2

    echo "🔗 Creating service: $name"
    curl -i -X POST "$KONG_ADMIN_URL/services/" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$name\",
            \"url\": \"$url\"
        }"
}

# Function to create route
create_route() {
    local service_name=$1
    local path=$2
    local name=$3

    echo "🛣️  Creating route: $name for service: $service_name"
    curl -i -X POST "$KONG_ADMIN_URL/services/$service_name/routes" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$name\",
            \"paths\": [\"$path\"],
            \"strip_path\": true
        }"
}

# Function to enable plugin on service
enable_plugin() {
    local service_name=$1
    local plugin_name=$2
    local config=$3

    echo "🔌 Enabling plugin: $plugin_name on service: $service_name"
    curl -i -X POST "$KONG_ADMIN_URL/services/$service_name/plugins" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$plugin_name\",
            \"config\": $config
        }"
}

# Create services
echo ""
echo "📋 Creating Kong services..."

create_service "demo-api" "$DEMO_API_URL"
create_service "mock-attacker" "$MOCK_ATTACKER_URL"

echo ""
echo "📋 Creating Kong routes..."

# Create routes
create_route "demo-api" "/demo" "demo-api-route"
create_route "mock-attacker" "/attack" "mock-attacker-route"

echo ""
echo "📋 Enabling plugins..."

# Enable rate limiting plugin on demo API for testing
rate_limit_config='{
    "minute": 60,
    "hour": 3600,
    "policy": "local",
    "fault_tolerant": true,
    "hide_client_headers": false
}'

enable_plugin "demo-api" "rate-limiting" "$rate_limit_config"

# Enable Kong Guard AI plugin on both services (if plugin is available)
kong_guard_ai_config='{
    "dry_run": false,
    "log_level": "debug",
    "rate_limit_enabled": true,
    "rate_limit_threshold": 100,
    "ip_blocking_enabled": true,
    "ai_detection_enabled": false,
    "notifications_enabled": true,
    "payload_analysis_enabled": true
}'

# Note: This will fail if the plugin is not properly installed, but that's expected during development
echo "🛡️  Attempting to enable Kong Guard AI plugin..."
enable_plugin "demo-api" "kong-guard-ai" "$kong_guard_ai_config" || echo "ℹ️  Kong Guard AI plugin not available yet (expected during development)"
enable_plugin "mock-attacker" "kong-guard-ai" "$kong_guard_ai_config" || echo "ℹ️  Kong Guard AI plugin not available yet (expected during development)"

echo ""
echo "✅ Kong configuration complete!"
echo ""
echo "🧪 Test the setup:"
echo "   Demo API via Kong:     curl http://localhost:8000/demo/status/200"
echo "   Mock Attacker via Kong: curl http://localhost:8000/attack/health"
echo "   Direct Demo API:       curl http://localhost:8080/status/200"
echo "   Direct Mock Attacker:  curl http://localhost:8090/health"
echo ""
echo "📊 View Kong configuration:"
echo "   Services:              curl http://localhost:8001/services"
echo "   Routes:                curl http://localhost:8001/routes"
echo "   Plugins:               curl http://localhost:8001/plugins"
echo ""
echo "🛡️  Once the Kong Guard AI plugin is developed, re-run this script to enable it."
