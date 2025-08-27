#!/bin/bash

set -e

echo "🛡️ Kong Guard AI - Three-Tier Configuration Setup"
echo "=================================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Service endpoints
KONG_UNPROTECTED_ADMIN="http://localhost:8001"
KONG_PROTECTED_ADMIN="http://localhost:8003"  
KONG_LOCAL_ADMIN="http://localhost:8005"
CLOUD_AI_SERVICE="http://localhost:18002"
LOCAL_AI_SERVICE="http://localhost:18003"

echo -e "${BLUE}🔍 Checking service availability...${NC}"

# Function to check service health
check_service() {
    local url=$1
    local name=$2
    
    if curl -s -f "$url" > /dev/null; then
        echo -e "${GREEN}✅ $name is available${NC}"
        return 0
    else
        echo -e "${RED}❌ $name is not available at $url${NC}"
        return 1
    fi
}

# Check all services
services_ready=true

check_service "$KONG_UNPROTECTED_ADMIN" "Kong Unprotected Admin" || services_ready=false
check_service "$KONG_PROTECTED_ADMIN" "Kong Protected Admin" || services_ready=false
check_service "$KONG_LOCAL_ADMIN" "Kong Local Admin" || services_ready=false
check_service "$CLOUD_AI_SERVICE/health" "Cloud AI Service" || services_ready=false
check_service "$LOCAL_AI_SERVICE/health" "Local AI Service" || services_ready=false

if [ "$services_ready" = false ]; then
    echo -e "${RED}❌ Not all services are ready. Please start the demo stack first:${NC}"
    echo "docker-compose -f docker-compose-demo.yml up -d"
    exit 1
fi

echo -e "${GREEN}✅ All services are ready!${NC}"
echo ""

# Function to create service
create_service() {
    local admin_url=$1
    local service_name=$2
    local backend_url=$3
    
    echo -e "${BLUE}📦 Creating service '$service_name' on $(echo $admin_url | sed 's|http://localhost:||')...${NC}"
    
    curl -s -X POST "$admin_url/services" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$service_name\",
            \"url\": \"$backend_url\"
        }" | jq -r '.name // "Error creating service"'
}

# Function to create route
create_route() {
    local admin_url=$1
    local service_name=$2
    local route_path=$3
    
    echo -e "${BLUE}🛤️  Creating route '$route_path' for service '$service_name'...${NC}"
    
    curl -s -X POST "$admin_url/services/$service_name/routes" \
        -H "Content-Type: application/json" \
        -d "{
            \"paths\": [\"$route_path\"],
            \"methods\": [\"GET\", \"POST\", \"PUT\", \"DELETE\", \"PATCH\"]
        }" | jq -r '.paths[0] // "Error creating route"'
}

# Function to add Kong Guard AI plugin
add_guard_ai_plugin() {
    local admin_url=$1
    local service_name=$2
    local ai_service_url=$3
    local tier_name=$4
    
    echo -e "${BLUE}🛡️  Adding Kong Guard AI plugin to '$service_name' (${tier_name})...${NC}"
    
    curl -s -X POST "$admin_url/services/$service_name/plugins" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"kong-guard-ai\",
            \"config\": {
                \"ai_service_url\": \"$ai_service_url\",
                \"enable_learning\": true,
                \"block_threshold\": 0.8,
                \"log_level\": \"info\",
                \"timeout\": 30000,
                \"retry_count\": 2,
                \"enable_websocket\": true,
                \"custom_headers\": {
                    \"X-Kong-Guard-Tier\": \"$tier_name\"
                }
            }
        }" | jq -r '.id // "Error adding plugin"'
}

echo -e "${YELLOW}🔧 Setting up three-tier Kong configuration...${NC}"
echo ""

# 1. Setup Unprotected Tier (no AI protection)
echo -e "${RED}🔓 TIER 1: Unprotected Kong Gateway${NC}"
create_service "$KONG_UNPROTECTED_ADMIN" "demo-backend-unprotected" "http://mock-backend:80"
create_route "$KONG_UNPROTECTED_ADMIN" "demo-backend-unprotected" "/api/unprotected"
echo -e "${YELLOW}   No protection plugins added - deliberately vulnerable${NC}"
echo ""

# 2. Setup Cloud AI Protected Tier
echo -e "${BLUE}☁️  TIER 2: Cloud AI Protected Kong Gateway${NC}"
create_service "$KONG_PROTECTED_ADMIN" "demo-backend-protected" "http://mock-backend:80"
create_route "$KONG_PROTECTED_ADMIN" "demo-backend-protected" "/api/protected"
add_guard_ai_plugin "$KONG_PROTECTED_ADMIN" "demo-backend-protected" "$CLOUD_AI_SERVICE" "cloud"
echo ""

# 3. Setup Local AI Protected Tier
echo -e "${GREEN}🏠 TIER 3: Local AI Protected Kong Gateway${NC}"
create_service "$KONG_LOCAL_ADMIN" "demo-backend-local" "http://mock-backend:80"  
create_route "$KONG_LOCAL_ADMIN" "demo-backend-local" "/api/local"
add_guard_ai_plugin "$KONG_LOCAL_ADMIN" "demo-backend-local" "$LOCAL_AI_SERVICE" "local"
echo ""

# Create additional routes for comprehensive testing
echo -e "${YELLOW}🔄 Creating comprehensive test routes...${NC}"

# Common endpoints for all tiers
endpoints=(
    "/api/users"
    "/api/login" 
    "/api/transfer"
    "/api/ping"
    "/api/download"
    "/api/callback"
    "/api/install"
    "/auth/ldap"
    "/comment"
)

for endpoint in "${endpoints[@]}"; do
    echo -e "${BLUE}  Adding routes for $endpoint...${NC}"
    
    # Unprotected routes
    create_route "$KONG_UNPROTECTED_ADMIN" "demo-backend-unprotected" "/unprotected$endpoint" > /dev/null
    
    # Protected routes (cloud)
    create_route "$KONG_PROTECTED_ADMIN" "demo-backend-protected" "/protected$endpoint" > /dev/null
    
    # Local AI routes
    create_route "$KONG_LOCAL_ADMIN" "demo-backend-local" "/local$endpoint" > /dev/null
done

echo ""
echo -e "${GREEN}✅ Three-tier Kong configuration complete!${NC}"
echo ""
echo -e "${YELLOW}📊 Service Endpoints:${NC}"
echo -e "🔓 Unprotected Kong:    http://localhost:8000"
echo -e "☁️  Cloud AI Protected:  http://localhost:8004"  
echo -e "🏠 Local AI Protected:   http://localhost:8006"
echo -e "🤖 Cloud AI Service:     http://localhost:18002"
echo -e "🏠 Local AI Service:     http://localhost:18003"
echo -e "📱 Demo Dashboard:       http://localhost:8090/enterprise_demo_dashboard.html"
echo ""
echo -e "${YELLOW}🧪 Test Commands:${NC}"
echo ""
echo -e "${RED}Unprotected (will allow malicious requests):${NC}"
echo "curl -X POST http://localhost:8000/unprotected/api/users \\"
echo "  -d \"id=1' OR '1'='1; DROP TABLE users;--\""
echo ""
echo -e "${BLUE}Cloud AI Protected (will block attacks):${NC}"  
echo "curl -X POST http://localhost:8004/protected/api/users \\"
echo "  -d \"id=1' OR '1'='1; DROP TABLE users;--\""
echo ""
echo -e "${GREEN}Local AI Protected (will block attacks locally):${NC}"
echo "curl -X POST http://localhost:8006/local/api/users \\"
echo "  -d \"id=1' OR '1'='1; DROP TABLE users;--\""
echo ""
echo -e "${YELLOW}🎬 To run automated demo:${NC}"
echo "python3 attack_comparison_engine.py"
echo ""
echo -e "${GREEN}🎉 Ready for enterprise demonstration!${NC}"