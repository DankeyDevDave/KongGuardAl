#!/bin/bash

# ============================================
# Configure ZapVend App to Route via Kong
# ============================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KONG_ADMIN_URL="http://localhost:18001"
KONG_PROXY_URL="http://localhost:18000"

# ZapVend Backend Configuration
ZAPVEND_BACKEND_URL="http://host.docker.internal:8000"  # If running locally
# ZAPVEND_BACKEND_URL="http://elec-vending-backend:8000"  # If in same Docker network

echo -e "${BLUE}🔧 Configuring ZapVend to route through Kong...${NC}"
echo ""

# 1. Create Service for ZapVend Backend
echo -e "${YELLOW}1️⃣ Creating ZapVend service in Kong...${NC}"

# Check if service already exists
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" $KONG_ADMIN_URL/services/zapvend-backend)

if [ "$HTTP_CODE" = "404" ]; then
  # Service doesn't exist, create it
  curl -X POST $KONG_ADMIN_URL/services \
    -H "Content-Type: application/json" \
    --silent --show-error \
    -d '{
      "name": "zapvend-backend",
      "protocol": "http",
      "host": "host.docker.internal",
      "port": 8000,
      "path": "/",
      "connect_timeout": 60000,
      "write_timeout": 60000,
      "read_timeout": 60000,
      "retries": 3
    }' | jq
else
  echo "Service 'zapvend-backend' already exists, skipping creation"
fi

echo ""

# 2. Create Routes for ZapVend API
echo -e "${YELLOW}2️⃣ Creating API route for ZapVend...${NC}"

# Main API route
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/routes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zapvend-api",
    "paths": ["/zapvend/api"],
    "strip_path": true,
    "preserve_host": false,
    "protocols": ["http", "https"],
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
  }' | jq

echo ""

# Auth routes (special handling)
echo -e "${YELLOW}3️⃣ Creating auth routes...${NC}"
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/routes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zapvend-auth",
    "paths": ["/zapvend/auth"],
    "strip_path": false,
    "preserve_host": false,
    "protocols": ["http", "https"]
  }' | jq

echo ""

# Static files / Frontend route
echo -e "${YELLOW}4️⃣ Creating frontend route...${NC}"
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/routes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zapvend-frontend",
    "paths": ["/zapvend"],
    "strip_path": true,
    "preserve_host": false,
    "protocols": ["http", "https"]
  }' | jq

echo ""

# 3. Configure Plugins for ZapVend Service
echo -e "${YELLOW}5️⃣ Configuring plugins for ZapVend...${NC}"

# Add CORS plugin for API routes
echo "  • Adding CORS support..."

# Check if CORS plugin already exists for this service
CORS_EXISTS=$(curl -s $KONG_ADMIN_URL/services/zapvend-backend/plugins | jq -r '.data[] | select(.name == "cors") | .id')

if [ -z "$CORS_EXISTS" ] || [ "$CORS_EXISTS" = "null" ]; then
  # CORS plugin doesn't exist, create it
  curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/plugins \
    -H "Content-Type: application/json" \
    --silent --show-error \
    -d '{
      "name": "cors",
      "config": {
        "origins": ["*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "headers": ["Accept", "Accept-Version", "Content-Length", "Content-MD5", "Content-Type", "Date", "X-Auth-Token", "Authorization"],
        "exposed_headers": ["X-Auth-Token", "Authorization"],
        "credentials": false,
        "max_age": 3600
      }
    }' | jq
else
  # CORS plugin exists, update it
  echo "CORS plugin already exists (ID: $CORS_EXISTS), updating configuration"
  curl -X PATCH $KONG_ADMIN_URL/plugins/$CORS_EXISTS \
    -H "Content-Type: application/json" \
    --silent --show-error \
    -d '{
      "config": {
        "origins": ["*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "headers": ["Accept", "Accept-Version", "Content-Length", "Content-MD5", "Content-Type", "Date", "X-Auth-Token", "Authorization"],
        "exposed_headers": ["X-Auth-Token", "Authorization"],
        "credentials": false,
        "max_age": 3600
      }
    }' | jq
fi

echo ""

# Add Rate Limiting
echo "  • Adding rate limiting..."
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rate-limiting",
    "config": {
      "minute": 100,
      "hour": 1000,
      "day": 10000,
      "policy": "local",
      "fault_tolerant": true,
      "hide_client_headers": false,
      "redis_ssl": false,
      "redis_ssl_verify": false
    }
  }' | jq

echo ""

# Add Request Size Limiting
echo "  • Adding request size limiting..."
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "request-size-limiting",
    "config": {
      "allowed_payload_size": 10,
      "size_unit": "megabytes",
      "require_content_length": false
    }
  }' | jq

echo ""

# Add Response Transformer (add security headers)
echo "  • Adding security headers..."
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "response-transformer",
    "config": {
      "add": {
        "headers": [
          "X-Frame-Options:SAMEORIGIN",
          "X-Content-Type-Options:nosniff",
          "X-XSS-Protection:1; mode=block",
          "Strict-Transport-Security:max-age=31536000; includeSubDomains"
        ]
      }
    }
  }' | jq

echo ""

# Add Request Transformer (for authentication headers if needed)
echo "  • Adding request transformer for auth headers..."
curl -X POST $KONG_ADMIN_URL/routes/zapvend-api/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "request-transformer",
    "config": {
      "add": {
        "headers": ["X-Forwarded-Prefix:/zapvend"]
      }
    }
  }' | jq

echo ""

# 4. Enable Kong Guard AI for ZapVend routes
echo -e "${YELLOW}6️⃣ Enabling Kong Guard AI protection...${NC}"
curl -X POST $KONG_ADMIN_URL/services/zapvend-backend/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "block_threshold": 0.7,
      "rate_limit_threshold": 0.5,
      "ddos_rpm_threshold": 200,
      "dry_run": false,
      "log_level": "info"
    }
  }' | jq

echo ""
echo -e "${GREEN}✅ ZapVend configuration complete!${NC}"
echo ""
echo -e "${BLUE}📚 Access URLs:${NC}"
echo "  • Via Kong Proxy: http://localhost:18000/zapvend"
echo "  • API Endpoint: http://localhost:18000/zapvend/api"
echo "  • Auth Endpoint: http://localhost:18000/zapvend/auth"
echo ""
echo -e "${YELLOW}🧪 Test Commands:${NC}"
echo "  # Test frontend access"
echo "  curl -I http://localhost:18000/zapvend"
echo ""
echo "  # Test API endpoint"
echo "  curl http://localhost:18000/zapvend/api/health"
echo ""
echo "  # Test with authentication header"
echo "  curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:18000/zapvend/api/meters"
echo ""
echo -e "${BLUE}🔍 View configuration:${NC}"
echo "  # List all services"
echo "  curl -s $KONG_ADMIN_URL/services | jq"
echo ""
echo "  # View ZapVend service details"
echo "  curl -s $KONG_ADMIN_URL/services/zapvend-backend | jq"
echo ""
echo "  # View routes"
echo "  curl -s $KONG_ADMIN_URL/services/zapvend-backend/routes | jq"
echo ""
echo "  # View plugins"
echo "  curl -s $KONG_ADMIN_URL/services/zapvend-backend/plugins | jq"
