#!/bin/bash

set -e

echo "=================================================="
echo "Kong Guard AI Plugin Deployment"
echo "=================================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if Kong is running
echo -e "${YELLOW}[DEPLOY]${NC} Checking Kong status..."
if ! curl -s http://localhost:8001 > /dev/null; then
    echo -e "${RED}[ERROR]${NC} Kong is not running. Please start Kong first."
    exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} Kong is running"

# Build Kong with plugin
echo -e "${YELLOW}[DEPLOY]${NC} Building Kong with Guard AI plugin..."
cd kong-plugin
docker build -t kong-guard-ai:latest .
cd ..

# Stop existing Kong
echo -e "${YELLOW}[DEPLOY]${NC} Stopping existing Kong container..."
docker-compose -f docker-compose-simple.yml stop kong

# Update docker-compose to use new image
echo -e "${YELLOW}[DEPLOY]${NC} Updating Kong to use Guard AI image..."
sed -i.bak 's|image: kong:3.8.0|image: kong-guard-ai:latest|' docker-compose-simple.yml

# Start Kong with plugin
echo -e "${YELLOW}[DEPLOY]${NC} Starting Kong with Guard AI plugin..."
docker-compose -f docker-compose-simple.yml up -d kong

# Wait for Kong to be ready
echo -e "${YELLOW}[DEPLOY]${NC} Waiting for Kong to be ready..."
sleep 10

# Verify plugin is loaded
echo -e "${YELLOW}[DEPLOY]${NC} Verifying plugin installation..."
if curl -s http://localhost:8001 | grep -q "kong-guard-ai"; then
    echo -e "${GREEN}[SUCCESS]${NC} Kong Guard AI plugin is loaded"
else
    echo -e "${RED}[WARNING]${NC} Plugin not found in loaded plugins list"
fi

# Create a test service and route
echo -e "${YELLOW}[DEPLOY]${NC} Creating test service and route..."

# Create service pointing to demo API
curl -s -X POST http://localhost:8001/services \
    -H "Content-Type: application/json" \
    -d '{
        "name": "demo-service",
        "url": "http://demo-api:80"
    }' > /dev/null

# Create route
curl -s -X POST http://localhost:8001/services/demo-service/routes \
    -H "Content-Type: application/json" \
    -d '{
        "name": "demo-route",
        "paths": ["/demo"]
    }' > /dev/null

# Enable Kong Guard AI plugin on the service
echo -e "${YELLOW}[DEPLOY]${NC} Enabling Kong Guard AI plugin..."
curl -s -X POST http://localhost:8001/services/demo-service/plugins \
    -H "Content-Type: application/json" \
    -d '{
        "name": "kong-guard-ai",
        "config": {
            "dry_run": true,
            "block_threshold": 0.8,
            "rate_limit_threshold": 0.6,
            "ddos_rpm_threshold": 100,
            "enable_ml": true,
            "enable_notifications": true,
            "notification_url": "http://mock-attacker:80/webhook",
            "enable_learning": true
        }
    }' > /dev/null

echo -e "${GREEN}[SUCCESS]${NC} Kong Guard AI plugin enabled on demo-service"

# Test the plugin
echo -e "${YELLOW}[DEPLOY]${NC} Testing plugin with normal request..."
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/demo/get
echo

echo -e "${YELLOW}[DEPLOY]${NC} Testing plugin with suspicious request (SQL injection)..."
curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/demo/get?query='; DROP TABLE users; --"
echo

# Check plugin status
echo -e "${YELLOW}[DEPLOY]${NC} Checking plugin status..."
curl -s http://localhost:8001/kong-guard-ai/status | jq .

echo -e "${GREEN}[SUCCESS]${NC} Kong Guard AI plugin deployed successfully!"
echo
echo "Available endpoints:"
echo "  - Kong Proxy: http://localhost:8000"
echo "  - Kong Admin: http://localhost:8001"
echo "  - Plugin Status: http://localhost:8001/kong-guard-ai/status"
echo "  - Plugin Incidents: http://localhost:8001/kong-guard-ai/incidents"
echo "  - Plugin Feedback: POST http://localhost:8001/kong-guard-ai/feedback"
echo
echo "Test commands:"
echo "  - Normal request: curl http://localhost:8000/demo/get"
echo "  - SQL injection test: curl 'http://localhost:8000/demo/get?q=DROP+TABLE'"
echo "  - XSS test: curl 'http://localhost:8000/demo/get?q=<script>alert(1)</script>'"
echo "  - DDoS simulation: for i in {1..200}; do curl http://localhost:8000/demo/get & done"