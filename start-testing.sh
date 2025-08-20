#!/bin/bash

# Kong Guard AI Testing Environment Launcher
# This script starts the full testing environment with UI

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🚀 Kong Guard AI Testing Environment${NC}"
echo -e "${CYAN}=====================================>${NC}"
echo

# Function to check if a service is running
check_service() {
    local service=$1
    local port=$2
    if lsof -i :$port > /dev/null 2>&1; then
        echo -e "${GREEN}✅ $service is running on port $port${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  $service is not running on port $port${NC}"
        return 1
    fi
}

# Function to wait for service
wait_for_service() {
    local service=$1
    local port=$2
    local max_wait=60
    local count=0
    
    echo -e "${BLUE}Waiting for $service on port $port...${NC}"
    while [ $count -lt $max_wait ]; do
        if lsof -i :$port > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $service is ready!${NC}"
            return 0
        fi
        sleep 1
        ((count++))
        echo -ne "."
    done
    echo
    echo -e "${RED}❌ Timeout waiting for $service${NC}"
    return 1
}

# Step 1: Check Docker
echo -e "${BLUE}Step 1: Checking Docker...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Docker is running${NC}"
echo

# Step 2: Start Kong and services
echo -e "${BLUE}Step 2: Starting Kong Guard AI services...${NC}"

# Check if services are already running
SERVICES_RUNNING=true
check_service "Kong Admin API" 8001 || SERVICES_RUNNING=false
check_service "Kong Proxy" 8000 || SERVICES_RUNNING=false
check_service "PostgreSQL" 5432 || SERVICES_RUNNING=false

if [ "$SERVICES_RUNNING" = false ]; then
    echo -e "${YELLOW}Starting services with Docker Compose...${NC}"
    
    # Try docker compose v2 first, then v1
    if docker compose version > /dev/null 2>&1; then
        docker compose up -d
    elif command -v docker-compose > /dev/null 2>&1; then
        docker-compose up -d
    else
        echo -e "${RED}❌ Docker Compose not found${NC}"
        exit 1
    fi
    
    # Wait for services to be ready
    wait_for_service "PostgreSQL" 5432
    sleep 5 # Give PostgreSQL time to initialize
    wait_for_service "Kong Admin API" 8001
    wait_for_service "Kong Proxy" 8000
else
    echo -e "${GREEN}✅ All services are already running${NC}"
fi
echo

# Step 3: Configure Kong Guard AI plugin
echo -e "${BLUE}Step 3: Configuring Kong Guard AI plugin...${NC}"

# Check if plugin is already configured
if curl -s http://localhost:8001/plugins | grep -q "kong-guard-ai"; then
    echo -e "${GREEN}✅ Kong Guard AI plugin is already configured${NC}"
else
    echo -e "${YELLOW}Setting up Kong Guard AI plugin...${NC}"
    
    # Create a test service if it doesn't exist
    curl -s -X POST http://localhost:8001/services \
        -d name=test-api \
        -d url=http://demo-api:80 > /dev/null 2>&1 || true
    
    # Create a route for the service
    curl -s -X POST http://localhost:8001/services/test-api/routes \
        -d paths[]=/api \
        -d strip_path=false > /dev/null 2>&1 || true
    
    # Enable Kong Guard AI plugin
    curl -s -X POST http://localhost:8001/services/test-api/plugins \
        -d name=kong-guard-ai \
        -d config.dry_run=true \
        -d config.log_only=false \
        -d config.sensitivity=medium \
        -d config.ml_enabled=true \
        -d config.threat_threshold=0.7 > /dev/null 2>&1 || true
    
    echo -e "${GREEN}✅ Kong Guard AI plugin configured${NC}"
fi
echo

# Step 4: Start web server for UI
echo -e "${BLUE}Step 4: Starting Testing UI...${NC}"

# Kill any existing Python server on port 8888
lsof -ti:8888 | xargs kill -9 2>/dev/null || true

# Start Python HTTP server in background
cd testing-ui
python3 -m http.server 8888 > /dev/null 2>&1 &
SERVER_PID=$!
cd ..

echo -e "${GREEN}✅ Testing UI server started (PID: $SERVER_PID)${NC}"
echo

# Step 5: Display access information
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}🎉 Kong Guard AI Testing Environment Ready!${NC}"
echo -e "${CYAN}========================================${NC}"
echo
echo -e "${BLUE}Access Points:${NC}"
echo -e "  📊 Testing Dashboard: ${GREEN}http://localhost:8888${NC}"
echo -e "  🔧 Kong Admin API:   ${GREEN}http://localhost:8001${NC}"
echo -e "  🌐 Kong Proxy:       ${GREEN}http://localhost:8000${NC}"
echo -e "  🗄️  PostgreSQL:      ${GREEN}localhost:5432${NC}"
echo -e "  📦 Demo API:         ${GREEN}http://localhost:8080${NC}"
echo
echo -e "${BLUE}Available Services:${NC}"
echo -e "  • Kong Gateway with Guard AI plugin"
echo -e "  • PostgreSQL database"
echo -e "  • Redis cache (if configured)"
echo -e "  • Demo API for testing"
echo -e "  • Testing Dashboard UI"
echo
echo -e "${YELLOW}Quick Commands:${NC}"
echo -e "  View logs:     docker-compose logs -f kong"
echo -e "  Stop services: docker-compose down"
echo -e "  View plugins:  curl http://localhost:8001/plugins"
echo -e "  Test API:      curl http://localhost:8000/api/test"
echo

# Check if browser should be opened
if [ "$1" != "--no-browser" ]; then
    echo -e "${BLUE}Opening Testing Dashboard in browser...${NC}"
    
    # Detect OS and open browser
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open http://localhost:8888
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v xdg-open > /dev/null; then
            xdg-open http://localhost:8888
        elif command -v gnome-open > /dev/null; then
            gnome-open http://localhost:8888
        fi
    fi
fi

echo
echo -e "${GREEN}Press Ctrl+C to stop the testing environment${NC}"
echo

# Keep script running and handle cleanup
trap cleanup EXIT INT TERM

cleanup() {
    echo
    echo -e "${YELLOW}Shutting down testing environment...${NC}"
    
    # Kill Python server
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Testing UI server stopped${NC}"
    fi
    
    # Optionally stop Docker services
    read -p "Stop Docker services? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if docker compose version > /dev/null 2>&1; then
            docker compose down
        elif command -v docker-compose > /dev/null 2>&1; then
            docker-compose down
        fi
        echo -e "${GREEN}✅ Docker services stopped${NC}"
    fi
    
    echo -e "${CYAN}Testing environment shutdown complete${NC}"
    exit 0
}

# Keep the script running
while true; do
    sleep 1
done