#!/bin/bash

# Kong Guard AI - Test Runner Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Kong Guard AI - Playwright Test Suite${NC}"
echo "======================================="

# Check if Kong is running
if ! curl -f http://localhost:18001 > /dev/null 2>&1; then
    echo -e "${YELLOW}Kong Admin API not responding. Starting Kong stack...${NC}"
    docker compose up -d
    echo "Waiting for Kong to be ready..."
    sleep 20
fi

# Verify services
echo -e "\n${GREEN}Checking services...${NC}"
if curl -f http://localhost:18001 > /dev/null 2>&1; then
    echo "✓ Kong Admin API: Online"
else
    echo -e "${RED}✗ Kong Admin API: Offline${NC}"
    exit 1
fi

if curl -f http://localhost:18000/test/get > /dev/null 2>&1; then
    echo "✓ Kong Proxy: Online"
else
    echo -e "${YELLOW}⚠ Kong Proxy: May be offline${NC}"
fi

# Check if web server is running
if ! lsof -i:8080 > /dev/null 2>&1; then
    echo -e "\n${YELLOW}Starting web server for dashboard...${NC}"
    python3 -m http.server 8080 > /dev/null 2>&1 &
    WEB_SERVER_PID=$!
    echo "Web server started (PID: $WEB_SERVER_PID)"
    sleep 2
else
    echo "✓ Web server: Already running on port 8080"
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo -e "\n${YELLOW}Installing dependencies...${NC}"
    npm install
fi

# Check if Playwright browsers are installed
if [ ! -d "$HOME/Library/Caches/ms-playwright" ]; then
    echo -e "\n${YELLOW}Installing Playwright browsers...${NC}"
    npx playwright install
fi

# Run tests based on argument
echo -e "\n${GREEN}Running tests...${NC}"
echo "======================================="

case "$1" in
    "ui")
        echo "Opening Playwright UI mode..."
        npx playwright test --ui
        ;;
    "debug")
        echo "Running tests in debug mode..."
        npx playwright test --debug
        ;;
    "headed")
        echo "Running tests in headed mode..."
        npx playwright test --headed
        ;;
    "status")
        echo "Running status check tests..."
        npx playwright test tests/e2e/01-status-checks.spec.ts
        ;;
    "normal")
        echo "Running normal traffic tests..."
        npx playwright test tests/e2e/02-normal-traffic.spec.ts
        ;;
    "attack")
        echo "Running attack simulation tests..."
        npx playwright test tests/e2e/03-attack-simulations.spec.ts
        ;;
    "plugin")
        echo "Running plugin management tests..."
        npx playwright test tests/e2e/04-plugin-management.spec.ts
        ;;
    "ui-test")
        echo "Running UI interaction tests..."
        npx playwright test tests/e2e/05-ui-interactions.spec.ts
        ;;
    "quick")
        echo "Running quick smoke tests..."
        npx playwright test --grep="should load dashboard|should send normal request|should detect and block SQL injection"
        ;;
    "report")
        echo "Opening test report..."
        npx playwright show-report
        ;;
    *)
        echo "Running all tests..."
        npx playwright test
        ;;
esac

# Show results
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✓ Tests completed successfully!${NC}"
    echo -e "Run '${YELLOW}./run-tests.sh report${NC}' to view detailed HTML report"
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    echo -e "Run '${YELLOW}./run-tests.sh report${NC}' to view detailed HTML report"
    exit 1
fi
