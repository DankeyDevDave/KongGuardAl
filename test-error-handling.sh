#!/bin/bash

# Test script to simulate errors and show Claude assistance visual feedback

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${BLUE}Kong Guard AI - Error Handling Test${NC}"
echo "===================================="
echo ""

# Create fake error log for testing
echo "Docker daemon is not running" > "$SCRIPT_DIR/errors.log"
echo "kong-database health check failed" >> "$SCRIPT_DIR/errors.log"
echo "kong-gateway failed to start: port 18001 already in use" >> "$SCRIPT_DIR/errors.log"

# Source the functions from the main script
source <(sed -n '/^# Function: Print colored output/,/^# Function: Show usage/p' launch-kong-guard.sh)

# Test the Claude assistance function
echo -e "${YELLOW}Simulating error condition...${NC}"
echo ""

# Create minimal test version of prepare_claude_assist
prepare_claude_assist_demo() {
    echo -e "${BLUE}🤖 Analyzing errors and preparing diagnostics...${NC}"
    echo ""
    
    echo -e "${YELLOW}📊 Collecting diagnostic information:${NC}"
    
    printf "  ├─ Reading error log"
    sleep 0.5
    printf " ✓\n"
    
    printf "  ├─ Checking container status"
    sleep 0.5
    printf " ✓\n"
    
    printf "  └─ Collecting container logs\n"
    
    local containers=("kong-gateway" "kong-database" "kong-redis" "demo-api")
    for container in "${containers[@]}"; do
        printf "     Checking %s" "$container"
        sleep 0.3
        printf " ✓\n"
    done
    
    echo ""
    echo -e "${GREEN}✅ Diagnostics collected and saved${NC}"
    echo ""
    
    echo -e "${BLUE}🤔 Would you like AI assistance to fix these issues? (demo - press Enter)${NC}"
    read -r
    
    echo ""
    echo -e "${GREEN}🚀 Initiating Claude AI assistance...${NC}"
    echo ""
    
    echo -e "${BLUE}📋 Claude will analyze:${NC}"
    echo "  • Error logs and diagnostics"
    echo "  • Container health status"
    echo "  • Service configuration issues"
    echo "  • Potential fixes and solutions"
    echo ""
    
    echo -e "${YELLOW}🧠 Processing with Claude AI...${NC}"
    echo "  ├─ Sending diagnostic data"
    sleep 0.5
    echo "  ├─ Analyzing error patterns"
    sleep 0.5
    echo "  └─ Generating solutions"
    sleep 0.5
    echo ""
    
    echo -e "${GREEN}🎯 Launching Claude with collected diagnostics...${NC}"
    echo ""
    echo "────────────────────────────────────────────────"
    echo ""
    echo "[Demo Mode: Claude would be called here with the diagnostics]"
    echo ""
    
    # Show sample errors that would be sent
    echo -e "${BLUE}Sample prompt that would be sent to Claude:${NC}"
    echo ""
    echo "Kong Guard AI services are failing to start. Please analyze these errors:"
    echo ""
    echo "=== ERRORS ==="
    cat "$SCRIPT_DIR/errors.log"
    echo ""
    echo "=== CONTAINER STATUS ==="
    echo "kong-gateway: Exited (1) 2 minutes ago"
    echo "kong-database: Up 5 minutes"
    echo "kong-redis: Up 5 minutes"
    echo ""
    echo "Please provide:"
    echo "1. Root cause of the failure"
    echo "2. Step-by-step fix"
    echo "3. Commands to verify the fix worked"
}

# Run the demo
prepare_claude_assist_demo

# Cleanup
rm -f "$SCRIPT_DIR/errors.log"

echo ""
echo -e "${GREEN}✅ Error handling demo complete!${NC}"
echo ""
echo "This demonstrates the visual feedback when errors occur and Claude assistance is triggered."