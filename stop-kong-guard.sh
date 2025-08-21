#!/bin/bash

# Stop Kong Guard AI services

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${BLUE}🛑 Stopping Kong Guard AI services...${NC}"

cd "$SCRIPT_DIR"

if docker compose version &> /dev/null; then
    docker compose down
else
    docker-compose down
fi

echo -e "${GREEN}✅ All services stopped${NC}"

# Optional: Clean volumes
if [ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ]; then
    echo -e "${BLUE}🗑️  Cleaning volumes...${NC}"
    if docker compose version &> /dev/null; then
        docker compose down -v
    else
        docker-compose down -v
    fi
    echo -e "${GREEN}✅ Volumes cleaned${NC}"
fi