#!/bin/bash
# Deploy WebSocket Configuration Fix to Production
# Usage: ./scripts/deployment/deploy-websocket-fix.sh

set -e

echo "🚀 Kong Guard AI - WebSocket Fix Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Production server details
PROD_SERVER="root@192.168.0.228"

# Check if we have uncommitted changes
if ! git diff-index --quiet HEAD -- dashboard/; then
    echo "⚠️  You have uncommitted changes in dashboard/"
    echo "Would you like to commit them now? (y/n)"
    read -r response
    if [ "$response" = "y" ]; then
        echo "📝 Committing changes..."
        git add dashboard/src/app/page.tsx dashboard/src/hooks/useRealtimeDashboard.ts
        git commit -m "fix: update WebSocket port configuration for production

- Changed WebSocket URL from port 8000 to 18002
- Added proper message handlers for real-time threat analysis
- Fixed dashboard connectivity with WebSocket backend

Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>"
        echo "✅ Changes committed"
    fi
fi

# Push to GitHub
echo ""
echo "📤 Pushing to GitHub..."
git push origin main
echo "✅ Pushed to main branch"

# SSH into production and deploy
echo ""
echo "🌐 Connecting to production server..."
ssh -t "$PROD_SERVER" << 'ENDSSH'
set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo -e "${GREEN}📍 Connected to production server${NC}"

# Find the correct directory
PROD_DIR=""
if [ -d "/opt/KongGuardAI" ]; then
    PROD_DIR="/opt/KongGuardAI"
    echo -e "${GREEN}✓${NC} Found directory: /opt/KongGuardAI"
elif [ -d "/opt/kong-guard-ai" ]; then
    PROD_DIR="/opt/kong-guard-ai"
    echo -e "${GREEN}✓${NC} Found directory: /opt/kong-guard-ai"
else
    echo -e "${RED}✗ Error: Kong Guard AI directory not found${NC}"
    exit 1
fi

cd "$PROD_DIR"

# Backup current state
echo ""
echo -e "${YELLOW}💾 Creating backup...${NC}"
BACKUP_DIR="/root/kongguard-backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r dashboard/src "$BACKUP_DIR/" 2>/dev/null || true
echo -e "${GREEN}✓${NC} Backup created: $BACKUP_DIR"

# Pull latest changes
echo ""
echo -e "${YELLOW}📥 Pulling latest changes...${NC}"
git fetch origin
git pull origin main
echo -e "${GREEN}✓${NC} Updated to latest version"

# Show what changed
echo ""
echo -e "${YELLOW}📋 Changes pulled:${NC}"
git log -1 --oneline

# Stop services
echo ""
echo -e "${YELLOW}⏹️  Stopping services...${NC}"
docker-compose down
echo -e "${GREEN}✓${NC} Services stopped"

# Rebuild dashboard
echo ""
echo -e "${YELLOW}🔨 Rebuilding dashboard with WebSocket fix...${NC}"
docker-compose build --no-cache dashboard
echo -e "${GREEN}✓${NC} Dashboard rebuilt"

# Start services
echo ""
echo -e "${YELLOW}▶️  Starting services...${NC}"
docker-compose up -d
echo -e "${GREEN}✓${NC} Services started"

# Wait for services to be ready
echo ""
echo -e "${YELLOW}⏳ Waiting for services to be healthy...${NC}"
sleep 10

# Check service status
echo ""
echo -e "${YELLOW}📊 Service Status:${NC}"
docker-compose ps

# Test WebSocket connection
echo ""
echo -e "${YELLOW}🧪 Testing WebSocket connectivity...${NC}"
if curl -sf http://localhost:18002/ > /dev/null; then
    echo -e "${GREEN}✓${NC} WebSocket service responding on port 18002"
else
    echo -e "${RED}✗${NC} WebSocket service not responding"
fi

# Test dashboard
if curl -sf http://localhost:3000/ > /dev/null; then
    echo -e "${GREEN}✓${NC} Dashboard responding on port 3000"
else
    echo -e "${RED}✗${NC} Dashboard not responding"
fi

# Show recent logs
echo ""
echo -e "${YELLOW}📜 Recent Dashboard Logs:${NC}"
docker-compose logs --tail=20 dashboard

echo ""
echo -e "${YELLOW}📜 Recent WebSocket Logs:${NC}"
docker-compose logs --tail=20 ai-service 2>/dev/null || docker-compose logs --tail=20 kong-guard-ai-cloud 2>/dev/null || echo "No WebSocket service logs found"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Next steps:"
echo "1. Open dashboard in browser"
echo "2. Check WebSocket connection in console"
echo "3. Verify real-time data is flowing"
echo ""
echo "Monitor logs with: docker-compose logs -f dashboard"
echo "Rollback if needed: cd $BACKUP_DIR && docker-compose up -d"
echo ""

ENDSSH

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Deployment script completed successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Production server: $PROD_SERVER"
echo "Dashboard URL: http://192.168.0.228:3000"
echo "WebSocket URL: ws://192.168.0.228:18002/ws"
echo ""
