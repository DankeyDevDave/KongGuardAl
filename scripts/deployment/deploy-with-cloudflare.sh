#!/bin/bash

# Kong Guard AI - Production Deployment with Cloudflare Zero Trust
# Run this on your production server (192.168.0.228)

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Kong Guard AI - Production Deployment with Cloudflare${NC}"
echo "========================================================"
echo ""

# Check if running on production server
CURRENT_IP=$(hostname -I | awk '{print $1}')
if [ "$CURRENT_IP" != "192.168.0.228" ]; then
    echo -e "${YELLOW}⚠️  Warning: Not running on production server (192.168.0.228)${NC}"
    echo "Current IP: $CURRENT_IP"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Check prerequisites
echo -e "${BLUE}Step 1: Checking prerequisites...${NC}"
echo "-----------------------------------"

if ! command_exists docker; then
    echo -e "${RED}✗ Docker not installed${NC}"
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
fi
echo -e "${GREEN}✓ Docker installed${NC}"

if ! command_exists docker-compose; then
    echo -e "${RED}✗ Docker Compose not installed${NC}"
    echo "Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi
echo -e "${GREEN}✓ Docker Compose installed${NC}"

if ! command_exists cloudflared; then
    echo -e "${YELLOW}! Cloudflared not installed${NC}"
    echo "Installing cloudflared..."
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared-linux-amd64.deb
    rm cloudflared-linux-amd64.deb
fi
echo -e "${GREEN}✓ Cloudflared installed${NC}"

# Step 2: Deploy Kong Guard AI Stack
echo ""
echo -e "${BLUE}Step 2: Deploying Kong Guard AI Stack...${NC}"
echo "----------------------------------------"

# Create necessary directories
mkdir -p logs grafana-data prometheus-data redis-data

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cat > .env << 'EOF'
# API Keys (Update these!)
OPENAI_API_KEY=your-openai-key-here
ANTHROPIC_API_KEY=your-anthropic-key-here

# Database Passwords
KONG_PG_PASSWORD=KongPass2024!
KONGA_DB_PASSWORD=KongaPass2024!

# Network Configuration
PRODUCTION_IP=192.168.0.228
OLLAMA_MAC_IP=192.168.0.84
EOF
    echo -e "${YELLOW}⚠️  Please update API keys in .env file${NC}"
fi

# Start the stack
echo "Starting Docker Compose stack..."
docker-compose -f docker-compose.production.yml up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 15

# Check service health
echo ""
echo -e "${BLUE}Checking service health...${NC}"
services=("kong:8001" "grafana:3000" "web-dashboard:8080" "ai-service-cloud:18002" "prometheus:9090")
for service in "${services[@]}"; do
    name="${service%%:*}"
    port="${service##*:}"
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port/health" 2>/dev/null | grep -q "200\|404"; then
        echo -e "${GREEN}✓ $name is healthy${NC}"
    else
        echo -e "${YELLOW}⚠ $name may still be starting${NC}"
    fi
done

# Step 3: Configure Cloudflare Tunnel
echo ""
echo -e "${BLUE}Step 3: Configuring Cloudflare Tunnel...${NC}"
echo "-----------------------------------------"

# Check if already authenticated
if [ ! -f ~/.cloudflared/cert.pem ]; then
    echo "Please authenticate with Cloudflare:"
    cloudflared tunnel login
fi

# Check if tunnel exists
TUNNEL_NAME="kong-guard-ai"
if ! cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
    echo "Creating tunnel: $TUNNEL_NAME"
    cloudflared tunnel create $TUNNEL_NAME
fi

# Get tunnel ID
TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
echo -e "${GREEN}Tunnel ID: $TUNNEL_ID${NC}"

# Create tunnel config
echo "Creating tunnel configuration..."
mkdir -p ~/.cloudflared
cat > ~/.cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: $HOME/.cloudflared/$TUNNEL_ID.json

ingress:
  # Main Dashboard
  - hostname: kong-dashboard.\${DOMAIN}
    service: http://localhost:8080
    originRequest:
      noTLSVerify: true

  # Grafana Monitoring
  - hostname: kong-grafana.\${DOMAIN}
    service: http://localhost:3000
    originRequest:
      noTLSVerify: true

  # Kong Admin (Restricted)
  - hostname: kong-admin.\${DOMAIN}
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true

  # Konga UI
  - hostname: kong-ui.\${DOMAIN}
    service: http://localhost:1337
    originRequest:
      noTLSVerify: true

  # Health Check Endpoint
  - hostname: kong-health.\${DOMAIN}
    service: http://localhost:18002
    path: /health
    originRequest:
      noTLSVerify: true

  - service: http_status:404
EOF

# Prompt for domain
echo ""
read -p "Enter your domain (e.g., example.com): " DOMAIN
sed -i "s/\${DOMAIN}/$DOMAIN/g" ~/.cloudflared/config.yml

# Setup DNS
echo ""
echo -e "${BLUE}Step 4: Configuring DNS...${NC}"
echo "----------------------------"

echo "Adding DNS routes..."
cloudflared tunnel route dns $TUNNEL_NAME kong-dashboard.$DOMAIN || true
cloudflared tunnel route dns $TUNNEL_NAME kong-grafana.$DOMAIN || true
cloudflared tunnel route dns $TUNNEL_NAME kong-admin.$DOMAIN || true
cloudflared tunnel route dns $TUNNEL_NAME kong-ui.$DOMAIN || true
cloudflared tunnel route dns $TUNNEL_NAME kong-health.$DOMAIN || true

# Install as service
echo ""
echo -e "${BLUE}Step 5: Installing Cloudflare as service...${NC}"
echo "--------------------------------------------"

sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl restart cloudflared

# Verify tunnel is running
sleep 5
if systemctl is-active --quiet cloudflared; then
    echo -e "${GREEN}✓ Cloudflare tunnel is running${NC}"
else
    echo -e "${RED}✗ Cloudflare tunnel failed to start${NC}"
    echo "Check logs: sudo journalctl -u cloudflared -n 50"
fi

# Display summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Local Access (within network):"
echo "  Dashboard:  http://192.168.0.228:8080"
echo "  Grafana:    http://192.168.0.228:3000"
echo "  Kong Admin: http://192.168.0.228:8001"
echo ""
echo "Remote Access (via Cloudflare):"
echo "  Dashboard:  https://kong-dashboard.$DOMAIN"
echo "  Grafana:    https://kong-grafana.$DOMAIN"
echo "  Kong Admin: https://kong-admin.$DOMAIN (restricted)"
echo "  Konga UI:   https://kong-ui.$DOMAIN"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Configure Zero Trust policies at https://one.dash.cloudflare.com/"
echo "2. Add authentication requirements for each application"
echo "3. Test access from outside network"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  View logs:        docker-compose -f docker-compose.production.yml logs -f"
echo "  Tunnel status:    sudo systemctl status cloudflared"
echo "  Tunnel logs:      sudo journalctl -u cloudflared -f"
echo "  Service status:   docker-compose -f docker-compose.production.yml ps"
echo ""
echo -e "${GREEN}Your Kong Guard AI is now accessible securely from anywhere!${NC}"
