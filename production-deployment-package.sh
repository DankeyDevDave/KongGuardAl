#!/bin/bash

# Kong Guard AI - Complete Production Deployment Package
# Transfer this script and the project to your production server and run it

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Kong Guard AI - Production Server Setup${NC}"
echo "==========================================="
echo ""
echo "This script will:"
echo "1. Install all dependencies"
echo "2. Deploy Kong Guard AI stack"
echo "3. Configure Cloudflare Zero Trust"
echo "4. Set up automatic startup"
echo ""

# Verify we're on the production server
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo -e "${YELLOW}Current server IP: $CURRENT_IP${NC}"

if [ "$CURRENT_IP" != "192.168.0.228" ]; then
    echo -e "${YELLOW}⚠️  Warning: This doesn't appear to be the production server (192.168.0.228)${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create project directory if needed
PROJECT_DIR="/opt/kong-guard-ai"
echo -e "${BLUE}Setting up project directory: $PROJECT_DIR${NC}"
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR
cd $PROJECT_DIR

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Docker if needed
if ! command_exists docker; then
    echo -e "${YELLOW}Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}✓ Docker installed${NC}"
    echo -e "${YELLOW}Note: You may need to log out and back in for docker group to take effect${NC}"
else
    echo -e "${GREEN}✓ Docker already installed${NC}"
fi

# Install Docker Compose if needed
if ! command_exists docker-compose; then
    echo -e "${YELLOW}Installing Docker Compose...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}✓ Docker Compose installed${NC}"
else
    echo -e "${GREEN}✓ Docker Compose already installed${NC}"
fi

# Install Cloudflared if needed
if ! command_exists cloudflared; then
    echo -e "${YELLOW}Installing Cloudflared...${NC}"
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared-linux-amd64.deb
    rm cloudflared-linux-amd64.deb
    echo -e "${GREEN}✓ Cloudflared installed${NC}"
else
    echo -e "${GREEN}✓ Cloudflared already installed${NC}"
fi

# Create necessary directories
echo -e "${BLUE}Creating required directories...${NC}"
mkdir -p logs grafana-data prometheus-data redis-data
mkdir -p grafana-local/provisioning/datasources
mkdir -p grafana-local/provisioning/dashboards
mkdir -p grafana-local/dashboards
mkdir -p ai-service
mkdir -p dashboards
mkdir -p kong-plugin/kong/plugins

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env configuration file...${NC}"
    cat > .env << 'EOF'
# Network Configuration
PRODUCTION_IP=192.168.0.228
OLLAMA_MAC_IP=192.168.0.84

# API Keys - PLEASE UPDATE THESE!
OPENAI_API_KEY=sk-your-openai-key-here
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here

# Database Passwords (change in production!)
KONG_PG_PASSWORD=KongPass2024!
KONGA_DB_PASSWORD=KongaPass2024!
KONGA_TOKEN_SECRET=km1GUr4RkcQD7DewhJPNXrCuZwcKmqjb

# Service Configuration
AI_PROVIDER=openai
LOG_LEVEL=INFO
EOF
    echo -e "${RED}⚠️  IMPORTANT: Edit .env file and add your API keys!${NC}"
fi

# Stop any existing services
echo -e "${BLUE}Stopping any existing services...${NC}"
docker-compose -f docker-compose.production.yml down 2>/dev/null || true

# Start the Kong Guard AI stack
echo -e "${BLUE}Starting Kong Guard AI stack...${NC}"
docker-compose -f docker-compose.production.yml up -d

# Wait for services to be ready
echo -e "${YELLOW}Waiting for services to initialize (30 seconds)...${NC}"
sleep 30

# Check service health
echo -e "${BLUE}Verifying service health...${NC}"
echo ""

# Function to check service health
check_service() {
    local name=$1
    local url=$2
    if curl -s -f -o /dev/null "$url" 2>/dev/null; then
        echo -e "${GREEN}✓ $name is healthy${NC}"
        return 0
    else
        echo -e "${RED}✗ $name is not responding${NC}"
        return 1
    fi
}

# Check each service
check_service "Kong Gateway" "http://localhost:8001"
check_service "Grafana" "http://localhost:3000/api/health"
check_service "Web Dashboard" "http://localhost:8080"
check_service "Prometheus" "http://localhost:9090/-/healthy"
check_service "Cloud AI Service" "http://localhost:18002/health"
check_service "Ollama AI Service" "http://localhost:18003/health"
check_service "Konga Admin UI" "http://localhost:1337"

echo ""
echo -e "${BLUE}=== Cloudflare Zero Trust Setup ===${NC}"
echo ""

# Check if cloudflared is authenticated
if [ ! -f ~/.cloudflared/cert.pem ]; then
    echo -e "${YELLOW}Please authenticate with Cloudflare:${NC}"
    echo "A browser window will open. Log in to your Cloudflare account."
    cloudflared tunnel login
else
    echo -e "${GREEN}✓ Already authenticated with Cloudflare${NC}"
fi

# Get domain from user
echo ""
read -p "Enter your domain name (e.g., example.com): " DOMAIN

# Create or get tunnel
TUNNEL_NAME="kong-guard-ai"
echo -e "${BLUE}Setting up Cloudflare tunnel: $TUNNEL_NAME${NC}"

# Check if tunnel exists
if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
    echo -e "${GREEN}✓ Tunnel already exists${NC}"
    TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
else
    echo "Creating new tunnel..."
    cloudflared tunnel create $TUNNEL_NAME
    TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
fi

echo -e "${GREEN}Tunnel ID: $TUNNEL_ID${NC}"

# Create Cloudflare tunnel configuration
echo -e "${BLUE}Creating tunnel configuration...${NC}"
mkdir -p ~/.cloudflared
cat > ~/.cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: $HOME/.cloudflared/$TUNNEL_ID.json

ingress:
  # Main Dashboard
  - hostname: kong.$DOMAIN
    service: http://localhost:8080
    originRequest:
      noTLSVerify: true

  # Grafana Monitoring
  - hostname: grafana.$DOMAIN
    service: http://localhost:3000
    originRequest:
      noTLSVerify: true

  # Kong Admin API (Restricted)
  - hostname: admin.$DOMAIN
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true

  # Konga UI
  - hostname: konga.$DOMAIN
    service: http://localhost:1337
    originRequest:
      noTLSVerify: true

  # AI Service Health
  - hostname: health.$DOMAIN
    service: http://localhost:18002
    path: /health
    originRequest:
      noTLSVerify: true

  - service: http_status:404
EOF

# Configure DNS
echo -e "${BLUE}Configuring DNS records...${NC}"
cloudflared tunnel route dns $TUNNEL_NAME kong.$DOMAIN || echo "DNS already configured"
cloudflared tunnel route dns $TUNNEL_NAME grafana.$DOMAIN || echo "DNS already configured"
cloudflared tunnel route dns $TUNNEL_NAME admin.$DOMAIN || echo "DNS already configured"
cloudflared tunnel route dns $TUNNEL_NAME konga.$DOMAIN || echo "DNS already configured"
cloudflared tunnel route dns $TUNNEL_NAME health.$DOMAIN || echo "DNS already configured"

# Install cloudflared as system service
echo -e "${BLUE}Installing Cloudflare tunnel as system service...${NC}"
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl restart cloudflared

# Verify tunnel is running
sleep 5
if systemctl is-active --quiet cloudflared; then
    echo -e "${GREEN}✓ Cloudflare tunnel is running${NC}"
else
    echo -e "${RED}✗ Cloudflare tunnel failed to start${NC}"
    echo "Check logs with: sudo journalctl -u cloudflared -n 50"
fi

# Create systemd service for Docker Compose
echo -e "${BLUE}Creating systemd service for automatic startup...${NC}"
sudo tee /etc/systemd/system/kong-guard-ai.service > /dev/null << EOF
[Unit]
Description=Kong Guard AI Stack
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/local/bin/docker-compose -f docker-compose.production.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.production.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kong-guard-ai.service

# Display final status
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}🎉 Production Deployment Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${BLUE}Local Network Access:${NC}"
echo "  Dashboard:    http://192.168.0.228:8080"
echo "  Grafana:      http://192.168.0.228:3000 (admin/KongGuard2024!)"
echo "  Kong Admin:   http://192.168.0.228:8001"
echo "  Konga UI:     http://192.168.0.228:1337"
echo ""
echo -e "${BLUE}Internet Access via Cloudflare:${NC}"
echo "  Dashboard:    https://kong.$DOMAIN"
echo "  Grafana:      https://grafana.$DOMAIN"
echo "  Kong Admin:   https://admin.$DOMAIN (configure access policy!)"
echo "  Konga UI:     https://konga.$DOMAIN"
echo "  Health Check: https://health.$DOMAIN"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT NEXT STEPS:${NC}"
echo ""
echo "1. Configure Zero Trust Access Policies:"
echo "   - Go to https://one.dash.cloudflare.com/"
echo "   - Navigate to Access > Applications"
echo "   - Add authentication for each hostname"
echo ""
echo "2. Update API Keys:"
echo "   - Edit $PROJECT_DIR/.env"
echo "   - Add your OpenAI/Anthropic API keys"
echo "   - Restart services: docker-compose -f docker-compose.production.yml restart"
echo ""
echo "3. Verify Ollama Connection:"
echo "   - Ensure Ollama is running on your Mac (192.168.0.84)"
echo "   - Test: curl http://192.168.0.84:11434/api/tags"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  View all logs:     docker-compose -f docker-compose.production.yml logs -f"
echo "  Restart services:  docker-compose -f docker-compose.production.yml restart"
echo "  Stop services:     docker-compose -f docker-compose.production.yml down"
echo "  Tunnel status:     sudo systemctl status cloudflared"
echo "  Tunnel logs:       sudo journalctl -u cloudflared -f"
echo ""
echo -e "${GREEN}Your Kong Guard AI is now deployed and accessible globally via Cloudflare!${NC}"
echo ""
echo "Project location: $PROJECT_DIR"
echo "Configuration: $PROJECT_DIR/.env"
echo "Tunnel config: ~/.cloudflared/config.yml"
