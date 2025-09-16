#!/bin/bash

# Kong Guard AI - Cloudflare Zero Trust Tunnel Setup
# This script sets up secure remote access to your dashboard via Cloudflare

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🔐 Kong Guard AI - Cloudflare Zero Trust Setup"
echo "=============================================="
echo ""

# Configuration
PRODUCTION_SERVER="192.168.0.228"
TUNNEL_NAME="kong-guard-ai"

echo "📋 Prerequisites:"
echo "----------------"
echo "1. Cloudflare account with a domain"
echo "2. cloudflared installed on production server"
echo "3. Access to production server via SSH"
echo ""

echo "📦 Step 1: Install cloudflared on Production Server"
echo "---------------------------------------------------"
cat << 'EOF'
# SSH to your production server
ssh user@192.168.0.228

# Install cloudflared (Ubuntu/Debian)
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Or using Docker (alternative)
docker pull cloudflare/cloudflared:latest
EOF

echo ""
echo "🔑 Step 2: Authenticate with Cloudflare"
echo "---------------------------------------"
cat << 'EOF'
# On production server, authenticate
cloudflared tunnel login

# This will open a browser to authenticate
# Copy the cert.pem to ~/.cloudflared/cert.pem
EOF

echo ""
echo "🚇 Step 3: Create the Tunnel"
echo "----------------------------"
cat << 'EOF'
# Create a new tunnel
cloudflared tunnel create kong-guard-ai

# List tunnels to get the tunnel ID
cloudflared tunnel list

# Note the Tunnel ID (looks like: a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6)
EOF

echo ""
echo "📝 Creating Cloudflare Tunnel Configuration..."
cat > cloudflared-config.yml << 'EOF'
# Cloudflare Tunnel Configuration for Kong Guard AI
# Place this at ~/.cloudflared/config.yml on production server

tunnel: TUNNEL_ID_HERE
credentials-file: /home/user/.cloudflared/TUNNEL_ID_HERE.json

ingress:
  # Kong Guard AI Dashboard (Primary)
  - hostname: kong-dashboard.yourdomain.com
    service: http://localhost:8080
    originRequest:
      noTLSVerify: true
      connectTimeout: 30s

  # Grafana Monitoring
  - hostname: kong-grafana.yourdomain.com
    service: http://localhost:3000
    originRequest:
      noTLSVerify: true

  # Kong Admin API (Secured)
  - hostname: kong-admin.yourdomain.com
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true
      # Add access policies in Zero Trust dashboard

  # Konga UI
  - hostname: kong-ui.yourdomain.com
    service: http://localhost:1337
    originRequest:
      noTLSVerify: true

  # AI Service Status (Read-only endpoints)
  - hostname: kong-ai.yourdomain.com
    service: http://localhost:18002
    originRequest:
      noTLSVerify: true
      # Only expose /health and /metrics endpoints

  # Catch-all rule (required)
  - service: http_status:404
EOF

echo ""
echo "🔒 Step 4: Configure Zero Trust Access Policies"
echo "-----------------------------------------------"
cat << 'EOF'
# In Cloudflare Zero Trust Dashboard:

1. Go to: https://one.dash.cloudflare.com/
2. Access > Applications > Add an application
3. Select "Self-hosted"
4. Configure each service:

For kong-dashboard.yourdomain.com:
- Application name: Kong Guard AI Dashboard
- Session Duration: 24 hours
- Application domain: kong-dashboard.yourdomain.com
- Identity providers: Choose your auth method (Google, GitHub, Email OTP)
- Policies:
  - Name: "Authorized Users"
  - Action: Allow
  - Include: Emails ending in @yourdomain.com (or specific emails)

For kong-admin.yourdomain.com (MORE RESTRICTIVE):
- Application name: Kong Admin API
- Session Duration: 1 hour
- Policies:
  - Name: "Admin Only"
  - Action: Allow
  - Include: Specific email addresses only
  - Require: Location in specific country
  - Require: Device posture check (optional)

For kong-grafana.yourdomain.com:
- Application name: Kong Monitoring
- Session Duration: 12 hours
- Policies: Same as dashboard
EOF

echo ""
echo "🐳 Creating Docker Compose Service for Tunnel..."
cat > docker-compose.cloudflare.yml << 'EOF'
version: '3.8'

services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared-tunnel
    restart: unless-stopped
    command: tunnel --no-autoupdate run
    environment:
      - TUNNEL_TOKEN=${TUNNEL_TOKEN}  # Alternative to config file
    volumes:
      - ./cloudflared:/home/nonroot/.cloudflared/
      - ./cloudflared-config.yml:/home/nonroot/.cloudflared/config.yml:ro
    networks:
      - kong-net
    depends_on:
      - web-dashboard
      - grafana
      - kong

networks:
  kong-net:
    external: true
EOF

echo ""
echo "🚀 Step 5: Start the Tunnel"
echo "---------------------------"
cat << 'EOF'
# Option A: Run as system service
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared

# Option B: Run with Docker Compose
docker-compose -f docker-compose.yml -f docker-compose.cloudflare.yml up -d

# Option C: Run standalone
cloudflared tunnel run kong-guard-ai
EOF

echo ""
echo "📋 Step 6: DNS Configuration"
echo "----------------------------"
cat << 'EOF'
# Add CNAME records in Cloudflare DNS:

kong-dashboard.yourdomain.com -> TUNNEL_ID.cfargotunnel.com
kong-grafana.yourdomain.com   -> TUNNEL_ID.cfargotunnel.com
kong-admin.yourdomain.com     -> TUNNEL_ID.cfargotunnel.com
kong-ui.yourdomain.com        -> TUNNEL_ID.cfargotunnel.com
kong-ai.yourdomain.com        -> TUNNEL_ID.cfargotunnel.com

# Or use cloudflared to add them:
cloudflared tunnel route dns kong-guard-ai kong-dashboard.yourdomain.com
cloudflared tunnel route dns kong-guard-ai kong-grafana.yourdomain.com
cloudflared tunnel route dns kong-guard-ai kong-admin.yourdomain.com
cloudflared tunnel route dns kong-guard-ai kong-ui.yourdomain.com
EOF

echo ""
echo "🔧 Creating systemd Service..."
cat > cloudflared.service << 'EOF'
[Unit]
Description=Cloudflare Tunnel for Kong Guard AI
After=network.target

[Service]
TimeoutStartSec=0
Type=notify
ExecStart=/usr/local/bin/cloudflared tunnel run --no-autoupdate kong-guard-ai
Restart=on-failure
RestartSec=5s
User=cloudflared
Group=cloudflared

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "🎯 Step 7: Test Your Setup"
echo "--------------------------"
cat << 'EOF'
# Test from anywhere (no VPN needed):

1. Dashboard:
   https://kong-dashboard.yourdomain.com

2. Grafana:
   https://kong-grafana.yourdomain.com

3. Kong Admin (restricted):
   https://kong-admin.yourdomain.com

# Check tunnel status:
cloudflared tunnel info kong-guard-ai

# View tunnel metrics:
https://dash.cloudflare.com/tunnels
EOF

echo ""
echo "🔐 Security Best Practices"
echo "--------------------------"
echo "1. ✅ Use Zero Trust policies for ALL endpoints"
echo "2. ✅ Enable 2FA for Cloudflare account"
echo "3. ✅ Restrict admin endpoints to specific users"
echo "4. ✅ Use device posture checks for sensitive access"
echo "5. ✅ Set short session durations for admin panels"
echo "6. ✅ Monitor access logs in Zero Trust dashboard"
echo "7. ✅ Use Service Tokens for API access (not browser access)"

echo ""
echo "📱 Mobile Access"
echo "----------------"
echo "Install Cloudflare One Agent (WARP) on mobile devices for seamless access:"
echo "- iOS: https://apps.apple.com/app/id1423538627"
echo "- Android: https://play.google.com/store/apps/details?id=com.cloudflare.onedotonedotonedotone"

echo ""
echo "Files created:"
echo "- cloudflared-config.yml (Tunnel configuration)"
echo "- docker-compose.cloudflare.yml (Docker integration)"
echo "- cloudflared.service (systemd service)"
echo ""
echo "Next steps:"
echo "1. Copy these files to your production server (192.168.0.228)"
echo "2. Follow the steps above to set up the tunnel"
echo "3. Configure Zero Trust policies in Cloudflare dashboard"
