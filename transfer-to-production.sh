#!/bin/bash

# Transfer Kong Guard AI to Production Server
# Run this from your Mac to deploy to production

set -e

# Configuration
PRODUCTION_SERVER="192.168.0.228"
PRODUCTION_USER="${1:-user}"  # Pass username as first argument
PROJECT_NAME="kong-guard-ai"

echo "🚀 Kong Guard AI - Transfer to Production Server"
echo "================================================"
echo ""
echo "Production Server: $PRODUCTION_USER@$PRODUCTION_SERVER"
echo "Project: $PROJECT_NAME"
echo ""

# Check if we can connect to production server
echo "Testing connection to production server..."
if ssh -o ConnectTimeout=5 $PRODUCTION_USER@$PRODUCTION_SERVER "echo 'Connection successful'" &>/dev/null; then
    echo "✅ Connection successful"
else
    echo "❌ Cannot connect to $PRODUCTION_USER@$PRODUCTION_SERVER"
    echo ""
    echo "Usage: ./transfer-to-production.sh [username]"
    echo "Example: ./transfer-to-production.sh jacques"
    exit 1
fi

# Create archive of essential files
echo ""
echo "📦 Creating deployment package..."
tar -czf kong-guard-ai-production.tar.gz \
    --exclude='*.log' \
    --exclude='logs/*' \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='*.tar.gz' \
    --exclude='grafana-data' \
    --exclude='prometheus-data' \
    --exclude='redis-data' \
    --exclude='kong-datastore' \
    --exclude='konga-datastore' \
    docker-compose.production.yml \
    docker-compose.yml \
    production-deployment-package.sh \
    manage-stack.sh \
    prometheus-config.yml \
    nginx-dashboard.conf \
    ai-service/ \
    dashboards/ \
    grafana-local/ \
    kong-plugin/ \
    mock-attacker/ \
    .env.example 2>/dev/null || true

echo "✅ Package created: kong-guard-ai-production.tar.gz"

# Transfer to production server
echo ""
echo "📤 Transferring to production server..."
scp kong-guard-ai-production.tar.gz $PRODUCTION_USER@$PRODUCTION_SERVER:/tmp/

# Execute deployment on production server
echo ""
echo "🔧 Executing deployment on production server..."
ssh $PRODUCTION_USER@$PRODUCTION_SERVER << 'REMOTE_SCRIPT'
set -e

echo "📦 Extracting package..."
cd /tmp
tar -xzf kong-guard-ai-production.tar.gz

echo "📁 Setting up project directory..."
sudo mkdir -p /opt/kong-guard-ai
sudo chown $USER:$USER /opt/kong-guard-ai

echo "📋 Moving files to /opt/kong-guard-ai..."
cp -r * /opt/kong-guard-ai/ 2>/dev/null || true
cd /opt/kong-guard-ai

echo "🔐 Setting permissions..."
chmod +x production-deployment-package.sh
chmod +x manage-stack.sh

echo ""
echo "✅ Files transferred successfully!"
echo ""
echo "📍 Project location: /opt/kong-guard-ai"
echo ""
echo "Next step: Run the deployment script"
echo "  cd /opt/kong-guard-ai"
echo "  ./production-deployment-package.sh"
REMOTE_SCRIPT

# Clean up local archive
rm kong-guard-ai-production.tar.gz

echo ""
echo "========================================="
echo "✅ Transfer Complete!"
echo "========================================="
echo ""
echo "Now SSH into the production server and run:"
echo ""
echo "  ssh $PRODUCTION_USER@$PRODUCTION_SERVER"
echo "  cd /opt/kong-guard-ai"
echo "  ./production-deployment-package.sh"
echo ""
echo "The deployment script will:"
echo "1. Install Docker, Docker Compose, and Cloudflared"
echo "2. Deploy the Kong Guard AI stack"
echo "3. Configure Cloudflare Zero Trust tunnel"
echo "4. Set up automatic startup on boot"
echo ""
echo "After deployment, you'll be able to access:"
echo "  Local:     http://192.168.0.228:8080"
echo "  Internet:  https://kong.yourdomain.com (via Cloudflare)"