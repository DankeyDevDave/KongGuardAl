#!/bin/bash

# Deploy Kong Guard AI to the Kong container (192.168.0.228)

echo "🚀 Deploying Kong Guard AI to Kong Container"
echo "============================================"
echo ""

# Configuration
KONG_HOST="192.168.0.228"
PROJECT_DIR="/opt/kong-guard-ai"
LOCAL_PROJECT_DIR="/Users/jacques/DevFolder/KongGuardAI"

echo "📦 Creating deployment package..."
# Create a clean package without unnecessary files
tar -czf /tmp/kong-guard-ai-deploy.tar.gz \
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
    -C "$LOCAL_PROJECT_DIR" .

echo "✅ Package created"
echo ""

echo "📤 Transferring to Kong container..."
scp /tmp/kong-guard-ai-deploy.tar.gz kong:$PROJECT_DIR.tar.gz

echo ""
echo "🔧 Setting up on Kong container..."
ssh kong << 'REMOTE_COMMANDS'
echo "Setting up Kong Guard AI..."

# Create project directory
mkdir -p /opt/kong-guard-ai
cd /opt/kong-guard-ai

# Extract the package
if [ -f /opt/kong-guard-ai.tar.gz ]; then
    tar -xzf /opt/kong-guard-ai.tar.gz
    rm /opt/kong-guard-ai.tar.gz
    echo "✅ Files extracted"
fi

# Create working directories
mkdir -p logs grafana-data prometheus-data redis-data

# Check what's already running
echo ""
echo "Current Docker status:"
docker ps

# Stop the unhealthy container
echo ""
echo "Stopping unhealthy container..."
docker stop df9433614288 2>/dev/null || true
docker rm df9433614288 2>/dev/null || true

# Check for docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo "Installing docker-compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cat > .env << 'EOF'
# Network Configuration
PRODUCTION_IP=192.168.0.228
OLLAMA_MAC_IP=192.168.0.84

# API Keys - UPDATE THESE!
OPENAI_API_KEY=your-openai-key-here
ANTHROPIC_API_KEY=your-anthropic-key-here

# Database Passwords
KONG_PG_PASSWORD=KongPass2024!
KONGA_DB_PASSWORD=KongaPass2024!
EOF
    echo "⚠️  Created .env file - please update API keys!"
fi

echo ""
echo "✅ Kong Guard AI is ready to deploy!"
echo ""
echo "Project location: /opt/kong-guard-ai"
echo ""
echo "Available compose files:"
ls -la | grep docker-compose
REMOTE_COMMANDS

# Clean up
rm /tmp/kong-guard-ai-deploy.tar.gz

echo ""
echo "========================================="
echo "✅ Deployment Package Transferred!"
echo "========================================="
echo ""
echo "Now SSH to Kong container and start services:"
echo ""
echo "  ssh kong"
echo "  cd /opt/kong-guard-ai"
echo "  "
echo "  # Update API keys in .env file:"
echo "  nano .env"
echo "  "
echo "  # Start the stack:"
echo "  docker-compose -f docker-compose.production.yml up -d"
echo "  "
echo "  # Or use the management script:"
echo "  ./manage-stack.sh start"
echo ""
echo "The unhealthy container has been stopped."
echo "You can now deploy the updated stack."
