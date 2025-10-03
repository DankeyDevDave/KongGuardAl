#!/bin/bash
set -e

# Production Deployment Script for Clerk Authentication
# Server: root@192.168.0.228
# Maintainer: DankeyDevDave (https://github.com/DankeyDevDave)
# Dashboard URL: https://YOUR_PRODUCTION_DOMAIN/

echo "==================================="
echo "Clerk Production Deployment Script"
echo "==================================="
echo ""

# SSH connection details
SERVER="root@192.168.0.228"
PROJECT_DIR="/opt/KongGuardAI"

echo "📡 Connecting to production server: $SERVER"
echo ""

ssh $SERVER << 'ENDSSH'
set -e

cd /opt/KongGuardAI

echo "📥 Pulling latest changes from GitHub..."
git pull origin main

echo ""
echo "🔑 Creating production .env.local with Clerk keys..."
cat > dashboard/.env.local << 'EOF'
# Clerk Production Keys - REPLACE WITH YOUR ACTUAL KEYS
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_YOUR_PUBLISHABLE_KEY_HERE
CLERK_SECRET_KEY=sk_live_YOUR_SECRET_KEY_HERE
EOF

echo "✅ Environment file created"
echo ""

echo "🛑 Stopping current dashboard..."
docker-compose -f docker-compose.dashboard.yml down

echo ""
echo "🔨 Building dashboard with Clerk authentication..."
docker-compose -f docker-compose.dashboard.yml build --no-cache kong-guard-dashboard

echo ""
echo "🚀 Starting dashboard..."
docker-compose -f docker-compose.dashboard.yml up -d

echo ""
echo "⏳ Waiting for dashboard to start..."
sleep 5

echo ""
echo "📊 Dashboard status:"
docker ps | grep dashboard

echo ""
echo "📝 Viewing logs (last 30 lines):"
docker logs kong-guard-dashboard --tail 30

echo ""
echo "==================================="
echo "✅ Deployment Complete!"
echo "==================================="
echo ""
echo "Dashboard URL: https://YOUR_PRODUCTION_DOMAIN/"
echo "Clerk Sign-In: https://YOUR_CLERK_DOMAIN/"
echo ""
echo "To view live logs:"
echo "  ssh root@192.168.0.228"
echo "  docker logs -f kong-guard-dashboard"
echo ""

ENDSSH

echo ""
echo "🎉 Production deployment completed successfully!"
echo ""
echo "Next steps:"
echo "1. Open: https://YOUR_PRODUCTION_DOMAIN/"
echo "2. You should be redirected to Clerk sign-in"
echo "3. Sign in or create account"
echo "4. You'll be redirected back to the dashboard"
echo ""
