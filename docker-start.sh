#!/bin/bash

# Kong Guard AI - Docker Development Stack Startup Script

set -e

echo "🚀 Starting Kong Guard AI Development Stack..."

# Load environment variables
if [ -f .env.docker ]; then
    echo "📄 Loading environment variables..."
    export $(cat .env.docker | grep -v '^#' | xargs)
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p plugins/kong-guard-ai
mkdir -p mock-attacker/html
mkdir -p redis-data
mkdir -p logs

# Set proper permissions
echo "🔐 Setting proper permissions..."
chmod +x docker-start.sh
chmod +x docker-stop.sh
chmod +x docker-reset.sh

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Pull latest images
echo "📥 Pulling latest Docker images..."
docker-compose pull

# Start the stack
echo "🔧 Starting Kong Guard AI stack..."
docker-compose up -d

echo "⏳ Waiting for services to be ready..."

# Wait for database to be ready
echo "   Waiting for PostgreSQL..."
until docker-compose exec -T kong-database pg_isready -U kong >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ✅ PostgreSQL ready"

# Wait for Kong to be ready
echo "   Waiting for Kong Gateway..."
until curl -s http://localhost:8001/status >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ✅ Kong Gateway ready"

# Wait for demo API to be ready
echo "   Waiting for Demo API..."
until curl -s http://localhost:8080/status/200 >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ✅ Demo API ready"

# Wait for mock attacker to be ready
echo "   Waiting for Mock Attacker service..."
until curl -s http://localhost:8090/health >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ✅ Mock Attacker service ready"

# Display service information
echo ""
echo "🎉 Kong Guard AI Development Stack is ready!"
echo ""
echo "📊 Service URLs:"
echo "   Kong Proxy:        http://localhost:8000"
echo "   Kong Admin API:     http://localhost:8001"
echo "   Kong Admin UI:      http://localhost:8002 (if enabled)"
echo "   Demo API (httpbin): http://localhost:8080"
echo "   Mock Attacker:      http://localhost:8090"
echo "   PostgreSQL:         localhost:5432"
echo "   Redis:              localhost:6379"
echo ""
echo "🔧 Useful commands:"
echo "   View logs:          docker-compose logs -f"
echo "   View Kong logs:     docker-compose logs -f kong"
echo "   Stop stack:         ./docker-stop.sh"
echo "   Reset stack:        ./docker-reset.sh"
echo ""
echo "🧪 Test the setup:"
echo "   curl http://localhost:8001/status"
echo "   curl http://localhost:8080/status/200"
echo "   curl http://localhost:8090/health"
echo ""
echo "📖 Next steps:"
echo "   1. Configure Kong services and routes"
echo "   2. Enable the kong-guard-ai plugin"
echo "   3. Test threat detection with mock attacker"
echo ""
