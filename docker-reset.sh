#!/bin/bash

# Kong Guard AI - Docker Development Stack Reset Script

set -e

echo "🔄 Resetting Kong Guard AI Development Stack..."

# Stop and remove all containers, networks, and volumes
docker-compose down -v --remove-orphans

# Remove any dangling images related to our stack
echo "🧹 Cleaning up Docker images..."
docker image prune -f

# Clean up local data directories
echo "🗑️  Cleaning up local data..."
rm -rf redis-data
rm -rf logs

echo "✅ Kong Guard AI Development Stack reset complete!"
echo ""
echo "💡 Run ./docker-start.sh to start fresh"