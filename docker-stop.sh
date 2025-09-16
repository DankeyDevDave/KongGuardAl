#!/bin/bash

# Kong Guard AI - Docker Development Stack Stop Script

set -e

echo "🛑 Stopping Kong Guard AI Development Stack..."

# Stop all services
docker-compose down

echo "✅ Kong Guard AI Development Stack stopped successfully!"
echo ""
echo "💡 To completely remove all data, run: ./docker-reset.sh"
echo "💡 To start again, run: ./docker-start.sh"
