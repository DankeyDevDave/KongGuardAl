#!/bin/bash

# Update Grafana datasource to connect directly to AI services

echo "🔧 Updating Grafana datasources to connect directly to AI services..."
echo "=================================================================="

# Restart Grafana with updated datasources
docker-compose -f grafana-local/docker-compose.yml down
docker-compose -f grafana-local/docker-compose.yml up -d

echo ""
echo "✅ Grafana Updated!"
echo ""
echo "📊 Access Grafana at: http://localhost:3000"
echo "👤 Username: admin"
echo "🔑 Password: KongGuard2024!"
echo ""
echo "📈 The Kong Guard AI Dashboard will now show:"
echo "   - Real-time threat detection metrics from Cloud AI (port 18002)"
echo "   - Local Ollama protection metrics (port 18003)"
echo ""
echo "🎯 Direct connections established - no Prometheus needed!"