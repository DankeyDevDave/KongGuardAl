#!/bin/bash

# Kong Guard AI - Local Grafana Setup (without Docker)
# This script downloads and runs Grafana locally

echo "🚀 Kong Guard AI - Setting up Local Grafana"
echo "==========================================="

# Check if Grafana is already installed via Homebrew
if command -v grafana-server &> /dev/null; then
    echo "✅ Grafana found (installed via Homebrew)"
else
    echo "📦 Installing Grafana via Homebrew..."
    brew install grafana
fi

# Create Grafana directories
mkdir -p ~/kong-guard-grafana/{data,logs,conf,dashboards,provisioning/{dashboards,datasources}}

# Create Grafana configuration
cat > ~/kong-guard-grafana/conf/grafana.ini << 'EOF'
[server]
http_port = 3000
root_url = http://localhost:3000

[security]
admin_user = admin
admin_password = KongGuard2024!

[paths]
data = /Users/jacques/kong-guard-grafana/data
logs = /Users/jacques/kong-guard-grafana/logs
provisioning = /Users/jacques/kong-guard-grafana/provisioning

[analytics]
reporting_enabled = false
check_for_updates = false

[log]
mode = console file
level = info
EOF

# Create datasources configuration
cat > ~/kong-guard-grafana/provisioning/datasources/kong-guard.yml << 'EOF'
apiVersion: 1

datasources:
  - name: KongGuardAI-Metrics
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: true

  - name: KongGuardAI-API
    type: prometheus
    access: proxy
    url: http://localhost:18002
    editable: true
EOF

# Create dashboard provisioning
cat > ~/kong-guard-grafana/provisioning/dashboards/dashboard.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'Kong Guard AI'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /Users/jacques/kong-guard-grafana/dashboards
EOF

# Copy dashboard
cp grafana-local/dashboards/kong-guard-ai-dashboard.json ~/kong-guard-grafana/dashboards/

echo ""
echo "📊 Starting Grafana Server..."
echo "=============================="

# Start Grafana with custom config
grafana-server \
    --config ~/kong-guard-grafana/conf/grafana.ini \
    --homepath /opt/homebrew/opt/grafana/share/grafana \
    --pidfile ~/kong-guard-grafana/grafana.pid \
    web &

GRAFANA_PID=$!
echo $GRAFANA_PID > ~/kong-guard-grafana/grafana.pid

echo ""
echo "✅ Grafana Started!"
echo "=================="
echo "📊 Dashboard: http://localhost:3000"
echo "👤 Username: admin"
echo "🔑 Password: KongGuard2024!"
echo ""
echo "📈 Kong Guard AI Dashboard will be auto-loaded"
echo ""
echo "To stop Grafana:"
echo "  kill $(cat ~/kong-guard-grafana/grafana.pid)"
echo ""
echo "Waiting for Grafana to be ready..."
sleep 5

# Check if Grafana is running
if curl -s http://localhost:3000/api/health > /dev/null; then
    echo "✅ Grafana is running and healthy!"
    echo ""
    echo "🎯 Access your Kong Guard AI Dashboard at:"
    echo "   http://localhost:3000/d/kong-guard-ai/kong-guard-ai-threat-detection-dashboard"
else
    echo "⚠️  Grafana might still be starting. Wait a moment and try:"
    echo "   http://localhost:3000"
fi
