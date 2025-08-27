#!/bin/bash

# Deploy Grafana to Supabase LXC Container (122)
# This script adds Grafana to the existing Supabase stack

echo "🚀 Deploying Grafana to Kong Guard AI Stack"
echo "=========================================="

# Configuration
GRAFANA_PORT=3333
GRAFANA_VERSION=latest
CONTAINER_NAME=grafana-kongguard

# SSH connection details
SSH_HOST="root@192.168.0.201"
LXC_ID="122"

# Grafana deployment via Docker
echo "📦 Deploying Grafana container..."

ssh $SSH_HOST "pct exec $LXC_ID -- docker run -d \
  --name=$CONTAINER_NAME \
  --restart=unless-stopped \
  --network=supabase_default \
  -p $GRAFANA_PORT:3000 \
  -v grafana-storage:/var/lib/grafana \
  -e 'GF_SECURITY_ADMIN_USER=admin' \
  -e 'GF_SECURITY_ADMIN_PASSWORD=KongGuard@2024' \
  -e 'GF_INSTALL_PLUGINS=grafana-piechart-panel,grafana-worldmap-panel,yesoreyeram-boomtable-panel,vonage-status-panel' \
  -e 'GF_USERS_ALLOW_SIGN_UP=false' \
  -e 'GF_SERVER_ROOT_URL=http://192.168.0.225:$GRAFANA_PORT' \
  -e 'GF_ANALYTICS_REPORTING_ENABLED=false' \
  grafana/grafana:$GRAFANA_VERSION"

if [ $? -eq 0 ]; then
    echo "✅ Grafana container deployed successfully!"
else
    echo "❌ Failed to deploy Grafana container"
    exit 1
fi

# Wait for Grafana to start
echo "⏳ Waiting for Grafana to initialize..."
sleep 15

# Create PostgreSQL data source configuration
echo "📊 Creating data source configuration..."

cat > /tmp/datasource.json <<EOF
{
  "name": "Kong Guard AI - Supabase",
  "type": "postgres",
  "access": "proxy",
  "url": "supabase-db:5432",
  "database": "postgres",
  "user": "supabase_admin",
  "secureJsonData": {
    "password": "Jlwain@321"
  },
  "jsonData": {
    "sslmode": "disable",
    "postgresVersion": 1500,
    "timescaledb": false,
    "schema": "kongguard"
  },
  "isDefault": true
}
EOF

# Copy and configure data source
echo "🔗 Configuring Supabase data source..."

scp /tmp/datasource.json $SSH_HOST:/tmp/
ssh $SSH_HOST "pct exec $LXC_ID -- docker exec $CONTAINER_NAME sh -c 'mkdir -p /etc/grafana/provisioning/datasources'"
ssh $SSH_HOST "pct exec $LXC_ID -- docker cp /tmp/datasource.json $CONTAINER_NAME:/etc/grafana/provisioning/datasources/supabase.yaml"

# Create initial dashboard
echo "📈 Creating Kong Guard AI dashboard..."

cat > /tmp/kongguard-dashboard.json <<'EOF'
{
  "dashboard": {
    "id": null,
    "uid": "kongguard-main",
    "title": "Kong Guard AI - Security Operations Center",
    "tags": ["security", "kong", "ai"],
    "timezone": "browser",
    "schemaVersion": 38,
    "version": 0,
    "refresh": "5s",
    "panels": [
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
        "id": 1,
        "title": "🛡️ Threats Blocked (24h)",
        "type": "stat",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT COUNT(*) as value FROM kongguard.attack_metrics WHERE blocked = true AND timestamp > NOW() - INTERVAL '24 hours'",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "green", "value": null},
                {"color": "red", "value": 100}
              ]
            },
            "unit": "short"
          }
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
        "id": 2,
        "title": "⚡ Avg Response Time",
        "type": "stat",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT ROUND(AVG(response_time_ms), 2) as value FROM kongguard.attack_metrics WHERE timestamp > NOW() - INTERVAL '1 hour'",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "unit": "ms",
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 100},
                {"color": "red", "value": 200}
              ]
            }
          }
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
        "id": 3,
        "title": "🎯 Protection Rate",
        "type": "gauge",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT ROUND(SUM(CASE WHEN blocked THEN 1 ELSE 0 END)::float / COUNT(*) * 100, 1) as value FROM kongguard.attack_metrics WHERE timestamp > NOW() - INTERVAL '24 hours'",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "max": 100,
            "min": 0,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"color": "red", "value": null},
                {"color": "yellow", "value": 80},
                {"color": "green", "value": 95}
              ]
            }
          }
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
        "id": 4,
        "title": "🌍 Unique Attackers",
        "type": "stat",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT COUNT(DISTINCT source_ip) as value FROM kongguard.attack_metrics WHERE timestamp > NOW() - INTERVAL '24 hours'",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "unit": "short"
          }
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
        "id": 5,
        "title": "📊 Attack Types Distribution",
        "type": "piechart",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT attack_type as metric, COUNT(*) as value FROM kongguard.attack_metrics WHERE timestamp > NOW() - INTERVAL '24 hours' GROUP BY attack_type ORDER BY value DESC",
          "refId": "A"
        }],
        "options": {
          "pieType": "donut",
          "legendDisplayMode": "list",
          "legendPlacement": "right"
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
        "id": 6,
        "title": "🔥 Threat Score Timeline",
        "type": "timeseries",
        "targets": [{
          "format": "time_series",
          "rawSql": "SELECT timestamp as time, threat_score as value, tier as metric FROM kongguard.attack_metrics WHERE timestamp > NOW() - INTERVAL '6 hours' ORDER BY timestamp",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "custom": {
              "drawStyle": "line",
              "lineInterpolation": "smooth",
              "lineWidth": 2,
              "fillOpacity": 10
            }
          }
        }
      },
      {
        "datasource": "Kong Guard AI - Supabase",
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 12},
        "id": 7,
        "title": "🚨 Recent Attack Activity",
        "type": "table",
        "targets": [{
          "format": "table",
          "rawSql": "SELECT timestamp, tier, attack_type, threat_score, CASE WHEN blocked THEN '🛡️ Blocked' ELSE '⚠️ Allowed' END as status, source_ip FROM kongguard.attack_metrics ORDER BY timestamp DESC LIMIT 100",
          "refId": "A"
        }]
      }
    ]
  },
  "overwrite": true
}
EOF

# Import dashboard
echo "📥 Importing dashboard..."

scp /tmp/kongguard-dashboard.json $SSH_HOST:/tmp/

# Wait for Grafana API to be ready
sleep 5

# Import using Grafana API
ssh $SSH_HOST "pct exec $LXC_ID -- curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d @/tmp/kongguard-dashboard.json \
  http://admin:KongGuard@2024@localhost:$GRAFANA_PORT/api/dashboards/db"

# Clean up temporary files
rm -f /tmp/datasource.json /tmp/kongguard-dashboard.json
ssh $SSH_HOST "rm -f /tmp/datasource.json /tmp/kongguard-dashboard.json"

echo ""
echo "=========================================="
echo "✅ Grafana Deployment Complete!"
echo "=========================================="
echo ""
echo "📊 Access Grafana at: http://192.168.0.225:$GRAFANA_PORT"
echo "👤 Username: admin"
echo "🔑 Password: KongGuard@2024"
echo ""
echo "📈 Dashboard: Kong Guard AI - Security Operations Center"
echo ""
echo "🔗 Data Source: Connected to Supabase PostgreSQL"
echo "   Database: postgres"
echo "   Schema: kongguard"
echo ""
echo "💡 Tips:"
echo "   - Dashboard auto-refreshes every 5 seconds"
echo "   - Click on any panel to explore data"
echo "   - Use time range selector for historical analysis"
echo "   - Create custom dashboards via + icon"
echo ""
echo "📝 To create alerts:"
echo "   1. Edit any panel"
echo "   2. Go to Alert tab"
echo "   3. Set threshold conditions"
echo "   4. Configure notification channels"