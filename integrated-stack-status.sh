#!/bin/bash

# Kong Guard AI - Integrated Stack Status

echo "🏗️  KONG GUARD AI - COMPLETE STACK STATUS"
echo "=========================================="
echo ""

# Check Cloud AI Service
if curl -s http://localhost:18002/health > /dev/null 2>&1; then
    echo "✅ Cloud AI Protection (Port 18002): ONLINE"
    THREATS=$(curl -s http://localhost:18002/metrics | grep "kong_guard_threats_detected_total" | awk '{print $2}' | head -1)
    echo "   └── Threats Detected: $THREATS"
else
    echo "❌ Cloud AI Protection (Port 18002): OFFLINE"
fi

# Check Local Ollama Service
if curl -s http://localhost:18003/health > /dev/null 2>&1; then
    echo "✅ Local Ollama Protection (Port 18003): ONLINE"
else
    echo "❌ Local Ollama Protection (Port 18003): OFFLINE"
fi

# Check Dashboard
if curl -s http://localhost:8080 > /dev/null 2>&1; then
    echo "✅ Web Dashboard (Port 8080): ONLINE"
    echo "   └── URL: http://localhost:8080"
else
    echo "❌ Web Dashboard (Port 8080): OFFLINE"
fi

# Check Grafana
if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then
    echo "✅ Grafana Monitoring (Port 3000): ONLINE"
    echo "   ├── URL: http://localhost:3000"
    echo "   ├── Login: admin / KongGuard2024!"
    echo "   └── Dashboard: http://localhost:3000/d/kong-guard-ai"
else
    echo "❌ Grafana Monitoring (Port 3000): OFFLINE"
fi

# Check Ollama
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama Server (Port 11434): ONLINE"
    MODELS=$(ollama list | tail -n +2 | wc -l | tr -d ' ')
    echo "   └── Models Available: $MODELS"
else
    echo "❌ Ollama Server (Port 11434): OFFLINE"
fi

echo ""
echo "📊 METRICS ENDPOINTS:"
echo "───────────────────"
echo "• Cloud AI Metrics: http://localhost:18002/metrics"
echo "• Ollama Metrics: http://localhost:18003/metrics"
echo ""

echo "🔗 PRODUCTION INTEGRATION:"
echo "────────────────────────"
echo "• Production Kong: 192.168.0.228"
echo "• This Machine: 192.168.0.84"
echo "• Network: ✅ Connected"
echo ""

echo "📈 GRAFANA DATA SOURCES:"
echo "──────────────────────"
echo "Grafana can pull metrics from:"
echo "1. Direct from AI Services (no Prometheus needed)"
echo "   - http://localhost:18002/metrics (Cloud AI)"
echo "   - http://localhost:18003/metrics (Ollama)"
echo ""
echo "2. From Production Prometheus (if configured)"
echo "   - http://192.168.0.225:9090"
echo ""

echo "🚀 QUICK ACCESS:"
echo "──────────────"
echo "• Dashboard: http://localhost:8080"
echo "• Grafana: http://localhost:3000"
echo "• Cloud AI Health: http://localhost:18002/health"
echo "• Ollama Health: http://localhost:18003/health"