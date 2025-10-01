#!/bin/bash
# Kong Guard AI - Demo Readiness Verification Script
# Author: DankeyDevDave (dankeydevdave@gmail.com)
# Date: 2025-01-30

echo "🔍 Kong Guard AI - Demo Readiness Check"
echo "========================================"
echo ""

# Check if services are running
check_service() {
    local name=$1
    local port=$2
    local endpoint=$3
    
    if curl -s -f -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:${port}${endpoint}" > /dev/null 2>&1; then
        echo "✅ ${name} (port ${port})"
        return 0
    else
        echo "❌ ${name} (port ${port}) - NOT RESPONDING"
        return 1
    fi
}

echo "📡 Service Status:"
echo "------------------"

# Check all critical services
check_service "Kong Gateway" "18000" "/status" || true
check_service "Dashboard" "3000" "/" || true
check_service "WebSocket" "18002" "/health" || true
check_service "Cloud AI" "28100" "/health" || true
check_service "Local AI" "28101" "/health" || true

echo ""
echo "🐳 Docker Containers:"
echo "---------------------"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "kong-guard|Kong"

echo ""
echo "📊 Database Metrics:"
echo "--------------------"
if [ -f "attack_metrics.db" ]; then
    METRIC_COUNT=$(sqlite3 attack_metrics.db "SELECT COUNT(*) FROM attack_metrics;" 2>/dev/null || echo "0")
    echo "✅ attack_metrics.db exists"
    echo "   Total measurements: ${METRIC_COUNT}"
else
    echo "⚠️  attack_metrics.db not found"
fi

echo ""
echo "🎤 Voice Narration Files:"
echo "-------------------------"
if [ -d "demo_recordings/voiceovers" ]; then
    VOICE_COUNT=$(ls -1 demo_recordings/voiceovers/*.wav 2>/dev/null | wc -l)
    echo "✅ Voice files: ${VOICE_COUNT} scenes"
else
    echo "⚠️  No voice files found - run: python3 generate_scene_voice.py --scene all"
fi

echo ""
echo "📂 Critical Files:"
echo "------------------"
check_file() {
    if [ -f "$1" ]; then
        echo "✅ $1"
    else
        echo "❌ $1 - MISSING"
    fi
}

check_file "hackathon_demo_recorder.py"
check_file "audio_manager.py"
check_file "narrator_timing.json"
check_file "demo_visual_effects.js"
check_file "MANUAL_RECORDING_SCRIPT.md"
check_file "LICENSE"
check_file "README.md"

echo ""
echo "🎬 Recording Commands:"
echo "----------------------"
echo "Automated recording:"
echo "  python3 hackathon_demo_recorder.py --headed --screenshots --video"
echo ""
echo "Manual recording:"
echo "  open http://localhost:3000"
echo "  # Then follow MANUAL_RECORDING_SCRIPT.md"
echo ""
echo "========================================"
echo "✅ Demo readiness check complete!"
echo ""
