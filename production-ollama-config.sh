#!/bin/bash

# Kong Guard AI - Production Configuration for Local Ollama
# This configures the production server to use Ollama running on your Mac

echo "🚀 Configuring Kong Guard AI to use Local Ollama"
echo "================================================"

# Your local machine details
LOCAL_MAC_IP="198.51.100.84"
OLLAMA_PORT="11434"
OLLAMA_MODEL="llama3.2:3b"  # Fast model you have installed

# Production server details
PRODUCTION_IP="198.51.100.228"
PRODUCTION_PORT="5000"

echo ""
echo "📊 Configuration:"
echo "  Local Ollama: http://$LOCAL_MAC_IP:$OLLAMA_PORT"
echo "  Model: $OLLAMA_MODEL"
echo "  Production API: http://$PRODUCTION_IP:$PRODUCTION_PORT"

echo ""
echo "🔧 Testing Ollama accessibility from production network..."

# Test from local network
if curl -s http://$LOCAL_MAC_IP:$OLLAMA_PORT/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama is accessible on local network"
else
    echo "❌ Ollama not accessible. Check if Ollama is running:"
    echo "   ollama serve"
    exit 1
fi

echo ""
echo "📝 Environment variables for production server:"
echo "================================================"
cat << EOF

# Add these to your production docker-compose.yml or .env file:

AI_PROVIDER=ollama
OLLAMA_HOST=http://$LOCAL_MAC_IP:$OLLAMA_PORT
OLLAMA_MODEL=$OLLAMA_MODEL

# Or run directly:
export AI_PROVIDER=ollama
export OLLAMA_HOST=http://$LOCAL_MAC_IP:$OLLAMA_PORT
export OLLAMA_MODEL=$OLLAMA_MODEL

EOF

echo "🐳 Docker Compose Update:"
echo "========================"
cat << 'EOF'

# Update your docker-compose.yml on production:

services:
  kong-guard-ai:
    environment:
      - AI_PROVIDER=ollama
      - OLLAMA_HOST=http://198.51.100.84:11434
      - OLLAMA_MODEL=llama3.2:3b
    extra_hosts:
      - "host.mac:198.51.100.84"  # Your Mac's IP

EOF

echo ""
echo "🧪 Test Commands:"
echo "================"
echo ""
echo "1. From production server, test Ollama connection:"
echo "   curl http://$LOCAL_MAC_IP:$OLLAMA_PORT/api/tags"
echo ""
echo "2. Test threat detection with Ollama:"
cat << 'EOF'
   curl -X POST http://198.51.100.84:11434/api/generate -d '{
     "model": "llama3.2:3b",
     "prompt": "Analyze for security threats: GET /admin?id=1 OR 1=1--",
     "stream": false
   }'
EOF

echo ""
echo "⚠️  IMPORTANT:"
echo "============"
echo "1. Keep your Mac running with Ollama active"
echo "2. Ensure your Mac doesn't sleep (System Settings > Energy Saver)"
echo "3. Your Mac IP must stay at $LOCAL_MAC_IP"
echo "4. Firewall must allow port $OLLAMA_PORT"
echo ""
echo "🔒 Security Note:"
echo "================"
echo "For production, consider:"
echo "- Setting up API authentication for Ollama"
echo "- Using a dedicated Ollama server instead of your Mac"
echo "- Implementing network security between servers"