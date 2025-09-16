#!/bin/bash

# Start AI service with Ollama on port 18003 for Local AI Protection

echo "🚀 Starting Local Ollama AI Service on port 18003"
echo "================================================="

# Set environment for Ollama
export PORT=18003
export AI_PROVIDER=ollama
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=llama3.2:3b

echo "Configuration:"
echo "  Port: $PORT"
echo "  Provider: $AI_PROVIDER"
echo "  Ollama Host: $OLLAMA_HOST"
echo "  Model: $OLLAMA_MODEL"
echo ""

# Check if Ollama is running
if ! curl -s $OLLAMA_HOST/api/tags > /dev/null 2>&1; then
    echo "⚠️  Ollama not running. Starting Ollama..."
    ollama serve > /dev/null 2>&1 &
    sleep 3
fi

echo "✅ Ollama is running"
echo ""

# Start the AI service
cd ai-service
python3 app.py
