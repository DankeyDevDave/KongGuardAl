#!/bin/bash

# Kong Guard AI - Multi-Provider API Key Setup Script
# This script helps configure API keys for multiple AI providers

echo "🚀 Kong Guard AI - Multi-Provider API Key Setup"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if API key is set
check_api_key() {
    local key_name=$1
    local env_var=$2
    if [ -n "${!env_var}" ]; then
        echo -e "${GREEN}✓${NC} $key_name: Configured"
        return 0
    else
        echo -e "${RED}✗${NC} $key_name: Not configured"
        return 1
    fi
}

# Function to prompt for API key
prompt_api_key() {
    local provider=$1
    local env_var=$2
    local url=$3

    echo ""
    echo -e "${BLUE}$provider Setup:${NC}"
    echo "1. Visit: $url"
    echo "2. Sign up/Login to get your API key"
    echo "3. Copy your API key"
    echo ""

    read -p "Enter your $provider API key (or press Enter to skip): " api_key

    if [ -n "$api_key" ]; then
        # Add to .env file
        echo "export $env_var=\"$api_key\"" >> .env
        echo -e "${GREEN}✓${NC} $provider API key saved to .env file"
        # Also set for current session
        export $env_var="$api_key"
    else
        echo -e "${YELLOW}⚠${NC} Skipped $provider setup"
    fi
}

echo "Checking current API key configuration..."
echo ""

check_api_key "OpenAI" "OPENAI_API_KEY"
check_api_key "Groq" "GROQ_API_KEY"
check_api_key "Gemini" "GEMINI_API_KEY"
check_api_key "Anthropic" "ANTHROPIC_API_KEY"

echo ""
echo "To enable multi-provider support, you need to configure API keys."
echo "This allows Kong Guard AI to automatically switch between providers"
echo "based on availability, speed, cost, and accuracy."
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    touch .env
    echo "# Kong Guard AI Environment Variables" > .env
    echo "# Add your API keys below" >> .env
    echo "" >> .env
fi

# Prompt for each provider
if ! check_api_key "OpenAI" "OPENAI_API_KEY" 2>/dev/null; then
    prompt_api_key "OpenAI" "OPENAI_API_KEY" "https://platform.openai.com/api-keys"
fi

if ! check_api_key "Groq" "GROQ_API_KEY" 2>/dev/null; then
    prompt_api_key "Groq" "GROQ_API_KEY" "https://console.groq.com/keys"
fi

if ! check_api_key "Gemini" "GEMINI_API_KEY" 2>/dev/null; then
    prompt_api_key "Gemini" "GEMINI_API_KEY" "https://makersuite.google.com/app/apikey"
fi

if ! check_api_key "Anthropic" "ANTHROPIC_API_KEY" 2>/dev/null; then
    prompt_api_key "Anthropic" "ANTHROPIC_API_KEY" "https://console.anthropic.com/"
fi

echo ""
echo "Setup complete! 🎉"
echo ""
echo "Next steps:"
echo "1. Source the environment variables:"
echo "   source .env"
echo ""
echo "2. Start the AI service:"
echo "   cd ai-service && python app.py"
echo ""
echo "3. Check provider status:"
echo "   curl http://localhost:18002/providers/stats"
echo ""
echo "For production deployment, add these variables to your deployment environment."
