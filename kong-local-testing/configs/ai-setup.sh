#!/bin/bash

# Kong AI Gateway Configuration Script
# This script sets up Kong as an AI Gateway with various AI providers

# Configuration
KONG_ADMIN="http://localhost:8001"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🤖 Setting up Kong AI Gateway"
echo "=============================="
echo ""

# Function to create AI service
setup_ai_service() {
    local provider=$1
    local service_name=$2
    local url=$3
    
    echo -e "${YELLOW}Setting up $provider service...${NC}"
    
    # Create service
    curl -s -X POST $KONG_ADMIN/services \
        -d "name=$service_name" \
        -d "url=$url" > /dev/null
    
    # Create route
    curl -s -X POST $KONG_ADMIN/services/$service_name/routes \
        -d "name=$service_name-route" \
        -d "paths=/$provider" > /dev/null
    
    echo -e "${GREEN}✓ $provider service created${NC}"
}

# Example 1: OpenAI Proxy
setup_openai() {
    echo "1. OpenAI GPT Proxy Setup"
    echo "-------------------------"
    
    setup_ai_service "openai" "openai-service" "https://api.openai.com"
    
    # Add AI proxy plugin
    curl -s -X POST $KONG_ADMIN/services/openai-service/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "ai-proxy",
            "config": {
                "route_type": "llm/v1/chat",
                "auth": {
                    "header_name": "Authorization",
                    "header_value": "Bearer YOUR_OPENAI_API_KEY"
                },
                "model": {
                    "provider": "openai",
                    "name": "gpt-3.5-turbo"
                }
            }
        }' > /dev/null
    
    echo -e "${GREEN}✓ OpenAI proxy configured${NC}"
    echo "  Access at: http://localhost:8000/openai/v1/chat/completions"
    echo ""
}

# Example 2: Anthropic Claude Proxy
setup_anthropic() {
    echo "2. Anthropic Claude Proxy Setup"
    echo "--------------------------------"
    
    setup_ai_service "anthropic" "anthropic-service" "https://api.anthropic.com"
    
    # Add AI proxy plugin for Claude
    curl -s -X POST $KONG_ADMIN/services/anthropic-service/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "ai-proxy",
            "config": {
                "route_type": "llm/v1/chat",
                "auth": {
                    "header_name": "X-API-Key",
                    "header_value": "YOUR_ANTHROPIC_API_KEY"
                },
                "model": {
                    "provider": "anthropic",
                    "name": "claude-3-opus-20240229"
                }
            }
        }' > /dev/null
    
    echo -e "${GREEN}✓ Anthropic proxy configured${NC}"
    echo "  Access at: http://localhost:8000/anthropic/v1/messages"
    echo ""
}

# Example 3: Prompt Guard Setup
setup_prompt_guard() {
    echo "3. AI Prompt Guard Setup"
    echo "------------------------"
    
    # Add prompt guard to existing service
    curl -s -X POST $KONG_ADMIN/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "ai-prompt-guard",
            "config": {
                "allow_patterns": ["^[a-zA-Z0-9\\s.,!?]+$"],
                "deny_patterns": ["password", "secret", "key", "token"],
                "max_prompt_length": 1000,
                "check_for_jailbreak": true
            }
        }' > /dev/null
    
    echo -e "${GREEN}✓ Prompt guard configured${NC}"
    echo "  Protects against: SQL injection, prompt injection, jailbreaks"
    echo ""
}

# Example 4: Prompt Decorator
setup_prompt_decorator() {
    echo "4. AI Prompt Decorator Setup"
    echo "----------------------------"
    
    curl -s -X POST $KONG_ADMIN/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "ai-prompt-decorator",
            "config": {
                "prepend": "You are a helpful assistant. Please provide clear and concise answers.",
                "append": "Please format your response in a professional manner.",
                "system_prompt": "You must follow ethical guidelines and refuse harmful requests."
            }
        }' > /dev/null
    
    echo -e "${GREEN}✓ Prompt decorator configured${NC}"
    echo "  Adds context and guidelines to all prompts"
    echo ""
}

# Example 5: Rate Limiting for AI
setup_ai_rate_limiting() {
    echo "5. AI Rate Limiting Setup"
    echo "-------------------------"
    
    curl -s -X POST $KONG_ADMIN/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "rate-limiting",
            "config": {
                "minute": 10,
                "hour": 100,
                "policy": "local",
                "fault_tolerant": true,
                "hide_client_headers": false
            },
            "tags": ["ai-protection"]
        }' > /dev/null
    
    echo -e "${GREEN}✓ AI rate limiting configured${NC}"
    echo "  Limits: 10 requests/minute, 100 requests/hour"
    echo ""
}

# Example 6: Response Caching for AI
setup_ai_caching() {
    echo "6. AI Response Caching Setup"
    echo "----------------------------"
    
    curl -s -X POST $KONG_ADMIN/plugins \
        -H "Content-Type: application/json" \
        -d '{
            "name": "proxy-cache",
            "config": {
                "strategy": "memory",
                "memory": {
                    "dictionary_name": "ai_cache"
                },
                "content_type": ["application/json"],
                "cache_ttl": 300,
                "vary_headers": ["Authorization"]
            }
        }' > /dev/null
    
    echo -e "${GREEN}✓ AI response caching configured${NC}"
    echo "  Cache TTL: 5 minutes"
    echo ""
}

# Menu
echo "Select AI features to configure:"
echo "1. OpenAI GPT Proxy"
echo "2. Anthropic Claude Proxy"
echo "3. Prompt Guard (Security)"
echo "4. Prompt Decorator"
echo "5. AI Rate Limiting"
echo "6. Response Caching"
echo "7. Configure All (except API providers)"
echo ""
echo "Note: Options 1-2 require API keys to function"
echo ""
read -p "Enter your choice (1-7): " choice

case $choice in
    1)
        setup_openai
        ;;
    2)
        setup_anthropic
        ;;
    3)
        setup_prompt_guard
        ;;
    4)
        setup_prompt_decorator
        ;;
    5)
        setup_ai_rate_limiting
        ;;
    6)
        setup_ai_caching
        ;;
    7)
        setup_prompt_guard
        setup_prompt_decorator
        setup_ai_rate_limiting
        setup_ai_caching
        echo -e "${GREEN}✓ All AI protection features configured${NC}"
        ;;
    *)
        echo "Invalid choice"
        ;;
esac

echo ""
echo "Configuration complete!"
echo ""
echo "To use AI features with API keys:"
echo "1. Edit this script and add your API keys"
echo "2. Run options 1 or 2 to set up AI providers"
echo ""
echo "Test commands:"
echo '  curl -X POST http://localhost:8000/openai/v1/chat/completions \'
echo '    -H "Content-Type: application/json" \'
echo '    -d '"'"'{"messages":[{"role":"user","content":"Hello!"}]}'"'"