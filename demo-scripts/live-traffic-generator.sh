#!/bin/bash

# Live Traffic Generator for Kong Guard AI Demo
# Sends mixed traffic (attacks and normal) to show AI analysis

echo "🚀 Starting Live Traffic Generator for AI Dashboard"
echo "📊 Dashboard: http://localhost:8080/ai-insights.html"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Attack patterns
SQL_ATTACKS=(
    "1' OR '1'='1"
    "admin'--"
    "' UNION SELECT * FROM users--"
    "1; DROP TABLE users--"
    "' OR 1=1 /*"
)

XSS_ATTACKS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert(1)>"
    "javascript:alert(document.cookie)"
    "<iframe src='javascript:alert(1)'>"
    "<body onload=alert('XSS')>"
)

PATH_TRAVERSALS=(
    "../../etc/passwd"
    "../../../windows/system32"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//etc/passwd"
)

NORMAL_QUERIES=(
    "page=1&limit=10"
    "search=product&category=electronics"
    "id=123456"
    "sort=price&order=asc"
    "filter=new&brand=apple"
)

# Function to send attack to AI service
send_to_ai() {
    local method=$1
    local path=$2
    local query=$3
    local threat_type=$4
    local ip="192.168.1.$((RANDOM % 255))"
    local rpm=$5
    
    curl -X POST http://localhost:8000/analyze \
        -H "Content-Type: application/json" \
        -d "{
            \"features\": {
                \"method\": \"$method\",
                \"path\": \"$path\",
                \"client_ip\": \"$ip\",
                \"user_agent\": \"$([ $threat_type == 'normal' ] && echo 'Mozilla/5.0' || echo 'AttackBot/1.0')\",
                \"requests_per_minute\": $rpm,
                \"content_length\": 0,
                \"query_param_count\": 2,
                \"header_count\": 5,
                \"hour_of_day\": $(date +%H),
                \"query\": \"$query\",
                \"headers\": {\"User-Agent\": \"Test\"}
            },
            \"context\": {
                \"previous_requests\": $((RANDOM % 100)),
                \"failed_attempts\": $([ $threat_type == 'normal' ] && echo 0 || echo $((RANDOM % 10))),
                \"anomaly_score\": $([ $threat_type == 'normal' ] && echo 0.1 || echo 0.8)
            }
        }" -s > /dev/null 2>&1 &
}

# Main loop
while true; do
    # Random selection of traffic type
    TRAFFIC_TYPE=$((RANDOM % 10))
    
    if [ $TRAFFIC_TYPE -lt 3 ]; then
        # 30% SQL Injection
        attack="${SQL_ATTACKS[$((RANDOM % ${#SQL_ATTACKS[@]}))]}"
        echo "🔴 [$(date +%H:%M:%S)] SQL Injection: $attack"
        send_to_ai "GET" "/api/users" "$attack" "sql" 50
        
    elif [ $TRAFFIC_TYPE -lt 5 ]; then
        # 20% XSS
        attack="${XSS_ATTACKS[$((RANDOM % ${#XSS_ATTACKS[@]}))]}"
        echo "🟠 [$(date +%H:%M:%S)] XSS Attack: ${attack:0:30}..."
        send_to_ai "POST" "/comment" "$attack" "xss" 80
        
    elif [ $TRAFFIC_TYPE -lt 6 ]; then
        # 10% Path Traversal
        attack="${PATH_TRAVERSALS[$((RANDOM % ${#PATH_TRAVERSALS[@]}))]}"
        echo "🟡 [$(date +%H:%M:%S)] Path Traversal: $attack"
        send_to_ai "GET" "/files" "$attack" "path" 60
        
    else
        # 40% Normal Traffic
        query="${NORMAL_QUERIES[$((RANDOM % ${#NORMAL_QUERIES[@]}))]}"
        echo "🟢 [$(date +%H:%M:%S)] Normal Traffic: $query"
        send_to_ai "GET" "/api/products" "$query" "normal" 10
    fi
    
    # Random delay between requests (0.5 to 3 seconds)
    sleep $(echo "scale=1; $((RANDOM % 25 + 5)) / 10" | bc)
done