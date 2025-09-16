#!/bin/bash

# Configure Kong Guard AI Plugin

echo "🔧 Configuring Kong Guard AI Plugin..."

# Add plugin globally (protects all routes)
curl -X POST http://localhost:18001/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "log_level": "info",
      "ml_threshold": 0.7,
      "patterns": {
        "sql_injection": true,
        "xss": true,
        "command_injection": true,
        "path_traversal": true,
        "xxe": true,
        "ldap_injection": true
      },
      "whitelist": [],
      "blacklist": [],
      "rate_limit_enabled": true,
      "rate_limit_minute": 60,
      "rate_limit_hour": 1000,
      "anomaly_detection": true,
      "ml_enabled": true,
      "response_action": "block",
      "response_status_code": 403,
      "response_message": "Request blocked by Kong Guard AI",
      "alert_enabled": false,
      "redis_host": "kong-redis",
      "redis_port": 6379,
      "redis_timeout": 1000,
      "redis_database": 0
    }
  }'

echo ""
echo "✅ Kong Guard AI Plugin configured globally!"
echo ""
echo "📊 Test the plugin:"
echo "  Normal request:  curl http://localhost:18000/demo/anything"
echo "  SQL injection:   curl 'http://localhost:18000/demo/anything?id=1 OR 1=1'"
echo "  XSS attempt:     curl 'http://localhost:18000/demo/anything?q=<script>alert(1)</script>'"
echo ""
echo "🔍 View plugin config:"
echo "  curl http://localhost:18001/plugins | jq"
