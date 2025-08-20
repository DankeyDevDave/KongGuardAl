# Kong Guard AI 🛡️🤖
## Autonomous API Threat Response Agent for Kong Gateway

[![Kong Version](https://img.shields.io/badge/Kong-3.8.0-blue)](https://konghq.com)
[![Plugin Version](https://img.shields.io/badge/Plugin-1.0.0-green)](https://github.com/yourusername/kong-guard-ai)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production_Ready-success)](https://github.com/yourusername/kong-guard-ai)

> Transform your Kong Gateway into an intelligent, self-healing security system that autonomously detects, classifies, and responds to API threats in real-time.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/kong-guard-ai.git
cd kong-guard-ai

# Start Kong with Guard AI plugin
docker-compose -f docker-compose-simple.yml up -d

# Verify installation
curl http://localhost:8001 | jq '.plugins.available_on_server' | grep kong-guard-ai

# Test the plugin
curl http://localhost:8000/demo/get  # Normal request (200 OK)
curl "http://localhost:8000/demo/get?q='; DROP TABLE users;"  # SQL injection (403 Blocked)
```

## 🎯 Key Features

- 🔍 **Real-time Threat Detection** - ML-powered anomaly detection with static rules and dynamic thresholds
- 🤖 **Autonomous Response** - Automatic blocking, rate limiting, and traffic rerouting
- 🧠 **Continuous Learning** - Operator feedback loop to adapt thresholds and reduce false positives
- 🔄 **Self-Healing** - Automatic rollback of problematic configurations
- 📊 **Comprehensive Reporting** - Detailed incident logs with webhook notifications
- 🛡️ **Multi-Layer Protection** - Combines static rules, ML models, and optional AI Gateway
- ⚡ **High Performance** - <10ms added latency, stateless design for horizontal scaling

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kong Guard AI Architecture                   │
└─────────────────────────────────────────────────────────────────┘

    Client Request
         │
         ▼
    Kong Gateway
         │
    ┌────┴────┐
    │ Plugin  │
    │ Access  │──────► Feature Extraction
    │ Phase   │              │
    └─────────┘              ▼
         │            Threat Detection
         │            ├── Static Rules (SQL, XSS, DDoS)
         │            ├── ML Anomaly Detection
         │            └── AI Gateway (Optional)
         │                   │
         ▼                   ▼
    ┌─────────┐        Threat Score
    │ Action  │              │
    │ Engine  │◄─────────────┘
    └────┬────┘
         │
    ┌────┴───────────────┐
    │                    │
    ▼                    ▼
  Block              Rate Limit
  (403)              (429)
```

## 📦 Installation

### Using Docker (Recommended)

```bash
# Build Kong with Guard AI plugin
cd kong-plugin
docker build -t kong-guard-ai:latest .

# Run with docker-compose
docker-compose -f docker-compose-simple.yml up -d
```

### Manual Installation

```bash
# Copy plugin files to Kong plugins directory
cp -r kong-plugin/kong/plugins/kong-guard-ai /usr/local/share/lua/5.1/kong/plugins/

# Set environment variable
export KONG_PLUGINS=bundled,kong-guard-ai

# Restart Kong
kong restart
```

## ⚙️ Configuration

### Basic Configuration

```yaml
_format_version: "3.0"

services:
  - name: my-api
    url: http://backend-api:80
    routes:
      - name: api-route
        paths:
          - /api
    plugins:
      - name: kong-guard-ai
        config:
          # Threat Detection
          block_threshold: 0.8        # Score above this = block
          rate_limit_threshold: 0.6   # Score above this = rate limit
          ddos_rpm_threshold: 100      # Requests/min for DDoS detection
          
          # Operating Mode
          dry_run: false               # Set true for testing
          
          # ML Configuration
          enable_ml: true
          anomaly_threshold: 0.7
          
          # Notifications
          enable_notifications: true
          notification_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
          
          # Learning
          enable_learning: true
          learning_rate: 0.001
```

### Advanced Configuration

```yaml
plugins:
  - name: kong-guard-ai
    config:
      # Detection Patterns
      sql_injection_patterns:
        - "union%s+select"
        - "drop%s+table"
        - "insert%s+into"
        - "select%s+from"
      
      xss_patterns:
        - "<script"
        - "javascript:"
        - "onerror="
        - "onload="
      
      # IP Management
      blocked_ips:
        - "192.168.1.100"
      whitelist_ips:
        - "10.0.0.0/8"
      
      # Response Actions
      auto_block_duration: 3600     # Block for 1 hour
      rate_limit_duration: 300      # Rate limit for 5 minutes
      rate_limit_requests: 10       # Allow 10 requests during rate limit
      
      # Logging
      log_level: "info"              # debug, info, warn, error
      metrics_enabled: true
```

## 🛡️ Threat Detection

### Static Rules

The plugin includes built-in detection for common attack patterns:

- **SQL Injection** - Detects SQL keywords and syntax in parameters
- **XSS Attacks** - Identifies JavaScript injection attempts
- **DDoS Patterns** - Monitors request rates and patterns
- **Credential Stuffing** - Detects rapid login attempts
- **Path Traversal** - Blocks directory traversal attempts

### ML-Based Detection

Anomaly detection using Isolation Forest algorithm considers:

- Request rate patterns
- Payload size anomalies
- Header count deviations
- Time-based anomalies
- Geographic anomalies
- User agent entropy

### Threat Scoring

Each request receives a threat score from 0.0 to 1.0:

- `0.0 - 0.3` - Normal traffic
- `0.3 - 0.6` - Suspicious (monitoring)
- `0.6 - 0.8` - High threat (rate limiting)
- `0.8 - 1.0` - Critical threat (blocking)

## 📊 Monitoring & Feedback

### Check Plugin Status

```bash
curl http://localhost:8001/kong-guard-ai/status
```

Response:
```json
{
  "plugin_version": "1.0.0",
  "operational": true,
  "metrics": {
    "threats_detected": 142,
    "false_positive_rate": 0.02,
    "active_blocks": 3,
    "active_rate_limits": 7
  }
}
```

### Provide Feedback

Help the system learn by providing feedback on decisions:

```bash
curl -X POST http://localhost:8001/kong-guard-ai/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc_123456",
    "decision_correct": false,
    "actual_threat": "false_positive",
    "operator_notes": "Legitimate traffic spike from campaign"
  }'
```

### View Incidents

```bash
curl http://localhost:8001/kong-guard-ai/incidents
```

## 🧪 Testing

### Test Attack Patterns

```bash
# SQL Injection
curl "http://localhost:8000/api?id=1'; DROP TABLE users; --"

# XSS Attack
curl "http://localhost:8000/api?search=<script>alert('XSS')</script>"

# DDoS Simulation
for i in {1..200}; do
  curl http://localhost:8000/api &
done

# Credential Stuffing
for i in {1..50}; do
  curl -X POST http://localhost:8000/api/login \
    -d "username=admin&password=pass$i"
done
```

### Dry Run Mode

Test without enforcement:

```yaml
plugins:
  - name: kong-guard-ai
    config:
      dry_run: true  # Log only, no blocking
```

## 📈 Performance

### Benchmarks

- **Latency Impact**: < 10ms per request
- **Throughput**: 10,000+ RPS per node
- **Memory Usage**: ~50MB baseline
- **CPU Usage**: < 5% at 1,000 RPS

### Optimization Tips

1. **Use DB-less mode** for better performance
2. **Adjust thresholds** based on your traffic patterns
3. **Enable caching** for repeat offenders
4. **Use geographic filtering** for regional APIs
5. **Implement whitelisting** for known good IPs

## 🔧 Troubleshooting

### Common Issues

#### Plugin Not Loading
```bash
# Check if plugin is available
curl http://localhost:8001 | jq '.plugins.available_on_server'

# Check Kong logs
docker logs kong-gateway --tail 50
```

#### High False Positive Rate
```yaml
# Increase thresholds
config:
  block_threshold: 0.9        # More conservative
  rate_limit_threshold: 0.7
```

#### Performance Issues
```yaml
# Disable ML for pure rule-based detection
config:
  enable_ml: false
  enable_notifications: false  # Reduce external calls
```

## 🚦 Use Cases

### 1. E-Commerce Protection
```yaml
config:
  # Strict protection for checkout
  block_threshold: 0.7
  # Monitor for credential stuffing
  ddos_rpm_threshold: 20
  # Track suspicious payment patterns
  enable_learning: true
```

### 2. Public API Defense
```yaml
config:
  # Higher tolerance for varied traffic
  block_threshold: 0.85
  # Higher rate limits
  ddos_rpm_threshold: 500
  # Focus on DDoS protection
  rate_limit_requests: 100
```

### 3. Internal API Security
```yaml
config:
  # Whitelist internal IPs
  whitelist_ips:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  # Lower thresholds for unknown IPs
  block_threshold: 0.6
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/kong-guard-ai.git

# Install dependencies
luarocks install busted
luarocks install kong-pdk

# Run tests
busted spec/

# Lint code
luacheck kong-plugin/
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Kong Inc. for the excellent API Gateway
- OpenResty community for Lua/Nginx integration
- OWASP for threat detection patterns
- The security research community

## 📞 Support

- 📧 Email: support@kongguardai.com
- 💬 Slack: [Join our community](https://kongguardai.slack.com)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/kong-guard-ai/issues)
- 📖 Docs: [Full Documentation](https://docs.kongguardai.com)

---

**Kong Guard AI** - Autonomous API Security for the Modern Web 🛡️🤖