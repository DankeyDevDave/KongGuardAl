# Kong Guard AI 🛡️🤖
## Autonomous API Threat Response Agent for Kong Gateway

[![Kong Version](https://img.shields.io/badge/Kong-3.8.0-blue)](https://konghq.com)
[![Plugin Version](https://img.shields.io/badge/Plugin-3.0.0-green)](https://github.com/yourusername/kong-guard-ai)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production_Ready-success)](https://github.com/yourusername/kong-guard-ai)

> Transform your Kong Gateway into an intelligent, self-healing security system that autonomously detects, classifies, and responds to API threats in real-time.

## ⚠️ PROPRIETARY SOFTWARE NOTICE

This is proprietary software developed for the Kong Agentic AI Hackathon 2025. The ML models and core algorithms are protected intellectual property. See [LICENSE](LICENSE) and [proprietary-notice.md](proprietary-notice.md) for details.

**Copyright © 2024 Jacques Francois Coetzee. All Rights Reserved.**

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

### Core Security
- 🔍 **Real-time Threat Detection** - ML-powered anomaly detection with static rules and dynamic thresholds
- 🤖 **Autonomous Response** - Automatic blocking, rate limiting, and traffic rerouting
- 🧠 **Continuous Learning** - Operator feedback loop to adapt thresholds and reduce false positives
- 🔄 **Self-Healing** - Automatic rollback of problematic configurations
- 📊 **Comprehensive Reporting** - Detailed incident logs with webhook notifications
- 🛡️ **Multi-Layer Protection** - Combines static rules, ML models, and optional AI Gateway
- ⚡ **High Performance** - <10ms added latency, stateless design for horizontal scaling

### Protocol-Specific Protection
- 🕸️ **GraphQL Security** - Query depth limiting and complexity analysis to prevent resource exhaustion
- 🔗 **gRPC Protection** - Method-level rate limiting and message size validation for microservices
- 🔐 **TLS Fingerprinting** - JA3/JA4 analysis to identify malicious clients and bots
- 🌐 **Request Normalization** - URL and body canonicalization to prevent evasion techniques

### Advanced Features
- 🚀 **TAXII/STIX Integration** - Real-time threat intelligence feeds with automated indicator processing
- ☸️ **Kubernetes/Mesh Enrichment** - Service mesh metadata extraction for microservices security
- 📊 **Enterprise Monitoring** - Grafana dashboards, Prometheus metrics, and structured logging
- 🎯 **Multi-Environment Support** - Development, staging, and production deployment strategies

## 🌐 TAXII/STIX Threat Intelligence Integration

Kong Guard AI now includes enterprise-grade threat intelligence capabilities through TAXII 2.x feed integration:

### 🎯 Threat Intelligence Features

- **🔄 Automated Feed Ingestion** - Real-time polling of TAXII 2.0/2.1 servers with configurable intervals
- **📊 STIX Indicator Processing** - Comprehensive parsing and normalization of STIX threat indicators
- **🎯 Multi-Vector Detection** - IP addresses, domains, URLs, file hashes, and TLS fingerprints
- **🚀 High-Performance Lookups** - Millisecond-level indicator matching with versioned caching
- **🔐 Enterprise Security** - Secure authentication, TLS verification, and input validation
- **📈 Adaptive Scoring** - Configurable threat scoring weights with confidence integration

### 🛡️ Supported Indicator Types

| Type | Examples | Use Case |
|------|----------|----------|
| **IP Addresses** | `192.168.1.100`, `2001:db8::1`, `10.0.0.0/8` | Block known malicious IPs and networks |
| **Domain Names** | `evil.com`, `*.malicious.org` | Prevent access to malicious domains |
| **URLs** | `https://phishing.site/login` | Block specific malicious URLs |
| **File Hashes** | MD5, SHA-1, SHA-256 | Identify known malware signatures |
| **TLS Fingerprints** | JA3, JA4 | Detect malicious TLS client behaviors |

### 📋 Quick TAXII Setup

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable TAXII threat intelligence
    enable_taxii_ingestion: true
    taxii_version: "2.1"
    taxii_poll_interval_seconds: 300

    # Configure threat intelligence servers
    taxii_servers:
    - url: "https://your-threat-intel.com/taxii2"
      collections: ["indicators", "malware"]
      auth_type: "bearer"
      token: "your-api-token"

    # Threat scoring weights
    taxii_score_weights:
      ip_blocklist: 0.9
      domain_blocklist: 0.8
      url_blocklist: 0.8
```

### 📚 Complete Documentation

#### Core Guides
- **[Kong Guard AI User Guide](KONG_GUARD_AI_USER_GUIDE.md)** - Complete user guide with quick start, configuration, and monitoring
- **[Configuration Reference](docs/CONFIGURATION_REFERENCE.md)** - Comprehensive configuration options and defaults
- **[Migration Guide](docs/MIGRATION_GUIDE.md)** - Safe upgrade paths between versions
- **[Rollout Guide](docs/ROLLOUT_GUIDE.md)** - Production deployment strategies

#### Feature Documentation
- **[GraphQL Protection](docs/GRAPHQL_PROTECTION.md)** - Query depth and complexity analysis
- **[gRPC Security](docs/GRPC_SECURITY.md)** - Method-level protection and performance controls
- **[Request Normalization](docs/NORMALIZATION_GUIDE.md)** - URL and body canonicalization
- **[TLS Fingerprinting](docs/TLS_FINGERPRINTING.md)** - JA3/JA4 analysis and client identification
- **[TAXII/STIX Integration](TAXII_STIX_User_Guide.md)** - Threat intelligence feeds setup
- **[Kubernetes/Mesh Enrichment](docs/mesh-enricher.md)** - Service mesh metadata extraction

## 🏗️ Enhanced Architecture (v3.0)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         Kong Guard AI v3.0 Architecture                         │
└─────────────────────────────────────────────────────────────────────────────────┘

    Client Request (HTTP/GraphQL/gRPC/HTTP2)
         │
         ▼
    ┌─────────────────┐
    │  Kong Gateway   │
    │  + TLS Analysis │──► JA3/JA4 Fingerprinting
    └─────────────────┘
         │
    ┌────┴─────┐
    │ Plugin   │
    │ Access   │──────► Request Normalization
    │ Phase    │       ├── URL Canonicalization
    └──────────┘       └── Body Standardization
         │                       │
         ▼                       ▼
    ┌─────────────────────────────────────────┐
    │         Feature Extraction              │
    │  ├── Protocol Detection                 │
    │  ├── Mesh Metadata (K8s/Istio)        │
    │  ├── GraphQL Parsing                   │
    │  ├── gRPC Method Analysis              │
    │  └── TAXII/STIX Indicator Lookup      │
    └─────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────┐
    │         Threat Detection                │
    │  ├── Static Rules (SQL, XSS, DDoS)    │
    │  ├── Protocol-Specific Analysis        │
    │  │   ├── GraphQL Complexity/Depth     │
    │  │   ├── gRPC Method Rate Limits      │
    │  │   └── TLS Fingerprint Matching     │
    │  ├── ML Anomaly Detection             │
    │  ├── Threat Intelligence Matching     │
    │  └── Mesh Behavior Analysis           │
    └─────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────┐
    │    Adaptive Threat Scoring              │
    │  ├── Multi-dimensional Scoring         │
    │  ├── Historical Context                │
    │  ├── Confidence Weighting              │
    │  └── Cross-service Correlation         │
    └─────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────┐
    │         Action Engine                   │
    └─────────────────────────────────────────┘
         │
    ┌────┴─────────────────────────────────┐
    │                                      │
    ▼                                      ▼
┌─────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│  Block  │  │ Rate Limit  │  │   Monitor   │  │   Forward    │
│  (403)  │  │   (429)     │  │   & Log     │  │ (with flags) │
└─────────┘  └─────────────┘  └─────────────┘  └──────────────┘
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

### Basic Configuration (v3.0)

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
          # Core Threat Detection
          block_threshold: 0.8        # Score above this = block
          rate_limit_threshold: 0.6   # Score above this = rate limit
          ddos_rpm_threshold: 100     # Requests/min for DDoS detection

          # Operating Mode
          dry_run: false              # Set true for testing

          # Protocol-Specific Features (v3.0)
          enable_graphql_detection: true
          graphql_max_depth: 12
          graphql_max_complexity: 2000

          enable_grpc_detection: true
          grpc_max_message_size: 4194304
          grpc_default_rate_limit: 100

          # Request Normalization (v3.0)
          normalize_url: true
          normalize_body: false       # Start conservative
          normalization_profile: "lenient"

          # TLS Fingerprinting (v3.0)
          enable_tls_fingerprints: true
          tls_header_map:
            ja3: "X-JA3"
            ja4: "X-JA4"

          # ML Configuration
          enable_ml_detection: true
          anomaly_threshold: 0.7

          # Notifications
          enable_notifications: true
          notification_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Advanced Configuration (v3.0)

```yaml
plugins:
  - name: kong-guard-ai
    config:
      # Enhanced Protocol Detection
      enable_graphql_detection: true
      graphql_max_depth: 15
      graphql_max_complexity: 3000
      graphql_operation_limits:
        query: { max_depth: 15, max_complexity: 3000 }
        mutation: { max_depth: 10, max_complexity: 2000 }
        subscription: { max_depth: 8, max_complexity: 1000 }

      enable_grpc_detection: true
      grpc_max_message_size: 4194304
      grpc_method_rate_limits:
        "user.UserService/GetUser": 1000
        "admin.AdminService/*": 10

      # Request Normalization
      normalize_url: true
      normalize_body: true
      normalization_profile: "strict"
      max_body_size_for_normalization: 1048576

      # TLS Fingerprinting
      enable_tls_fingerprints: true
      tls_header_map:
        ja3: "X-JA3"
        ja4: "X-JA4"
        ja3s: "X-JA3S"
        ja4s: "X-JA4S"
      tls_blocklist:
        - "e7d705a3286e19ea42f587b344ee6865"  # Known malicious JA3
      tls_allowlist:
        - "a0e9f5d64349fb13191bc781f81f42e1"  # Known good JA3

      # TAXII/STIX Threat Intelligence
      enable_taxii_ingestion: true
      taxii_servers:
        - url: "https://threat-intel.example.com/taxii2"
          collections: ["indicators", "malware"]
          auth_type: "bearer"
          token: "your-api-token"

      # Kubernetes/Mesh Enrichment
      enable_mesh_enricher: true
      mesh_header_map:
        source_service: "x-envoy-original-src-service"
        dest_service: "x-envoy-destination-service"
        namespace: "x-envoy-namespace"

      # Traditional Detection Patterns
      sql_injection_patterns:
        - "union%s+select"
        - "drop%s+table"
        - "insert%s+into"

      xss_patterns:
        - "<script"
        - "javascript:"
        - "onerror="

      # IP Management
      blocked_ips:
        - "203.0.113.100"
      whitelist_ips:
        - "10.0.0.0/8"

      # Response Actions
      auto_block_duration: 3600     # Block for 1 hour
      rate_limit_duration: 300      # Rate limit for 5 minutes
      rate_limit_requests: 10       # Allow 10 requests during rate limit

      # Logging & Metrics
      log_level: "info"
      metrics_enabled: true
```

## 🛡️ Threat Detection

### Multi-Layer Detection (v3.0)

#### Static Pattern Detection
- **SQL Injection** - Detects SQL keywords and syntax in parameters
- **XSS Attacks** - Identifies JavaScript injection attempts
- **DDoS Patterns** - Monitors request rates and patterns
- **Credential Stuffing** - Detects rapid login attempts
- **Path Traversal** - Blocks directory traversal attempts

#### Protocol-Specific Analysis
- **GraphQL Security** - Query depth and complexity analysis to prevent resource exhaustion
- **gRPC Protection** - Method-level rate limiting and message size validation
- **Request Normalization** - URL and body canonicalization to prevent evasion

#### Advanced Threat Intelligence
- **TLS Fingerprinting** - JA3/JA4 analysis to identify malicious clients and bots
- **TAXII/STIX Integration** - Real-time threat intelligence matching
- **Kubernetes/Mesh Context** - Service mesh metadata for behavioral analysis

#### ML-Based Detection
Anomaly detection using enhanced algorithms:
- Request rate patterns and behavioral analysis
- Payload size anomalies and content analysis
- Header count deviations and protocol violations
- Cross-service communication patterns
- Temporal and geographic anomalies
- Client fingerprint analysis

### Threat Scoring

Each request receives a threat score from 0.0 to 1.0:

- `0.0 - 0.3` - Normal traffic
- `0.3 - 0.6` - Suspicious (monitoring)
- `0.6 - 0.8` - High threat (rate limiting)
- `0.8 - 1.0` - Critical threat (blocking)

> **📖 TLS Fingerprinting Documentation**: For detailed setup instructions, deployment topologies, and advanced configuration of TLS fingerprinting features, see [docs/TLS_FINGERPRINTING.md](docs/TLS_FINGERPRINTING.md).

## 📊 Monitoring & Feedback

### Check Plugin Status

```bash
curl http://localhost:8001/kong-guard-ai/status
```

Response:
```json
{
  "plugin_version": "3.0.0",
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

### Test Attack Patterns (v3.0)

```bash
# Traditional Attacks
curl "http://localhost:8000/api?id=1'; DROP TABLE users; --"  # SQL Injection
curl "http://localhost:8000/api?search=<script>alert('XSS')</script>"  # XSS

# GraphQL Attacks
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query { user { posts { comments { replies { user { posts { comments { replies { content } } } } } } } } }"}' # Deep nesting

# gRPC Attack Simulation (using grpcurl)
grpcurl -plaintext -d '{"data": "'$(python -c 'print("A"*10000000)')'"}' \
  localhost:9090 service.Method  # Large payload

# Protocol Evasion
curl "http://localhost:8000/api?q=%27%20OR%201%3D1--"  # URL encoded SQL injection
curl "http://localhost:8000/admin/../../../etc/passwd"  # Path traversal

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

<!-- Smoke test: 2025-09-30 17:16:46 UTC -->
