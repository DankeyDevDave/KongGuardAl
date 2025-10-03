# Kong Guard AI User Guide
## Comprehensive Security Platform for Kong Gateway

### **Overview**

Kong Guard AI transforms your Kong Gateway into an intelligent, multi-layered security platform that provides:

- ** Real-time Threat Detection** - ML-powered anomaly detection with static rules and dynamic thresholds
- ** Autonomous Response** - Automatic blocking, rate limiting, and traffic rerouting
- ** Continuous Learning** - Operator feedback loop to adapt thresholds and reduce false positives
- ** Multi-Protocol Protection** - HTTP/S, GraphQL, gRPC, and WebSocket security
- ** Threat Intelligence** - TAXII/STIX feed integration for real-time threat data
- ** Advanced Fingerprinting** - TLS (JA3/JA4) and service mesh metadata analysis
- ** Comprehensive Monitoring** - Detailed metrics and alerting capabilities

---

## **Quick Start**

### **Basic Installation**

```bash
# Clone the repository
git clone https://github.com/DankeyDevDave/KongGuardAI.git kong-guard-ai
cd kong-guard-ai

# Start Kong with Guard AI plugin
docker-compose -f docker-compose-simple.yml up -d

# Test basic functionality
curl "http://localhost:8000/demo/get?q='; DROP TABLE users;" # Should be blocked
```

### **Essential Configuration**

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Core settings
    block_threshold: 0.8
    rate_limit_threshold: 0.6
    dry_run: false # Set to true for testing

    # Enable key features
    enable_ml_detection: true
    enable_notifications: true
    metrics_enabled: true
```

---

## **Core Security Features**

### **1. Traditional Threat Detection**

**SQL Injection Protection**
```yaml
config:
  sql_injection_patterns:
    - "union%s+select"
    - "drop%s+table"
    - "insert%s+into"
    - "select%s+from"
```

**XSS Prevention**
```yaml
config:
  xss_patterns:
    - "<script"
    - "javascript:"
    - "onerror="
    - "onload="
```

**DDoS Protection**
```yaml
config:
  ddos_rpm_threshold: 100
  rate_limit_duration: 300
  rate_limit_requests: 10
```

### **2. Machine Learning Detection**

```yaml
config:
  enable_ml_detection: true
  anomaly_threshold: 0.7
  enable_learning: true
  learning_rate: 0.001
```

**Features analyzed:**
- Request patterns and timing
- Payload characteristics
- Header anomalies
- Geographic and behavioral patterns

### **3. AI Gateway Integration**

```yaml
config:
  enable_ai_gateway: true
  ai_service_url: "http://ai-service:8000"
  ai_model: "claude-3-haiku"
  ai_temperature: 0.1
```

Provides advanced threat analysis using large language models for complex attack pattern recognition.

---

## **Advanced Protocol Protection**

### **GraphQL Security**

Protect GraphQL APIs from query complexity attacks:

```yaml
config:
  enable_graphql_detection: true
  graphql_max_depth: 12
  graphql_max_complexity: 2000
```

**Features:**
- Query depth limiting to prevent deeply nested queries
- Complexity scoring to block resource-intensive operations
- Automatic detection of GraphQL endpoints

**Example blocked query:**
```graphql
query AttackQuery {
  user {
    posts {
      comments {
        replies {
          # ... deeply nested structure
        }
      }
    }
  }
}
```

### **gRPC Security**

Secure gRPC services with method-level controls:

```yaml
config:
  enable_grpc_detection: true
  grpc_max_message_size: 4194304 # 4MB
  grpc_blocked_methods:
    - "admin.*"
    - "*.DeleteUser"
  grpc_rate_limit_per_method: 100
```

**Features:**
- Method pattern blocking (wildcard support)
- Message size limits
- Per-method rate limiting
- Automatic gRPC detection

### **Request Normalization**

Standardize requests before analysis to improve detection accuracy:

```yaml
config:
  normalize_url: true
  normalize_body: false
  normalization_profile: "lenient" # or "strict"
```

**URL Normalization:**
- Decode percent-encoding
- Normalize path separators
- Remove redundant slashes
- Case normalization

**Body Normalization:**
- JSON pretty-printing standardization
- XML formatting normalization
- Form data ordering

---

## **Advanced Security Features**

### **TLS Fingerprinting**

Analyze TLS client behavior to detect malicious tools and bots:

```yaml
config:
  enable_tls_fingerprints: true
  tls_header_map:
    ja3: "X-JA3"
    ja4: "X-JA4"
    tls_version: "X-TLS-Version"
  tls_cache_ttl_seconds: 600
  tls_score_weights:
    match_blocklist: 0.7
    ua_mismatch: 0.2
    rare_fingerprint: 0.2
```

**Supported Headers:**
- JA3/JA3S fingerprints
- JA4/JA4S fingerprints
- TLS version and cipher information
- SNI (Server Name Indication)

### **TAXII/STIX Threat Intelligence**

Integrate real-time threat intelligence feeds:

```yaml
config:
  enable_taxii_ingestion: true
  taxii_version: "2.1"
  taxii_poll_interval_seconds: 300
  taxii_servers:
    - url: "https://threat-intel.example.com/taxii2"
      collections: ["indicators", "malware"]
      auth_type: "bearer"
      token: "your-api-token"
```

**Supported Indicators:**
- IP addresses and CIDR blocks
- Domain names (wildcards supported)
- URLs and URL patterns
- File hashes (MD5, SHA-1, SHA-256)
- TLS fingerprints (JA3/JA4)

### **Kubernetes/Service Mesh Integration**

Analyze service mesh metadata for advanced threat detection:

```yaml
config:
  enable_mesh_enricher: true
  mesh_header_map:
    namespace: "X-K8s-Namespace"
    service: "X-K8s-Service"
    mesh_source: "X-Mesh-Source"
  mesh_risky_namespaces:
    - "admin"
    - "kube-system"
  mesh_score_weights:
    cross_namespace: 0.3
    risky_namespace: 0.8
    unusual_pair: 0.3
```

**Detects:**
- Cross-namespace communication anomalies
- Access to high-privilege namespaces
- Unusual service communication patterns
- Missing service mesh metadata

---

## **Monitoring and Alerting**

### **Metrics Collection**

```yaml
config:
  metrics_enabled: true
  log_level: "info"
  log_threats: true
  log_decisions: true
```

**Available Metrics:**
- Total requests processed
- Threats detected by type
- Blocking and rate limiting actions
- AI analysis performance
- Protocol-specific metrics (GraphQL, gRPC)
- Mesh communication patterns

### **Notifications**

Configure alerts for security events:

```yaml
config:
  enable_notifications: true
  notification_channels: ["webhook", "slack"]
  notification_url: "https://hooks.slack.com/your-webhook"
```

**Notification Types:**
- High-severity threats blocked
- Unusual traffic patterns detected
- New threat intelligence indicators
- System health alerts

### **Grafana Integration**

Monitor Kong Guard AI with Grafana dashboards:

```bash
# Start monitoring stack
docker-compose -f docker-compose-with-monitoring.yml up -d

# Access Grafana
open http://localhost:3000
```

**Dashboard Panels:**
- Threat detection rates
- Request processing latency
- AI analysis success rates
- Geographic threat distribution
- Service mesh communication flows

---

## **Configuration Reference**

### **Threat Thresholds**

```yaml
config:
  block_threshold: 0.8 # Block requests above this score
  rate_limit_threshold: 0.6 # Rate limit suspicious requests
  anomaly_threshold: 0.7 # ML anomaly detection sensitivity
```

### **Performance Tuning**

```yaml
config:
  ai_service_timeout: 500 # AI analysis timeout (ms)
  mesh_cache_ttl_seconds: 300 # Mesh metadata cache TTL
  taxii_poll_interval_seconds: 300 # Threat intel refresh rate
```

### **Security Policies**

```yaml
config:
  blocked_countries: ["XX", "YY"] # ISO country codes
  blocked_ips: ["192.168.1.100"] # Specific IP addresses
  whitelist_ips: ["10.0.0.0/8"] # Trusted IP ranges
```

---

## **Incident Response**

### **High-Severity Threats**

When Kong Guard AI detects critical threats:

1. **Immediate Response:**
   - Request blocked with 403 status
   - Incident ID generated for tracking
   - Notifications sent to configured channels

2. **Investigation:**
   ```bash
   # Check recent threats
   curl http://localhost:8001/kong-guard-ai/metrics

   # Review specific incident
   grep "incident_id:12345" /var/log/kong/error.log
   ```

3. **Mitigation:**
   - Update threat intelligence feeds
   - Adjust detection thresholds if needed
   - Review and update blocking rules

### **False Positive Handling**

```yaml
config:
  enable_learning: true
  feedback_endpoint: "/kong-guard-ai/feedback"
```

**Feedback API:**
```bash
# Mark detection as false positive
curl -X POST http://localhost:8001/kong-guard-ai/feedback \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "12345", "feedback": "false_positive"}'
```

---

## **Operational Procedures**

### **Daily Operations**

**Morning Security Check:**
```bash
# Check overnight activity
curl http://localhost:8001/kong-guard-ai/metrics | jq .

# Review threat intelligence updates
curl http://localhost:8001/kong-guard-ai/taxii/status
```

**Threat Analysis:**
```bash
# View top threat sources
curl http://localhost:8001/kong-guard-ai/threats/top-sources

# Check mesh communication patterns
curl http://localhost:8001/kong-guard-ai/mesh/pairs
```

### **Maintenance Tasks**

**Weekly:**
- Review false positive feedback
- Update threat intelligence configurations
- Analyze performance metrics
- Check for plugin updates

**Monthly:**
- Security posture assessment
- Configuration optimization
- Disaster recovery testing
- Documentation updates

---

## **Troubleshooting**

### **Common Issues**

**No threats detected:**
- Verify plugin is enabled on routes
- Check threat thresholds (may be too high)
- Ensure traffic is reaching Kong

**High false positive rate:**
- Review detection patterns
- Adjust threshold values
- Enable learning mode
- Check for legitimate automation

**Performance issues:**
- Monitor AI service response times
- Optimize caching settings
- Review resource allocation

### **Debug Mode**

```yaml
config:
  log_level: "debug"
  log_requests: true
  dry_run: true # Test without blocking
```

**Log Analysis:**
```bash
# Follow Kong logs
tail -f /var/log/kong/error.log | grep kong-guard-ai

# Check AI service logs
docker logs ai-service

# Monitor metrics
watch -n 5 'curl -s http://localhost:8001/kong-guard-ai/metrics'
```

---

## **Additional Resources**

### **Documentation Links**
- [Configuration Reference](docs/CONFIGURATION_REFERENCE.md)
- [Migration Guide](docs/MIGRATION_GUIDE.md)
- [TLS Fingerprinting](docs/TLS_FINGERPRINTING.md)
- [TAXII/STIX Integration](TAXII_STIX_User_Guide.md)
- [Mesh Enricher](docs/mesh-enricher.md)
- [Examples and Recipes](docs/EXAMPLES.md)

### **Support**
- GitHub Issues: Report bugs and feature requests
- Security Issues: security@yourcompany.com
- Community: Kong Community Forum

### **Development**
- Plugin Development Guide
- API Reference
- Testing Framework
- Contributing Guidelines

---

## **Security Considerations**

### **Data Privacy**
- Configure log sanitization for PII
- Review data retention policies
- Implement secure key management
- Regular security audits

### **Production Deployment**
- Use TLS for all communications
- Implement proper RBAC
- Monitor for security updates
- Maintain incident response procedures

This comprehensive guide covers all Kong Guard AI capabilities. For specific implementation details, refer to the linked documentation in each section.