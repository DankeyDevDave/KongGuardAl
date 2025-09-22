# Kong Guard AI Rollout Guide
## Production Deployment Strategy and Best Practices

### 📋 **Overview**

This guide provides comprehensive strategies for safely deploying Kong Guard AI to production environments, including phased rollouts, monitoring strategies, and risk mitigation approaches.

---

## 🎯 **Rollout Strategy Framework**

### **Three-Phase Approach**

| Phase | Duration | Goal | Risk Level |
|-------|----------|------|------------|
| **Observe** | 1-2 weeks | Monitor and learn without enforcement | 🟢 Low |
| **Rate Limit** | 1-2 weeks | Apply rate limiting only | 🟡 Medium |
| **Enforce** | Ongoing | Full blocking with gradual threshold reduction | 🔴 High |

---

## 📊 **Phase 1: Observe Mode**

### **Configuration**
```yaml
plugins:
- name: kong-guard-ai
  config:
    # CRITICAL: No enforcement
    dry_run: true
    block_threshold: 1.0  # Never block
    rate_limit_threshold: 1.0  # Never rate limit

    # Maximum logging and monitoring
    log_level: "debug"
    log_requests: true
    log_threats: true
    log_decisions: true
    metrics_enabled: true

    # Enable all detection features for observation
    enable_ml_detection: true
    enable_graphql_detection: true
    enable_grpc_detection: true
    enable_tls_fingerprints: true
    enable_mesh_enricher: true  # If in K8s
    enable_taxii_ingestion: true  # If threat feeds available

    # Conservative detection settings
    anomaly_threshold: 0.8
    graphql_max_depth: 20  # Permissive initially
    graphql_max_complexity: 5000
    grpc_max_message_size: 8388608  # 8MB
```

### **Monitoring Objectives**
- **Traffic Patterns**: Understand normal vs. anomalous behavior
- **Performance Impact**: Measure latency and resource usage
- **Detection Accuracy**: Identify potential false positives
- **Feature Usage**: Determine which protocols/features are used

### **Key Metrics to Track**
```bash
# Traffic analysis
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  total_requests: .total_requests,
  unique_ips: .unique_client_ips,
  avg_requests_per_ip: (.total_requests / .unique_client_ips),
  peak_rpm: .peak_requests_per_minute
}'

# Threat landscape
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  potential_threats: .threats_detected,
  sql_injection_attempts: .sql_injection_patterns,
  xss_attempts: .xss_patterns,
  ddos_patterns: .ddos_patterns,
  graphql_complex_queries: .graphql_over_limit,
  grpc_large_messages: .grpc_oversized_messages
}'

# Performance impact
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  avg_latency_ms: .avg_processing_latency,
  p95_latency_ms: .p95_processing_latency,
  memory_usage_mb: .memory_usage,
  cpu_usage_percent: .cpu_usage
}'
```

### **Daily Review Process**
```bash
#!/bin/bash
# daily-observe-review.sh

echo "=== Kong Guard AI Daily Observation Report ==="
echo "Date: $(date)"

# Traffic summary
echo -e "\n📊 Traffic Summary:"
curl -s http://localhost:8001/kong-guard-ai/metrics | jq -r '
  "Total requests: \(.total_requests)",
  "Unique IPs: \(.unique_client_ips)",
  "Peak RPM: \(.peak_requests_per_minute)"
'

# Threat detection summary
echo -e "\n🚨 Threat Detection (Would-be Actions):"
curl -s http://localhost:8001/kong-guard-ai/metrics | jq -r '
  "Would block: \(.would_block_requests)",
  "Would rate limit: \(.would_rate_limit_requests)",
  "Top threat types: \(.top_threat_types | join(", "))"
'

# Performance impact
echo -e "\n⚡ Performance Impact:"
curl -s http://localhost:8001/kong-guard-ai/metrics | jq -r '
  "Avg latency: \(.avg_processing_latency)ms",
  "Memory usage: \(.memory_usage_mb)MB",
  "Error rate: \(.error_rate_percent)%"
'

# Feature utilization
echo -e "\n🔧 Feature Utilization:"
curl -s http://localhost:8001/kong-guard-ai/metrics | jq -r '
  "GraphQL requests: \(.graphql_requests)",
  "gRPC requests: \(.grpc_requests)",
  "Mesh requests: \(.mesh_requests)",
  "TLS fingerprinted: \(.tls_fingerprinted_requests)"
'
```

### **Success Criteria for Phase 1**
- [ ] Zero impact on application performance (< 5ms added latency)
- [ ] Complete traffic pattern baseline established
- [ ] False positive rate understood and acceptable (< 5%)
- [ ] All features working correctly in observation mode
- [ ] Operations team familiar with monitoring tools

---

## ⚠️ **Phase 2: Rate Limit Mode**

### **Configuration**
```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable rate limiting only
    dry_run: false
    block_threshold: 1.0  # Still no blocking
    rate_limit_threshold: 0.7  # Conservative threshold

    # Rate limiting settings
    rate_limit_duration: 300  # 5 minutes
    rate_limit_requests: 20   # Generous limit

    # Continue monitoring
    log_level: "info"
    log_threats: true
    log_decisions: true

    # Tune thresholds based on Phase 1 observations
    anomaly_threshold: 0.75  # Slightly more sensitive
    graphql_max_depth: 15    # Tighten based on observations
    graphql_max_complexity: 3000
    grpc_max_message_size: 4194304  # 4MB

    # Enable notifications for rate limiting
    enable_notifications: true
    notification_channels: ["webhook", "log"]
```

### **Gradual Threshold Reduction**

**Week 1: Conservative**
```yaml
config:
  rate_limit_threshold: 0.8
  rate_limit_requests: 30
  rate_limit_duration: 300
```

**Week 2: Moderate**
```yaml
config:
  rate_limit_threshold: 0.7
  rate_limit_requests: 20
  rate_limit_duration: 300
```

**Week 3: Targeted**
```yaml
config:
  rate_limit_threshold: 0.6
  rate_limit_requests: 15
  rate_limit_duration: 300
```

### **Monitoring Rate Limiting Impact**
```bash
# Rate limiting effectiveness
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  rate_limited_requests: .rate_limited_requests,
  rate_limited_ips: .rate_limited_unique_ips,
  avg_rate_limit_duration: .avg_rate_limit_duration,
  top_rate_limited_patterns: .top_rate_limited_patterns
}'

# Business impact assessment
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  legitimate_traffic_affected: .false_positive_rate_limits,
  customer_complaints: .support_tickets_security_related,
  conversion_rate_impact: .conversion_rate_change_percent
}'
```

### **Rate Limiting Feedback Loop**
```bash
#!/bin/bash
# rate-limit-feedback.sh

# Check for false positives in rate limiting
check_false_positives() {
    echo "Checking for potential false positives..."

    # Look for rate-limited legitimate patterns
    curl -s http://localhost:8001/kong-guard-ai/rate-limited-patterns | jq -r '
        .patterns[] | select(.false_positive_likelihood > 0.3) |
        "Potential FP: \(.pattern) - \(.count) occurrences"
    '
}

# Adjust thresholds based on feedback
adjust_thresholds() {
    local false_positive_rate="$1"

    if (( $(echo "$false_positive_rate > 0.05" | bc -l) )); then
        echo "High false positive rate detected. Raising thresholds..."

        curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
             -d "config.rate_limit_threshold=0.75" \
             -d "config.rate_limit_requests=25"
    fi
}
```

### **Success Criteria for Phase 2**
- [ ] Rate limiting effectively reduces attack impact
- [ ] False positive rate for rate limiting < 3%
- [ ] No significant impact on legitimate user experience
- [ ] Operations team comfortable with incident response
- [ ] Monitoring and alerting systems validated

---

## 🛡️ **Phase 3: Enforcement Mode**

### **Configuration**
```yaml
plugins:
- name: kong-guard-ai
  config:
    # Full enforcement mode
    dry_run: false
    block_threshold: 0.8
    rate_limit_threshold: 0.6

    # Optimized settings based on previous phases
    anomaly_threshold: 0.7
    graphql_max_depth: 12
    graphql_max_complexity: 2000
    grpc_max_message_size: 4194304

    # Production logging
    log_level: "info"
    log_threats: true
    log_decisions: true
    log_requests: false

    # Full notification suite
    enable_notifications: true
    notification_channels: ["webhook", "slack"]
    notification_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

### **Gradual Enforcement Rollout**

**Week 1: High Confidence Threats Only**
```yaml
config:
  block_threshold: 0.9  # Only block obvious attacks
  rate_limit_threshold: 0.6
```

**Week 2: Moderate Threats**
```yaml
config:
  block_threshold: 0.85
  rate_limit_threshold: 0.6
```

**Week 3: Standard Production**
```yaml
config:
  block_threshold: 0.8
  rate_limit_threshold: 0.6
```

**Week 4+: Optimized**
```yaml
config:
  block_threshold: 0.75  # Based on environment tuning
  rate_limit_threshold: 0.55
```

### **Circuit Breaker Implementation**
```yaml
# Emergency circuit breaker configuration
config:
  # Auto-disable blocking if false positive rate too high
  auto_disable_threshold: 0.1  # 10% false positive rate
  auto_disable_duration: 300   # Disable for 5 minutes
  auto_disable_notification: true
```

---

## 🎯 **Environment-Specific Rollout Strategies**

### **Microservices Architecture**

**Service-by-Service Rollout**
```yaml
# Start with internal APIs (lower risk)
services:
- name: internal-api
  plugins:
  - name: kong-guard-ai
    config:
      block_threshold: 0.7  # More sensitive for internal

# Progress to public APIs
services:
- name: public-api
  plugins:
  - name: kong-guard-ai
    config:
      block_threshold: 0.8  # Conservative for public

# Finish with critical APIs
services:
- name: payment-api
  plugins:
  - name: kong-guard-ai
    config:
      block_threshold: 0.9  # Very conservative for critical
      enable_notifications: true
```

### **Multi-Environment Rollout**

**Development → Staging → Production**
```bash
# Development environment (aggressive testing)
export KONG_GUARD_CONFIG="dev-aggressive.yaml"
deploy_to_dev() {
    curl -X POST http://dev-kong:8001/plugins \
         -d @dev-aggressive.yaml
}

# Staging environment (production-like)
export KONG_GUARD_CONFIG="staging-conservative.yaml"
deploy_to_staging() {
    curl -X POST http://staging-kong:8001/plugins \
         -d @staging-conservative.yaml
}

# Production environment (validated settings)
export KONG_GUARD_CONFIG="production-tuned.yaml"
deploy_to_production() {
    # Only after successful staging validation
    curl -X POST http://prod-kong:8001/plugins \
         -d @production-tuned.yaml
}
```

### **Geographic Rollout**

```yaml
# Region-specific configurations
regions:
  us-east:
    config:
      block_threshold: 0.8
      blocked_countries: ["XX", "YY"]  # Higher risk regions

  eu-west:
    config:
      block_threshold: 0.75  # GDPR considerations
      log_level: "warn"      # Reduced logging for privacy

  asia-pacific:
    config:
      block_threshold: 0.85  # Different threat landscape
      enable_mesh_enricher: true  # K8s prevalent
```

---

## 📈 **Monitoring and Alerting**

### **Critical Alerts**

```yaml
# High-priority alerts
alerts:
  - name: "High False Positive Rate"
    condition: "false_positive_rate > 0.05"
    severity: "critical"
    action: "Auto-adjust thresholds"

  - name: "Performance Degradation"
    condition: "avg_latency > 50ms"
    severity: "warning"
    action: "Investigate bottlenecks"

  - name: "Attack Wave Detected"
    condition: "threats_per_minute > 100"
    severity: "info"
    action: "Monitor and document"
```

### **Rollout Health Dashboard**

```bash
# Key metrics for rollout health
rollout_health_check() {
    local phase="$1"

    echo "=== Kong Guard AI Rollout Health - Phase $phase ==="

    # Core health metrics
    curl -s http://localhost:8001/kong-guard-ai/health | jq '{
        status: .status,
        uptime: .uptime_hours,
        memory_usage: .memory_usage_mb,
        error_rate: .error_rate_percent
    }'

    # Rollout-specific metrics
    case "$phase" in
        "observe")
            curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
                traffic_baseline: .baseline_established,
                feature_coverage: .features_tested_percent,
                performance_impact: .latency_increase_percent
            }'
            ;;
        "rate-limit")
            curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
                rate_limited: .rate_limited_requests,
                false_positives: .false_positive_rate,
                user_impact: .user_complaints
            }'
            ;;
        "enforce")
            curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
                blocked_attacks: .blocked_requests,
                legitimate_blocked: .false_positive_blocks,
                security_improvement: .attack_reduction_percent
            }'
            ;;
    esac
}
```

---

## 🚨 **Incident Response During Rollout**

### **Incident Classification**

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| **P0** | Service outage, high false positive rate | 5 minutes | Immediate rollback |
| **P1** | Performance degradation, moderate false positives | 15 minutes | Threshold adjustment |
| **P2** | Feature malfunction, low false positives | 1 hour | Investigation and tuning |
| **P3** | Documentation issues, minor bugs | 24 hours | Standard bug fix process |

### **Emergency Procedures**

**Immediate Rollback**
```bash
#!/bin/bash
# emergency-rollback.sh

emergency_rollback() {
    echo "EMERGENCY: Rolling back Kong Guard AI"

    # 1. Switch to dry-run mode immediately
    curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
         -d "config.dry_run=true" \
         -d "config.block_threshold=1.0"

    # 2. Notify operations team
    curl -X POST "$SLACK_WEBHOOK_URL" \
         -d '{"text": "🚨 EMERGENCY: Kong Guard AI rolled back to observation mode"}'

    # 3. Log incident
    echo "$(date): Emergency rollback executed" >> /var/log/kong-guard-ai/incidents.log

    echo "Rollback completed. System in safe mode."
}

# Trigger conditions
check_emergency_conditions() {
    local false_positive_rate=$(curl -s http://localhost:8001/kong-guard-ai/metrics | jq .false_positive_rate)
    local error_rate=$(curl -s http://localhost:8001/kong-guard-ai/metrics | jq .error_rate)

    if (( $(echo "$false_positive_rate > 0.1" | bc -l) )) || (( $(echo "$error_rate > 0.05" | bc -l) )); then
        emergency_rollback
    fi
}
```

**Graceful Degradation**
```bash
# gradual-degrade.sh

graceful_degradation() {
    local severity="$1"

    case "$severity" in
        "high")
            # Raise thresholds significantly
            curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
                 -d "config.block_threshold=0.95" \
                 -d "config.rate_limit_threshold=0.8"
            ;;
        "medium")
            # Moderate threshold adjustment
            curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
                 -d "config.block_threshold=0.9" \
                 -d "config.rate_limit_threshold=0.75"
            ;;
        "low")
            # Minor tuning
            curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
                 -d "config.block_threshold=0.85"
            ;;
    esac
}
```

---

## 📋 **Rollout Checklist**

### **Pre-Rollout Preparation**
- [ ] **Environment Setup**
  - [ ] Kong Gateway properly configured
  - [ ] Monitoring stack deployed (Prometheus, Grafana)
  - [ ] Log aggregation configured (ELK/EFK stack)
  - [ ] Alert management system configured

- [ ] **Team Preparation**
  - [ ] Operations team trained on Kong Guard AI
  - [ ] Incident response procedures documented
  - [ ] Emergency contacts identified
  - [ ] Rollback procedures tested

- [ ] **Testing Validation**
  - [ ] Plugin tested in staging environment
  - [ ] Performance benchmarks established
  - [ ] Security test suite executed
  - [ ] Integration tests passed

### **Phase Checkpoints**

**Observe Phase**
- [ ] Traffic baseline established
- [ ] Performance impact measured (< 5ms)
- [ ] Feature functionality validated
- [ ] False positive patterns identified
- [ ] Team comfortable with monitoring tools

**Rate Limit Phase**
- [ ] Rate limiting effectiveness demonstrated
- [ ] False positive rate acceptable (< 3%)
- [ ] User experience impact minimal
- [ ] Threshold tuning validated
- [ ] Incident response procedures tested

**Enforce Phase**
- [ ] Blocking effectiveness demonstrated
- [ ] Security posture improved
- [ ] False positive rate minimal (< 1%)
- [ ] Performance within acceptable limits
- [ ] Full operational procedures validated

### **Post-Rollout Validation**
- [ ] Security metrics improved
- [ ] No regression in application performance
- [ ] Monitoring and alerting operational
- [ ] Documentation updated
- [ ] Team knowledge transfer completed
- [ ] Success metrics achieved

---

This comprehensive rollout guide provides a structured approach to safely deploying Kong Guard AI in production environments while minimizing risk and ensuring operational success.