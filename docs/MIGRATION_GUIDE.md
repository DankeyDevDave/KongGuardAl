# Kong Guard AI Migration Guide
## Safe Upgrade Paths and Version Migration

### **Overview**

This guide provides step-by-step instructions for migrating between Kong Guard AI versions, including breaking changes, backward compatibility notes, and safe rollout strategies.

---

## **Version Overview**

| Version | Release Date | Key Features | Breaking Changes |
|---------|-------------|--------------|------------------|
| **v1.0.0** | 2024-11-20 | Basic threat detection, SQL injection, XSS | Initial release |
| **v2.0.0** | 2024-12-16 | AI integration, ML detection, TAXII/STIX | Configuration schema changes |
| **v3.0.0** | 2025-01-19 | GraphQL/gRPC, TLS fingerprinting, Mesh enrichment | New feature flags, schema updates |

---

## **Migration Paths**

### **v1.0 → v2.0 Migration**

#### **Breaking Changes**
- Plugin schema restructured for AI features
- New required dependencies (AI service)
- Database schema changes for learning data
- Log format modifications

#### **Migration Steps**

1. **Backup Current Configuration**
   ```bash
   # Export current plugin configuration
   curl -s http://localhost:8001/plugins | jq '.data[] | select(.name=="kong-guard-ai")' > kong-guard-ai-v1-config.json

   # Backup Kong database
   kong db backup kong-backup-v1.sql
   ```

2. **Update Plugin Files**
   ```bash
   # Stop Kong
   kong stop

   # Backup existing plugin
   cp -r /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai-v1-backup

   # Install new plugin version
   cp -r kong-plugin/kong/plugins/kong-guard-ai /usr/local/share/lua/5.1/kong/plugins/

   # Start Kong
   kong start
   ```

3. **Update Configuration Schema**
   ```yaml
   # v1.0 configuration
   plugins:
   - name: kong-guard-ai
     config:
       threat_threshold: 0.8 # DEPRECATED
       enable_sql_detection: true # DEPRECATED

   # v2.0 configuration
   plugins:
   - name: kong-guard-ai
     config:
       block_threshold: 0.8 # NEW
       rate_limit_threshold: 0.6 # NEW
       enable_ml_detection: true # NEW
       enable_ai_gateway: false # NEW - start disabled
   ```

4. **Gradual Feature Rollout**
   ```yaml
   # Phase 1: Basic migration
   config:
     block_threshold: 0.8
     rate_limit_threshold: 0.6
     enable_ml_detection: false # Keep disabled initially
     enable_ai_gateway: false # Keep disabled initially

   # Phase 2: Enable ML (after 1 week)
   config:
     enable_ml_detection: true
     anomaly_threshold: 0.8 # Start conservative

   # Phase 3: Enable AI Gateway (after 2 weeks)
   config:
     enable_ai_gateway: true
     ai_service_url: "http://ai-service:8000"
   ```

#### **Compatibility Notes**
- ** Backward Compatible**: Core threat detection patterns
- ** Backward Compatible**: Basic IP blocking functionality
- ** Breaking Change**: Configuration parameter names
- ** Breaking Change**: Log message format
- ** Breaking Change**: Admin API endpoints

---

### **v2.0 → v3.0 Migration**

#### **Breaking Changes**
- New protocol-specific configurations
- Enhanced schema validation
- Additional dependencies for TLS/Mesh features
- New metrics format

#### **Migration Steps**

1. **Pre-Migration Assessment**
   ```bash
   # Check current configuration compatibility
   curl -s http://localhost:8001/plugins | jq '.data[] | select(.name=="kong-guard-ai") | .config' > current-config.json

   # Validate against v3.0 schema
   kong config validate -c current-config.json
   ```

2. **Update Plugin with Backward Compatibility**
   ```yaml
   # Safe v3.0 configuration (all new features disabled)
   plugins:
   - name: kong-guard-ai
     config:
       # Existing v2.0 settings (unchanged)
       block_threshold: 0.8
       rate_limit_threshold: 0.6
       enable_ml_detection: true
       enable_ai_gateway: true

       # New v3.0 features (start disabled)
       enable_graphql_detection: false
       enable_grpc_detection: false
       enable_tls_fingerprints: false
       enable_taxii_ingestion: false
       enable_mesh_enricher: false
       normalize_url: false
       normalize_body: false
   ```

3. **Phased Feature Enablement**

   **Phase 1: Request Normalization (Week 1)**
   ```yaml
   config:
     normalize_url: true
     normalize_body: false # Start with URL only
     normalization_profile: "lenient"
   ```

   **Phase 2: Protocol-Specific Protection (Week 2-3)**
   ```yaml
   config:
     enable_graphql_detection: true
     graphql_max_depth: 15 # Start conservative
     graphql_max_complexity: 3000

     enable_grpc_detection: true
     grpc_max_message_size: 4194304
     grpc_rate_limit_per_method: 200 # Start permissive
   ```

   **Phase 3: Advanced Features (Week 4+)**
   ```yaml
   config:
     enable_tls_fingerprints: true
     enable_taxii_ingestion: true # If threat feeds available
     enable_mesh_enricher: true # If in K8s environment
   ```

#### **Compatibility Notes**
- ** Backward Compatible**: All v2.0 configurations work unchanged
- ** Backward Compatible**: API endpoints and response formats
- ** Backward Compatible**: Log formats (with new optional fields)
- ** New Features**: All new capabilities are opt-in via feature flags

---

## **Safe Rollout Strategies**

### **Blue-Green Deployment**

```bash
# 1. Deploy v3.0 to staging environment
docker-compose -f docker-compose-staging.yml up -d

# 2. Test with production traffic sample
curl -X POST http://staging:8001/plugins \
  -d "name=kong-guard-ai" \
  -d "config.dry_run=true"

# 3. Monitor for 24-48 hours
grep "kong-guard-ai" /var/log/kong/access.log | tail -1000

# 4. Switch production traffic
# Update load balancer to point to new environment
```

### **Canary Deployment**

```yaml
# Route-specific rollout
routes:
- name: test-route-v3
  paths: ["/api/v1/test"]
  plugins:
  - name: kong-guard-ai
    config:
      # v3.0 configuration with new features
      enable_graphql_detection: true
      enable_mesh_enricher: true

- name: production-routes
  paths: ["/api/v1/*"]
  plugins:
  - name: kong-guard-ai
    config:
      # v2.0 configuration (stable)
      block_threshold: 0.8
      enable_ml_detection: true
```

### **Progressive Feature Rollout**

```yaml
# Week 1: Observation mode
config:
  dry_run: true
  log_level: "debug"
  enable_graphql_detection: true
  enable_grpc_detection: true

# Week 2: Rate limiting only
config:
  dry_run: false
  block_threshold: 1.0 # Never block
  rate_limit_threshold: 0.6

# Week 3: Gradual enforcement
config:
  block_threshold: 0.9 # Very high threshold
  rate_limit_threshold: 0.6

# Week 4: Full enforcement
config:
  block_threshold: 0.8 # Production threshold
  rate_limit_threshold: 0.6
```

---

## **Configuration Migration Tools**

### **Automated Configuration Converter**

```bash
#!/bin/bash
# migrate-config.sh

convert_v1_to_v2() {
    local config_file="$1"

    # Replace deprecated parameters
    sed -i 's/threat_threshold/block_threshold/g' "$config_file"
    sed -i 's/enable_sql_detection/enable_ml_detection/g' "$config_file"

    # Add new required parameters
    echo " rate_limit_threshold: 0.6" >> "$config_file"
    echo " enable_ai_gateway: false" >> "$config_file"
}

convert_v2_to_v3() {
    local config_file="$1"

    # Add new feature flags (disabled by default)
    cat >> "$config_file" << EOF
  # New v3.0 features (disabled for safe migration)
  enable_graphql_detection: false
  enable_grpc_detection: false
  enable_tls_fingerprints: false
  enable_taxii_ingestion: false
  enable_mesh_enricher: false
  normalize_url: false
  normalize_body: false
EOF
}

# Usage
convert_v2_to_v3 "kong-guard-ai-config.yaml"
```

### **Configuration Validation**

```bash
# Validate configuration before applying
validate_config() {
    local config_file="$1"

    # Check required fields
    if ! grep -q "block_threshold" "$config_file"; then
        echo "ERROR: Missing required field: block_threshold"
        return 1
    fi

    # Check value ranges
    local threshold=$(grep "block_threshold:" "$config_file" | awk '{print $2}')
    if (( $(echo "$threshold > 1.0" | bc -l) )); then
        echo "ERROR: block_threshold must be <= 1.0"
        return 1
    fi

    echo "Configuration validation passed"
    return 0
}
```

---

## **Migration Monitoring**

### **Key Metrics to Monitor**

```bash
# Performance impact
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  total_requests: .total_requests,
  avg_latency: .avg_processing_latency,
  memory_usage: .memory_usage_mb
}'

# Threat detection rates
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  threats_detected: .threats_detected,
  false_positive_rate: .false_positive_rate,
  blocking_rate: .requests_blocked
}'

# Feature adoption
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '{
  graphql_requests: .graphql_requests,
  grpc_requests: .grpc_requests,
  mesh_requests: .mesh_requests,
  tls_fingerprinted: .tls_fingerprinted_requests
}'
```

### **Health Checks**

```bash
# Comprehensive health check script
#!/bin/bash

check_plugin_health() {
    echo "Checking Kong Guard AI health..."

    # Check plugin is loaded
    if ! kong plugins list | grep -q "kong-guard-ai"; then
        echo " Plugin not loaded"
        return 1
    fi

    # Check threat detection is working
    local response=$(curl -s -w "%{http_code}" "http://localhost:8000/test?q='; DROP TABLE users;" -o /dev/null)
    if [ "$response" != "403" ]; then
        echo " Threat detection not working (expected 403, got $response)"
        return 1
    fi

    # Check AI service (if enabled)
    if curl -s http://localhost:8001/kong-guard-ai/config | grep -q '"enable_ai_gateway": true'; then
        if ! curl -s http://ai-service:8000/health > /dev/null; then
            echo " AI service not responding"
            return 1
        fi
    fi

    echo " All health checks passed"
    return 0
}
```

---

## **Rollback Procedures**

### **Emergency Rollback**

```bash
# Immediate rollback script
#!/bin/bash

emergency_rollback() {
    echo "Performing emergency rollback..."

    # 1. Disable plugin immediately
    curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
         -d "enabled=false"

    # 2. Restore previous plugin version
    cp -r /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai-backup/* \
          /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/

    # 3. Reload Kong
    kong reload

    # 4. Re-enable with old configuration
    curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
         -d "enabled=true"

    echo "Rollback completed"
}
```

### **Graceful Rollback**

```yaml
# Gradual rollback process
# Phase 1: Disable new features
config:
  enable_graphql_detection: false
  enable_grpc_detection: false
  enable_tls_fingerprints: false
  enable_mesh_enricher: false

# Phase 2: Return to v2.0 configuration
config:
  block_threshold: 0.8
  rate_limit_threshold: 0.6
  enable_ml_detection: true
  enable_ai_gateway: true

# Phase 3: If needed, return to v1.0 basics
config:
  block_threshold: 0.8
  enable_ml_detection: false
  enable_ai_gateway: false
```

---

## **Troubleshooting Migration Issues**

### **Common Problems**

**Configuration Not Applied**
```bash
# Check configuration syntax
kong config validate

# Verify plugin configuration
curl http://localhost:8001/plugins/kong-guard-ai | jq .config

# Check Kong error logs
tail -f /var/log/kong/error.log | grep kong-guard-ai
```

**Performance Degradation**
```bash
# Identify performance bottlenecks
curl http://localhost:8001/kong-guard-ai/metrics | jq '{
  avg_latency: .avg_processing_latency,
  ai_service_latency: .ai_service_avg_latency,
  ml_processing_time: .ml_avg_processing_time
}'

# Disable heavy features temporarily
curl -X PATCH http://localhost:8001/plugins/kong-guard-ai \
     -d "config.enable_ai_gateway=false" \
     -d "config.normalize_body=false"
```

**Feature Not Working**
```bash
# Debug specific features
curl http://localhost:8001/kong-guard-ai/debug | jq '{
  graphql_detection: .features.graphql_enabled,
  grpc_detection: .features.grpc_enabled,
  tls_fingerprinting: .features.tls_enabled
}'

# Check feature dependencies
curl http://localhost:8001/kong-guard-ai/dependencies
```

---

## **Migration Checklist**

### **Pre-Migration**
- [ ] Backup current Kong configuration
- [ ] Backup Kong database
- [ ] Document current plugin settings
- [ ] Test migration in staging environment
- [ ] Prepare rollback procedures
- [ ] Schedule maintenance window

### **During Migration**
- [ ] Stop Kong gracefully
- [ ] Install new plugin version
- [ ] Update configuration with new schema
- [ ] Start Kong and verify plugin loads
- [ ] Test basic functionality
- [ ] Monitor error logs for issues

### **Post-Migration**
- [ ] Verify all routes are working
- [ ] Check threat detection is active
- [ ] Monitor performance metrics
- [ ] Enable new features gradually
- [ ] Update monitoring dashboards
- [ ] Train operations team on new features

### **Validation Tests**
- [ ] SQL injection still blocked
- [ ] XSS attacks still detected
- [ ] DDoS protection working
- [ ] New features respond correctly
- [ ] Performance within acceptable limits
- [ ] No false positives introduced

---

This migration guide provides comprehensive instructions for safely upgrading Kong Guard AI while minimizing risk and ensuring continuity of service.