# Kong Guard AI Configuration Examples
## Real-World Use Cases and Production Configurations

### **Overview**

This document provides practical configuration examples for Kong Guard AI across different industries, deployment scenarios, and security requirements. Each example includes complete configurations, monitoring setups, and operational considerations.

---

## **Industry-Specific Configurations**

### **E-Commerce Platform**

Complete protection for online retail with payment processing and user data.

```yaml
# E-commerce Configuration
plugins:
- name: kong-guard-ai
  config:
    # Core Protection
    block_threshold: 0.8
    rate_limit_threshold: 0.6
    ddos_rpm_threshold: 200

    # E-commerce specific patterns
    sql_injection_patterns:
      - "union.*select.*from.*users"
      - "drop.*table.*orders"
      - "select.*password.*from"
      - "update.*users.*set.*password"

    # Payment protection
    credit_card_patterns:
      - "4[0-9]{12}(?:[0-9]{3})?" # Visa
      - "5[1-5][0-9]{14}" # Mastercard
      - "3[47][0-9]{13}" # Amex

    # Protocol-specific protection
    enable_graphql_detection: true
    graphql_max_depth: 8 # Conservative for product catalog
    graphql_max_complexity: 1500

    # Checkout flow protection
    grpc_method_rate_limits:
      "payment.PaymentService/ProcessPayment": 10
      "cart.CartService/Checkout": 20
      "inventory.InventoryService/ReserveItems": 50
      "user.UserService/CreateAccount": 30

    # Request normalization
    normalize_url: true
    normalize_body: true
    max_body_size_for_normalization: 524288 # 512KB

    # Customer behavior tracking
    enable_mesh_enricher: true
    mesh_service_pairs:
      "web-frontend->product-api": { baseline_rpm: 1000, suspicious_multiplier: 3.0 }
      "mobile-app->user-api": { baseline_rpm: 500, suspicious_multiplier: 4.0 }
      "checkout->payment-api": { baseline_rpm: 50, suspicious_multiplier: 10.0 }

    # Threat intelligence
    enable_taxii_ingestion: true
    taxii_servers:
    - url: "https://threat-intel.retail-security.com/taxii2"
      collections: ["retail-threats", "payment-fraud"]
      auth_type: "api_key"
      api_key: "${RETAIL_THREAT_INTEL_KEY}"

    # Seasonal adjustments
    adaptive_thresholds:
      black_friday_mode:
        ddos_rpm_threshold: 1000
        rate_limit_threshold: 0.8
      normal_mode:
        ddos_rpm_threshold: 200
        rate_limit_threshold: 0.6

    # Customer data protection
    pii_detection_patterns:
      - "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b" # SSN
      - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b" # Email

    # Monitoring
    log_level: "info"
    enable_notifications: true
    notification_url: "${SLACK_WEBHOOK_URL}"
```

---

### **Financial Services API**

High-security configuration for banking and financial applications.

```yaml
# Financial Services Configuration
plugins:
- name: kong-guard-ai
  config:
    # Strict security thresholds
    block_threshold: 0.7
    rate_limit_threshold: 0.5
    ddos_rpm_threshold: 50

    # Financial-specific protection
    enable_ml_detection: true
    anomaly_threshold: 0.6

    # Account protection patterns
    account_protection:
      max_login_attempts: 3
      account_lockout_duration: 1800 # 30 minutes
      suspicious_transfer_threshold: 10000

    # gRPC service protection
    enable_grpc_detection: true
    grpc_method_rate_limits:
      "account.AccountService/GetBalance": 100
      "transaction.TransactionService/Transfer": 5
      "transaction.TransactionService/GetHistory": 50
      "admin.AdminService/*": 2

    grpc_max_message_size: 65536 # 64KB limit
    grpc_block_reflection: true
    grpc_require_valid_proto: true

    # TLS fingerprinting for fraud detection
    enable_tls_fingerprints: true
    tls_header_map:
      ja3: "X-JA3-Fingerprint"
      ja4: "X-JA4-Fingerprint"

    tls_blocklist:
      - "e7d705a3286e19ea42f587b344ee6865" # Known fraud tools
      - "suspicious_client_*"

    tls_rate_limit_per_fp: 20 # Very restrictive

    # Request normalization (strict)
    normalize_url: true
    normalize_body: true
    normalization_profile: "strict"

    # Compliance logging
    enable_audit_logging: true
    audit_sensitive_fields:
      - "account_number"
      - "routing_number"
      - "transaction_amount"

    # Geographic restrictions
    geo_blocking:
      blocked_countries: ["XX", "YY"] # High-risk countries
      allowed_countries: ["US", "CA", "GB"]

    # Advanced threat detection
    enable_taxii_ingestion: true
    taxii_servers:
    - url: "https://financial-crimes.gov/taxii2"
      collections: ["financial-threats", "fraud-indicators"]
      auth_type: "certificate"
      cert_path: "/certs/fintech-threat-intel.pem"

    # Real-time monitoring
    enable_real_time_alerting: true
    alert_thresholds:
      failed_logins_per_minute: 10
      large_transfer_amount: 50000
      unusual_api_usage: 200

    log_level: "debug" # Full audit trail
    metrics_enabled: true
```

---

### **Healthcare API (HIPAA Compliant)**

Privacy-focused configuration for healthcare data protection.

```yaml
# Healthcare Configuration
plugins:
- name: kong-guard-ai
  config:
    # HIPAA-compliant settings
    block_threshold: 0.75
    rate_limit_threshold: 0.6
    ddos_rpm_threshold: 100

    # Patient data protection
    phi_protection:
      enabled: true
      detect_medical_record_numbers: true
      detect_patient_ids: true
      mask_sensitive_data: true

    # Healthcare-specific patterns
    healthcare_patterns:
      medical_record_injection:
        - "select.*from.*patients"
        - "update.*medical_records"
        - "delete.*from.*prescriptions"

      phi_exposure:
        - "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b" # SSN
        - "\\b[0-9]{10}\\b" # Medical Record Number

    # API-specific protection
    enable_graphql_detection: true
    graphql_max_depth: 10
    graphql_operation_limits:
      query: { max_depth: 10, max_complexity: 2000 }
      mutation: { max_depth: 6, max_complexity: 1000 }

    # Microservices protection
    grpc_method_rate_limits:
      "patient.PatientService/GetRecord": 50
      "prescription.PrescriptionService/Create": 20
      "billing.BillingService/ProcessClaim": 30

    # Compliance features
    audit_trail:
      enabled: true
      include_request_body: false # Privacy protection
      include_response_body: false
      track_data_access: true

    # Access control integration
    enable_mesh_enricher: true
    mesh_access_control:
      require_service_identity: true
      validate_rbac_headers: true

    # Data encryption verification
    require_tls: true
    min_tls_version: "1.2"

    # Request sanitization
    normalize_url: true
    normalize_body: false # Preserve medical data format

    # Privacy-preserving monitoring
    privacy_mode: true
    log_level: "warn" # Minimal logging for privacy
    anonymize_logs: true

    # Compliance reporting
    enable_compliance_reports: true
    report_schedule: "daily"

    notification_url: "${SECURITY_TEAM_WEBHOOK}"
```

---

## **Deployment Scenarios**

### **Multi-Region Global API**

Configuration for globally distributed APIs with regional compliance.

```yaml
# Global Multi-Region Configuration
plugins:
- name: kong-guard-ai
  config:
    # Base configuration
    block_threshold: 0.8
    rate_limit_threshold: 0.65

    # Regional adaptations
    regional_settings:
      us_east:
        ddos_rpm_threshold: 500
        enable_strict_compliance: true

      eu_west:
        ddos_rpm_threshold: 300
        gdpr_mode: true
        data_residency: "eu"

      asia_pacific:
        ddos_rpm_threshold: 200
        localization_required: true

    # Global threat intelligence
    enable_taxii_ingestion: true
    taxii_servers:
    - url: "https://global-threat-intel.example.com/taxii2"
      collections: ["global-threats", "regional-indicators"]
      region_filter: "${AWS_REGION}"

    # Cross-region correlation
    enable_global_correlation: true
    correlation_window: 300 # 5 minutes

    # Protocol support
    enable_graphql_detection: true
    enable_grpc_detection: true

    # Performance optimization
    cache_threat_intel: true
    cache_ttl: 600 # 10 minutes

    # Regional monitoring
    metrics_by_region: true
    regional_dashboards: true
```

---

### **Kubernetes/Istio Service Mesh**

Complete configuration for cloud-native microservices.

```yaml
# Kubernetes/Istio Configuration
plugins:
- name: kong-guard-ai
  config:
    # Service mesh integration
    enable_mesh_enricher: true
    mesh_header_map:
      source_service: "x-envoy-original-src-service"
      dest_service: "x-envoy-destination-service"
      namespace: "x-envoy-namespace"
      cluster: "x-envoy-cluster"
      source_workload: "x-workload-name"
      trace_id: "x-trace-id"

    # Service-to-service security
    mesh_service_pairs:
      "frontend->backend":
        baseline_rpm: 1000
        suspicious_multiplier: 3.0
        allowed_namespaces: ["production", "staging"]

      "api-gateway->auth-service":
        baseline_rpm: 500
        suspicious_multiplier: 5.0
        required_headers: ["authorization"]

      "data-processor->database":
        baseline_rpm: 200
        suspicious_multiplier: 2.0
        max_concurrent: 50

    # Cross-namespace anomaly detection
    cross_namespace_analysis:
      enabled: true
      suspicious_cross_ns_threshold: 10
      blocked_namespace_patterns:
        - "test-*"
        - "debug-*"

    # Container-aware threat detection
    container_security:
      detect_escape_attempts: true
      monitor_privileged_containers: true
      validate_service_accounts: true

    # Cloud-native protocols
    enable_grpc_detection: true
    grpc_service_discovery: true
    grpc_namespace_isolation: true

    # Kubernetes-specific patterns
    k8s_attack_patterns:
      - "kubectl.*exec"
      - "docker.*run.*privileged"
      - "crictl.*exec"

    # Observability integration
    metrics_labels:
      - "source_namespace"
      - "destination_service"
      - "workload_name"
      - "cluster_name"

    # Performance in mesh
    mesh_optimization:
      cache_service_metadata: true
      batch_mesh_updates: true
      async_threat_analysis: true

    log_level: "info"
    structured_logging: true
```

---

### **Edge/CDN Integration**

Configuration for edge computing and CDN scenarios.

```yaml
# Edge/CDN Configuration
plugins:
- name: kong-guard-ai
  config:
    # Edge-optimized settings
    block_threshold: 0.85
    rate_limit_threshold: 0.7

    # High-volume handling
    ddos_rpm_threshold: 2000
    burst_capacity: 5000

    # Geographic distribution
    geo_aware_blocking: true
    edge_locations:
      - region: "us-west"
        pop: "seattle"
        local_cache_size: 10000

      - region: "eu-central"
        pop: "frankfurt"
        local_cache_size: 8000

    # CDN-specific threats
    cdn_attack_patterns:
      cache_poisoning:
        - "cache-control.*no-cache.*max-age=0"
        - "pragma.*no-cache"

      bandwidth_exhaustion:
        - "range.*bytes=0-99999999"
        - "accept-encoding.*,.*,.*,.*" # Compression bombing

    # Fast path processing
    enable_fast_path: true
    fast_path_rules:
      - pattern: "/static/*"
        action: "allow"

      - pattern: "/health"
        action: "allow"

      - pattern: "/api/v1/*"
        action: "analyze"

    # Edge caching
    edge_threat_cache:
      enabled: true
      cache_size: 50000
      ttl: 300

    # Minimal latency processing
    processing_timeout_ms: 10
    enable_ml_detection: false # Too slow for edge

    # Basic normalization only
    normalize_url: true
    normalize_body: false

    # Edge monitoring
    edge_metrics: true
    real_time_dashboards: true

    log_level: "warn" # Minimal logging at edge
```

---

## **Development and Testing**

### **Development Environment**

Safe configuration for development with comprehensive logging.

```yaml
# Development Configuration
plugins:
- name: kong-guard-ai
  config:
    # Permissive thresholds
    block_threshold: 0.95
    rate_limit_threshold: 0.9
    ddos_rpm_threshold: 1000

    # Development mode
    dry_run: true # Log only, no blocking
    debug_mode: true

    # Full feature testing
    enable_graphql_detection: true
    graphql_max_depth: 20
    graphql_max_complexity: 10000

    enable_grpc_detection: true
    grpc_max_message_size: 10485760 # 10MB
    grpc_block_reflection: false # Allow for testing

    # Comprehensive normalization
    normalize_url: true
    normalize_body: true
    normalization_profile: "lenient"

    # Full TLS analysis
    enable_tls_fingerprints: true
    tls_log_all_fingerprints: true

    # Development threat intel (sandboxed)
    enable_taxii_ingestion: false # Disable in dev

    # Verbose logging
    log_level: "debug"
    log_all_requests: true
    log_threat_analysis: true

    # Development metrics
    detailed_metrics: true
    metrics_export_interval: 30

    # Testing helpers
    test_mode_headers:
      - "X-Test-Attack-Type"
      - "X-Test-Expected-Score"

    # Performance testing
    load_test_mode: false
    benchmark_mode: false
```

---

### **Staging Environment**

Production-like configuration with enhanced monitoring.

```yaml
# Staging Configuration
plugins:
- name: kong-guard-ai
  config:
    # Production-like thresholds
    block_threshold: 0.8
    rate_limit_threshold: 0.6
    ddos_rpm_threshold: 200

    # Staging-specific settings
    dry_run: false
    staging_mode: true

    # Full feature validation
    enable_graphql_detection: true
    graphql_max_depth: 12
    graphql_max_complexity: 2000

    enable_grpc_detection: true
    grpc_max_message_size: 4194304

    # Request normalization testing
    normalize_url: true
    normalize_body: true
    normalization_profile: "strict"

    # TLS testing
    enable_tls_fingerprints: true

    # Staging threat intel
    enable_taxii_ingestion: true
    taxii_servers:
    - url: "https://staging-threat-intel.example.com/taxii2"
      collections: ["test-indicators"]

    # Enhanced monitoring
    log_level: "info"
    enable_detailed_metrics: true

    # Staging notifications
    enable_notifications: true
    notification_url: "${STAGING_WEBHOOK_URL}"

    # Load testing support
    load_test_exemptions:
      - ip: "10.0.100.0/24" # Load test subnet
      - user_agent: "LoadTestAgent/*"
```

---

## **Operational Configurations**

### **High-Availability Setup**

Configuration for mission-critical applications.

```yaml
# High-Availability Configuration
plugins:
- name: kong-guard-ai
  config:
    # Reliable thresholds
    block_threshold: 0.8
    rate_limit_threshold: 0.6

    # HA-specific settings
    enable_ha_mode: true
    node_coordination: true

    # Distributed caching
    distributed_cache:
      enabled: true
      backend: "redis"
      cluster_nodes:
        - "redis-1:6379"
        - "redis-2:6379"
        - "redis-3:6379"

    # Failover configuration
    failover_settings:
      health_check_interval: 30
      unhealthy_threshold: 3
      fallback_mode: "permissive"

    # Data replication
    threat_intel_replication:
      enabled: true
      sync_interval: 60
      conflict_resolution: "latest_wins"

    # Performance optimization
    async_processing: true
    batch_operations: true
    connection_pooling: true

    # Monitoring for HA
    cluster_metrics: true
    node_health_metrics: true
    replication_lag_monitoring: true

    # Alerting
    ha_alerting:
      node_failure_alert: true
      replication_lag_alert: 300 # 5 minutes
      cluster_split_brain_alert: true
```

---

### **Zero-Downtime Updates**

Configuration supporting seamless updates.

```yaml
# Zero-Downtime Configuration
plugins:
- name: kong-guard-ai
  config:
    # Version compatibility
    version: "3.0.0"
    backward_compatibility: true

    # Rolling update support
    rolling_update_mode: true
    config_versioning: true

    # Graceful degradation
    graceful_degradation:
      enabled: true
      fallback_rules:
        - condition: "ml_service_unavailable"
          action: "use_static_rules"

        - condition: "threat_intel_stale"
          action: "reduce_confidence"

    # Configuration hot-reload
    hot_reload: true
    config_validation: true

    # State preservation
    preserve_learning_data: true
    migrate_threat_cache: true

    # Update monitoring
    update_metrics: true
    rollback_capability: true

    # Feature flags for gradual rollout
    feature_flags:
      new_ml_model: false
      enhanced_normalization: false
      experimental_detection: false
```

---

This comprehensive set of examples demonstrates Kong Guard AI's flexibility across different industries, deployment scenarios, and operational requirements. Each configuration can be adapted based on specific security needs, compliance requirements, and performance constraints.