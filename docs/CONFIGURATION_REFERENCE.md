# Kong Guard AI Configuration Reference
## Complete Guide to All Configuration Options

### 📋 **Overview**

This document provides comprehensive documentation for all Kong Guard AI configuration options, including default values, valid ranges, and practical use cases.

---

## 🎯 **Core Threat Detection Settings**

### **Threat Thresholds**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `block_threshold` | number | 0.8 | 0-1 | Threat score threshold for blocking requests |
| `rate_limit_threshold` | number | 0.6 | 0-1 | Threat score threshold for rate limiting |
| `ddos_rpm_threshold` | integer | 100 | 1+ | Requests per minute threshold for DDoS detection |

**Example:**
```yaml
config:
  block_threshold: 0.8
  rate_limit_threshold: 0.6
  ddos_rpm_threshold: 100
```

### **Operating Mode**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dry_run` | boolean | false | Enable dry-run mode (log only, no enforcement) |

**Example:**
```yaml
config:
  dry_run: true  # Test mode - log threats but don't block
```

---

## 🤖 **Machine Learning Configuration**

### **ML Detection Settings**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_ml_detection` | boolean | true | - | Enable machine learning-based detection |
| `anomaly_threshold` | number | 0.7 | 0-1 | Anomaly score threshold for ML detection |

**Example:**
```yaml
config:
  enable_ml_detection: true
  anomaly_threshold: 0.7
```

### **Learning and Feedback**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_learning` | boolean | true | - | Enable continuous learning from feedback |
| `learning_rate` | number | 0.001 | 0-1 | Learning rate for threshold adaptation |
| `feedback_endpoint` | string | "/kong-guard-ai/feedback" | - | Endpoint for operator feedback |

**Example:**
```yaml
config:
  enable_learning: true
  learning_rate: 0.001
  feedback_endpoint: "/kong-guard-ai/feedback"
```

---

## 🧠 **AI Gateway Integration**

### **AI Service Configuration**

| Parameter | Type | Default | Options | Description |
|-----------|------|---------|---------|-------------|
| `enable_ai_gateway` | boolean | false | - | Enable Kong AI Gateway integration |
| `ai_service_url` | string | "http://ai-service:8000" | - | URL of AI threat analysis service |
| `ai_model` | string | "claude-3-haiku" | claude-3-haiku, claude-3-sonnet, gpt-4, gpt-3.5-turbo, llama2 | AI model for analysis |
| `ai_temperature` | number | 0.1 | 0-1 | AI model temperature for consistency |

**Example:**
```yaml
config:
  enable_ai_gateway: true
  ai_service_url: "http://ai-service:8000"
  ai_model: "claude-3-haiku"
  ai_temperature: 0.1
```

---

## 📢 **Notifications Configuration**

### **Notification Settings**

| Parameter | Type | Default | Options | Description |
|-----------|------|---------|---------|-------------|
| `enable_notifications` | boolean | true | - | Enable threat notifications |
| `notification_url` | string | - | - | Webhook URL for notifications |
| `notification_channels` | array | ["webhook"] | webhook, slack, email, log | Notification channels to use |

**Example:**
```yaml
config:
  enable_notifications: true
  notification_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
  notification_channels: ["webhook", "slack", "log"]
```

---

## 🔄 **Response Actions**

### **Action Configuration**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `auto_block_duration` | integer | 3600 | Duration to block threats (seconds) |
| `rate_limit_duration` | integer | 300 | Duration for rate limiting (seconds) |
| `rate_limit_requests` | integer | 10 | Requests allowed during rate limit period |

**Example:**
```yaml
config:
  auto_block_duration: 3600  # 1 hour
  rate_limit_duration: 300   # 5 minutes
  rate_limit_requests: 10    # 10 requests per period
```

---

## 🏗️ **Admin API Integration**

### **Admin API Settings**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_admin_api` | boolean | true | Enable Admin API integration |
| `admin_api_url` | string | "http://localhost:8001" | Kong Admin API URL |

**Example:**
```yaml
config:
  enable_admin_api: true
  admin_api_url: "http://localhost:8001"
```

---

## 📝 **Logging and Monitoring**

### **Log Configuration**

| Parameter | Type | Default | Options | Description |
|-----------|------|---------|---------|-------------|
| `log_level` | string | "info" | debug, info, warn, error, critical | General logging level |
| `log_threats` | boolean | true | - | Log detected threats |
| `log_requests` | boolean | false | - | Log all requests (verbose) |
| `log_decisions` | boolean | true | - | Log blocking/rate-limiting decisions |
| `metrics_enabled` | boolean | true | - | Enable metrics collection |

**Example:**
```yaml
config:
  log_level: "info"
  log_threats: true
  log_requests: false
  log_decisions: true
  metrics_enabled: true
```

---

## 🔧 **Request Normalization**

### **Normalization Settings**

| Parameter | Type | Default | Options | Description |
|-----------|------|---------|---------|-------------|
| `normalize_url` | boolean | true | - | Enable URL canonicalization |
| `normalize_body` | boolean | false | - | Enable request body normalization |
| `normalization_profile` | string | "lenient" | lenient, strict | Normalization strictness profile |

**Example:**
```yaml
config:
  normalize_url: true
  normalize_body: false
  normalization_profile: "lenient"
```

**Normalization Profiles:**
- **lenient**: Basic normalization, preserves most original formatting
- **strict**: Aggressive normalization, may alter semantics

---

## 🕸️ **GraphQL Protection**

### **GraphQL Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_graphql_detection` | boolean | true | - | Enable GraphQL request detection |
| `graphql_max_depth` | integer | 12 | 1-1000 | Maximum allowed GraphQL selection set depth |
| `graphql_max_complexity` | integer | 2000 | 1-1000000 | Maximum allowed GraphQL complexity score |

**Example:**
```yaml
config:
  enable_graphql_detection: true
  graphql_max_depth: 12
  graphql_max_complexity: 2000
```

**Complexity Calculation:**
- Each field adds 1 to complexity
- Nested fields multiply complexity
- Arrays and connections add multipliers

---

## 🔌 **gRPC Protection**

### **gRPC Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_grpc_detection` | boolean | true | - | Enable gRPC request detection |
| `grpc_max_message_size` | integer | 4194304 | 1024-104857600 | Maximum gRPC message size (bytes) |
| `grpc_blocked_methods` | array | [] | - | Blocked gRPC service.method patterns |
| `grpc_rate_limit_per_method` | integer | 100 | 1-10000 | Rate limit per gRPC method per minute |

**Example:**
```yaml
config:
  enable_grpc_detection: true
  grpc_max_message_size: 4194304  # 4MB
  grpc_blocked_methods:
    - "admin.*"
    - "*.DeleteUser"
    - "dangerous.Service/*"
  grpc_rate_limit_per_method: 100
```

**Method Pattern Syntax:**
- `*` matches any string
- `admin.*` blocks all methods in admin service
- `*.DeleteUser` blocks DeleteUser method in any service

---

## 🔒 **TLS Fingerprinting**

### **TLS Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_tls_fingerprints` | boolean | false | - | Enable TLS fingerprinting detection |
| `tls_cache_ttl_seconds` | integer | 600 | 60-3600 | TTL for TLS fingerprint cache |
| `tls_rare_fp_min_ips` | integer | 5 | 1-100 | Min unique IPs before FP not rare |
| `tls_rate_limit_per_fp` | integer | 120 | 1-10000 | Rate limit per fingerprint per minute |

**Example:**
```yaml
config:
  enable_tls_fingerprints: true
  tls_cache_ttl_seconds: 600
  tls_rare_fp_min_ips: 5
  tls_rate_limit_per_fp: 120
```

### **TLS Header Mapping**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tls_header_map.ja3` | string | "X-JA3" | Header name for JA3 fingerprint |
| `tls_header_map.ja3s` | string | "X-JA3S" | Header name for JA3S fingerprint |
| `tls_header_map.ja4` | string | "X-JA4" | Header name for JA4 fingerprint |
| `tls_header_map.ja4s` | string | "X-JA4S" | Header name for JA4S fingerprint |
| `tls_header_map.tls_version` | string | "X-TLS-Version" | Header name for TLS version |
| `tls_header_map.tls_cipher` | string | "X-TLS-Cipher" | Header name for TLS cipher |
| `tls_header_map.sni` | string | "X-TLS-ServerName" | Header name for SNI |

### **TLS Scoring Weights**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `tls_score_weights.match_blocklist` | number | 0.7 | 0-1 | Score for blocklist matches |
| `tls_score_weights.match_allowlist` | number | -0.4 | -1-0 | Score for allowlist matches |
| `tls_score_weights.ua_mismatch` | number | 0.2 | 0-1 | Score for User-Agent mismatches |
| `tls_score_weights.rare_fingerprint` | number | 0.2 | 0-1 | Score for rare fingerprints |
| `tls_score_weights.velocity` | number | 0.3 | 0-1 | Score for high velocity |

### **TLS Lists**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tls_blocklist` | array | [] | Blocked TLS fingerprints (supports wildcards) |
| `tls_allowlist` | array | [] | Allowed TLS fingerprints (supports wildcards) |

**Example:**
```yaml
config:
  tls_header_map:
    ja3: "X-JA3"
    ja4: "X-JA4"
    tls_version: "X-TLS-Version"
  tls_score_weights:
    match_blocklist: 0.7
    ua_mismatch: 0.2
    rare_fingerprint: 0.2
  tls_blocklist:
    - "d4f0b8e4f8b4d4a4f8e4f8b4d4a4f8e4"  # Known malicious JA3
    - "malicious-tool-*"  # Pattern match
  tls_allowlist:
    - "chrome-*"  # Allow Chrome variants
```

---

## 🌐 **TAXII/STIX Threat Intelligence**

### **TAXII Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_taxii_ingestion` | boolean | false | - | Enable TAXII threat intelligence |
| `taxii_version` | string | "2.1" | 2.0, 2.1 | TAXII protocol version |
| `taxii_poll_interval_seconds` | integer | 300 | 60-86400 | Polling interval for feeds |
| `taxii_cache_ttl_seconds` | integer | 3600 | 300-604800 | Cache TTL for indicators |
| `taxii_max_objects_per_poll` | integer | 500 | 10-10000 | Max objects per poll |
| `taxii_http_timeout_ms` | integer | 2000 | 1000-30000 | HTTP timeout for requests |

**Example:**
```yaml
config:
  enable_taxii_ingestion: true
  taxii_version: "2.1"
  taxii_poll_interval_seconds: 300
  taxii_cache_ttl_seconds: 3600
```

### **TAXII Server Configuration**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | ✅ | TAXII server base URL |
| `collections` | array | ❌ | Collection IDs to poll |
| `auth_type` | string | ❌ | Authentication type (none, basic, bearer) |
| `username` | string | ❌ | Username for basic auth |
| `password` | string | ❌ | Password for basic auth |
| `token` | string | ❌ | Bearer token for auth |

**Example:**
```yaml
config:
  taxii_servers:
    - url: "https://threat-intel.example.com/taxii2"
      collections: ["indicators", "malware"]
      auth_type: "bearer"
      token: "your-api-token"
    - url: "https://public-feed.example.org/taxii2"
      collections: ["public-indicators"]
      auth_type: "none"
```

### **TAXII Scoring Weights**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `taxii_score_weights.ip_blocklist` | number | 0.9 | 0-1 | Score for IP blocklist matches |
| `taxii_score_weights.ip_allowlist` | number | -0.5 | -1-0 | Score for IP allowlist matches |
| `taxii_score_weights.domain_blocklist` | number | 0.8 | 0-1 | Score for domain blocklist matches |
| `taxii_score_weights.url_blocklist` | number | 0.8 | 0-1 | Score for URL blocklist matches |
| `taxii_score_weights.ja3_blocklist` | number | 0.7 | 0-1 | Score for JA3 blocklist matches |
| `taxii_score_weights.regex_match` | number | 0.6 | 0-1 | Score for regex pattern matches |

### **TAXII Advanced Settings**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `taxii_enable_dedup` | boolean | true | Enable deduplication of indicators |
| `taxii_tls_insecure_skip_verify` | boolean | false | Skip TLS verification (insecure) |
| `taxii_proxy_url` | string | - | HTTP proxy URL for connections |

### **TAXII Retry Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `taxii_retry_backoff_ms.initial` | integer | 200 | 100-5000 | Initial backoff delay (ms) |
| `taxii_retry_backoff_ms.max` | integer | 5000 | 1000-60000 | Maximum backoff delay (ms) |
| `taxii_retry_backoff_ms.factor` | number | 2 | 1.1-10 | Backoff multiplication factor |

**Example:**
```yaml
config:
  taxii_score_weights:
    ip_blocklist: 0.9
    domain_blocklist: 0.8
    url_blocklist: 0.8
  taxii_retry_backoff_ms:
    initial: 200
    max: 5000
    factor: 2
  taxii_enable_dedup: true
```

---

## 🕸️ **Kubernetes/Service Mesh Integration**

### **Mesh Configuration**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_mesh_enricher` | boolean | false | - | Enable mesh metadata enrichment |
| `mesh_cache_ttl_seconds` | integer | 300 | 60-3600 | TTL for mesh metadata cache |
| `mesh_pair_window_seconds` | integer | 3600 | 300-86400 | Time window for tracking service pairs |

**Example:**
```yaml
config:
  enable_mesh_enricher: true
  mesh_cache_ttl_seconds: 300
  mesh_pair_window_seconds: 3600
```

### **Mesh Header Mapping**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mesh_header_map.trace_id` | string | "X-Request-ID" | Header for trace/correlation ID |
| `mesh_header_map.namespace` | string | "X-K8s-Namespace" | Header for Kubernetes namespace |
| `mesh_header_map.workload` | string | "X-K8s-Workload" | Header for workload/deployment |
| `mesh_header_map.service` | string | "X-K8s-Service" | Header for service name |
| `mesh_header_map.pod` | string | "X-K8s-Pod" | Header for pod name |
| `mesh_header_map.zone` | string | "X-K8s-Zone" | Header for availability zone |
| `mesh_header_map.mesh_source` | string | "X-Mesh-Source" | Header for source service identity |

### **Mesh Risk Configuration**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mesh_risky_namespaces` | array | ["admin", "kube-system", "istio-system"] | High-risk namespaces |

### **Mesh Scoring Weights**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `mesh_score_weights.cross_namespace` | number | 0.3 | 0-1 | Score for cross-namespace traffic |
| `mesh_score_weights.risky_namespace` | number | 0.3 | 0-1 | Score for risky namespace involvement |
| `mesh_score_weights.unusual_pair` | number | 0.3 | 0-1 | Score for unusual service pairs |
| `mesh_score_weights.missing_headers` | number | 0.1 | 0-1 | Score for missing mesh headers |

**Example:**
```yaml
config:
  mesh_header_map:
    namespace: "X-K8s-Namespace"
    service: "X-K8s-Service"
    mesh_source: "X-Mesh-Source"
  mesh_risky_namespaces:
    - "admin"
    - "kube-system"
    - "istio-system"
    - "monitoring"
  mesh_score_weights:
    cross_namespace: 0.3
    risky_namespace: 0.8
    unusual_pair: 0.3
    missing_headers: 0.1
```

---

## 🔍 **Pattern Detection Rules**

### **SQL Injection Patterns**

| Parameter | Type | Default |
|-----------|------|---------|
| `sql_injection_patterns` | array | ["union%s+select", "drop%s+table", "insert%s+into", "select%s+from"] |

### **XSS Patterns**

| Parameter | Type | Default |
|-----------|------|---------|
| `xss_patterns` | array | ["<script", "javascript:", "onerror=", "onload="] |

**Example:**
```yaml
config:
  sql_injection_patterns:
    - "union%s+select"
    - "drop%s+table"
    - "insert%s+into"
    - "select%s+from"
    - "exec%s*\\("
  xss_patterns:
    - "<script"
    - "javascript:"
    - "onerror="
    - "onload="
    - "vbscript:"
```

---

## 🌍 **Geographic & IP Configuration**

### **IP Controls**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `blocked_countries` | array | [] | Blocked country codes (ISO 3166-1 alpha-2) |
| `blocked_ips` | array | [] | Blocked IP addresses and CIDR ranges |
| `whitelist_ips` | array | [] | Whitelisted IP addresses and CIDR ranges |

**Example:**
```yaml
config:
  blocked_countries: ["XX", "YY"]  # ISO country codes
  blocked_ips:
    - "192.168.1.100"
    - "10.0.0.0/8"
    - "2001:db8::/32"
  whitelist_ips:
    - "172.16.0.0/12"
    - "trusted.example.com"  # Resolved to IP
```

---

## ⚙️ **Complete Configuration Example**

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Core threat detection
    block_threshold: 0.8
    rate_limit_threshold: 0.6
    ddos_rpm_threshold: 100
    dry_run: false

    # Machine learning
    enable_ml_detection: true
    anomaly_threshold: 0.7
    enable_learning: true
    learning_rate: 0.001

    # AI Gateway
    enable_ai_gateway: true
    ai_service_url: "http://ai-service:8000"
    ai_model: "claude-3-haiku"
    ai_temperature: 0.1

    # Notifications
    enable_notifications: true
    notification_channels: ["webhook", "slack"]
    notification_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

    # Logging
    log_level: "info"
    log_threats: true
    log_decisions: true
    metrics_enabled: true

    # Request normalization
    normalize_url: true
    normalize_body: false
    normalization_profile: "lenient"

    # GraphQL protection
    enable_graphql_detection: true
    graphql_max_depth: 12
    graphql_max_complexity: 2000

    # gRPC security
    enable_grpc_detection: true
    grpc_max_message_size: 4194304
    grpc_blocked_methods: ["admin.*", "*.DeleteUser"]
    grpc_rate_limit_per_method: 100

    # TLS fingerprinting
    enable_tls_fingerprints: true
    tls_header_map:
      ja3: "X-JA3"
      ja4: "X-JA4"
    tls_score_weights:
      match_blocklist: 0.7
      ua_mismatch: 0.2

    # TAXII threat intelligence
    enable_taxii_ingestion: true
    taxii_version: "2.1"
    taxii_poll_interval_seconds: 300
    taxii_servers:
      - url: "https://threat-intel.example.com/taxii2"
        collections: ["indicators"]
        auth_type: "bearer"
        token: "your-token"

    # Mesh enrichment
    enable_mesh_enricher: true
    mesh_header_map:
      namespace: "X-K8s-Namespace"
      service: "X-K8s-Service"
      mesh_source: "X-Mesh-Source"
    mesh_risky_namespaces: ["admin", "kube-system"]
    mesh_score_weights:
      cross_namespace: 0.3
      risky_namespace: 0.8

    # Geographic controls
    blocked_countries: []
    blocked_ips: []
    whitelist_ips: ["10.0.0.0/8"]

    # Response actions
    auto_block_duration: 3600
    rate_limit_duration: 300
    rate_limit_requests: 10
```

---

## 🎯 **Use Case Configurations**

### **High Security Environment**
```yaml
config:
  block_threshold: 0.6          # Lower threshold
  enable_tls_fingerprints: true
  enable_mesh_enricher: true
  enable_taxii_ingestion: true
  normalization_profile: "strict"
```

### **Performance Optimized**
```yaml
config:
  enable_ml_detection: false    # Disable ML for speed
  enable_ai_gateway: false      # No AI analysis
  normalize_body: false         # Skip body normalization
  log_requests: false           # Reduce logging
```

### **Development Environment**
```yaml
config:
  dry_run: true                 # Log only, don't block
  log_level: "debug"           # Verbose logging
  enable_learning: false       # No learning
  block_threshold: 0.9         # High threshold
```

This configuration reference provides complete documentation for all Kong Guard AI options with practical examples for different deployment scenarios.