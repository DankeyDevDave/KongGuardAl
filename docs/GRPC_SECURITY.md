# gRPC Security Guide
## Method-Level Protection and Performance Controls for gRPC APIs

### **Overview**

Kong Guard AI provides specialized security controls for gRPC APIs, offering method-level protection, message size validation, and performance-aware rate limiting. This feature automatically detects gRPC endpoints and applies sophisticated analysis to prevent resource exhaustion and malicious method invocations.

---

## **gRPC Security Challenges**

### **Method Abuse and Resource Exhaustion**

**High-Frequency Method Calls**
```protobuf
// Attacker repeatedly calls expensive methods
service UserService {
  rpc GenerateReport(ReportRequest) returns (ReportResponse); // Expensive operation
  rpc CalculateAnalytics(AnalyticsRequest) returns (AnalyticsResponse); // CPU intensive
}

// Attack pattern: Rapid fire requests
for i in range(10000):
    stub.GenerateReport(request) // DoS attempt
```

**Large Message Payloads**
```protobuf
message DataUpload {
  bytes payload = 1; // Potential for massive payloads
  repeated string items = 2; // Array bombing
}

// Attack: Send 100MB+ messages
request = DataUpload()
request.payload = b'A' * 100_000_000 // Memory exhaustion
```

**Method Enumeration**
```bash
# Attackers probe for available methods
grpcurl -plaintext server:9090 list
grpcurl -plaintext server:9090 list package.Service
grpcurl -plaintext server:9090 describe package.Service.Method
```

---

## **Configuration**

### **Basic Setup**
```yaml
plugins:
- name: kong-guard-ai
  config:
    enable_grpc_detection: true
    grpc_max_message_size: 4194304 # 4MB
    grpc_default_rate_limit: 100 # requests per minute
```

### **Advanced Configuration**
```yaml
plugins:
- name: kong-guard-ai
  config:
    enable_grpc_detection: true

    # Message size controls
    grpc_max_message_size: 4194304 # 4MB default
    grpc_check_request_size: true
    grpc_check_response_size: true

    # Method-specific rate limiting
    grpc_method_rate_limits:
      "user.UserService/GetUser": 1000 # High frequency allowed
      "user.UserService/CreateUser": 50 # Moderate frequency
      "admin.AdminService/DeleteAll": 1 # Very restrictive
      "report.ReportService/GenerateReport": 10 # Expensive operation

    # Performance controls
    grpc_analysis_timeout_ms: 50
    grpc_enable_reflection_blocking: true
    grpc_block_unknown_methods: false

    # Security features
    grpc_require_valid_proto: true
    grpc_log_method_calls: true
```

---

## **gRPC Detection and Analysis**

### **Automatic gRPC Detection**

Kong Guard AI detects gRPC traffic using:

1. **Content-Type headers**: `application/grpc`, `application/grpc+proto`
2. **HTTP/2 protocol**: gRPC requires HTTP/2
3. **Path patterns**: Method names in format `/package.Service/Method`
4. **Header patterns**: `grpc-*` headers, `:method POST`

### **Method Analysis**
```yaml
config:
  grpc_method_analysis:
    enabled: true
    track_frequency: true
    track_response_times: true
    detect_enumeration: true
```

**Detection Examples:**
```bash
# Normal gRPC call
POST /user.UserService/GetUser HTTP/2
Content-Type: application/grpc
grpc-encoding: gzip

# Detected as: service=user.UserService, method=GetUser
```

### **Message Size Analysis**
```yaml
config:
  grpc_size_analysis:
    max_request_size: 4194304 # 4MB
    max_response_size: 10485760 # 10MB
    warn_threshold: 1048576 # 1MB warning
```

---

## **Method-Level Rate Limiting**

### **Per-Method Configuration**
```yaml
config:
  grpc_method_rate_limits:
    # Format: "package.Service/Method": requests_per_minute
    "user.UserService/GetUser": 1000
    "user.UserService/ListUsers": 100
    "user.UserService/CreateUser": 50
    "user.UserService/UpdateUser": 100
    "user.UserService/DeleteUser": 20

    # Admin methods - very restrictive
    "admin.AdminService/ListAllUsers": 10
    "admin.AdminService/DeleteAllData": 1

    # Expensive operations
    "report.ReportService/GenerateMonthlyReport": 5
    "analytics.AnalyticsService/RunComplexQuery": 10
```

### **Dynamic Rate Limiting**
```yaml
config:
  grpc_dynamic_limits:
    enabled: true
    base_limit: 100 # Default for unlisted methods

    # Adjust limits based on response time
    slow_method_threshold_ms: 1000
    slow_method_limit_reduction: 0.5 # Reduce by 50%

    # Adjust based on error rates
    high_error_threshold: 0.1 # 10% error rate
    high_error_limit_reduction: 0.3 # Reduce by 30%
```

### **Rate Limiting Scope**
```yaml
config:
  grpc_rate_limit_scope:
    per_client_ip: true
    per_service: false
    per_method: true
    time_window_seconds: 60
```

---

## **Message Size Protection**

### **Request Size Validation**
```yaml
config:
  grpc_request_validation:
    max_message_size: 4194304 # 4MB
    max_field_count: 1000
    max_array_length: 10000
    max_string_length: 65536
```

### **Response Size Monitoring**
```yaml
config:
  grpc_response_monitoring:
    max_response_size: 10485760 # 10MB
    warn_on_large_response: true
    warn_threshold: 1048576 # 1MB
    track_response_sizes: true
```

### **Size-Based Blocking**
```protobuf
// Example: This would be blocked
message LargeUpload {
  bytes data = 1; // If > 4MB, blocked
  repeated string items = 2; // If > 10k items, blocked
}
```

**Configuration Example:**
```yaml
config:
  grpc_size_limits:
    "file.FileService/Upload": 52428800 # 50MB for file uploads
    "image.ImageService/ProcessImage": 20971520 # 20MB for images
    "data.DataService/BulkImport": 104857600 # 100MB for bulk data
```

---

## **Method Blocking Examples**

### **Reflection API Blocking**
```yaml
config:
  grpc_block_reflection: true
  grpc_reflection_methods:
    - "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
    - "grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
```

**Blocked Response:**
```json
{
  "code": 12,
  "message": "Method not available: reflection disabled for security",
  "details": "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo blocked by Kong Guard AI"
}
```

### **Administrative Method Protection**
```yaml
config:
  grpc_admin_methods:
    block_by_default: true
    allowed_methods:
      - "admin.AdminService/GetStatus" # Read-only allowed
    blocked_methods:
      - "admin.AdminService/DeleteAll"
      - "admin.AdminService/ResetDatabase"
      - "debug.DebugService/*" # Block entire debug service
```

### **Rate Limit Exceeded Response**
```json
{
  "code": 8,
  "message": "Rate limit exceeded for method",
  "details": "user.UserService/CreateUser limited to 50 requests per minute"
}
```

---

## **Monitoring and Metrics**

### **gRPC-Specific Metrics**
```bash
# Method call statistics
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '.grpc | {
  total_requests: .grpc_requests_total,
  methods_detected: .grpc_unique_methods,
  avg_message_size: .grpc_avg_message_size,
  blocked_requests: .grpc_requests_blocked
}'

# Rate limiting metrics
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '.grpc.rate_limiting | {
  rate_limited_requests: .requests_rate_limited,
  top_limited_methods: .most_limited_methods,
  current_rates: .current_request_rates
}'

# Performance metrics
curl -s http://localhost:8001/kong-guard-ai/metrics | jq '.grpc.performance | {
  avg_processing_time: .avg_grpc_analysis_time_ms,
  slowest_methods: .slowest_methods,
  largest_messages: .largest_message_sizes
}'
```

### **Method Performance Analysis**
```bash
# Top methods by frequency
curl -s http://localhost:8001/kong-guard-ai/grpc/methods/top-frequency | jq '.methods[] | {
  method: .name,
  requests_per_minute: .frequency,
  avg_response_time: .avg_duration_ms
}'

# Methods exceeding size limits
curl -s http://localhost:8001/kong-guard-ai/grpc/methods/large-messages | jq '.methods[] | {
  method: .name,
  avg_request_size: .avg_request_bytes,
  avg_response_size: .avg_response_bytes,
  max_size_seen: .max_size_bytes
}'
```

### **Real-Time Monitoring**
```bash
# Live method call monitoring
curl -s http://localhost:8001/kong-guard-ai/grpc/live-stats | jq '{
  active_connections: .active_grpc_connections,
  current_rps: .requests_per_second,
  active_methods: .currently_called_methods
}'
```

---

## **Performance Optimization**

### **Analysis Optimization**
```yaml
config:
  grpc_performance:
    analysis_timeout_ms: 50 # Quick analysis timeout
    cache_method_info: true # Cache method metadata
    cache_size_limits: true # Cache size calculations
    skip_body_analysis: false # Analyze message content

    # Selective analysis
    analyze_only_new_methods: false
    skip_known_safe_methods: true
```

### **Caching Strategy**
```yaml
config:
  grpc_caching:
    cache_method_metadata: true
    method_cache_ttl: 300 # 5 minutes
    size_limit_cache_ttl: 600 # 10 minutes
    rate_limit_cache_ttl: 60 # 1 minute
```

### **Selective Protection**
```yaml
# Apply gRPC protection only to specific services
routes:
- name: grpc-api-routes
  protocols: ["grpc", "grpcs"]
  paths: ["/user.", "/admin.", "/report."]
  plugins:
  - name: kong-guard-ai
    config:
      enable_grpc_detection: true
      grpc_method_rate_limits:
        "user.UserService/*": 1000
        "admin.AdminService/*": 10

- name: internal-grpc
  protocols: ["grpc"]
  paths: ["/internal."]
  plugins:
  - name: kong-guard-ai
    config:
      enable_grpc_detection: false # Skip protection for internal services
```

---

## **Advanced Features**

### **Service-Level Configuration**
```yaml
config:
  grpc_service_limits:
    "user.UserService":
      max_concurrent_requests: 1000
      max_requests_per_minute: 10000
      max_message_size: 1048576 # 1MB

    "admin.AdminService":
      max_concurrent_requests: 10
      max_requests_per_minute: 100
      max_message_size: 65536 # 64KB
      require_authentication: true
```

### **Client-Based Limits**
```yaml
config:
  grpc_client_limits:
    per_ip_limits:
      max_methods_per_minute: 100
      max_unique_methods: 50
      max_total_bytes: 10485760 # 10MB per minute

    suspicious_behavior:
      rapid_method_switching: 10 # Max 10 different methods per minute
      large_message_threshold: 5242880 # 5MB
      reflection_attempts: 0 # Block any reflection attempts
```

### **Health Check Integration**
```yaml
config:
  grpc_health_checks:
    enabled: true
    health_service_method: "grpc.health.v1.Health/Check"
    exempt_from_rate_limits: true
    monitor_health_responses: true
```

---

## **Security Best Practices**

### **Production Configuration**
```yaml
# Production-hardened gRPC protection
config:
  enable_grpc_detection: true

  # Conservative message sizes
  grpc_max_message_size: 1048576 # 1MB default
  grpc_check_request_size: true
  grpc_check_response_size: true

  # Security hardening
  grpc_block_reflection: true
  grpc_require_valid_proto: true
  grpc_block_unknown_methods: true

  # Rate limiting
  grpc_default_rate_limit: 100
  grpc_method_rate_limits:
    "admin.*": 10
    "debug.*": 0 # Block entirely
    "*.Delete*": 20
    "*.Create*": 50

  # Performance
  grpc_analysis_timeout_ms: 30
  grpc_log_method_calls: true
```

### **Development Configuration**
```yaml
# Development-friendly settings
config:
  enable_grpc_detection: true

  # Permissive limits
  grpc_max_message_size: 10485760 # 10MB
  grpc_default_rate_limit: 1000

  # Development features
  grpc_block_reflection: false # Allow reflection for development
  grpc_log_all_methods: true
  grpc_dry_run: true # Log only, don't block

  # Performance
  grpc_analysis_timeout_ms: 100
```

---

## **Incident Response**

### **Method Blocking Response**
```json
{
  "code": 7,
  "message": "Method access denied",
  "details": "admin.AdminService/DeleteAll blocked by security policy",
  "metadata": {
    "incident_id": "kg-ai-grpc-20250119-001",
    "timestamp": "2025-01-19T10:30:45Z",
    "reason": "administrative_method_blocked"
  }
}
```

### **Rate Limit Response**
```json
{
  "code": 8,
  "message": "Rate limit exceeded",
  "details": "Method user.UserService/CreateUser rate limited: 50 requests per minute",
  "metadata": {
    "rate_limit": {
      "limit": 50,
      "window": "1m",
      "current": 51,
      "reset_time": "2025-01-19T10:31:00Z"
    }
  }
}
```

### **Size Limit Response**
```json
{
  "code": 8,
  "message": "Message size exceeded",
  "details": "Request message size 5242880 bytes exceeds limit of 4194304 bytes",
  "metadata": {
    "size_limit": {
      "max_allowed": 4194304,
      "actual_size": 5242880,
      "method": "file.FileService/Upload"
    }
  }
}
```

---

## **Troubleshooting**

### **Common Issues**

**gRPC Detection Not Working**
```yaml
# Solution: Verify detection settings
config:
  enable_grpc_detection: true
  grpc_detection_headers:
    - "content-type: application/grpc"
    - "content-type: application/grpc+proto"
  grpc_detection_paths:
    - "*/.*" # Pattern for service/method paths
```

**Rate Limits Too Restrictive**
```yaml
# Solution: Adjust method-specific limits
config:
  grpc_method_rate_limits:
    "user.UserService/GetUser": 2000 # Increase from 1000
    "user.UserService/ListUsers": 500 # Increase from 100
```

**Performance Impact**
```yaml
# Solution: Optimize analysis settings
config:
  grpc_analysis_timeout_ms: 25 # Shorter timeout
  grpc_cache_method_info: true
  grpc_skip_body_analysis: true # For high-throughput services
```

### **Debug Mode**
```yaml
config:
  log_level: "debug"
  grpc_log_all_methods: true
  grpc_log_analysis_details: true
```

**Debug Output Example:**
```
[DEBUG] gRPC method detected: user.UserService/GetUser
[DEBUG] Method rate limit: 1000/min, current: 1
[DEBUG] Message size: 1024 bytes, limit: 4194304 bytes
[DEBUG] Analysis time: 5ms
```

---

## **Configuration Examples**

### **E-commerce API**
```yaml
config:
  enable_grpc_detection: true
  grpc_method_rate_limits:
    "product.ProductService/SearchProducts": 2000
    "product.ProductService/GetProduct": 5000
    "cart.CartService/AddItem": 500
    "cart.CartService/Checkout": 50
    "payment.PaymentService/ProcessPayment": 100
    "admin.ProductService/CreateProduct": 20
    "admin.ProductService/DeleteProduct": 10
```

### **Financial Services**
```yaml
config:
  enable_grpc_detection: true
  grpc_method_rate_limits:
    "account.AccountService/GetBalance": 1000
    "transaction.TransactionService/Transfer": 50
    "transaction.TransactionService/GetHistory": 200
    "admin.AdminService/*": 5
  grpc_require_valid_proto: true
  grpc_block_reflection: true
  grpc_max_message_size: 65536 # 64KB for financial data
```

### **Microservices Platform**
```yaml
config:
  enable_grpc_detection: true
  grpc_service_limits:
    "user.*": { max_requests_per_minute: 10000 }
    "auth.*": { max_requests_per_minute: 5000 }
    "data.*": { max_requests_per_minute: 1000 }
    "admin.*": { max_requests_per_minute: 100 }
  grpc_client_limits:
    per_ip_limits:
      max_methods_per_minute: 500
      max_unique_methods: 100
```

---

gRPC Security provides essential protection for modern microservices architectures, preventing method abuse and resource exhaustion while maintaining the high performance that makes gRPC valuable for service-to-service communication.