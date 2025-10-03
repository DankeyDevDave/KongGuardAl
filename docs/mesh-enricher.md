# Kubernetes/Service Mesh Metadata Enricher

The Kong Guard AI mesh enricher adds powerful Kubernetes and service mesh awareness to threat detection by analyzing trusted metadata headers from Istio, Envoy, or other service mesh proxies.

## Overview

The mesh enricher extracts and analyzes metadata about service-to-service communications to detect:

- **Cross-namespace anomalies**: Unusual communication patterns between namespaces
- **Risky namespace access**: Traffic involving high-privilege or system namespaces
- **Unusual service pairs**: First-time or rare service-to-service communications
- **Missing mesh headers**: Requests lacking expected service mesh metadata (low trust)

## Configuration

### Enabling the Feature

```yaml
plugins:
- name: kong-guard-ai
  config:
    enable_mesh_enricher: true
```

### Header Mapping

Configure which HTTP headers contain mesh metadata:

```yaml
mesh_header_map:
  trace_id: "X-Request-ID" # Trace/correlation ID
  namespace: "X-K8s-Namespace" # Kubernetes namespace
  workload: "X-K8s-Workload" # Workload/deployment name
  service: "X-K8s-Service" # Service name
  pod: "X-K8s-Pod" # Pod name
  zone: "X-K8s-Zone" # Availability zone
  mesh_source: "X-Mesh-Source" # Source service identity
```

### Risk Configuration

Define high-risk namespaces that trigger alerts:

```yaml
mesh_risky_namespaces:
  - "admin"
  - "kube-system"
  - "istio-system"
  - "monitoring"
```

### Scoring Weights

Adjust threat scoring for different mesh scenarios:

```yaml
mesh_score_weights:
  cross_namespace: 0.3 # Cross-namespace communication
  risky_namespace: 0.3 # Risky namespace involvement
  unusual_pair: 0.3 # Unusual service communication pair
  missing_headers: 0.1 # Missing mesh metadata
```

### Cache and Tracking

Configure caching and historical tracking:

```yaml
mesh_cache_ttl_seconds: 300 # Metadata cache TTL
mesh_pair_window_seconds: 3600 # Service pair tracking window
```

## Header Contract

### Required Headers

For effective threat detection, your service mesh should inject these headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-K8s-Namespace` | Source namespace | `production` |
| `X-K8s-Service` | Source service name | `user-service` |
| `X-Mesh-Source` | Full source identity | `frontend-service.production` |

### Optional Headers

Additional headers for enhanced analysis:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Request-ID` | Trace correlation ID | `req-12345-abcde` |
| `X-K8s-Workload` | Workload/deployment | `user-deployment-v2` |
| `X-K8s-Pod` | Source pod name | `user-pod-abc123` |
| `X-K8s-Zone` | Availability zone | `us-west-2a` |

## Istio Configuration

### Envoy Filter Example

Configure Istio to inject mesh metadata headers:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: mesh-metadata-headers
  namespace: istio-system
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.lua
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
          inline_code: |
            function envoy_on_request(request_handle)
              -- Extract metadata from Envoy's node metadata
              local headers = request_handle:headers()

              -- Add namespace header
              local namespace = os.getenv("POD_NAMESPACE")
              if namespace then
                headers:add("X-K8s-Namespace", namespace)
              end

              -- Add service header
              local service = os.getenv("SERVICE_NAME")
              if service then
                headers:add("X-K8s-Service", service)
              end

              -- Add workload header
              local workload = os.getenv("WORKLOAD_NAME")
              if workload then
                headers:add("X-K8s-Workload", workload)
              end

              -- Add pod header
              local pod = os.getenv("POD_NAME")
              if pod then
                headers:add("X-K8s-Pod", pod)
              end

              -- Add zone header
              local zone = os.getenv("NODE_ZONE")
              if zone then
                headers:add("X-K8s-Zone", zone)
              end

              -- Add source identity
              if namespace and service then
                headers:add("X-Mesh-Source", service .. "." .. namespace)
              end
            end
```

### Service Account Configuration

Ensure services have proper RBAC permissions for metadata access:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mesh-aware-service
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mesh-metadata-reader
rules:
- apiGroups: [""]
  resources: ["services", "pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: mesh-metadata-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: mesh-metadata-reader
subjects:
- kind: ServiceAccount
  name: mesh-aware-service
  namespace: production
```

## Threat Detection Scenarios

### Cross-Namespace Communication

**Scenario**: Service in `frontend` namespace calling service in `backend` namespace.

**Detection**: When source and destination namespaces differ.

**Response**: Elevated threat score, increased monitoring.

**Example Headers**:
```
X-K8s-Namespace: frontend
X-K8s-Service: web-app
X-Mesh-Source: web-app.frontend
# Destination: api-service.backend (from Kong route config)
```

### Risky Namespace Access

**Scenario**: Service attempting to access `kube-system` namespace.

**Detection**: Either source or destination namespace is in risky list.

**Response**: High threat score, potential blocking.

**Example Headers**:
```
X-K8s-Namespace: production
X-K8s-Service: user-service
X-Mesh-Source: user-service.production
# Attempting to access: admin-api.kube-system
```

### Unusual Service Pairs

**Scenario**: First-time communication between two services.

**Detection**: Service pair has low historical count (< 5 occurrences).

**Response**: Moderate threat score, enhanced logging.

**Example**: New microservice calling established database service.

### Missing Mesh Headers

**Scenario**: Request lacks expected service mesh metadata.

**Detection**: Critical headers (namespace, service) are missing.

**Response**: Low threat score, trust reduction.

**Implications**: Request may be:
- From external client (expected)
- From compromised service (concerning)
- From misconfigured service (needs attention)

## Metrics and Monitoring

### Available Metrics

The mesh enricher tracks these metrics in Kong's shared memory:

| Metric | Description |
|--------|-------------|
| `mesh_requests` | Total requests with mesh metadata |
| `non_mesh_requests` | Total requests without mesh metadata |
| `mesh_threats` | Mesh-related threats detected |
| `mesh_cross_namespace_requests` | Cross-namespace communications |
| `mesh_cross_namespace_threats` | Cross-namespace threats |
| `mesh_risky_namespace_threats` | Risky namespace access attempts |
| `mesh_unusual_pair_threats` | Unusual service pair communications |
| `mesh_missing_headers_threats` | Requests with missing headers |

### Per-Namespace/Service Metrics

Dynamic metrics with 1-hour TTL:

- `mesh_namespace:{namespace}` - Requests per namespace
- `mesh_service:{service}` - Requests per service

### Grafana Dashboard Queries

Example Prometheus/Grafana queries for mesh metrics:

```promql
# Cross-namespace communication rate
rate(kong_shared_dict_mesh_cross_namespace_requests[5m])

# Risky namespace access attempts
rate(kong_shared_dict_mesh_risky_namespace_threats[5m])

# Service communication diversity
count by (namespace) (kong_shared_dict_mesh_service)
```

## Operational Considerations

### Performance Impact

- **CPU**: Minimal overhead for header parsing and analysis
- **Memory**: Service pair tracking uses shared memory with TTL
- **Latency**: < 1ms additional processing time per request

### Trust Boundary

The mesh enricher assumes headers are **trusted** and injected by:
- Istio/Envoy sidecar proxies
- Kubernetes ingress controllers
- Service mesh control planes

**Security Note**: Never rely on client-provided mesh headers for security decisions.

### Rollout Strategy

1. **Phase 1**: Enable in monitoring mode (`dry_run: true`)
2. **Phase 2**: Tune scoring weights based on observed patterns
3. **Phase 3**: Enable enforcement for high-confidence detections
4. **Phase 4**: Gradually lower thresholds as patterns stabilize

### Troubleshooting

#### Common Issues

**No mesh metadata detected**:
- Verify Istio/Envoy filter configuration
- Check header names match `mesh_header_map`
- Ensure service mesh is injecting headers

**High false positive rate**:
- Review `mesh_risky_namespaces` configuration
- Adjust `mesh_score_weights` for your environment
- Increase `mesh_pair_window_seconds` for learning

**Missing cross-namespace detections**:
- Verify Kong route configuration includes namespace tags
- Check `get_destination_info()` logic in enricher
- Enable debug logging for detailed analysis

#### Debug Logging

Enable detailed mesh enricher logging:

```yaml
config:
  log_level: "debug"
  log_requests: true
```

Look for log entries containing:
- "Mesh metadata extracted"
- "Mesh-based threat detected"
- "No mesh metadata found"

## Integration Examples

### Kong Enterprise with Istio

```yaml
# Kong route with mesh awareness
apiVersion: configuration.konghq.com/v1
kind: KongIngress
metadata:
  name: mesh-aware-route
  annotations:
    konghq.com/strip-path: "true"
route:
  tags:
    - "namespace:production"
    - "workload:api-deployment"
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    konghq.com/plugins: kong-guard-ai
    kubernetes.io/ingress.class: kong
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

### Complete Kong Guard AI Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable mesh enricher
    enable_mesh_enricher: true

    # Mesh configuration
    mesh_header_map:
      namespace: "X-K8s-Namespace"
      service: "X-K8s-Service"
      workload: "X-K8s-Workload"
      mesh_source: "X-Mesh-Source"
      trace_id: "X-Request-ID"

    mesh_risky_namespaces:
      - "kube-system"
      - "istio-system"
      - "admin"
      - "monitoring"

    mesh_score_weights:
      cross_namespace: 0.2 # Lower for microservices
      risky_namespace: 0.8 # High for admin access
      unusual_pair: 0.3 # Moderate for new services
      missing_headers: 0.1 # Low for external traffic

    # Threat thresholds
    block_threshold: 0.8 # Block high-confidence threats
    rate_limit_threshold: 0.4 # Rate limit suspicious activity

    # General configuration
    dry_run: false # Enable enforcement
    log_level: "info"
    enable_notifications: true
    metrics_enabled: true
```

This configuration provides comprehensive mesh-aware threat detection while maintaining reasonable performance and false positive rates for production environments.