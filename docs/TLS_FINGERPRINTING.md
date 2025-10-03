# TLS Fingerprinting in Kong Guard AI

## Overview

Kong Guard AI's TLS fingerprinting feature provides advanced threat detection capabilities by analyzing client and server TLS handshake characteristics. This feature leverages JA3, JA4, JA3S, and JA4S fingerprints to identify potentially malicious clients even when they use legitimate user agents or rotate IP addresses.

## Supported Fingerprint Types

### Client Fingerprints
- **JA3**: MD5 hash of TLS client hello parameters (SSL version, cipher suites, extensions, elliptic curves, elliptic curve formats)
- **JA4**: Enhanced client fingerprint with improved evasion resistance and better format

### Server Fingerprints
- **JA3S**: MD5 hash of TLS server hello parameters
- **JA4S**: Enhanced server fingerprint corresponding to JA4

## Configuration

### Basic Configuration

```yaml
plugins:
- name: kong-guard-ai
  config:
    # Enable TLS fingerprinting
    enable_tls_fingerprints: true

    # Configure header mapping (customize based on your proxy setup)
    tls_header_map:
      ja3: "X-JA3"
      ja3s: "X-JA3S"
      ja4: "X-JA4"
      ja4s: "X-JA4S"
      tls_version: "X-TLS-Version"
      tls_cipher: "X-TLS-Cipher"
      sni: "X-TLS-ServerName"

    # Cache settings
    tls_cache_ttl_seconds: 600

    # Threat intelligence lists
    tls_blocklist:
      - "e7d705a3286e19ea42f587b344ee6865" # Known malicious JA3
      - "malicious*" # Wildcard pattern
      - "*bot*fingerprint*" # Pattern matching

    tls_allowlist:
      - "a0e9f5d64349fb13191bc781f81f42e1" # Known good JA3
      - "chrome*" # Chrome fingerprints
      - "*legitimate*" # Trusted patterns

    # Scoring weights
    tls_score_weights:
      match_blocklist: 0.7 # Increase threat score by 0.7 for blocklist matches
      match_allowlist: -0.4 # Decrease threat score by 0.4 for allowlist matches
      ua_mismatch: 0.2 # User-Agent mismatch with fingerprint
      rare_fingerprint: 0.2 # Fingerprint seen from few unique IPs
      velocity: 0.3 # High request rate from single fingerprint

    # Behavioral thresholds
    tls_rare_fp_min_ips: 5 # Minimum IPs before fingerprint is "common"
    tls_rate_limit_per_fp: 120 # Requests per minute per fingerprint
```

### Advanced Configuration

```yaml
# Production-ready configuration with comprehensive lists
tls_blocklist:
  # Known malware fingerprints
  - "e7d705a3286e19ea42f587b344ee6865"
  - "8b2c8b6dcee6af7e4a72b3d3b5f6d7a8"

  # Bot/automation tool patterns
  - "curl*"
  - "python*"
  - "*bot*"
  - "*scanner*"

  # Suspicious patterns
  - "*randomized*"
  - "*custom*"

tls_allowlist:
  # Major browser fingerprints
  - "a0e9f5d64349fb13191bc781f81f42e1" # Chrome 91
  - "b1e8f5d74359fb13191bc781f81f43f2" # Firefox 89
  - "c2f9g6e85460gc24202cd892g92g54g3" # Safari 14

  # Mobile browsers
  - "mobile*chrome*"
  - "mobile*safari*"

  # Legitimate automation
  - "googlebot*"
  - "bingbot*"
```

## Deployment Topologies

### Edge Proxy Setup (Recommended)

```
Internet → Edge Proxy → Kong → Backend
          (JA3/JA4)
```

Configure your edge proxy (Nginx, HAProxy, Cloudflare, etc.) to extract TLS fingerprints and add them as headers:

#### Nginx Configuration
```nginx
server {
    listen 443 ssl;

    # JA3 fingerprinting (requires nginx-ssl-ja3 module)
    set $ja3_hash $ssl_ja3_hash;
    set $ja3s_hash $ssl_ja3s_hash;

    location / {
        proxy_set_header X-JA3 $ja3_hash;
        proxy_set_header X-JA3S $ja3s_hash;
        proxy_set_header X-TLS-Version $ssl_protocol;
        proxy_set_header X-TLS-Cipher $ssl_cipher;
        proxy_set_header X-TLS-ServerName $ssl_server_name;

        proxy_pass http://kong-upstream;
    }
}
```

#### HAProxy Configuration
```
frontend https_frontend
    bind *:443 ssl crt /path/to/cert.pem

    # Capture JA3 fingerprint (requires HAProxy 2.4+)
    http-request set-header X-JA3 %[ssl_fc_ja3]
    http-request set-header X-TLS-Version %[ssl_fc_protocol]
    http-request set-header X-TLS-Cipher %[ssl_fc_cipher]

    default_backend kong_backend
```

### Sidecar Proxy Setup

```
Client → Istio/Envoy → Kong → Service
         (JA3/JA4)
```

Configure Envoy sidecar to extract TLS fingerprints:

```yaml
# Envoy filter for JA3 extraction
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: ja3-fingerprint
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.wasm
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
          config:
            configuration:
              "@type": type.googleapis.com/google.protobuf.StringValue
              value: |
                {
                  "add_ja3_header": true,
                  "header_name": "X-JA3"
                }
```

## Threat Detection Capabilities

### 1. Blocklist/Allowlist Matching

Exact and wildcard pattern matching against known threat intelligence:

```yaml
# Exact matches
- "e7d705a3286e19ea42f587b344ee6865"

# Prefix matching
- "malicious*"

# Suffix matching
- "*suspicious"

# Contains matching
- "*bot*fingerprint*"
```

### 2. User-Agent Mismatch Detection

Detects when TLS fingerprints don't match the declared User-Agent:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
JA3: curl_fingerprint_hash
→ Suspicious mismatch detected
```

### 3. Rare Fingerprint Detection

Identifies fingerprints seen from fewer than the configured threshold of unique IP addresses:

```
Fingerprint: custom_tool_fingerprint
Unique IPs: 2 (threshold: 5)
→ Flagged as rare/suspicious
```

### 4. Velocity-Based Detection

Rate limiting based on requests per fingerprint:

```
Fingerprint: bot_fingerprint
Rate: 200 RPM (threshold: 120 RPM)
→ High velocity detected
```

## Metrics and Monitoring

### Available Metrics

Kong Guard AI exposes the following TLS-related metrics via `ngx.shared.kong_cache`:

```lua
-- Request metrics
tls_requests_with_fingerprints -- Total requests with valid TLS fingerprints
tls_ja3_fingerprints -- Requests with JA3 fingerprints
tls_ja4_fingerprints -- Requests with JA4 fingerprints
tls_ja3s_fingerprints -- Requests with JA3S fingerprints
tls_ja4s_fingerprints -- Requests with JA4S fingerprints

-- Threat metrics
tls_threats_detected -- Threats detected via TLS fingerprinting
```

### Monitoring Dashboard

Example Grafana queries:

```promql
# TLS fingerprint coverage
rate(tls_requests_with_fingerprints[5m]) / rate(total_requests[5m])

# TLS threat detection rate
rate(tls_threats_detected[5m])

# Fingerprint type distribution
rate(tls_ja3_fingerprints[5m])
rate(tls_ja4_fingerprints[5m])
```

### Log Analysis

TLS fingerprint data is included in threat logs:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "warn",
  "message": "Threat detected in request",
  "data": {
    "score": 0.8,
    "type": "tls_fingerprint_threat",
    "client_ip": "192.168.1.100",
    "path": "/api/sensitive",
    "tls_fingerprints": {
      "ja3": "e7d705a3286e19ea42f587b344ee6865",
      "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
      "tls_version": "1.3",
      "fingerprint_count": 2
    }
  }
}
```

## Security Considerations

### Privacy Protection

- **No PII Storage**: Only hashed fingerprints are stored, not raw TLS parameters
- **TTL Enforcement**: Cached fingerprint data expires automatically
- **Anonymization**: IP tracking uses aggregated counters, not individual tracking

### Evasion Resistance

- **Multiple Fingerprint Types**: JA3, JA4, and server fingerprints for comprehensive coverage
- **Wildcard Patterns**: Flexible matching to catch variations
- **Behavioral Analysis**: Velocity and rarity detection beyond static signatures

### Performance Optimization

- **Shared Cache**: Efficient memory usage with Kong's shared dictionary
- **Fast Path**: Early header validation to avoid expensive processing
- **TTL Management**: Automatic cleanup of stale fingerprint data

## Rollout Strategy

### Phase 1: Observe (Recommended Start)

```yaml
enable_tls_fingerprints: true
dry_run: true # Log only, no enforcement
tls_score_weights:
  match_blocklist: 0.1 # Low weights for observation
  match_allowlist: -0.05
  ua_mismatch: 0.05
  rare_fingerprint: 0.05
  velocity: 0.1
```

Monitor logs and metrics to:
- Verify fingerprint extraction is working
- Identify false positives
- Tune blocklist/allowlist
- Establish baseline metrics

### Phase 2: Rate Limiting

```yaml
dry_run: false
rate_limit_threshold: 0.4 # Enable rate limiting
tls_score_weights:
  match_blocklist: 0.3 # Moderate weights
  velocity: 0.2 # Focus on high-velocity threats
```

Start enforcing rate limits for suspicious fingerprints while continuing to observe blocking scenarios.

### Phase 3: Full Enforcement

```yaml
block_threshold: 0.8 # Enable blocking
tls_score_weights:
  match_blocklist: 0.7 # Production weights
  match_allowlist: -0.4
  ua_mismatch: 0.2
  rare_fingerprint: 0.2
  velocity: 0.3
```

Enable full threat blocking with tuned weights based on observations from previous phases.

## Troubleshooting

### Common Issues

#### No Fingerprints Detected
```bash
# Check headers are being set by upstream proxy
curl -H "X-JA3: test123" https://your-api.com/test

# Verify Kong Guard AI logs
tail -f /path/to/kong/logs/error.log | grep "TLS fingerprints"
```

#### High False Positives
- Review and expand allowlist with legitimate fingerprints
- Reduce scoring weights for initial deployment
- Check User-Agent matching logic

#### Performance Impact
- Monitor shared cache usage
- Reduce cache TTL if memory pressure
- Consider async processing for high-volume APIs

### Debug Mode

Enable detailed logging:

```yaml
log_level: debug
log_requests: true
```

This will log all TLS fingerprint extraction attempts and scoring decisions.

## Integration Examples

### Kong Declarative Config

```yaml
_format_version: "3.0"

services:
- name: protected-api
  url: http://backend-service:8000

routes:
- name: api-route
  service: protected-api
  paths: ["/api"]

plugins:
- name: kong-guard-ai
  service: protected-api
  config:
    enable_tls_fingerprints: true
    tls_header_map:
      ja3: "X-JA3"
      ja4: "X-JA4"
    tls_blocklist:
      - "e7d705a3286e19ea42f587b344ee6865"
    tls_score_weights:
      match_blocklist: 0.7
    block_threshold: 0.8
```

### Kubernetes Deployment

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: kong-guard-ai-tls
plugin: kong-guard-ai
config:
  enable_tls_fingerprints: true
  tls_header_map:
    ja3: "X-JA3"
    ja4: "X-JA4"
  tls_blocklist:
    - "malicious_fingerprint_hash"
  block_threshold: 0.8
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: protected-api
  annotations:
    konghq.com/plugins: kong-guard-ai-tls
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

## Best Practices

1. **Start with Observation**: Always begin with `dry_run: true` and low scoring weights
2. **Regular Updates**: Keep blocklist/allowlist updated with latest threat intelligence
3. **Monitor Performance**: Track cache hit rates and processing overhead
4. **Tune Gradually**: Adjust scoring weights based on real traffic patterns
5. **Validate Upstream**: Ensure upstream proxy correctly extracts fingerprints
6. **Backup Detection**: Don't rely solely on TLS fingerprints; use as part of layered security

## Support and Resources

- **Issue Reporting**: Use GitHub issues for bug reports and feature requests
- **Threat Intelligence**: Consider integrating with commercial TI feeds for blocklist updates
- **Community**: Join Kong community forums for best practices and troubleshooting
- **Documentation**: This document covers basic usage; see Kong Guard AI main documentation for advanced features