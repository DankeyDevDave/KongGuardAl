# Kong Guard AI - TAXII/STIX Threat Intelligence Integration

## Overview

Kong Guard AI now includes comprehensive support for ingesting threat intelligence from TAXII 2.x feeds, processing STIX indicators, and using this intelligence to enhance threat detection capabilities. This integration allows the plugin to automatically consume threat feeds from external sources and apply them in real-time to protect your APIs.

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Configuration](#configuration)
4. [Setup Guide](#setup-guide)
5. [TAXII Server Configuration](#taxii-server-configuration)
6. [Supported Indicators](#supported-indicators)
7. [Threat Scoring](#threat-scoring)
8. [Monitoring and Metrics](#monitoring-and-metrics)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)
11. [Performance Tuning](#performance-tuning)
12. [API Reference](#api-reference)

## Features

### Core Capabilities

- **TAXII 2.0/2.1 Protocol Support**: Full compatibility with TAXII 2.0 and 2.1 standards
- **STIX Indicator Processing**: Automatic parsing and normalization of STIX threat indicators
- **Real-time Threat Detection**: Immediate application of threat intelligence to incoming requests
- **Multiple Authentication Methods**: Support for no auth, basic auth, and bearer token authentication
- **Intelligent Caching**: Efficient memory management with versioned indicator sets
- **Automatic Polling**: Configurable polling intervals with error handling and backoff
- **Comprehensive Coverage**: Support for IPs, domains, URLs, file hashes, and TLS fingerprints

### Supported Indicator Types

- **IP Addresses**: IPv4 and IPv6 addresses with CIDR range support
- **Domain Names**: FQDN matching with IDNA normalization
- **URLs**: Full URL matching with path and query normalization
- **File Hashes**: MD5, SHA-1, and SHA-256 hash matching
- **TLS Fingerprints**: JA3 and JA4 fingerprint detection
- **Regex Patterns**: Safe regex pattern matching with sandboxing

## Architecture

### Component Overview

```
┌─────────────────┐ ┌──────────────────┐ ┌─────────────────┐
│ TAXII Feeds │───▶│ TAXII Scheduler │───▶│ STIX Parser │
└─────────────────┘ └──────────────────┘ └─────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐ ┌──────────────────┐ ┌─────────────────┐
│ Request Handler │◀───│ Threat Cache │◀───│ Normalizer │
└─────────────────┘ └──────────────────┘ └─────────────────┘
```

### Data Flow

1. **TAXII Scheduler** polls configured TAXII servers periodically
2. **STIX Parser** processes incoming STIX indicator objects
3. **Normalizer** extracts and validates indicators of compromise (IoCs)
4. **Threat Cache** stores normalized indicators in versioned sets
5. **Request Handler** performs real-time lookups against cached indicators

## Configuration

### Basic TAXII Configuration

```lua
{
  name = "kong-guard-ai",
  config = {
    -- Enable TAXII threat intelligence
    enable_taxii_ingestion = true,

    -- TAXII protocol version
    taxii_version = "2.1", -- or "2.0"

    -- Polling configuration
    taxii_poll_interval_seconds = 300, -- 5 minutes
    taxii_cache_ttl_seconds = 3600, -- 1 hour
    taxii_max_objects_per_poll = 500, -- Objects per request

    -- HTTP configuration
    taxii_http_timeout_ms = 2000, -- 2 seconds
    taxii_retry_backoff_ms = {
      initial = 200,
      max = 5000,
      factor = 2
    },

    -- Security settings
    taxii_tls_insecure_skip_verify = false,
    taxii_enable_dedup = true,

    -- Server configuration
    taxii_servers = {
      {
        url = "https://taxii.example.com",
        collections = {"indicators", "malware"},
        auth_type = "bearer",
        token = "your-api-token"
      }
    },

    -- Threat scoring weights
    taxii_score_weights = {
      ip_blocklist = 0.9,
      ip_allowlist = -0.5,
      domain_blocklist = 0.8,
      domain_allowlist = -0.4,
      url_blocklist = 0.8,
      url_allowlist = -0.4,
      ja3_blocklist = 0.7,
      ja3_allowlist = -0.3,
      ja4_blocklist = 0.7,
      ja4_allowlist = -0.3,
      regex_match = 0.6
    }
  }
}
```

## Setup Guide

### Step 1: Install Dependencies

Ensure required Lua modules are available:

```bash
# Install required dependencies
luarocks install lua-resty-http
luarocks install lua-resty-ipmatcher
luarocks install lua-cjson
```

### Step 2: Configure Kong

Add the plugin configuration to your Kong setup:

```bash
# Using Kong Admin API
curl -X POST http://localhost:8001/plugins \
  -H "Content-Type: application/json" \
  -d @taxii-config.json
```

### Step 3: Verify Installation

Check that the plugin loads correctly:

```bash
# Check plugin status
curl http://localhost:8001/plugins | jq '.data[] | select(.name=="kong-guard-ai")'

# Check logs for TAXII initialization
tail -f /usr/local/kong/logs/error.log | grep TAXII
```

### Step 4: Test Threat Detection

```bash
# Test with a potentially malicious IP (if in your threat feed)
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/your-api

# Check if request was blocked or allowed
echo $? # 0 = allowed, non-zero = blocked
```

## TAXII Server Configuration

### Authentication Methods

#### No Authentication
```lua
{
  url = "https://open.taxii.server.com",
  auth_type = "none"
}
```

#### Basic Authentication
```lua
{
  url = "https://secure.taxii.server.com",
  auth_type = "basic",
  username = "your-username",
  password = "your-password"
}
```

#### Bearer Token
```lua
{
  url = "https://api.taxii.server.com",
  auth_type = "bearer",
  token = "your-bearer-token"
}
```

### Collection Filtering

```lua
{
  url = "https://taxii.server.com",
  collections = {
    "malware-indicators", -- Specific collection
    "ip-blocklist", -- Another collection
    "domain-reputation" -- Third collection
  },
  auth_type = "none"
}
```

To poll all available collections, omit the `collections` array or set it to an empty array.

### Multiple Server Configuration

```lua
taxii_servers = {
  {
    url = "https://threat-feed-1.com",
    collections = {"indicators"},
    auth_type = "bearer",
    token = "token-1"
  },
  {
    url = "https://threat-feed-2.com",
    collections = {"malware", "phishing"},
    auth_type = "basic",
    username = "user",
    password = "pass"
  },
  {
    url = "https://open-threat-feed.org",
    auth_type = "none"
  }
}
```

## Supported Indicators

### STIX Pattern Examples

#### IP Addresses
```stix
[ipv4-addr:value = '192.168.1.100']
[ipv6-addr:value = '2001:db8::1']
[ipv4-addr:value = '10.0.0.0/8'] -- CIDR ranges
```

#### Domain Names
```stix
[domain-name:value = 'malicious.example.com']
[domain-name:value = '*.evil.com'] -- Wildcard patterns
```

#### URLs
```stix
[url:value = 'https://malicious.example.com/malware.exe']
[url:value = 'http://phishing.site.com/login']
```

#### File Hashes
```stix
[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
[file:hashes.SHA-1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']
[file:hashes.SHA-256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
```

#### TLS Fingerprints
```stix
# JA3 fingerprints in description or custom fields
description: "JA3: 769,47-53-5-10-49161-49162"

# JA4 fingerprints
description: "JA4: t13d1516h2_8daaf6152771_b0da82dd1658"
```

### Label-Based Classification

The plugin automatically classifies indicators based on their labels:

#### Blocklist Indicators
- `malicious-activity`
- `malware`
- `phishing`
- `botnet`
- `exploit`
- `attack`
- `threat`
- `bad`
- `block`

#### Allowlist Indicators
- `benign`
- `trusted`
- `whitelist`
- `safe`
- `allow`

## Threat Scoring

### Scoring System

The plugin uses a weighted scoring system where different indicator types contribute different amounts to the overall threat score:

```lua
-- Default weights
taxii_score_weights = {
  ip_blocklist = 0.9, -- High confidence for IP blocks
  ip_allowlist = -0.5, -- Strong negative weight for allowlist
  domain_blocklist = 0.8, -- High confidence for domain blocks
  domain_allowlist = -0.4, -- Moderate negative weight
  url_blocklist = 0.8, -- High confidence for URL blocks
  url_allowlist = -0.4, -- Moderate negative weight
  ja3_blocklist = 0.7, -- Moderate confidence for TLS fingerprints
  ja3_allowlist = -0.3, -- Lower negative weight
  ja4_blocklist = 0.7, -- Moderate confidence for JA4
  ja4_allowlist = -0.3, -- Lower negative weight
  regex_match = 0.6 -- Moderate confidence for regex matches
}
```

### Threat Actions

Based on the final threat score, the plugin takes different actions:

- **Score ≥ 0.8**: Block request (HTTP 403)
- **Score ≥ 0.6**: Rate limit request
- **Score < 0.6**: Allow request (may log for monitoring)

### Custom Weights

Adjust weights based on your threat intelligence confidence:

```lua
-- High-confidence threat feed
taxii_score_weights = {
  ip_blocklist = 0.95, -- Very high confidence
  domain_blocklist = 0.90,
  url_blocklist = 0.90
}

-- Lower-confidence or experimental feed
taxii_score_weights = {
  ip_blocklist = 0.6, -- Lower confidence
  domain_blocklist = 0.5,
  url_blocklist = 0.5
}
```

## Monitoring and Metrics

### Built-in Metrics

The plugin exposes several metrics for monitoring TAXII operations:

```lua
-- Polling metrics
taxii_polls_total -- Total number of polling attempts
taxii_indicators_loaded -- Total indicators loaded
taxii_errors_total -- Total errors encountered
taxii_last_success_ts -- Timestamp of last successful poll

-- Performance metrics
taxii_last_poll_duration_ms -- Duration of last polling cycle
```

### Accessing Metrics

Metrics are stored in Kong's shared dictionary and can be accessed via custom endpoints:

```bash
# Check TAXII status (requires custom endpoint)
curl http://localhost:8001/taxii/status

# Example response
{
  "enabled": true,
  "running": true,
  "servers_configured": 2,
  "last_poll": "2023-12-01T10:30:00Z",
  "metrics": {
    "polls_total": 145,
    "indicators_loaded": 2847,
    "errors_total": 3
  },
  "cache": {
    "version": "23",
    "total_indicators": 2847,
    "by_type": {
      "ip": 1205,
      "domain": 892,
      "url": 445,
      "ja3": 305
    }
  }
}
```

### Logging

Configure appropriate log levels to monitor TAXII operations:

```lua
-- In Kong configuration
log_level = info -- or debug for more detailed logs
```

Log messages include:

- TAXII server connectivity status
- Polling cycle results
- Indicator processing statistics
- Cache update operations
- Threat detection matches

## Troubleshooting

### Common Issues

#### 1. TAXII Server Connection Failures

**Symptoms**: No indicators loaded, connection errors in logs

**Solutions**:
```bash
# Test connectivity manually
curl -v https://your-taxii-server.com/taxii/

# Check DNS resolution
nslookup your-taxii-server.com

# Verify authentication
curl -H "Authorization: Bearer your-token" https://your-taxii-server.com/taxii/
```

#### 2. No Threat Intelligence Matches

**Symptoms**: All requests allowed, no blocking occurring

**Possible causes**:
- No indicators loaded (check polling logs)
- Incorrect threat score weights
- Dry run mode enabled
- Test IPs not in threat feed

**Debug steps**:
```bash
# Check if indicators are loaded
grep "indicators_loaded" /usr/local/kong/logs/error.log

# Verify cache contents
# (requires custom debug endpoint)
curl http://localhost:8001/taxii/cache/stats
```

#### 3. High Memory Usage

**Symptoms**: Kong memory usage growing over time

**Solutions**:
- Reduce `taxii_cache_ttl_seconds`
- Lower `taxii_max_objects_per_poll`
- Implement indicator filtering
- Monitor cache cleanup operations

#### 4. Slow Request Processing

**Symptoms**: Increased API latency

**Optimizations**:
- Tune cache lookup algorithms
- Reduce number of regex patterns
- Optimize indicator types
- Consider async processing

### Debug Configuration

Enable detailed logging for troubleshooting:

```lua
{
  config = {
    log_level = "debug",
    log_threats = true,
    log_requests = false, -- Only enable for debugging
    log_decisions = true,

    -- TAXII debugging
    taxii_http_timeout_ms = 5000, -- Longer timeout
    taxii_retry_backoff_ms = {
      initial = 500, -- Longer initial delay
      max = 10000, -- Longer max delay
      factor = 2
    }
  }
}
```

## Security Considerations

### Network Security

1. **TLS Verification**: Always verify TAXII server certificates
```lua
taxii_tls_insecure_skip_verify = false -- Never disable in production
```

2. **Network Segmentation**: Isolate Kong instances accessing TAXII feeds
3. **Firewall Rules**: Restrict outbound connections to known TAXII servers

### Authentication Security

1. **Token Management**: Use secure token storage and rotation
2. **Principle of Least Privilege**: Request only necessary collections
3. **Credential Protection**: Store sensitive credentials securely

```lua
-- Use environment variables for sensitive data
{
  auth_type = "bearer",
  token = os.getenv("TAXII_BEARER_TOKEN")
}
```

### Data Security

1. **Indicator Validation**: All indicators are validated before caching
2. **Regex Sandboxing**: Regex patterns are safety-checked
3. **Memory Protection**: Cache implements bounds checking

### Operational Security

1. **Monitor for Injection**: Watch for malicious STIX data
2. **Rate Limiting**: Implement TAXII server rate limits
3. **Audit Logging**: Log all threat intelligence operations

## Performance Tuning

### Polling Optimization

```lua
-- Balanced configuration for medium-traffic sites
{
  taxii_poll_interval_seconds = 300, -- 5 minutes
  taxii_max_objects_per_poll = 500, -- Moderate batch size
  taxii_cache_ttl_seconds = 3600, -- 1 hour cache
  taxii_http_timeout_ms = 2000 -- 2 second timeout
}

-- High-performance configuration for high-traffic sites
{
  taxii_poll_interval_seconds = 600, -- 10 minutes
  taxii_max_objects_per_poll = 1000, -- Larger batches
  taxii_cache_ttl_seconds = 7200, -- 2 hour cache
  taxii_http_timeout_ms = 5000 -- Longer timeout
}

-- Real-time configuration for security-critical environments
{
  taxii_poll_interval_seconds = 60, -- 1 minute
  taxii_max_objects_per_poll = 200, -- Smaller batches
  taxii_cache_ttl_seconds = 1800, -- 30 minute cache
  taxii_http_timeout_ms = 1000 -- Fast timeout
}
```

### Memory Management

1. **Cache Sizing**: Configure Kong shared dictionaries appropriately
```nginx
# In Kong configuration
lua_shared_dict kong_cache 256m # Increase for large threat feeds
```

2. **Indicator Filtering**: Filter indicators at ingestion time
3. **Cleanup Scheduling**: Ensure proper cache cleanup

### Request Processing Optimization

1. **Early Exits**: Check allowlists first
2. **Efficient Lookups**: Optimize data structures
3. **Async Processing**: Consider background threat checking

## API Reference

### Configuration Schema

#### Core TAXII Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_taxii_ingestion` | boolean | `false` | Enable TAXII threat intelligence |
| `taxii_version` | string | `"2.1"` | TAXII protocol version (`"2.0"` or `"2.1"`) |
| `taxii_poll_interval_seconds` | integer | `300` | Polling interval (60-86400) |
| `taxii_cache_ttl_seconds` | integer | `3600` | Cache TTL (300-604800) |
| `taxii_max_objects_per_poll` | integer | `500` | Max objects per poll (10-10000) |

#### HTTP Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `taxii_http_timeout_ms` | integer | `2000` | HTTP timeout (1000-30000) |
| `taxii_retry_backoff_ms` | record | See below | Retry backoff configuration |
| `taxii_tls_insecure_skip_verify` | boolean | `false` | Skip TLS verification (insecure) |
| `taxii_proxy_url` | string | `nil` | HTTP proxy URL |

#### Retry Backoff Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `initial` | integer | `200` | Initial backoff delay (100-5000) |
| `max` | integer | `5000` | Maximum backoff delay (1000-60000) |
| `factor` | number | `2` | Backoff multiplication factor (1.1-10) |

#### Server Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | - | TAXII server base URL (required) |
| `collections` | array | `[]` | Collection IDs to poll (empty = all) |
| `auth_type` | string | `"none"` | Authentication type |
| `username` | string | - | Username for basic auth |
| `password` | string | - | Password for basic auth |
| `token` | string | - | Bearer token |

#### Scoring Weights

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip_blocklist` | number | `0.9` | IP blocklist match weight (0-1) |
| `ip_allowlist` | number | `-0.5` | IP allowlist match weight (-1-0) |
| `domain_blocklist` | number | `0.8` | Domain blocklist match weight (0-1) |
| `domain_allowlist` | number | `-0.4` | Domain allowlist match weight (-1-0) |
| `url_blocklist` | number | `0.8` | URL blocklist match weight (0-1) |
| `url_allowlist` | number | `-0.4` | URL allowlist match weight (-1-0) |
| `ja3_blocklist` | number | `0.7` | JA3 blocklist match weight (0-1) |
| `ja3_allowlist` | number | `-0.3` | JA3 allowlist match weight (-1-0) |
| `ja4_blocklist` | number | `0.7` | JA4 blocklist match weight (0-1) |
| `ja4_allowlist` | number | `-0.3` | JA4 allowlist match weight (-1-0) |
| `regex_match` | number | `0.6` | Regex pattern match weight (0-1) |

### Example Configurations

#### OpenCTI TAXII Server

```lua
{
  taxii_servers = {
    {
      url = "https://your-opencti.com/taxii2",
      collections = {"indicators"},
      auth_type = "bearer",
      token = "your-opencti-token"
    }
  }
}
```

#### MISP TAXII Server

```lua
{
  taxii_servers = {
    {
      url = "https://your-misp.com/servers/taxii2",
      collections = {"misp-galaxy", "threat-actors"},
      auth_type = "basic",
      username = "misp-user",
      password = "misp-password"
    }
  }
}
```

#### Multiple Threat Feeds

```lua
{
  taxii_servers = {
    {
      url = "https://high-confidence-feed.com",
      collections = ["critical-threats"],
      auth_type = "bearer",
      token = "critical-feed-token"
    },
    {
      url = "https://community-feed.org",
      auth_type = "none"
    }
  },
  taxii_score_weights = {
    ip_blocklist = 0.85, -- Slightly lower confidence for mixed feeds
    domain_blocklist = 0.75
  }
}
```

## Best Practices

### 1. Gradual Rollout

1. **Start with Dry Run**: Enable monitoring without blocking
2. **Use Allow Lists**: Begin with known-good indicators
3. **Monitor Closely**: Watch for false positives
4. **Gradually Increase**: Raise threat thresholds over time

### 2. Feed Selection

1. **Reputation**: Choose well-established threat intelligence providers
2. **Relevance**: Select feeds relevant to your threat landscape
3. **Quality**: Prefer feeds with confidence scores and validation
4. **Coverage**: Balance comprehensive coverage with false positive rates

### 3. Maintenance

1. **Regular Updates**: Keep TAXII configurations current
2. **Feed Rotation**: Periodically evaluate and update threat feeds
3. **Performance Monitoring**: Track plugin performance impact
4. **Security Reviews**: Regularly audit TAXII configurations

### 4. Integration

1. **SIEM Integration**: Feed threat detection logs to your SIEM
2. **Incident Response**: Include threat intelligence in response procedures
3. **Threat Hunting**: Use Kong logs for proactive threat hunting
4. **Metrics Dashboard**: Create dashboards for threat intelligence metrics

---

This completes the comprehensive TAXII/STIX integration guide for Kong Guard AI. The implementation provides enterprise-grade threat intelligence capabilities while maintaining high performance and security standards.