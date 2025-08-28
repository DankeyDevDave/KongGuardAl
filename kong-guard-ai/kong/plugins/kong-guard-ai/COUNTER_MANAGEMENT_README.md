# Kong Guard AI - Counter Management System

## Overview

The Counter Management System provides high-performance, memory-efficient tracking of API traffic metrics using Kong's shared memory dictionaries (`ngx.shared.dict`). This system enables real-time monitoring, rate limiting, and anomaly detection across both global and per-IP dimensions.

## Features

- **High-Performance Counters**: O(1) counter operations with minimal memory overhead
- **Time-Windowed Tracking**: 1-minute, 5-minute, and 1-hour sliding windows
- **Per-IP and Global Metrics**: Separate tracking for individual clients and system-wide metrics
- **Response Time Percentiles**: P50, P95, P99 response time tracking using histogram buckets
- **Status Code Distribution**: Automatic categorization and tracking of HTTP status codes
- **Memory Management**: Automatic expiration, cleanup, and memory usage monitoring
- **Lock-Free Operations**: Designed for high-concurrency without global locks

## Architecture

### Shared Memory Configuration

The system uses two shared memory zones configured in `nginx-kong.conf`:

```nginx
lua_shared_dict kong_guard_ai_counters 10m;  # Counter storage
lua_shared_dict kong_guard_ai_data 10m;      # Metadata and configuration
```

### Key Structure

Keys are structured for efficient lookups and automatic expiration:

```
# Per-IP counters with time windows
ip:{ip_address}:{counter_type}:{window_seconds}:{time_bucket}

# Global counters with time windows  
global:all:{counter_type}:{window_seconds}:{time_bucket}

# Response time percentile buckets
p:{identifier}:{bucket_max_ms}:{window_seconds}:{time_bucket}

# Examples:
ip:203.0.113.100:req:60:123456789    # 1-minute request counter for IP
global:all:resp:300:123456789        # 5-minute global response counter
p:global:500:3600:123456789          # 1-hour global <500ms response bucket
```

### Counter Types

- `req` - Request counters
- `resp` - Response counters  
- `err` - Error/threat counters
- `status:{code}` - Specific status code counters
- `status:{category}` - Status category counters (2xx, 3xx, 4xx, 5xx)

## API Reference

### Core Functions

#### `counters.init(config)`
Initializes the counter management system.

**Parameters:**
- `config` - Plugin configuration object

**Returns:**
- `boolean` - Success status

#### `counters.increment_ip_counter(ip, counter_type, window, increment)`
Increments a per-IP counter.

**Parameters:**
- `ip` (string) - Client IP address
- `counter_type` (string) - Type of counter (use `counters.COUNTER_TYPES`)
- `window` (number, optional) - Specific time window in seconds
- `increment` (number, optional) - Value to add (default: 1)

**Returns:**
- `table` - Counter values for different time windows

**Example:**
```lua
local results = counters.increment_ip_counter("203.0.113.100", counters.COUNTER_TYPES.REQUESTS)
-- Results: {minute = 15, five_minutes = 42, hour = 158, lifetime = 1205}
```

#### `counters.increment_global_counter(counter_type, window, increment)`
Increments a global counter.

**Parameters:**
- `counter_type` (string) - Type of counter
- `window` (number, optional) - Specific time window in seconds
- `increment` (number, optional) - Value to add (default: 1)

**Returns:**
- `table` - Counter values for different time windows

#### `counters.track_response_time(ip, response_time_ms, window)`
Records response time for percentile calculation.

**Parameters:**
- `ip` (string, optional) - Client IP address for per-IP tracking
- `response_time_ms` (number) - Response time in milliseconds
- `window` (number, optional) - Specific time window in seconds

#### `counters.track_status_code(ip, status_code, window)`
Records status code distribution.

**Parameters:**
- `ip` (string, optional) - Client IP address for per-IP tracking
- `status_code` (number) - HTTP status code
- `window` (number, optional) - Specific time window in seconds

### Query Functions

#### `counters.get_ip_stats(ip, counter_type)`
Retrieves statistics for a specific IP address.

**Parameters:**
- `ip` (string) - Client IP address
- `counter_type` (string, optional) - Specific counter type to retrieve

**Returns:**
- `table` - Statistics organized by counter type and time window

**Example:**
```lua
local stats = counters.get_ip_stats("203.0.113.100")
-- Returns:
-- {
--   req = {minute = 15, five_minutes = 42, hour = 158, lifetime = 1205},
--   resp = {minute = 14, five_minutes = 41, hour = 157, lifetime = 1200},
--   err = {minute = 1, five_minutes = 1, hour = 1, lifetime = 5}
-- }
```

#### `counters.get_global_stats(counter_type)`
Retrieves global system statistics.

**Returns:**
- `table` - Global statistics organized by counter type and time window

#### `counters.get_response_time_percentiles(identifier, window)`
Calculates response time percentiles.

**Parameters:**
- `identifier` (string) - "global" or specific IP address
- `window` (number, optional) - Time window in seconds

**Returns:**
- `table` - Percentile data: `{p50, p95, p99, total}`

#### `counters.get_error_rate(identifier, window)`
Calculates error rate percentage.

**Parameters:**
- `identifier` (string) - "global" or specific IP address  
- `window` (number, optional) - Time window in seconds

**Returns:**
- `table` - Error rate data: `{error_rate, total_requests, total_errors}`

### System Functions

#### `counters.get_memory_usage()`
Returns shared memory usage statistics.

**Returns:**
- `table` - Memory usage for both shared dictionaries

#### `counters.get_system_stats()`
Returns comprehensive system statistics.

**Returns:**
- `table` - Complete system overview including counters, memory, and performance metrics

#### `counters.maintenance()`
Performs periodic maintenance and cleanup.

**Returns:**
- `table` - Maintenance statistics

## Integration with Handler

### Access Phase Integration

```lua
-- Track incoming requests
local client_ip = request_metadata.client_ip

-- Increment global request counter
counters.increment_global_counter(counters.COUNTER_TYPES.REQUESTS)

-- Increment per-IP request counter
counters.increment_ip_counter(client_ip, counters.COUNTER_TYPES.REQUESTS)

-- Track threats/errors when detected
if threat_detected then
    counters.increment_global_counter(counters.COUNTER_TYPES.ERRORS)
    counters.increment_ip_counter(client_ip, counters.COUNTER_TYPES.ERRORS)
end
```

### Log Phase Integration

```lua
-- Track response metrics
local client_ip = request_metadata.client_ip
local status_code = response_metadata.status_code
local response_time_ms = response_metadata.total_latency_ms

-- Increment response counters
counters.increment_global_counter(counters.COUNTER_TYPES.RESPONSES)
counters.increment_ip_counter(client_ip, counters.COUNTER_TYPES.RESPONSES)

-- Track status code distribution
counters.track_status_code(client_ip, status_code)

-- Track response time percentiles
counters.track_response_time(client_ip, response_time_ms)
```

## HTTP Endpoints

### Status Endpoint
**URL:** `/guard-ai/status`
**Method:** GET
**Description:** Returns comprehensive plugin status with counter metrics

**Response Example:**
```json
{
  "plugin": "kong-guard-ai",
  "version": "1.0.0",
  "status": "active",
  "timestamp": 1692454800,
  "counters": {
    "global": {
      "req": {"minute": 1205, "five_minutes": 5420, "hour": 18750, "lifetime": 125000},
      "resp": {"minute": 1200, "five_minutes": 5400, "hour": 18700, "lifetime": 124500},
      "err": {"minute": 5, "five_minutes": 20, "hour": 50, "lifetime": 500}
    },
    "memory_usage": {
      "counters_dict": {"total_bytes": 10485760, "used_bytes": 2500000, "usage_percent": 23},
      "data_dict": {"total_bytes": 10485760, "used_bytes": 1800000, "usage_percent": 17}
    },
    "performance": {
      "uptime_seconds": 86400,
      "response_times": {"p50": 45, "p95": 180, "p99": 320, "total": 124500},
      "error_rate": {"error_rate": 0.4, "total_requests": 125000, "total_errors": 500}
    }
  }
}
```

### IP Metrics Endpoint
**URL:** `/guard-ai/metrics/ip/{ip_address}`
**Method:** GET
**Description:** Returns detailed metrics for a specific IP address

**Response Example:**
```json
{
  "ip": "203.0.113.100",
  "timestamp": 1692454800,
  "counters": {
    "req": {"minute": 15, "five_minutes": 42, "hour": 158, "lifetime": 1205},
    "resp": {"minute": 14, "five_minutes": 41, "hour": 157, "lifetime": 1200},
    "err": {"minute": 1, "five_minutes": 1, "hour": 1, "lifetime": 5}
  },
  "performance": {
    "response_times": {"p50": 52, "p95": 195, "p99": 340, "total": 1200},
    "error_rate": {"error_rate": 0.41, "total_requests": 1205, "total_errors": 5}
  }
}
```

### Memory Usage Endpoint
**URL:** `/guard-ai/memory`
**Method:** GET
**Description:** Returns shared memory usage statistics

**Response Example:**
```json
{
  "timestamp": 1692454800,
  "counters_dict": {
    "total_bytes": 10485760,
    "used_bytes": 2500000,
    "free_bytes": 7985760,
    "usage_percent": 23
  },
  "data_dict": {
    "total_bytes": 10485760,
    "used_bytes": 1800000,
    "free_bytes": 8685760,
    "usage_percent": 17
  }
}
```

## Performance Characteristics

### Memory Efficiency
- **Counter Key Size**: ~50-80 bytes per key
- **Automatic Expiration**: Keys expire after 2x their time window
- **Memory Overhead**: <5% of total request processing time
- **Capacity**: 10MB shared memory supports ~100K+ active counters

### Concurrency
- **Lock-Free**: All operations use atomic increments
- **High Throughput**: Supports 10K+ RPS with minimal contention
- **Worker Isolation**: Each worker maintains independent local caches

### Time Complexity
- **Counter Operations**: O(1) for all increment/get operations
- **Percentile Calculation**: O(k) where k = number of buckets (constant)
- **Cleanup**: O(1) amortized through probabilistic cleanup

## Configuration

### Shared Memory Sizing

Adjust shared memory size based on traffic volume:

```nginx
# For high traffic (>10K RPS)
lua_shared_dict kong_guard_ai_counters 50m;
lua_shared_dict kong_guard_ai_data 20m;

# For medium traffic (1K-10K RPS)  
lua_shared_dict kong_guard_ai_counters 20m;
lua_shared_dict kong_guard_ai_data 10m;

# For low traffic (<1K RPS)
lua_shared_dict kong_guard_ai_counters 10m;
lua_shared_dict kong_guard_ai_data 5m;
```

### Time Window Configuration

Modify time windows in `counters.lua`:

```lua
local TIME_WINDOWS = {
    MINUTE = 60,        -- 1 minute
    FIVE_MINUTES = 300, -- 5 minutes  
    HOUR = 3600,        -- 1 hour
    DAY = 86400         -- 1 day (custom)
}
```

### Response Time Buckets

Customize response time percentile buckets:

```lua
local RESPONSE_TIME_BUCKETS = {
    10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000  -- milliseconds
}
```

## Testing

### Validation Script

Run the comprehensive validation script:

```bash
./scripts/validate-counter-system.sh
```

### Manual Testing

```bash
# Generate test traffic
for i in {1..100}; do
  curl -H "X-Forwarded-For: 203.0.113.100" http://localhost:8000/test
done

# Check global stats
curl http://localhost:8001/guard-ai/status | jq '.counters.global'

# Check IP-specific stats  
curl http://localhost:8001/guard-ai/metrics/ip/203.0.113.100 | jq '.counters'

# Monitor memory usage
curl http://localhost:8001/guard-ai/memory | jq '.'
```

### Performance Testing

```bash
# High-load testing with ab
ab -n 10000 -c 100 http://localhost:8000/test

# Check system remains responsive
curl http://localhost:8001/guard-ai/status
```

## Troubleshooting

### Common Issues

1. **Shared Memory Full**
   - Symptom: Warnings about failed counter increments
   - Solution: Increase shared memory size or reduce retention windows

2. **High Memory Usage**
   - Symptom: Memory usage >80%
   - Solution: Implement more aggressive cleanup or increase memory

3. **Missing Counter Data**
   - Symptom: Endpoints return zero values
   - Solution: Verify plugin is loaded and traffic is flowing

### Debug Commands

```bash
# Check shared memory usage
curl http://localhost:8001/guard-ai/memory

# Verify plugin is loaded
curl http://localhost:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'

# Monitor Kong logs for counter errors
docker logs kong | grep "Kong Guard AI Counters"
```

## Best Practices

1. **Monitor Memory Usage**: Keep shared memory usage below 80%
2. **Tune Time Windows**: Adjust based on analysis requirements
3. **Implement Alerts**: Monitor error rates and high latency
4. **Regular Cleanup**: Ensure periodic maintenance runs
5. **Performance Testing**: Validate under expected load

## Future Enhancements

- **Redis Backend**: Optional Redis storage for persistence
- **Custom Metrics**: User-defined counter types
- **Alerting Integration**: Built-in threshold alerts
- **Historical Data**: Long-term storage and analysis
- **Dashboard Integration**: Grafana/Prometheus exporters