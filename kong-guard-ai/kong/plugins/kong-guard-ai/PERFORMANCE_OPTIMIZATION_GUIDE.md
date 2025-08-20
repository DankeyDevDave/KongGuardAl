# Kong Guard AI - Performance Optimization Guide

## Overview

Kong Guard AI implements comprehensive performance optimization to ensure instrumentation overhead remains below 10ms under high load. This guide covers the performance optimization features, monitoring capabilities, and configuration options.

## Performance Architecture

### Core Components

1. **Performance Optimizer** (`performance_optimizer.lua`)
   - Request-level performance monitoring
   - Circuit breaker implementation  
   - Memory usage tracking
   - CPU sampling and analysis
   - Optimization recommendations

2. **Benchmarking Suite** (`benchmarking_suite.lua`)
   - Integration with wrk, hey, and Apache Bench
   - Automated baseline vs instrumented comparisons
   - Memory leak detection
   - Stress testing capabilities

3. **Performance Dashboard** (`performance_dashboard.lua`)
   - Real-time monitoring interface
   - JSON metrics endpoints
   - Health check capabilities
   - Alert management

## Performance Thresholds

### Critical Limits
- **Request Processing**: < 10ms per request
- **Memory Growth**: < 50MB per worker
- **CPU Usage**: < 80% sustained
- **Circuit Breaker**: 5 failures triggers open state

### Monitoring Levels
- **Minimal**: 0.1% sampling, basic metrics
- **Balanced**: 1% sampling, full monitoring (default)
- **Detailed**: 10% sampling, comprehensive analysis

## Configuration

### Performance Schema Fields

```yaml
performance:
  optimization_level: "balanced"     # minimal, balanced, detailed
  max_processing_time_ms: 10        # Maximum allowed processing time
  enable_circuit_breaker: true      # Enable circuit breaker protection
  sampling_rate: 0.01              # Percentage of requests to sample
  memory_limit_mb: 100             # Memory alert threshold
  enable_dashboard: true           # Enable performance dashboard
  dashboard_auth: "api-key"        # Dashboard authentication method
```

### Circuit Breaker Configuration

```yaml
circuit_breaker:
  failure_threshold: 5             # Failures before opening
  recovery_timeout_seconds: 60    # Time before attempting recovery
  success_threshold: 3             # Successes needed to close
```

## Performance Monitoring

### Dashboard Endpoints

- `/_guard_ai/performance` - HTML dashboard interface
- `/_guard_ai/metrics` - JSON metrics for monitoring systems
- `/_guard_ai/health` - Health check endpoint

### Key Metrics

1. **Request Metrics**
   - Total requests processed
   - Average processing time
   - 95th/99th percentile latency
   - Requests within threshold

2. **Memory Metrics**
   - Current worker memory usage
   - Peak memory consumption
   - Memory growth over time
   - Baseline comparison

3. **CPU Metrics**
   - Current CPU usage estimate
   - CPU usage trends
   - High CPU alert frequency

4. **Circuit Breaker Status**
   - Current state (closed/open/half-open)
   - Failure count
   - Last state change

## Optimization Techniques

### String Operations
- Use `table.concat()` instead of string concatenation
- Pre-allocate string buffers when possible
- Minimize string allocations in hot paths

### Table Operations
- Pre-allocate tables with known sizes
- Use efficient iteration patterns
- Cache frequently accessed table values

### ngx.shared.dict Optimization
- Batch operations when possible
- Use appropriate expiration times
- Monitor memory usage and cleanup

### Lazy Evaluation
- Cache expensive computations
- Use conditional evaluation for costly operations
- Implement smart cache invalidation

## Benchmarking

### Running Performance Tests

```bash
# Basic performance test
curl -X POST http://localhost:8001/plugins \
  -d "name=kong-guard-ai" \
  -d "config.enable_benchmarking=true"

# Run comprehensive benchmark
./scripts/benchmark-configuration.sh

# Specific load test
wrk -t4 -c100 -d30s http://localhost:8000/test
```

### Benchmark Scenarios

1. **Baseline Test**: No plugin enabled
2. **Dry Run Test**: Plugin in monitoring mode
3. **Active Minimal**: Basic threat detection
4. **Active Full**: Complete threat analysis
5. **Stress Test**: High concurrency load

### Expected Results

| Scenario | RPS | Avg Latency | 99th Percentile | Overhead |
|----------|-----|-------------|-----------------|----------|
| Baseline | 5000+ | < 2ms | < 10ms | 0% |
| Dry Run | 4800+ | < 3ms | < 12ms | < 5% |
| Active Minimal | 4500+ | < 5ms | < 15ms | < 10% |
| Active Full | 4000+ | < 8ms | < 20ms | < 20% |

## Troubleshooting

### High Processing Time

1. **Check Circuit Breaker Status**
   ```bash
   curl http://localhost:8000/_guard_ai/health
   ```

2. **Review Performance Metrics**
   ```bash
   curl http://localhost:8000/_guard_ai/metrics | jq '.performance'
   ```

3. **Adjust Optimization Level**
   ```yaml
   config:
     performance:
       optimization_level: "minimal"
       sampling_rate: 0.001
   ```

### Memory Growth Issues

1. **Monitor Memory Trends**
   - Check dashboard for memory growth patterns
   - Review cleanup frequency
   - Validate cache sizes

2. **Adjust Cache Settings**
   ```yaml
   config:
     performance:
       cache_cleanup_interval: 500  # More frequent cleanup
       max_cache_size: 500          # Smaller cache size
   ```

### Circuit Breaker Activation

1. **Identify Root Cause**
   - Check recent performance metrics
   - Review error logs
   - Validate upstream performance

2. **Adjust Thresholds**
   ```yaml
   config:
     performance:
       max_processing_time_ms: 15   # Increase threshold
       circuit_breaker:
         failure_threshold: 10      # More lenient
   ```

## Best Practices

### Development
- Always benchmark changes against baseline
- Use minimal optimization during development
- Monitor memory usage during testing

### Production
- Start with balanced optimization
- Monitor performance dashboard regularly
- Set up alerts for threshold violations
- Schedule regular performance reviews

### Scaling
- Monitor per-worker memory usage
- Adjust worker count based on load
- Use external monitoring for trends
- Plan capacity based on benchmark results

## Integration with Monitoring Systems

### Prometheus Integration

```yaml
# Sample Prometheus scrape config
scrape_configs:
  - job_name: 'kong-guard-ai'
    static_configs:
      - targets: ['kong:8000']
    metrics_path: '/_guard_ai/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Key panels to include:
- Request processing time trends
- Memory usage over time
- Circuit breaker state changes
- Error rate correlation
- Performance recommendations

### Alerting Rules

```yaml
# Sample alerting rules
groups:
  - name: kong-guard-ai
    rules:
      - alert: HighProcessingTime
        expr: kong_guard_ai_avg_processing_time_ms > 8
        for: 5m
        
      - alert: CircuitBreakerOpen
        expr: kong_guard_ai_circuit_breaker_state == 1
        for: 1m
        
      - alert: MemoryGrowth
        expr: kong_guard_ai_memory_growth_mb > 50
        for: 10m
```

## Performance Optimization Roadmap

### Immediate Optimizations
- ✅ Request-level performance monitoring
- ✅ Circuit breaker implementation
- ✅ Memory usage tracking
- ✅ Performance dashboard

### Near-term Enhancements
- JIT compilation optimization
- Connection pooling improvements
- Advanced caching strategies
- ML-based performance prediction

### Long-term Goals
- Auto-scaling based on performance
- Predictive performance analytics
- Advanced anomaly detection
- Performance-based configuration tuning

## Support and Documentation

- **Performance Issues**: Check dashboard and adjust optimization level
- **Memory Leaks**: Review cleanup intervals and cache sizes
- **Circuit Breaker**: Investigate upstream issues and adjust thresholds
- **Benchmarking**: Use provided scripts and compare against baselines

For additional support, review the Kong Guard AI documentation and performance monitoring guides.