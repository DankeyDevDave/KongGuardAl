# Kong Guard AI - Operational Runbook

**Purpose**: Comprehensive guide for diagnosing and resolving Kong Guard AI operational issues  
**Audience**: SRE, DevOps, Support Engineers  
**Last Updated**: 2024

---

## Quick Reference - Common Issues

| Symptom | Likely Cause | Quick Fix | Runbook Section |
|---------|--------------|-----------|-----------------|
| High latency (>2s) | LLM provider slow/down | Check provider health, failover | [RB-001](#rb-001-llm-provider-degradation) |
| Requests blocked unexpectedly | Policy misconfiguration | Check policy thresholds | [RB-002](#rb-002-unexpected-blocking) |
| Cache miss rate >80% | Cache poisoning or version mismatch | Check cache health | [RB-003](#rb-003-cache-performance-degradation) |
| "Quota exceeded" errors | Provider quota limits hit | Check circuit breaker status | [RB-004](#rb-004-provider-quota-exhaustion) |
| False positives spike | Model drift or new attack patterns | Review feedback, adjust thresholds | [RB-005](#rb-005-false-positive-rate-spike) |
| Memory usage growing | Cache not evicting properly | Check cache size limits | [RB-006](#rb-006-memory-leak) |
| PII leaked in logs | PII scrubber misconfigured | Verify scrubber settings | [RB-007](#rb-007-pii-leakage) |
| Feedback not working | JWT token expired/invalid | Check authentication | [RB-008](#rb-008-feedback-endpoint-failures) |

---

## RB-001: LLM Provider Degradation

### Symptoms
- Response times >2 seconds
- Timeout errors in logs
- Circuit breaker state = OPEN
- `X-GuardAI-Provider` header showing fallback provider

### Diagnosis

**1. Check Circuit Breaker Status**
```bash
# Get provider health status
curl http://localhost:8000/api/admin/circuit-breaker/status

# Look for:
# - circuit_state: "open" or "half_open"
# - failure_count > threshold
# - recent errors
```

**2. Check Provider Response Times**
```bash
# Check metrics
curl http://localhost:8000/api/admin/metrics | jq '.provider_metrics'

# Look for:
# - p95_latency_ms > 2000
# - p99_latency_ms > 5000
# - success_rate < 95%
```

**3. Check Provider API Status**
```bash
# OpenAI
curl https://status.openai.com/api/v2/status.json

# Gemini
curl https://status.cloud.google.com/

# Groq (check their status page)
```

### Resolution Steps

**Immediate Actions**:
1. **Force Provider Failover**
```python
# Via admin API
curl -X POST http://localhost:8000/api/admin/circuit-breaker/openai/open \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

2. **Adjust Provider Priority**
```python
# Temporarily prioritize faster provider
curl -X PUT http://localhost:8000/api/admin/config/provider-priority \
  -H "Content-Type: application/json" \
  -d '{"priority": "speed", "excluded_providers": ["openai"]}'
```

3. **Increase Timeout Thresholds** (if all providers slow)
```python
# Adjust timeout in config
curl -X PUT http://localhost:8000/api/admin/config/timeout \
  -d '{"timeout_seconds": 10}'
```

**Long-term Solutions**:
- Set up monitoring alerts for provider latency
- Implement multi-region provider endpoints
- Add more provider fallback options
- Consider caching more aggressively

### Verification
```bash
# Monitor for 5 minutes
watch -n 10 'curl -s http://localhost:8000/api/admin/metrics | jq ".provider_metrics[] | select(.circuit_state == \"closed\")"'

# Expected: circuit_state returns to "closed", latency < 1000ms
```

### Escalation
If provider is down >30 minutes:
- Contact provider support
- Consider temporary dry-run mode
- Notify customers of degraded service

---

## RB-002: Unexpected Blocking

### Symptoms
- Legitimate requests blocked
- Users reporting access denied
- `X-GuardAI-Action: block` in headers
- `X-GuardAI-Score` higher than expected

### Diagnosis

**1. Check Specific Request**
```bash
# Get request details from logs
grep "REQUEST_BLOCKED" /var/log/kong-guard-ai/access.log | tail -1

# Or via API
curl "http://localhost:8000/api/admin/requests/{request_id}"
```

**2. Review Policy Configuration**
```bash
# Check which policy matched
curl http://localhost:8000/api/admin/policies | jq '.policies[] | select(.endpoint_pattern == "/api/your-path/*")'

# Check thresholds
# - block_threshold: Should be 0.7-0.8 for normal endpoints
# - Is dry_run_mode: false?
```

**3. Check Threat Analysis**
```bash
# Review the analysis reasoning
curl "http://localhost:8000/api/admin/analysis/{request_id}" | jq '.reasoning'

# Check indicators
jq '.indicators[]'
```

### Resolution Steps

**Immediate Actions**:
1. **Enable Dry-Run Mode** (stop blocking while investigating)
```bash
# For specific endpoint
curl -X PUT http://localhost:8000/api/admin/policies/api-users \
  -H "Content-Type: application/json" \
  -d '{"dry_run_mode": true}'

# For all endpoints (emergency)
curl -X PUT http://localhost:8000/api/admin/config/global-dry-run \
  -d '{"enabled": true}'
```

2. **Adjust Policy Threshold**
```bash
# Increase block threshold for endpoint
curl -X PUT http://localhost:8000/api/admin/policies/api-users \
  -d '{"block_threshold": 0.85}' # Was 0.7
```

3. **Add to Allowlist** (if specific client)
```bash
# Add IP to allowlist
curl -X POST http://localhost:8000/api/admin/policies/api-users/allowlist \
  -d '{"ip_address": "203.0.113.10"}'
```

**Long-term Solutions**:
- Submit false positive feedback
- Retrain model with feedback data
- Add exception patterns
- Review and tune policies monthly

### Verification
```bash
# Test the previously blocked request
curl -H "X-GuardAI-DryRun: true" http://your-api/endpoint

# Check headers:
# X-GuardAI-WouldBlock: false (should be false now)
# X-GuardAI-Score: <0.7 (should be below threshold)
```

### Prevention
- Use dry-run mode when deploying new policies
- Monitor false positive rate daily
- Set up alerts for FP rate >5%
- Regular policy reviews

---

## RB-003: Cache Performance Degradation

### Symptoms
- Cache hit rate <50% (normally >70%)
- Higher LLM costs
- Increased latency
- `invalid_signatures` metric increasing
- `version_mismatches` errors

### Diagnosis

**1. Check Cache Health**
```bash
# Get cache statistics
curl http://localhost:8000/api/admin/cache/stats

# Look for:
# - cache_hit_rate < 0.5
# - poisoning_attempts_blocked > 0
# - version_mismatches > 0
```

**2. Check Cache Tier Health**
```bash
# Per-tier metrics
curl http://localhost:8000/api/admin/cache/stats | jq '.tier_health'

# Look for:
# - precision < 0.8 (too many false positives cached)
# - recall < 0.7 (missing valid threats)
```

**3. Check for Version Mismatch**
```bash
# Check current versions
curl http://localhost:8000/api/admin/cache/stats | jq '.versions'

# Compare to expected:
# - signature: "1.0.0"
# - model: "1.0.0"
```

### Resolution Steps

**Immediate Actions**:
1. **Clear Invalid Cache Entries**
```bash
# Flush all caches (nuclear option)
curl -X POST http://localhost:8000/api/admin/cache/flush

# Or flush specific tier
curl -X POST http://localhost:8000/api/admin/cache/flush/signature
```

2. **Update Version Binding** (if version changed)
```bash
# Update cache to new version
curl -X PUT http://localhost:8000/api/admin/cache/version \
  -d '{"signature_version": "1.1.0", "model_version": "1.0.0"}'
```

3. **Investigate Poisoning Attempts**
```bash
# Get recent poisoning attempts
curl http://localhost:8000/api/admin/cache/poisoning-attempts

# Review suspicious IPs/patterns
# Consider blocking source
```

**Long-term Solutions**:
- Implement cache warming after deployments
- Monitor cache health metrics
- Set up alerts for hit rate <60%
- Regular cache audits

### Verification
```bash
# Monitor cache hit rate recovery
watch -n 30 'curl -s http://localhost:8000/api/admin/cache/stats | jq ".cache_hit_rate"'

# Expected: Hit rate recovers to >0.7 within 1 hour
```

### Prevention
- Always update cache versions after model deployments
- Use signed cache entries (already implemented)
- Monitor poisoning attempts
- Regular cache health checks

---

## RB-004: Provider Quota Exhaustion

### Symptoms
- "Rate limit exceeded" errors
- `X-GuardAI-Provider` switching frequently
- Circuit breaker showing quota errors
- Requests queuing/timing out

### Diagnosis

**1. Check Current Quota Usage**
```bash
# Get quota status for all providers
curl http://localhost:8000/api/admin/circuit-breaker/status | jq '.[] | {provider: .provider, rpm: .quota.rpm_used, tpm: .quota.tpm_used}'

# Look for:
# - rpm_used close to limit
# - tpm_used close to limit
```

**2. Check Request Rate**
```bash
# Get current RPS
curl http://localhost:8000/api/admin/metrics | jq '.requests_per_second'

# Calculate: RPS * 60 = RPM needed
# Compare to provider RPM limits
```

**3. Identify High-Volume Endpoints**
```bash
# Get top endpoints by request count
curl http://localhost:8000/api/admin/analytics/top-endpoints | jq '.[] | {path, count, cache_hit_rate}'

# Look for:
# - High count with low cache_hit_rate
# - Endpoints that should be cached
```

### Resolution Steps

**Immediate Actions**:
1. **Enable Aggressive Caching**
```bash
# Increase cache TTLs
curl -X PUT http://localhost:8000/api/admin/cache/config \
  -d '{"signature_ttl": 604800, "behavioral_ttl": 86400}'

# Enable negative caching
curl -X PUT http://localhost:8000/api/admin/cache/config \
  -d '{"enable_negative_cache": true, "negative_ttl": 7200}'
```

2. **Rate Limit High-Volume Clients**
```bash
# Add rate limit to problematic endpoint
curl -X PUT http://localhost:8000/api/admin/policies/high-volume-path \
  -d '{"rate_limit_rpm": 50}'
```

3. **Disable LLM for Low-Risk Endpoints**
```bash
# Disable LLM analysis for static/public endpoints
curl -X PUT http://localhost:8000/api/admin/policies/static \
  -d '{"enable_llm_analysis": false}'
```

**Long-term Solutions**:
- Upgrade provider tier/quota
- Add more LLM providers
- Implement request prioritization
- Optimize cache strategy

### Verification
```bash
# Monitor quota usage
watch -n 60 'curl -s http://localhost:8000/api/admin/circuit-breaker/status | jq ".[].quota"'

# Expected: Usage stays below 80% of limits
```

### Cost Impact
Track cost per day:
```bash
curl http://localhost:8000/api/admin/metrics | jq '.cost_per_day_usd'

# Alert if >expected budget
```

---

## RB-005: False Positive Rate Spike

### Symptoms
- Feedback reports showing >10% false positives
- User complaints about blocking
- `X-GuardAI-FP-URL` being used frequently
- Dashboard showing FP trend upward

### Diagnosis

**1. Check False Positive Rate**
```bash
# Get FP metrics
curl http://localhost:8000/api/admin/feedback/stats | jq '.false_positive_rate'

# Normal: <5%
# Warning: 5-10%
# Critical: >10%
```

**2. Analyze FP Patterns**
```bash
# Get recent false positives
curl http://localhost:8000/api/admin/feedback/false-positives?limit=100 | jq '.[] | {threat_type, reasoning, operator_consensus}'

# Look for patterns:
# - Same threat_type repeatedly
# - Specific endpoint patterns
# - Specific threat indicators
```

**3. Review Operator Feedback**
```bash
# Get consensus from trusted operators
curl http://localhost:8000/api/admin/feedback/consensus | jq '.[] | select(.false_positive_weight > .true_positive_weight)'
```

### Resolution Steps

**Immediate Actions**:
1. **Adjust Problematic Threat Thresholds**
```bash
# If SQL injection showing many FPs
curl -X PUT http://localhost:8000/api/admin/policies/api-db \
  -d '{"threat_actions": {"sql_injection": "log_only"}}'
```

2. **Add Exception Patterns**
```bash
# Add known-safe patterns
curl -X POST http://localhost:8000/api/admin/exceptions \
  -d '{"pattern": "SELECT.*FROM graphql", "threat_type": "sql_injection", "reason": "GraphQL introspection"}'
```

3. **Enable Dry-Run While Investigating**
```bash
curl -X PUT http://localhost:8000/api/admin/policies/problematic-endpoint \
  -d '{"dry_run_mode": true}'
```

**Long-term Solutions**:
- Retrain ML model with feedback
- Update threat signatures
- Implement context-aware detection
- Regular feedback review sessions

### Verification
```bash
# Monitor FP rate over next 24 hours
curl http://localhost:8000/api/admin/feedback/stats?window=24h | jq '.false_positive_rate'

# Expected: FP rate drops below 5%
```

### Prevention
- Weekly feedback review
- Monthly model retraining
- Operator training on feedback quality
- A/B test policy changes

---

## RB-006: Memory Leak

### Symptoms
- Kong/plugin memory usage growing continuously
- OOMKilled pods/containers
- Cache size exceeding limits
- Slow garbage collection

### Diagnosis

**1. Check Memory Usage**
```bash
# Container memory
docker stats kong-guard-ai --no-stream

# Or Kubernetes
kubectl top pod -l app=kong-guard-ai
```

**2. Check Cache Sizes**
```bash
# Get cache sizes
curl http://localhost:8000/api/admin/cache/stats | jq '{
  signature_cache: .signature_cache_size,
  behavioral_cache: .behavioral_cache_size,
  response_cache: .response_cache_size,
  negative_cache: .negative_cache_size,
  total: (.signature_cache_size + .behavioral_cache_size + .response_cache_size + .negative_cache_size)
}'

# Compare to limits:
# - signature_cache: max 10000
# - behavioral_cache: max 5000
# - response_cache: max 1000
# - negative_cache: max 2000
```

**3. Check for Leaked Objects**
```bash
# Get object counts (Python)
curl http://localhost:8000/api/admin/debug/objects | jq '.top_objects'
```

### Resolution Steps

**Immediate Actions**:
1. **Flush Caches**
```bash
# Emergency cache flush
curl -X POST http://localhost:8000/api/admin/cache/flush
```

2. **Reduce Cache Limits**
```bash
# Temporarily reduce limits
curl -X PUT http://localhost:8000/api/admin/cache/config \
  -d '{"max_signature_cache": 5000, "max_behavioral_cache": 2000}'
```

3. **Restart Service** (if critical)
```bash
# Kubernetes
kubectl rollout restart deployment/kong-guard-ai

# Docker
docker restart kong-guard-ai
```

**Long-term Solutions**:
- Implement cache size monitoring
- Add memory limits to containers
- Review cache eviction policies
- Profile memory usage

### Verification
```bash
# Monitor memory for 1 hour
watch -n 300 'docker stats kong-guard-ai --no-stream | grep kong-guard-ai'

# Expected: Memory stable or decreasing
```

### Prevention
- Set container memory limits
- Alert on memory >80%
- Regular memory profiling
- Automated cache cleanup

---

## RB-007: PII Leakage

### Symptoms
- PII found in logs/monitoring
- GDPR/compliance alerts
- Audit findings
- User data exposed to LLM providers

### Diagnosis

**1. Check PII Scrubber Status**
```bash
# Verify scrubber is enabled
curl http://localhost:8000/api/admin/config/pii-scrubber | jq '.enabled'

# Expected: true
```

**2. Check Scrubber Statistics**
```bash
# Get scrubbing stats
curl http://localhost:8000/api/admin/pii-scrubber/stats | jq '{
  enabled: .enabled,
  patterns_loaded: .patterns_loaded,
  categories: .pattern_categories
}'
```

**3. Review Recent Logs for PII**
```bash
# Search for email patterns in logs (should be none)
grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /var/log/kong-guard-ai/*.log

# Search for phone patterns
grep -E '\([0-9]{3}\) [0-9]{3}-[0-9]{4}' /var/log/kong-guard-ai/*.log
```

### Resolution Steps

**Immediate Actions**:
1. **Enable PII Scrubber** (if disabled)
```bash
curl -X PUT http://localhost:8000/api/admin/config/pii-scrubber \
  -d '{"enabled": true}'
```

2. **Update Policy to Enforce Scrubbing**
```bash
# Ensure all policies have PII scrubbing
curl -X PUT http://localhost:8000/api/admin/policies/ALL \
  -d '{"enable_pii_scrubbing": true, "pii_exclude_categories": []}'
```

3. **Rotate Logs** (remove exposed PII)
```bash
# Archive and truncate logs with PII
mv /var/log/kong-guard-ai/access.log /secure/archive/access.log.$(date +%Y%m%d)
truncate -s 0 /var/log/kong-guard-ai/access.log
```

**Long-term Solutions**:
- Implement log scrubbing at ingestion
- Add PII detection patterns
- Regular compliance audits
- Training for operators

### Verification
```bash
# Test PII scrubbing
curl -X POST http://localhost:8000/test-endpoint \
  -d '{"email": "test@example.com", "phone": "(555) 123-4567"}'

# Check logs - should see:
# email: "<EMAIL_REDACTED>"
# phone: "<PHONE_REDACTED>"
```

### Incident Response
If PII was leaked:
1. Notify DPO/legal team
2. Assess scope of exposure
3. Notify affected users (if required)
4. File incident report
5. Implement corrective actions

---

## RB-008: Feedback Endpoint Failures

### Symptoms
- 401 Unauthorized errors
- Feedback submissions failing
- `X-GuardAI-FP-URL` not working
- Operators unable to report issues

### Diagnosis

**1. Check Authentication**
```bash
# Verify JWT token
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8000/api/feedback/validate-token

# Expected: 200 OK with operator info
```

**2. Check Operator Permissions**
```bash
# Get operator role
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8000/api/feedback/me | jq '.role'

# Verify role is not "viewer" (viewers can't submit)
```

**3. Check Rate Limiting**
```bash
# Check if rate limited
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8000/api/feedback/limits | jq '{
  limit: .max_feedback_per_hour,
  current: .current_count,
  remaining: .remaining
}'
```

### Resolution Steps

**Immediate Actions**:
1. **Generate New JWT Token**
```bash
# Generate fresh token for operator
curl -X POST http://localhost:8000/api/admin/operators/generate-token \
  -d '{"email": "analyst@company.com"}' | jq '.token'
```

2. **Increase Rate Limit** (if hit limit)
```bash
# Temporarily increase limit
curl -X PUT http://localhost:8000/api/admin/feedback/config \
  -d '{"max_feedback_per_hour": 100}'
```

3. **Upgrade Operator Role** (if permission issue)
```bash
# Upgrade viewer to analyst
curl -X PUT http://localhost:8000/api/admin/operators/user@company.com \
  -d '{"role": "analyst"}'
```

**Long-term Solutions**:
- Implement token refresh mechanism
- Add operator self-service portal
- Monitor rate limit hits
- Regular permission audits

### Verification
```bash
# Test feedback submission
curl -X POST http://localhost:8000/api/feedback/report-fp \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -d '{
    "request_id": "test_123",
    "feedback_type": "false_positive",
    "reason": "Test submission"
  }'

# Expected: 200 OK with feedback_id
```

---

## Monitoring & Alerting

### Key Metrics to Monitor

**Performance Metrics**:
```
- Request latency (p50, p95, p99)
- Throughput (requests/second)
- Cache hit rate
- Provider response time
```

**Security Metrics**:
```
- Threat detection rate
- False positive rate
- Block rate
- Cache poisoning attempts
```

**Operational Metrics**:
```
- Circuit breaker state
- Provider quota usage
- Memory usage
- Cache size
```

### Recommended Alerts

**Critical**:
```
- All LLM providers down (page on-call)
- Memory usage >90% (page on-call)
- PII detected in logs (immediate escalation)
- False positive rate >20% (page on-call)
```

**Warning**:
```
- Provider latency >2s (notify team)
- Cache hit rate <60% (notify team)
- Circuit breaker open >5min (notify team)
- Provider quota >80% (notify team)
```

**Info**:
```
- Policy changes (log only)
- New operator added (log only)
- Cache flushed (log only)
```

### Health Check Endpoints

```bash
# Overall health
curl http://localhost:8000/health

# Component health
curl http://localhost:8000/health/detailed | jq '{
  overall: .status,
  llm_providers: .components.llm_providers,
  cache: .components.cache,
  feedback: .components.feedback
}'
```

---

## Troubleshooting Tools

### Debug Mode
```bash
# Enable debug logging
curl -X PUT http://localhost:8000/api/admin/config/log-level \
  -d '{"level": "DEBUG"}'

# Remember to disable after troubleshooting!
```

### Request Tracing
```bash
# Trace specific request through system
curl -H "X-GuardAI-Trace: true" http://your-api/endpoint

# Check trace in logs
grep "TRACE_ID" /var/log/kong-guard-ai/debug.log
```

### Admin Dashboard
```bash
# Access admin dashboard
open http://localhost:8000/admin/dashboard

# Includes:
# - Real-time metrics
# - Provider health
# - Cache statistics
# - Recent alerts
```

---

## Escalation Paths

### Level 1 (Support Engineer)
- Follow runbooks above
- Check monitoring dashboards
- Review recent changes
- Attempt standard fixes

### Level 2 (SRE)
- Deep dive into logs
- Performance profiling
- Infrastructure scaling
- Code-level debugging

### Level 3 (Engineering)
- Code fixes required
- Architecture changes
- Provider escalation
- Incident post-mortem

---

## Post-Incident Actions

After resolving any incident:

1. **Document Resolution**
   - Update runbook if needed
   - Add to knowledge base
   - Share learnings with team

2. **Implement Preventions**
   - Add monitoring/alerts
   - Improve automation
   - Update policies

3. **Conduct Post-Mortem** (for P0/P1)
   - Root cause analysis
   - Timeline of events
   - Action items

4. **Test Recovery Procedures**
   - Verify fixes work
   - Document new procedures
   - Update automation

---

## Additional Resources

- [Kong Guard AI Documentation](../README.md)
- [Security Hardening Guide](../SECURITY_HARDENING_COMPLETE.md)
- [API Reference](../docs/API_REFERENCE.md)
- [Monitoring Setup](../docs/MONITORING.md)

---

**Document Version**: 1.0  
**Last Reviewed**: 2024  
**Next Review**: Quarterly
