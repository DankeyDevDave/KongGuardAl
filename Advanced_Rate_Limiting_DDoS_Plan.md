## Advanced Rate Limiting & DDoS Protection — Detailed Task List

### Objectives
- Implement adaptive rate limiting based on threat scores
- Add DDoS mitigation with challenge-response mechanisms
- Provide geographic rate limiting and advanced circuit breakers

---

### 1) Schema additions (config) [Task 11B.1]
- [ ] Add `enable_adaptive_rate_limiting` (boolean, default false)
- [ ] Add `adaptive_rate_config` (record):
  - [ ] `base_rate_per_minute` (int, default 60)
  - [ ] `threat_score_multiplier` (number, default 2.0)
  - [ ] `min_rate_per_minute` (int, default 5)
  - [ ] `max_rate_per_minute` (int, default 1000)
- [ ] Add `ddos_protection` (record):
  - [ ] `enable_ddos_mitigation` (boolean, default false)
  - [ ] `ddos_threshold_rps` (int, default 100)
  - [ ] `challenge_response_enabled` (boolean, default true)
  - [ ] `challenge_timeout_seconds` (int, default 30)
- [ ] Add `geographic_limiting` (record):
  - [ ] `enable_geo_limiting` (boolean, default false)
  - [ ] `geo_rate_limits` (array<record>):
    - [ ] `country_code` (string)
    - [ ] `rate_per_minute` (int)
- [ ] Add `circuit_breakers` (record):
  - [ ] `enable_circuit_breakers` (boolean, default false)
  - [ ] `failure_threshold` (int, default 5)
  - [ ] `recovery_timeout_seconds` (int, default 60)

---

### 2) Adaptive rate limiter `adaptive_rate_limiter.lua` [Task 11B.2]
- [ ] Create module scaffold and exports
- [ ] Implement threat-based rate calculation:
  - [ ] Adjust rate based on threat score
  - [ ] Apply min/max bounds
  - [ ] Smooth rate changes to avoid oscillation
- [ ] Implement rate tracking:
  - [ ] Per-IP rate counters with sliding windows
  - [ ] Rate history for trend analysis
- [ ] Implement rate limit enforcement:
  - [ ] Check current rate against calculated limit
  - [ ] Return rate limit status and remaining quota
- [ ] Unit tests for rate calculation and enforcement

---

### 3) DDoS mitigation `ddos_mitigator.lua` [Task 11B.3]
- [ ] Create module scaffold and exports
- [ ] Implement DDoS detection:
  - [ ] Global RPS monitoring
  - [ ] Per-IP RPS analysis
  - [ ] Pattern recognition for attack signatures
- [ ] Implement challenge-response:
  - [ ] Generate cryptographic challenges
  - [ ] Validate challenge responses
  - [ ] Challenge difficulty adjustment
- [ ] Implement mitigation actions:
  - [ ] Temporary IP blocking
  - [ ] Challenge requirement enforcement
  - [ ] Traffic shaping
- [ ] Unit tests for DDoS detection and mitigation

---

### 4) Geographic rate limiter `geo_rate_limiter.lua` [Task 11B.4]
- [ ] Create module scaffold and exports
- [ ] Implement IP geolocation:
  - [ ] Integration with GeoIP database
  - [ ] Fallback for unknown locations
- [ ] Implement country-based rate limiting:
  - [ ] Per-country rate limits
  - [ ] Rate tracking by country
- [ ] Implement geographic anomaly detection:
  - [ ] Unusual geographic patterns
  - [ ] Cross-border attack detection
- [ ] Unit tests for geolocation and rate limiting

---

### 5) Circuit breaker `circuit_breaker.lua` [Task 11B.5]
- [ ] Create module scaffold and exports
- [ ] Implement circuit states:
  - [ ] Closed (normal operation)
  - [ ] Open (circuit tripped)
  - [ ] Half-open (testing recovery)
- [ ] Implement failure tracking:
  - [ ] Failure count and rate monitoring
  - [ ] Success rate calculation
- [ ] Implement recovery logic:
  - [ ] Automatic recovery attempts
  - [ ] Gradual traffic restoration
- [ ] Unit tests for circuit breaker logic

---

### 6) Handler integration [Task 11B.6]
- [ ] Wire adaptive rate limiter into access phase
- [ ] Wire DDoS mitigator into threat detection
- [ ] Wire geographic limiter into rate limiting
- [ ] Wire circuit breakers into request processing
- [ ] Add rate limiting features to `features` table:
  - [ ] `adaptive_rate_limit`
  - [ ] `ddos_risk_score`
  - [ ] `geo_rate_limit`
  - [ ] `circuit_breaker_state`
- [ ] Include rate limiting results in `threat_details`

---

### 7) Advanced response mechanisms [Task 11B.7]
- [ ] Implement challenge pages:
  - [ ] JavaScript-based challenges
  - [ ] CAPTCHA integration (optional)
  - [ ] Progressive challenge difficulty
- [ ] Implement traffic shaping:
  - [ ] Bandwidth limiting
  - [ ] Request queuing
  - [ ] Priority-based processing
- [ ] Implement graceful degradation:
  - [ ] Service availability during attacks
  - [ ] Essential function preservation

---

### 8) Metrics and monitoring [Task 11B.8]
- [ ] Add rate limiting metrics:
  - [ ] Rate limit violations
  - [ ] Adaptive rate adjustments
  - [ ] Geographic distribution
- [ ] Add DDoS metrics:
  - [ ] Attack detection counts
  - [ ] Challenge success rates
  - [ ] Mitigation effectiveness
- [ ] Add circuit breaker metrics:
  - [ ] Circuit state changes
  - [ ] Failure rates
  - [ ] Recovery times

---

### 9) Documentation and testing [Task 11B.9]
- [ ] Documentation:
  - [ ] Rate limiting configuration guide
  - [ ] DDoS protection setup
  - [ ] Geographic limiting examples
- [ ] Testing:
  - [ ] Unit tests for all rate limiting modules
  - [ ] Load testing for DDoS scenarios
  - [ ] Integration tests for circuit breakers

---

### Acceptance criteria
- [ ] Adaptive rate limiting adjusts based on threat scores
- [ ] DDoS mitigation detects and responds to attacks
- [ ] Geographic rate limiting works per country
- [ ] Circuit breakers protect against cascading failures
- [ ] All rate limiting mechanisms integrate seamlessly
- [ ] Performance impact is minimal during normal operation
- [ ] All tests pass and documentation is complete
