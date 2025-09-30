## JA3/JA4 TLS Fingerprinting — Detailed Task List

### Objectives
- Identify and enrich requests with JA3/JA4/JA3S/JA4S TLS fingerprints
- Use fingerprints in scoring, allow/block decisions, and rate limiting
- Provide metrics and operator controls; default safe rollout (observe-first)

### Prerequisites
- Ingress/sidecar populates headers where possible: `X-JA3`, `X-JA3S`, `X-JA4`, `X-JA4S`
- Optional: `X-TLS-Version`, `X-TLS-Cipher`, `X-TLS-ServerName`

---

### 1) Schema additions (config) [Task 6.1]
- [ ] Add `enable_tls_fingerprints` (boolean, default false)
- [ ] Add `tls_header_map` (record) with keys:
  - [ ] `ja3`
  - [ ] `ja3s`
  - [ ] `ja4`
  - [ ] `ja4s`
  - [ ] `tls_version`
  - [ ] `tls_cipher`
  - [ ] `sni`
- [ ] Add `tls_cache_ttl_seconds` (int, default 600)
- [ ] Add `tls_blocklist` (array<string>)
- [ ] Add `tls_allowlist` (array<string>)
- [ ] Add `tls_score_weights` (record) with fields:
  - [ ] `match_blocklist` (number, default +0.7)
  - [ ] `match_allowlist` (number, default -0.4)
  - [ ] `ua_mismatch` (number, default +0.2)
  - [ ] `rare_fingerprint` (number, default +0.2)
  - [ ] `velocity` (number, default +0.3)
- [ ] Add `tls_rare_fp_min_ips` (int, default 5)
- [ ] Add `tls_rate_limit_per_fp` (int per minute, default 120)
- [ ] Validate defaults and descriptions

---

### 2) Module: `tls_enricher.lua` [Task 6.2]
- [ ] Create module scaffold and exports
- [ ] Implement `read_headers(request, config)`
  - [ ] Resolve actual header names from `tls_header_map`
  - [ ] Extract values: `ja3`, `ja3s`, `ja4`, `ja4s`, optional `tls_version`, `tls_cipher`, `sni`
- [ ] Implement `normalize(value)`
  - [ ] Validate hex-ish tokens, strip spaces, lowercase
  - [ ] Defensive length/charset checks
- [ ] Implement `enrich(fp_set)`
  - [ ] Return `{ ja3, ja3s, ja4, ja4s, tls_version, tls_cipher, sni, valid = true/false }`
- [ ] Implement shared cache integration (using `ngx.shared.kong_cache`)
  - [ ] `cache_get(key)` / `cache_set(key, value, ttl)` with TTL from config
- [ ] Unit tests for header parsing, normalization, enrich

---

### 3) Handler integration [Task 6.3]
- [ ] Wire `tls_enricher` into access/feature extraction when `enable_tls_fingerprints` is true
- [ ] Populate `features.tls = { ja3, ja3s, ja4, ja4s, tls_version, tls_cipher, sni }`
- [ ] Persist counters in `ngx.shared.kong_cache`:
  - [ ] `tls_fp_count:<fp>` increments per request
  - [ ] `tls_fp_unique_ip:<fp>:<window>` approximate uniqueness tracking
- [ ] Include TLS section in `kong.ctx.plugin.threat_data`

---

### 4) Threat intel matching & scoring [Task 6.4]
- [ ] Exact and wildcard matching against `tls_blocklist` and `tls_allowlist`
  - [ ] `*` wildcard support (prefix/suffix)
- [ ] Scoring rules:
  - [ ] Blocklist match → add `match_blocklist` to score (e.g., +0.7)
  - [ ] Allowlist match → add `match_allowlist` (negative); floor at 0
- [ ] Annotate `threat_type` as `tls_blocklisted`/`tls_allowlisted` when applicable
- [ ] Prepare extension hook for TAXII-driven updates

---

### 5) Heuristics & anomaly scoring [Task 6.5]
- [ ] UA-to-JA3 plausibility map (small curated set for major browsers)
  - [ ] If mismatch → add `ua_mismatch`
- [ ] Rare fingerprint detection
  - [ ] If `unique_ips(fp)` < `tls_rare_fp_min_ips` and traffic rising → add `rare_fingerprint`
- [ ] Velocity per fingerprint
  - [ ] If RPM for fingerprint > `tls_rate_limit_per_fp` → add `velocity` and/or set `threat_type = "tls_fp_rate_limited"`

---

### 6) Metrics [Task 6.6]
- [ ] Counters: per-fingerprint hits, per-fingerprint unique IPs/window
- [ ] Optional: minute cron (timer) log of top-K fingerprints (rate-limited)
- [ ] Include in existing totals (e.g., `threats_detected`)

---

### 7) Documentation [Task 6.7]
- [ ] User guide updates:
  - [ ] Header contract and expected deployment topologies (edge vs sidecar)
  - [ ] Config reference with examples
  - [ ] Privacy/PII notes and roll-out guidance (observe-first)
- [ ] Changelog entry

---

### 8) Testing [Task 6.8]
- [ ] Unit tests
  - [ ] Normalization: valid/invalid tokens
  - [ ] Matching: exact/wildcard/blocklist/allowlist
  - [ ] Heuristics: UA mismatch, rarity, velocity
- [ ] Integration tests (kong-pongo)
  - [ ] Inject headers and assert features/scoring/limits
  - [ ] Negative cases: missing headers, malformed values
- [ ] Performance checks (cache effectiveness, minimal overhead)

---

### 9) Rollout strategy
- [ ] Phase 1: enable feature, log-only (weights low), no enforcement
- [ ] Phase 2: enable per-fingerprint rate limiting
- [ ] Phase 3: enforce blocklist (production)

---

### Acceptance criteria
- [ ] With valid headers, `features.tls` is populated and present in logs/notifications
- [ ] Blocklist match elevates score above block threshold (when enforcement enabled)
- [ ] Per-fingerprint rate limit works at configured threshold
- [ ] Graceful no-op when headers missing; no error logs
- [ ] Unit + integration tests green in CI
