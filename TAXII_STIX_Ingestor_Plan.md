## TAXII/STIX Feed Ingestor — Detailed Task List

### Objectives
- Ingest STIX indicators from TAXII 2.x feeds.
- Normalize indicators to internal sets (IP/Domain/URL/Regex/JA3/JA4).
- Enrich detection pipeline and scoring with block/allow matches.
- Keep runtime overhead low via shared cache and incremental polling.

### Prerequisites
- Identify TAXII server(s), collections, and credentials.
- Confirm network access from Kong nodes to TAXII endpoints.

---

### 1) Schema additions (config) [Task 7.1]
- [ ] Add `enable_taxii_ingestion` (boolean, default false)
- [ ] Add `taxii_version` (string: "2.0"|"2.1", default "2.1")
- [ ] Add `taxii_servers` (array<record>):
  - [ ] `url` (string)
  - [ ] `collections` (array<string>)
  - [ ] `auth_type` (string: "none"|"basic"|"bearer")
  - [ ] `username` (string, optional)
  - [ ] `password` (string, optional)
  - [ ] `token` (string, optional)
- [ ] Add `taxii_poll_interval_seconds` (int, default 300)
- [ ] Add `taxii_cache_ttl_seconds` (int, default 3600)
- [ ] Add `taxii_max_objects_per_poll` (int, default 500)
- [ ] Add `taxii_http_timeout_ms` (int, default 2000)
- [ ] Add `taxii_retry_backoff_ms` (record: initial=200, max=5000, factor=2)
- [ ] Add `taxii_enable_dedup` (boolean, default true)
- [ ] Add `taxii_tls_insecure_skip_verify` (boolean, default false)
- [ ] Add `taxii_proxy_url` (string, optional)
- [ ] Update descriptions and defaults

---

### 2) TAXII client module `taxii_client.lua` [Task 7.2]
- [ ] Scaffold module and exports
- [ ] Discovery endpoints (2.0 vs 2.1)
  - [ ] `/taxii/` root discovery
  - [ ] Collections list per server
- [ ] Objects polling
  - [ ] Support filters: `added_after`, `limit`, `next`/pagination
  - [ ] Cursor maintenance per collection
- [ ] Auth
  - [ ] Basic and Bearer support (headers)
- [ ] Resilience
  - [ ] Retries with exponential backoff
  - [ ] Timeouts from config
  - [ ] Structured errors and logging
- [ ] Unit tests (mock HTTP)

---

### 3) STIX normalizer `stix_normalizer.lua` [Task 7.3]
- [ ] Parse indicator SDOs (type: `indicator`, `pattern` field)
- [ ] Extract common IoCs and normalize:
  - [ ] IPv4/IPv6 addresses (and CIDRs when available)
  - [ ] Domain names (IDNA handling)
  - [ ] URLs (normalized path/query)
  - [ ] File hashes (md5/sha1/sha256) — store but not matched initially
  - [ ] Regex indicators (safe compile; sandbox or filter)
  - [ ] JA3/JA3S/JA4/JA4S (via pattern conventions)
- [ ] Validate and canonicalize each type
- [ ] Produce internal sets `{ ip_set, cidr_set, domain_set, url_set, regex_set, ja3_set, ja4_set }`
- [ ] Record validity windows (valid_from/until) when present
- [ ] Unit tests for parsing and normalization

---

### 4) Cache bridge `taxii_cache.lua` [Task 7.4]
- [ ] Shared dict layout (versioned namespace):
  - [ ] `taxii:version` (current working set id)
  - [ ] `taxii:<version>:type:<key>` for each indicator
- [ ] Atomic swap on update
  - [ ] Build new working set; swap `taxii:version` atomically
  - [ ] GC previous set after grace period
- [ ] Access helpers: `contains_ip/domain/url/regex/ja3/ja4`
- [ ] Memory and key-space budgeting
- [ ] Unit tests (swap, lookups, GC)

---

### 5) Detection hook integration [Task 7.5]
- [ ] In `handler.lua:detect_threat` add lookups when enabled
  - [ ] IP (client_ip), domain/URL (from normalized path/query), JA3/JA4 (from TLS features)
- [ ] Scoring/decision rules
  - [ ] Blocklist match → raise score (configurable weight) and set `threat_type = "taxii_blocklisted"`
  - [ ] Allowlist match → lower score (configurable negative weight)
  - [ ] Optional early block for high-confidence indicators
- [ ] Annotate `threat_details.taxii = { matches = [...], server = ..., collection = ... }`
- [ ] Unit tests (mock cache)

---

### 6) Scheduler & state [Task 7.6]
- [ ] Timer to poll periodically (`ngx.timer.at`)
- [ ] Maintain `added_after` per server/collection in shared dict
- [ ] Metrics & health
  - [ ] `taxii_polls_total`, `taxii_errors_total`, `taxii_indicators_loaded`
  - [ ] `taxii_last_success_ts` per collection
- [ ] Backoff on repeated failures
- [ ] Integration test (with client + cache)

---

### 7) Documentation [Task 7.7]
- [ ] User guide section: configuration, examples, security notes
- [ ] Example TAXII server (OpenCTI/MISP) config snippet
- [ ] Rollout guidance: observe-first → rate-limit → block
- [ ] Changelog entry

---

### 8) Testing plan [Task 7.8]
- [ ] Unit tests for client, normalizer, cache bridge, detection hook
- [ ] Integration tests (kong-pongo) with mocked TAXII endpoints
- [ ] Performance checks: ingestion time, cache lookup latency

---

### Acceptance criteria
- [ ] Indicators load from TAXII on schedule; shared cache populated and versioned
- [ ] Detection hook matches indicators and adjusts scores/decisions
- [ ] Errors/backoffs handled gracefully; health metrics exposed
- [ ] Documentation and tests completed; CI green
