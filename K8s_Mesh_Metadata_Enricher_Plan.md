## K8s/Mesh Metadata Enricher — Detailed Task List

### Objectives
- Enrich requests with K8s/Service Mesh metadata from trusted headers (Istio/Envoy).
- Use metadata to detect cross-namespace anomalies and unusual caller/callee pairs.
- Provide metrics and low-overhead caching with safe defaults.

### Prerequisites
- Mesh/ingress configured to pass through trusted headers.
- Agreed header contract and trust boundary.

---

### 1) Schema additions (config) [Task 8.1]
- [ ] Add `enable_mesh_enricher` (boolean, default false)
- [ ] Add `mesh_header_map` (record) with keys:
  - [ ] `trace_id` (e.g., `x-request-id` or `traceparent`)
  - [ ] `namespace`
  - [ ] `workload`
  - [ ] `service`
  - [ ] `pod`
  - [ ] `zone`
  - [ ] `mesh_source` (upstream caller identity)
- [ ] Add `mesh_cache_ttl_seconds` (int, default 300)
- [ ] Add `mesh_risky_namespaces` (array<string>)
- [ ] Add `mesh_score_weights` (record):
  - [ ] `cross_namespace` (+0.3)
  - [ ] `risky_namespace` (+0.3)
  - [ ] `unusual_pair` (+0.3)
  - [ ] `missing_headers` (+0.1)
- [ ] Add `mesh_pair_window_seconds` (int, default 3600)
- [ ] Validate defaults and descriptions

---

### 2) Module: `mesh_enricher.lua` [Task 8.2]
- [ ] Create module scaffold and exports
- [ ] Implement `read_headers(request, config)`
  - [ ] Resolve header names from `mesh_header_map`
  - [ ] Extract values and sanitize (lengths/charset)
- [ ] Implement `normalize(mesh)`
  - [ ] Trim/normalize whitespace; lowercase namespace/service/workload
  - [ ] Validate identifiers (DNS-1123/label rules where applicable)
- [ ] Implement shared cache helpers (optional)
- [ ] Unit tests for read/normalize

---

### 3) Handler integration [Task 8.3]
- [ ] Wire `mesh_enricher` in access/feature extraction when enabled
- [ ] Populate `features.mesh = { namespace, workload, service, pod, zone, trace_id, mesh_source }`
- [ ] Persist pair counters in `ngx.shared`:
  - [ ] `mesh_pair_count:<src>:<dst>` with TTL= `mesh_pair_window_seconds`
- [ ] Include `mesh` in `kong.ctx.plugin.threat_data`

---

### 4) Heuristics & scoring [Task 8.4]
- [ ] Cross-namespace anomalies (src.ns != dst.ns) → add `cross_namespace`
- [ ] Risky namespace present → add `risky_namespace`
- [ ] Unusual caller/callee pair (low historical count) → add `unusual_pair`
- [ ] Missing headers (low trust) → add `missing_headers`

---

### 5) Controls (optional) [Task 8.5]
- [ ] Per-pair rate limit if RPM > threshold
- [ ] Per-namespace soft quota (rate-limit rather than block by default)

---

### 6) Metrics [Task 8.6]
- [ ] Counters: per-namespace, per-service, pair anomalies
- [ ] Export top-K anomalous pairs (rate-limited logs)

---

### 7) Docs & Tests [Task 8.7]
- [ ] Documentation: header contract, config examples, rollout guidance
- [ ] Integration tests (kong-pongo): synthetic headers and assertions
- [ ] Unit tests for normalization and heuristics

---

### Acceptance criteria
- [ ] `features.mesh` populated when headers present; no-op otherwise
- [ ] Cross-namespace and unusual pairs adjust threat score as configured
- [ ] Metrics/counters increment and are observable
- [ ] Tests pass; no performance regressions
