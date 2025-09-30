## Feature Flags, Dashboards, ADRs — Detailed Task List

### Objectives
- Central gating for features with safe defaults and observability.
- Dashboards for threat types and subsystem metrics.
- Architectural Decision Records for key decisions.

---

### 1) Feature flags [Task 10.1]
- [ ] Central registry of flags mapping to config fields
- [ ] Optional env-var overrides (non-production only)
- [ ] Flag evaluation helper used in handler paths

---

### 2) Prometheus metrics [Task 10.2]
- [ ] Add counters/gauges:
  - [ ] Threat types and scores
  - [ ] GraphQL depth/complexity exceedances
  - [ ] gRPC per-method rates/blocks
  - [ ] TLS fingerprint matches / rate-limits
  - [ ] TAXII indicator matches
  - [ ] Mesh anomalies

---

### 3) Grafana dashboards [Task 10.3]
- [ ] Panels for each subsystem with drill-down
- [ ] SLOs and thresholds highlighted
- [ ] Example dashboard JSON

---

### 4) ADRs [Task 10.4]
- [ ] ADR: normalization profiles and defaults
- [ ] ADR: caching & shared dict strategy
- [ ] ADR: TAXII ingestion model
- [ ] ADR: scoring weights philosophy

---

### 5) Admin endpoints (optional) [Task 10.5]
- [ ] Read-only status endpoints for features/metrics
- [ ] Health endpoints for ingestors/schedulers

---

### 6) E2E tests [Task 10.6]
- [ ] Smoke tests across features with flags on/off
- [ ] Basic golden-path validation

---

### Acceptance criteria
- [ ] Flags centrally managed; no hidden paths bypassing flags
- [ ] Dashboards provide at-a-glance health and hotspots
- [ ] ADRs checked in and referenced in docs
