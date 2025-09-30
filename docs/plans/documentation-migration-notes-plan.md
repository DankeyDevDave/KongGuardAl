## Documentation & Migration Notes — Detailed Task List

### Objectives
- Update user guide with new capabilities (GraphQL, gRPC, TLS, TAXII, Mesh).
- Provide migration/upgrade guidance and changelog entries.
- Ensure privacy and rollout guidance are clearly documented.

---

### 1) User guide structure [Task 9.1]
- [ ] Add sections for each capability:
  - [ ] URL/body normalization
  - [ ] GraphQL limits
  - [ ] gRPC method controls
  - [ ] TLS fingerprinting (JA3/JA4)
  - [ ] TAXII/STIX ingestion
  - [ ] K8s/Mesh enricher
- [ ] Update configuration reference with new fields and examples

---

### 2) Migration/upgrade notes [Task 9.2]
- [ ] Versioned changes and defaults
- [ ] Safe rollout paths (observe → rate-limit → block)
- [ ] Backward compatibility notes
- [ ] Known limitations

---

### 3) Examples and recipes [Task 9.3]
- [ ] Example configs for each feature
- [ ] Troubleshooting guide (common misconfigurations)
- [ ] Privacy considerations (headers/logs, PII, data retention)

---

### 4) Changelog and README updates [Task 9.4]
- [ ] Changelog entries per feature
- [ ] README feature matrix and quickstart snippets

---

### Acceptance criteria
- [ ] User guide covers all new features with examples
- [ ] Migration steps allow gradual adoption
- [ ] Changelog and README updated
