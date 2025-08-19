### KongGuardAI — Autonomous API Threat Response Agent for Kong

Kong plugin (Lua-first) that monitors API traffic, detects threats, and can automatically remediate via the Kong Admin API. Optional integration with Kong AI Gateway enables LLM-assisted anomaly analysis. Built for Kong Gateway 3.x+ with <10ms added latency, stateless design, and declarative configuration.

### Features
- **Traffic instrumentation**: access/log phase hooks with structured logging
- **Detection**: static rules (IP blacklist, method denylist, path regex) and threshold/anomaly detection (bursts, 5xx spikes, payload size)
- **Remediation**: Admin API actions (rate-limiting, request-termination, ACL/IP restriction), route/service modification, rollback
- **Configuration & safety**: declarative config with global `dry_run` gate
- **Notifications**: Slack/Email/webhooks with dedup/backoff; incident export
- **Status endpoint**: read-only JSON, secured with key-auth
- **Operator feedback**: confirm/undo actions to adapt thresholds/allowlists

### Quick start (Docker)
Prereqs: Docker, Docker Compose

```bash
docker-compose up -d --build
# Optional validations
./scripts/validate-all.sh
```

Enable the plugin on a test Service/Route (example):
```bash
# Create a demo Service and Route
curl -sS -X POST http://localhost:8001/services \
  -d name=demo -d url=http://mock:8080
curl -sS -X POST http://localhost:8001/services/demo/routes \
  -d name=demo-route -d paths[]=/demo

# Enable the plugin with dry run
curl -sS -X POST http://localhost:8001/services/demo/plugins \
  -d name=kong-guard-ai \
  -d config.dry_run=true \
  -d config.ip_blacklist[]=203.0.113.1 \
  -d config.method_denylist[]=TRACE

# Send traffic through Kong
curl -i http://localhost:8000/demo
```

Stop stack:
```bash
docker-compose down
```

### Configuration (schema highlights)
```yaml
name: kong-guard-ai
config:
  dry_run: true
  ip_blacklist: ["203.0.113.1", "198.51.100.7"]
  method_denylist: ["TRACE", "TRACK"]
  rate_limit: { per_ip_per_minute: 300 }
  burst_threshold: { per_ip_per_10s: 100 }
  path_regex_denylist: ["^/admin", "^/internal"]
  admin_api:
    url: "http://kong:8001" # internal Admin API URL
    auth: null               # optional auth if required
  notification_targets:
    webhook: "http://webhook:9000/incident"
    slack: null
  ai_gateway:
    enabled: false
    service: "ai-proxy"
```
- All enforcement paths are gated by `dry_run` when enabled
- Prefer O(1) lookups (tables/sets), shared dict counters, and log-phase heavy work

### Status endpoint (optional)
- Expose a read-only JSON endpoint secured with key-auth (plugin status, config snapshot, recent incidents)
- Configure as a dedicated Service/Route; apply `key-auth`

### Remediation
- Core: apply rate limits, request termination, ACL/IP restriction
- Advanced: route/service modification and safe rollback (decK/Konnect or snapshots)
- Idempotent with retry/backoff and audit logging

### Development
- Plugin source (example path): `plugins/kong-guard-ai/`
- Docker config: `docker-compose.yml`, `kong/`, `kong.conf`
- Scripts: `scripts/validate-*.sh`, `setup-kong.sh`
- PRD: `prd.txt`

Common scripts:
```bash
./docker-start.sh                          # start local stack
./scripts/validate-plugin-lifecycle.sh     # validate plugin basics
./scripts/validate-admin-api-compatibility.sh
```

### Testing
Uses busted tests for rule logic and enforcement paths.
```bash
# Run tests inside the Kong container (name may vary)
docker exec -it $(docker ps --filter name=kong --format '{{.ID}}') \
  busted -v /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/spec
```

### Tasks & planning (Taskmaster)
- Tasks live in `.taskmaster/tasks/tasks.json` (tags: `master`, `assistant-parse`, `assistant-local`)
- Helpful commands:
  - `task-master next` — pick the next task
  - `task-master expand --id=<id> --research` — generate subtasks
  - `task-master set-status --id=<id> --status=in-progress|done`

### IDE assistant system prompt
- Tuned prompt: `system-prompt.txt`
- Example usage (Claude):
```bash
claude --append-system-prompt "$(cat system-prompt.txt)"
```

### Latest docs via Context7 MCP (optional)
- Prefer Context7 MCP for authoritative, up-to-date docs
- Config snippet and usage guidance included in `system-prompt.txt`

### Security & performance
- Target <10ms added latency; avoid blocking I/O in access phase
- Never log secrets; secure Admin API usage; key-auth for status endpoint
- Stateless by default; shared dict for counters/windows; external stores optional

### License
TBD

### References
- PRD: `prd.txt`
- For latest Kong docs: use Context7 MCP (see `system-prompt.txt`)
