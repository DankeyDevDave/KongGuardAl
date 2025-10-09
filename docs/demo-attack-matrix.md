# Demo Attack Scenarios – Expected vs Actual

## Unprotected Gateway (reference)

| Scenario | Expected result (Unprotected) | Actual result |
|---|---|---|
| SQL Injection | Forwarded to upstream; 2xx likely. No enforcement. Audit: threat_type=sql_injection, action=allow, blocked=false. | Observed: Requests=160 tier total; Blocked=0; Allowed=all; Status 2xx; Activity shows ALLOWED. |
| XSS Attack | Forwarded; 2xx likely. No enforcement. Audit: threat_type=xss, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed; latency ~2ms. |
| Command Injection | Forwarded; 2xx likely. No enforcement. Audit: threat_type=cmd_injection, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed. |
| Path Traversal | Forwarded; 2xx likely. No enforcement. Audit: threat_type=path_traversal, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed. |
| LDAP Injection | Forwarded; 2xx likely. No enforcement. Audit: threat_type=ldap_injection, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed. |
| Business Logic | Forwarded; 2xx likely. No enforcement. Audit: threat_type=business_logic, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed. |
| Ransomware C2 | Forwarded; 2xx likely. No enforcement. Audit: threat_type=ransomware, action=allow, blocked=false. | Observed: Allowed; ALLOWED entries in feed. |
| Normal Traffic | Forwarded as normal; 2xx. | Observed: Allowed; ALLOWED entries in feed; no blocks. |
| Attack Flood – Low (10 rps) | All allowed; no 429; Threats Blocked=0. | Observed: Allowed; Threats Blocked remained 0. |
| Attack Flood – Medium (50 rps) | All allowed; no rate limit; Threats Blocked=0. | Observed: Allowed; no throttling seen. |
| Attack Flood – High (200 rps) | All allowed; upstream may slow; Threats Blocked=0. | Observed: Allowed; gateway did not block. |
| Attack Flood – Extreme (1000+ rps) | All allowed; upstream saturation possible; Threats Blocked=0. | Observed: Allowed; enforcement off. |

## Cloud AI Protection

Aggregate (from latest run): Requests=160, Blocked=62, Detection=38.8%, Avg Latency=272ms

Evidence (Cloud service logs):

```text
🚀 Kong Guard AI - Threat Analysis Service
📊 AI Provider: gemini
🔍 Starting on http://localhost:8000
```

Note: Provider reported as gemini for this run (environment-controlled). If OpenAI is intended here, switch AI_PROVIDER or model config accordingly.

| Scenario | Expected result (Cloud AI) | Actual result |
|---|---|---|
| SQL Injection | Blocked by AI policy; 403 (or 401/451 depending policy). Audit: threat_type=sql_injection, action=block, blocked=true, ai_confidence≥threshold. | Observed: BLOCKED (threat 82%). |
| XSS Attack | Blocked; 403. Audit: threat_type=xss, action=block, blocked=true. | Observed: MONITORED (60%) – not blocked in this run. |
| Command Injection | Blocked; 403. Audit: threat_type=cmd_injection, action=block, blocked=true. | Observed: MONITORED (12%) – not blocked in this run. |
| Path Traversal | Blocked; 403. Audit: threat_type=path_traversal, action=block, blocked=true. | Observed: MONITORED (41%) – not blocked in this run. |
| LDAP Injection | Blocked; 403. Audit: threat_type=ldap_injection, action=block, blocked=true. | Observed: MONITORED (61%) – not blocked in this run. |
| Business Logic | Typically blocked when high-confidence; otherwise challenged/allowed with alert. Audit: action=block or allow_with_alert; confidence recorded. | Observed: BLOCKED (28%). |
| Ransomware C2 | Blocked; 403. Audit: threat_type=ransomware, action=block, blocked=true. | Observed: BLOCKED (74%). |
| Normal Traffic | Allowed; 2xx. Minimal latency overhead; audit: action=allow. | Observed: BLOCKED (86%) with some allows in feed. |
| Attack Flood – Low (10 rps) | Mostly allowed; baseline protection; no 429. |  |
| Attack Flood – Medium (50 rps) | Adaptive protection may start throttling; some 429s; audit shows rate_limit events. |  |
| Attack Flood – High (200 rps) | Rate-limiting/auto-blocking engaged; 429/403 prevalent; protection KPIs increase. |  |
| Attack Flood – Extreme (1000+ rps) | Aggressive mitigation (429/403); sustained protection; upstream safeguarded. |  |

## Local AI Protection (Ollama)

Aggregate (from latest run): Requests=160, Blocked=54, Detection=33.8%, Avg Latency=65ms

Evidence (Local service logs):

```text
🚀 Kong Guard AI - Threat Analysis Service
📊 AI Provider: ollama
🔍 Starting on http://localhost:8000
```

Model configuration (compose):

```309:316:config/docker/docker-compose.yml
    ports:
      - "${AI_OLLAMA_EXTERNAL_PORT:-28101}:8000"
    environment:
      - PORT=8000
      - AI_PROVIDER=ollama
      - OLLAMA_HOST=http://host.docker.internal:11434
      - OLLAMA_MODEL=llama3.2:3b
```

| Scenario | Expected result (Local AI) | Actual result |
|---|---|---|
| SQL Injection | Blocked; 403. Audit: threat_type=sql_injection, action=block, blocked=true. | Observed: BLOCKED (14% threat). |
| XSS Attack | Blocked; 403. Audit: threat_type=xss, action=block, blocked=true. | Observed: BLOCKED (60% threat). |
| Command Injection | Blocked; 403. Audit: threat_type=cmd_injection, action=block, blocked=true. | Observed: MONITORED (43%) – not blocked in this run. |
| Path Traversal | Blocked; 403. Audit: threat_type=path_traversal, action=block, blocked=true. | Observed: BLOCKED (12% threat). |
| LDAP Injection | Blocked; 403. Audit: threat_type=ldap_injection, action=block, blocked=true. | Observed: BLOCKED (59% threat). |
| Business Logic | Block if confident; else allow with alert. Slightly higher latency vs cloud possible. | Observed: BLOCKED (34% threat). |
| Ransomware C2 | Blocked; 403. Audit: threat_type=ransomware, action=block, blocked=true. | Observed: BLOCKED (64% threat). |
| Normal Traffic | Allowed; 2xx. Latency near local model baseline. | Observed: BLOCKED (85% threat) with some allows in feed. |
| Attack Flood – Low (10 rps) | Allowed; no 429. | Observed: Mixed – some blocks; overall tier detection ~33.8%. |
| Attack Flood – Medium (50 rps) | Rate limiting may begin; some 429s; CPU load rises. | Observed: Mixed – mitigation present; latency ~65ms avg. |
| Attack Flood – High (200 rps) | Rate-limiting/mitigation engaged; many 429/403; stable gateway. | Observed: Increased blocking; upstream protected. |
| Attack Flood – Extreme (1000+ rps) | Strong throttling/blocks; upstream protected; possible graceful shedding. | Observed: Aggressive blocking; stability maintained. |


---

Demo audit backend (WebSocket service) evidence:

```text
🚀 Kong Guard AI - Real-Time Threat Analysis Service
📊 AI Provider: openai
🔌 WebSocket: ws://localhost:18002/ws
```

Root JSON:

```json
{"service":"Kong Guard AI - Real-Time Threat Analysis","status":"operational","version":"3.0.0","ai_provider":"openai","websocket":"/ws","dashboard":"/dashboard"}
```


