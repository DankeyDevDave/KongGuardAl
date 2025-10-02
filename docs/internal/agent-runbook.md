# Claude Agent SDK Integration - Operations Runbook

## Overview

KongGuardAI integrates Claude Agent SDK to provide autonomous security operations through three specialized agents:
- **Security Triage Copilot**: Read-only incident analysis and triage recommendations
- **Adaptive Policy Tuner**: Proposes configuration adjustments based on threat patterns
- **DevOps Assistant**: CI/CD security checks and demo readiness validation

## Prerequisites

- Anthropic API Key with Claude access
- Docker environment (staging/production)
- Access to attack_metrics.db and system logs
- Appropriate permissions in `.claude/settings.json`

## Agent Activation

### Environment Variables

```bash
# Enable the agent SDK features
export ENABLE_AGENT_SDK=true

# Provide Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### Verification

```bash
# Test agent availability
python3 ai-service/agents/run_security_triage.py --test-mode

# Check logs for agent initialization
tail -f logs/ai-service.log | grep "agent"
```

## Security Triage Copilot

### Purpose
Analyzes recent incidents and provides actionable security recommendations without making changes.

### Usage

```bash
# Get incident summary from last 24 hours
python3 ai-service/agents/tools/get_incidents.py --since-hours 24

# Run triage analysis (when SDK enabled)
python3 ai-service/agents/run_security_triage.py
```

### Expected Output
- Incident count and severity breakdown
- Top attack categories and source IPs
- Blocked vs. allowed ratio analysis
- Recommended actions (rate limiting, IP blocks, monitoring adjustments)

### Success Criteria
- ✅ >90% coverage of key signals (IPs, categories, error spikes)
- ✅ All recommendations are non-destructive (propose only)
- ✅ Secrets and sensitive data properly redacted

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Returns `None` | Check ENABLE_AGENT_SDK=true and ANTHROPIC_API_KEY is set |
| No incidents found | Verify attack_metrics.db exists and has recent data |
| API rate limits | Implement prompt caching, reduce frequency |

## Adaptive Policy Tuner

### Purpose
Analyzes threat patterns and proposes safe configuration diffs for Kong Guard AI.

### Usage

```bash
# Generate policy diff recommendations
python3 ai-service/agents/tools/propose_policy_diffs.py --since-hours 24
```

### Output Format
```json
{
  "decision": "lower_thresholds|raise_thresholds|no_change",
  "delta": 0.05,
  "current_thresholds": {
    "block_critical": 0.90,
    "block_high": 0.80,
    "challenge": 0.70,
    "monitor": 0.60
  },
  "proposed_thresholds": { ... },
  "diff": "unified diff output"
}
```

### Approval Workflow

1. **Review**: Examine proposed diff for safety and correctness
2. **Validate**: Test proposed thresholds in staging environment
3. **Apply**: Manually apply changes if approved:
   ```bash
   # Review the diff
   cat policy.diff
   
   # Apply if approved (manual step)
   patch -p1 < policy.diff
   ```
4. **Monitor**: Watch metrics for unintended effects

### Safety Guardrails
- ❌ **Never auto-applies** configuration changes
- ✅ All changes are proposed as reviewable diffs
- ✅ Thresholds clamped to safe ranges (0.10-0.99)
- ✅ Maintains descending order of severity thresholds

## DevOps Assistant (CI Integration)

### Purpose
Provides read-only security checks in CI/CD pipeline.

### GitHub Actions Integration

The Security Review Gate workflow runs automatically on PRs:

```yaml
# .github/workflows/security-review.yml
# Triggered on: pull_request to main, develop, feature/**
```

### Workflow Steps

1. **Incident Summary**: Fetches last 24h of attack data
2. **Security Gate**: Optional strict checking (if `SECURITY_GATE_STRICT` secret set)
3. **Policy Diff**: Generates and uploads proposed configuration changes
4. **PR Comments**: Posts summary and recommendations to pull request

### Manual Trigger

```bash
# Via GitHub CLI
gh workflow run security-review.yml

# Check status
gh run list --workflow=security-review.yml
```

### Interpreting Results

**Gate Passed**: 
- Incident patterns are within normal parameters
- No critical security concerns detected

**Gate Failed** (Strict Mode):
- More incidents allowed than blocked
- Requires investigation before merge

### Success Criteria
- ✅ No false positives in PR blocking
- ✅ Actionable suggestions in PR comments
- ✅ < 5% flakiness rate

## Observability

### Structured Logging

Agent actions are logged with structured context:

```python
# Example log entry
{
  "timestamp": "2025-10-02T10:00:00Z",
  "agent": "security-triage",
  "action": "analyze_incidents",
  "summary": {
    "total_incidents": 100,
    "blocked": 75,
    "allowed": 25
  },
  "duration_ms": 1250,
  "status": "success"
}
```

### Metrics

Key Prometheus metrics:

```
# Tool invocations
agent_tool_calls_total{agent="security-triage",tool="get_incidents"}

# Failures
agent_tool_failures_total{agent="policy-tuner",error_type="timeout"}

# Latency
agent_operation_duration_seconds{agent="devops-assistant",operation="security_gate"}
```

### Grafana Dashboard

Access agent monitoring dashboard:
1. Navigate to Grafana: `http://localhost:3001`
2. Dashboard → "Agent Operations"
3. View: Tool call rates, error rates, latency percentiles

## Data Privacy & Compliance

### Redaction Layer

All agent outputs pass through redaction:

```python
from agents.redaction import redact_text, redact_dict

# Automatically redacts:
# - Bearer tokens
# - API keys
# - Authorization headers
# - Long payloads (truncated > 2000 chars)
```

### Audit Trail

Agent actions are logged for compliance:

```bash
# Review agent audit log
tail -f logs/agent-audit.log

# Search for specific incident
grep "incident_123" logs/agent-audit.log
```

### Data Retention

- Agent logs: 90 days
- Incident data: 1 year (compressed after 30 days)
- Audit trails: 3 years

## Rollout Plan

### Phase 1: Security Triage (Current)
- ✅ Read-only analysis in staging
- ✅ Manual review of recommendations
- ⏳ Monitor for 2 weeks before production

### Phase 2: DevOps Assistant  
- ⏳ CI integration (read-only checks)
- ⏳ Validate PR comment quality
- ⏳ Production enable after 1 week

### Phase 3: Policy Tuner
- ⏳ Diff generation only (no apply)
- ⏳ Human approval required for all changes
- ⏳ Optional controlled apply (future)

## Emergency Procedures

### Disable Agents Immediately

```bash
# Set environment variable
export ENABLE_AGENT_SDK=false

# Restart services
docker-compose restart ai-service

# Verify disabled
curl http://localhost:28100/health | jq '.agents.enabled'
# Should return: false
```

### Incident Response

If agent causes unexpected behavior:

1. **Disable**: Set `ENABLE_AGENT_SDK=false`
2. **Capture State**: Save logs, metrics, recent incident data
3. **Analyze**: Review agent actions in logs
4. **Report**: File incident report with relevant data
5. **Fix**: Apply hotfix if needed, update agent prompts/permissions
6. **Test**: Validate fix in staging before re-enabling

## Contact & Support

- **On-Call**: Check PagerDuty rotation
- **Slack**: #kong-guard-ai-agents
- **Docs**: https://docs.kongguard.ai/agents
- **Issues**: https://github.com/KongGuardAI/issues

## Changelog

| Date | Change | Author |
|------|--------|--------|
| 2025-10-02 | Initial agent runbook created | System |
| 2025-10-02 | Added Security Triage Copilot documentation | System |
| 2025-10-02 | Added CI integration guide | System |
