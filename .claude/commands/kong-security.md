# Kong Guard AI Security Operations

Manage Kong Guard AI security plugin with Claude-Flow coordination.

## Usage
```
/kong-security [operation] [parameters]
```

## Parameters
- `operation`: status, metrics, threats, incidents, config
- `parameters`: operation-specific options

## Steps

1. Check Kong Guard AI plugin status
2. Analyze current threat landscape
3. Review security metrics and alerts
4. Coordinate incident response if needed
5. Update security configurations
6. Generate security reports

## Examples
```bash
# Check Kong Guard AI status
curl http://localhost:8001/_guard_ai/status

# View threat metrics
curl http://localhost:8001/_guard_ai/metrics

# Spawn security response team
npx claude-flow@alpha agent spawn --type security \
  --name "Incident Response Team"

# Store security incident
npx claude-flow@alpha memory store "incident-$(date +%s)" \
  "SQL injection attempt from IP 203.0.113.100 - blocked" \
  --namespace security-incidents

# Train threat prediction model
npx claude-flow@alpha neural train --pattern prediction \
  --training-data "threat-intelligence.json" --epochs 25
```

## Security Operations
- **Threat Detection**: Real-time monitoring
- **Incident Response**: Automated coordination  
- **Forensic Analysis**: Agent-powered investigation
- **Pattern Learning**: Neural threat prediction
- **Configuration**: Dynamic policy updates

## Integration Points
- **Kong Gateway**: Plugin lifecycle management
- **Claude-Flow**: Agent coordination for incidents
- **Neural Models**: Threat prediction and analysis
- **Memory**: Incident history and threat intelligence

## Alert Thresholds
- 🔴 **Critical**: >90% threat confidence
- 🟡 **High**: >80% threat confidence  
- 🟢 **Medium**: >60% threat confidence
- ℹ️ **Low**: <60% threat confidence

This enables AI-powered security operations for Kong Gateway.