# Kong Guard AI - Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to Kong Guard AI security incidents, performance issues, and operational emergencies.

## Incident Classification

### Security Incidents

- **P0 - Critical Security Breach**: Active attack detected, immediate blocking required
- **P1 - High Security Alert**: Persistent threats, automated responses may not be sufficient
- **P2 - Medium Security Event**: Elevated threat patterns, monitoring required
- **P3 - Low Security Notice**: Suspicious activity within normal thresholds

### Performance Incidents

- **P0 - Service Down**: Kong Gateway or Kong Guard AI completely unavailable
- **P1 - High Latency**: Response times > 500ms impacting user experience
- **P2 - Resource Issues**: Memory/CPU usage > 85%, potential impact
- **P3 - Performance Degradation**: Minor performance impact, investigate when possible

### Operational Incidents

- **P0 - Data Loss**: Database corruption, missing critical data
- **P1 - Integration Failure**: AI Gateway, notifications, or admin API failures
- **P2 - Configuration Issues**: Plugin misconfiguration affecting functionality
- **P3 - Monitoring Issues**: Metrics collection or alerting problems

## Security Incident Response

### P0 - Critical Security Breach

**Immediate Actions (0-5 minutes)**

1. **Verify the Alert**
   ```bash
   # Check Kong Guard AI logs for threat details
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --tail=100 | grep -i "threat_level.*[9]"
   
   # Check for ongoing attacks
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=10m | grep -i "enforcement_action"
   ```

2. **Enable Emergency Mode**
   ```bash
   # Enable maximum protection immediately
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.threat_threshold=5.0" \
     --data "config.enable_auto_blocking=true" \
     --data "config.block_duration_seconds=7200"
   ```

3. **Block Attacking IPs**
   ```bash
   # Get attacking IP addresses
   ATTACK_IPS=$(kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=10m | grep -i "threat_level.*[9]" | grep -oP 'ip=\K[0-9.]+' | sort -u)
   
   # Add to IP blacklist
   for ip in $ATTACK_IPS; do
     curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
       --data "config.ip_blacklist[]=${ip}"
   done
   ```

4. **Notify Security Team**
   ```bash
   # Send immediate notification
   curl -X POST "${SLACK_WEBHOOK_URL}" \
     -H 'Content-type: application/json' \
     --data '{
       "text": "🚨 CRITICAL SECURITY BREACH DETECTED",
       "attachments": [
         {
           "color": "danger",
           "fields": [
             {
               "title": "Threat Level",
               "value": "9.0+ (Critical)",
               "short": true
             },
             {
               "title": "Time",
               "value": "'$(date)'",
               "short": true
             },
             {
               "title": "Action Taken",
               "value": "Emergency blocking enabled",
               "short": false
             }
           ]
         }
       ]
     }'
   ```

**Investigation Phase (5-30 minutes)**

5. **Gather Attack Details**
   ```bash
   # Extract detailed attack information
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=1h | \
     grep -i "threat_level.*[8-9]" > /tmp/attack-details-$(date +%Y%m%d-%H%M).log
   
   # Analyze attack patterns
   cat /tmp/attack-details-*.log | jq '.attack_type' | sort | uniq -c
   cat /tmp/attack-details-*.log | jq '.client_ip' | sort | uniq -c
   ```

6. **Check for Data Exfiltration**
   ```bash
   # Look for large response sizes
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=1h | \
     grep -i "response_size" | awk '$3 > 1000000' # Responses > 1MB
   
   # Check for sensitive data patterns in requests
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=1h | \
     grep -iE "(ssn|credit.*card|password|token|api.*key)"
   ```

7. **Validate System Integrity**
   ```bash
   # Check Kong configuration integrity
   curl -X GET http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} | jq .
   
   # Verify database integrity
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- kong health
   
   # Check for unauthorized configuration changes
   kubectl get events -n kong-guard-ai --sort-by='.lastTimestamp' | grep -i "configmap\|secret"
   ```

**Containment Phase (30-60 minutes)**

8. **Implement Additional Security Measures**
   ```bash
   # Enable enhanced monitoring
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.enable_learning=true" \
     --data "config.learning_sample_rate=1.0" \
     --data "config.log_level=debug"
   
   # Enable AI Gateway for all suspicious requests
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.ai_analysis_threshold=4.0"
   ```

9. **Coordinate with Infrastructure Team**
   ```bash
   # Check WAF logs if applicable
   aws wafv2 get-sampled-requests --web-acl-arn ${WAF_ARN} --rule-metric-name ${RULE_NAME} --scope CLOUDFRONT --time-window StartTime=$(date -d '1 hour ago' +%s),EndTime=$(date +%s) --max-items 100
   
   # Review CloudTrail for API calls
   aws logs filter-log-events --log-group-name /aws/cloudtrail --start-time $(date -d '1 hour ago' +%s)000 --filter-pattern "{ $.sourceIPAddress = \"${ATTACK_IP}\" }"
   ```

**Recovery Phase (1-4 hours)**

10. **Gradual Service Restoration**
    ```bash
    # Monitor attack cessation
    kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=30m | \
      grep -i "threat_level.*[8-9]" | wc -l
    
    # If attacks stopped, gradually reduce restrictions
    if [ $(kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=30m | grep -i "threat_level.*[8-9]" | wc -l) -eq 0 ]; then
      curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
        --data "config.threat_threshold=6.5"
    fi
    ```

### P1 - High Security Alert

**Immediate Actions (0-10 minutes)**

1. **Assess Threat Level**
   ```bash
   # Check recent high-severity threats
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=15m | \
     grep -i "threat_level.*[7-8]" | head -20
   
   # Count threats per minute
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=15m | \
     grep -i "threat_detected" | awk '{print $1" "$2}' | cut -c1-16 | uniq -c
   ```

2. **Enhance Monitoring**
   ```bash
   # Increase sensitivity temporarily
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.threat_threshold=6.5" \
     --data "config.notification_threshold=6.0"
   ```

3. **Document Incident**
   ```bash
   # Create incident log
   echo "$(date): P1 Security Alert - High threat activity detected" >> /var/log/kong-guard-ai-incidents.log
   
   # Extract relevant logs
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=30m | \
     grep -i "threat_level.*[7-8]" > /tmp/p1-incident-$(date +%Y%m%d-%H%M).log
   ```

**Investigation Phase (10-60 minutes)**

4. **Pattern Analysis**
   ```bash
   # Analyze attack patterns
   cat /tmp/p1-incident-*.log | jq '.attack_type' | sort | uniq -c | sort -nr
   cat /tmp/p1-incident-*.log | jq '.user_agent' | sort | uniq -c | sort -nr
   cat /tmp/p1-incident-*.log | jq '.request_path' | sort | uniq -c | sort -nr
   ```

5. **Determine Response Strategy**
   ```bash
   # Check if rate limiting is effective
   RATE_LIMITED=$(kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=30m | grep -i "rate_limit.*applied" | wc -l)
   THREATS_BLOCKED=$(kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-guard-ai --since=30m | grep -i "request.*blocked" | wc -l)
   
   echo "Rate limits applied: $RATE_LIMITED"
   echo "Threats blocked: $THREATS_BLOCKED"
   
   # If rate limiting isn't working, consider IP blocking
   if [ $RATE_LIMITED -gt 0 ] && [ $THREATS_BLOCKED -lt $((RATE_LIMITED / 2)) ]; then
     echo "Rate limiting ineffective, consider IP blocking"
   fi
   ```

## Performance Incident Response

### P0 - Service Down

**Immediate Actions (0-2 minutes)**

1. **Verify Service Status**
   ```bash
   # Check Kong Gateway pods
   kubectl get pods -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway
   
   # Test Kong endpoints
   curl -I http://${KONG_PROXY_URL}/
   curl -I http://${KONG_ADMIN_URL}/status
   ```

2. **Check Recent Changes**
   ```bash
   # Check recent deployments
   kubectl rollout history deployment/kong-gateway -n kong-guard-ai
   
   # Check recent configuration changes
   kubectl get events -n kong-guard-ai --sort-by='.lastTimestamp' | head -20
   ```

3. **Emergency Rollback if Needed**
   ```bash
   # If recent deployment caused the issue
   kubectl rollout undo deployment/kong-gateway -n kong-guard-ai
   
   # Monitor rollback
   kubectl rollout status deployment/kong-gateway -n kong-guard-ai
   ```

**Diagnosis Phase (2-15 minutes)**

4. **Collect Diagnostic Information**
   ```bash
   # Pod status and logs
   kubectl describe pods -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --tail=200
   
   # Resource usage
   kubectl top pods -n kong-guard-ai
   kubectl top nodes
   ```

5. **Check Dependencies**
   ```bash
   # Database connectivity
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- pg_isready -h ${PG_HOST} -U kong
   
   # DNS resolution
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- nslookup ${PG_HOST}
   
   # Network connectivity
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- curl -I http://httpbin.org/status/200
   ```

**Resolution Phase (15-60 minutes)**

6. **Address Root Cause**
   ```bash
   # If database is down
   if ! kubectl exec -n kong-guard-ai deployment/kong-gateway -- pg_isready -h ${PG_HOST} -U kong; then
     echo "Database connectivity issue detected"
     # Check RDS status
     aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_ID}
   fi
   
   # If out of resources
   kubectl top pods -n kong-guard-ai | awk 'NR>1 && ($3+0) > 85 {print $1" is using "$3" CPU"}'
   kubectl top pods -n kong-guard-ai | awk 'NR>1 && ($4+0) > 85 {print $1" is using "$4" memory"}'
   ```

### P1 - High Latency

**Immediate Actions (0-5 minutes)**

1. **Measure Current Latency**
   ```bash
   # Test response times
   for i in {1..10}; do
     curl -w "Response time: %{time_total}s\n" -o /dev/null -s http://${KONG_PROXY_URL}/status/200
     sleep 1
   done
   
   # Check metrics endpoint
   curl -s http://${KONG_PROXY_URL}:8100/metrics | grep -i latency
   ```

2. **Quick Performance Check**
   ```bash
   # Check if Kong Guard AI processing is the bottleneck
   kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=5m | \
     grep -i "processing_time" | awk '{print $NF}' | sort -n | tail -10
   
   # Check for memory pressure
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- cat /proc/meminfo | grep -E "MemAvailable|MemFree"
   ```

**Optimization Phase (5-30 minutes)**

3. **Temporary Performance Optimization**
   ```bash
   # Reduce Kong Guard AI processing intensity
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.max_processing_time_ms=3" \
     --data "config.max_payload_size=65536"
   
   # Disable AI Gateway temporarily if enabled
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.ai_gateway_enabled=false"
   ```

4. **Scale Resources if Needed**
   ```bash
   # Scale Kong pods horizontally
   kubectl scale deployment kong-gateway --replicas=5 -n kong-guard-ai
   
   # Increase resource limits
   kubectl patch deployment kong-gateway -n kong-guard-ai -p='{"spec":{"template":{"spec":{"containers":[{"name":"kong-gateway","resources":{"limits":{"memory":"4Gi","cpu":"2"}}}]}}}}'
   ```

## Operational Incident Response

### P0 - Data Loss

**Immediate Actions (0-5 minutes)**

1. **Stop All Write Operations**
   ```bash
   # Scale down Kong to prevent further data corruption
   kubectl scale deployment kong-gateway --replicas=0 -n kong-guard-ai
   
   # Put Kong in maintenance mode if possible
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "enabled=false"
   ```

2. **Assess Damage**
   ```bash
   # Check database integrity
   kubectl exec -n kong-guard-ai deployment/postgres -- psql -U kong -d kong -c "SELECT COUNT(*) FROM services;"
   kubectl exec -n kong-guard-ai deployment/postgres -- psql -U kong -d kong -c "SELECT COUNT(*) FROM routes;"
   
   # Check for corruption
   kubectl exec -n kong-guard-ai deployment/postgres -- psql -U kong -d kong -c "SELECT pg_database_size('kong');"
   ```

**Recovery Phase (5-60 minutes)**

3. **Restore from Backup**
   ```bash
   # Get latest backup
   LATEST_BACKUP=$(aws s3 ls s3://${BACKUP_BUCKET}/database/ | sort | tail -n 1 | awk '{print $4}')
   
   # Download backup
   aws s3 cp s3://${BACKUP_BUCKET}/database/${LATEST_BACKUP} /tmp/
   
   # Restore database
   kubectl exec -n kong-guard-ai deployment/postgres -- psql -U kong -d kong < /tmp/${LATEST_BACKUP}
   ```

4. **Validate Restoration**
   ```bash
   # Test database connectivity and data integrity
   kubectl exec -n kong-guard-ai deployment/postgres -- psql -U kong -d kong -c "SELECT COUNT(*) FROM services;"
   
   # Start Kong with minimal configuration
   kubectl scale deployment kong-gateway --replicas=1 -n kong-guard-ai
   
   # Verify Kong can connect to database
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- kong health
   ```

### P1 - Integration Failure

**AI Gateway Failure**

1. **Disable AI Gateway**
   ```bash
   # Temporarily disable AI Gateway to maintain core functionality
   curl -X PATCH http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} \
     --data "config.ai_gateway_enabled=false"
   
   # Verify plugin still functions without AI
   curl -X GET http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID}
   ```

2. **Test AI Gateway Connectivity**
   ```bash
   # Test direct connection to AI service
   curl -X POST "${AI_GATEWAY_ENDPOINT}/v1/chat/completions" \
     -H "Authorization: Bearer ${AI_API_KEY}" \
     -H "Content-Type: application/json" \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}],"max_tokens":10}'
   ```

**Notification System Failure**

1. **Test Notification Channels**
   ```bash
   # Test Slack webhook
   curl -X POST "${SLACK_WEBHOOK_URL}" \
     -H 'Content-type: application/json' \
     --data '{"text": "Kong Guard AI notification test"}'
   
   # Test email SMTP
   kubectl exec -n kong-guard-ai deployment/kong-gateway -- \
     curl -s --url smtps://${SMTP_SERVER}:465 \
     --ssl-reqd \
     --mail-from ${EMAIL_FROM} \
     --mail-rcpt test@example.com \
     --user ${EMAIL_USER}:${EMAIL_PASSWORD} \
     -T - << EOF
   From: ${EMAIL_FROM}
   To: test@example.com
   Subject: Kong Guard AI Test
   
   Test notification
   EOF
   ```

## Post-Incident Procedures

### Incident Documentation

```bash
#!/bin/bash
# Post-incident documentation script

INCIDENT_ID="INC-$(date +%Y%m%d-%H%M)"
INCIDENT_DIR="/tmp/incident-${INCIDENT_ID}"
mkdir -p ${INCIDENT_DIR}

echo "=== Kong Guard AI Incident Report ===" > ${INCIDENT_DIR}/incident-report.md
echo "Incident ID: ${INCIDENT_ID}" >> ${INCIDENT_DIR}/incident-report.md
echo "Date: $(date)" >> ${INCIDENT_DIR}/incident-report.md
echo "" >> ${INCIDENT_DIR}/incident-report.md

# Collect logs
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=2h > ${INCIDENT_DIR}/kong-logs.txt

# Collect configuration
kubectl get configmap kong-guard-ai-config -n kong-guard-ai -o yaml > ${INCIDENT_DIR}/config-snapshot.yaml
curl -X GET http://${KONG_ADMIN_URL}/plugins/${PLUGIN_ID} > ${INCIDENT_DIR}/plugin-config.json

# Collect metrics
curl -s http://${KONG_PROXY_URL}:8100/metrics > ${INCIDENT_DIR}/metrics-snapshot.txt

# Performance data
kubectl top pods -n kong-guard-ai > ${INCIDENT_DIR}/resource-usage.txt
kubectl get events -n kong-guard-ai --sort-by='.lastTimestamp' > ${INCIDENT_DIR}/k8s-events.txt

echo "Incident documentation collected in ${INCIDENT_DIR}"
```

### Root Cause Analysis

```bash
#!/bin/bash
# Root cause analysis template

echo "=== Root Cause Analysis ==="
echo "1. Timeline of Events:"
echo "   - When was the incident first detected?"
echo "   - What alerts fired?"
echo "   - What actions were taken?"

echo ""
echo "2. Root Cause:"
echo "   - What was the fundamental cause?"
echo "   - Why didn't existing monitoring catch it earlier?"
echo "   - What failed in our defenses?"

echo ""
echo "3. Impact Assessment:"
echo "   - How many requests were affected?"
echo "   - What was the business impact?"
echo "   - Were there any security implications?"

echo ""
echo "4. Response Effectiveness:"
echo "   - How quickly was the incident detected?"
echo "   - How effective was the response?"
echo "   - What worked well?"
echo "   - What could be improved?"

echo ""
echo "5. Action Items:"
echo "   - What immediate fixes are needed?"
echo "   - What long-term improvements should be made?"
echo "   - Who is responsible for each action?"
echo "   - What are the target completion dates?"
```

### Prevention Measures

1. **Enhance Monitoring**
   ```bash
   # Add more granular alerts based on incident
   # Update AlertManager configuration
   # Add custom metrics for specific failure modes
   ```

2. **Improve Automation**
   ```bash
   # Create automated responses for common incidents
   # Implement circuit breakers for external dependencies
   # Add automatic scaling based on threat volume
   ```

3. **Update Documentation**
   ```bash
   # Update runbooks with lessons learned
   # Create new troubleshooting guides
   # Improve monitoring dashboards
   ```

This incident response runbook provides comprehensive procedures for handling security, performance, and operational incidents with Kong Guard AI, ensuring rapid response and effective resolution.