# Kong Guard AI - GDPR Compliance Guide

## Overview

This document outlines how Kong Guard AI handles personal data and ensures compliance with the General Data Protection Regulation (GDPR) when deployed in production environments.

## Data Processing Overview

### What Data We Process

Kong Guard AI processes the following categories of data:

1. **Network Data**
   - IP addresses (personal data under GDPR)
   - Request headers (may contain personal identifiers)
   - User agents
   - Request timestamps

2. **Request Content**
   - HTTP request bodies (analyzed for threats)
   - URL parameters
   - Form data (when analyzing payloads)

3. **Response Data**
   - Response sizes
   - Response status codes
   - Response timing metrics

4. **Log Data**
   - Threat detection events
   - Enforcement actions
   - Performance metrics
   - Error messages

### Legal Basis for Processing

Kong Guard AI processes personal data under the following GDPR legal bases:

1. **Legitimate Interest (Article 6(1)(f))**
   - Cybersecurity and threat protection
   - Prevention of fraud and abuse
   - Network security monitoring

2. **Legal Obligation (Article 6(1)(c))**
   - Compliance with cybersecurity regulations
   - Incident reporting requirements

3. **Consent (Article 6(1)(a))**
   - When explicitly obtained for enhanced monitoring
   - For analytics and performance optimization

## Data Protection Measures

### Data Minimization

Kong Guard AI implements several data minimization strategies:

```lua
-- Configuration for data minimization
config = {
    -- Limit payload analysis size
    max_payload_size = 65536, -- 64KB maximum
    
    -- Anonymize IP addresses
    anonymize_ip = true,
    ip_anonymization_method = "mask_last_octet", -- 192.168.1.x
    
    -- Limit log retention
    log_retention_days = 30,
    
    -- Disable sensitive data logging
    log_request_body = false,
    log_response_body = false,
    
    -- Sample data collection
    learning_sample_rate = 0.01 -- Only 1% of requests
}
```

### IP Address Anonymization

Kong Guard AI can anonymize IP addresses to reduce GDPR impact:

```lua
-- IP anonymization function
local function anonymize_ip(ip)
    if config.anonymize_ip then
        if ip:match("^%d+%.%d+%.%d+%.%d+$") then -- IPv4
            return ip:gsub("(%d+)$", "0") -- Replace last octet with 0
        elseif ip:match("^[%x:]+$") then -- IPv6
            return ip:gsub(":[%x]+:[%x]+:[%x]+$", ":0:0:0") -- Mask last 48 bits
        end
    end
    return ip
end
```

### Data Retention

Automated data retention policies:

```yaml
# Data retention configuration
retention_policies:
  threat_logs:
    retention_days: 30
    after_retention: "anonymize" # or "delete"
  
  performance_metrics:
    retention_days: 90
    after_retention: "aggregate" # Keep aggregated data only
  
  learning_data:
    retention_days: 7
    after_retention: "delete"
  
  audit_logs:
    retention_days: 2555 # 7 years for legal compliance
    after_retention: "archive"
```

### Encryption

All personal data is encrypted:

1. **At Rest**
   - Database encryption with AWS RDS encryption
   - S3 bucket encryption for log storage
   - Kubernetes secrets encryption

2. **In Transit**
   - TLS 1.3 for all API communications
   - mTLS for internal service communication
   - Encrypted log shipping

3. **In Processing**
   - Memory encryption where supported
   - Secure key management with AWS KMS

## Data Subject Rights

### Right to Information (Articles 13-14)

Kong Guard AI provides transparency through:

1. **Privacy Notice Configuration**
```lua
config = {
    privacy_notice = {
        enabled = true,
        data_controller = "Your Company Name",
        contact_email = "privacy@yourcompany.com",
        legal_basis = "legitimate_interest",
        retention_period = "30 days",
        rights_information = true
    }
}
```

2. **Data Processing Documentation**
   - Purpose of processing clearly defined
   - Legal basis documented
   - Retention periods specified
   - Data subject rights explained

### Right of Access (Article 15)

Implementing data subject access requests:

```bash
#!/bin/bash
# Data Subject Access Request (DSAR) script

# Extract all data for a specific IP address
IP_ADDRESS="$1"
OUTPUT_DIR="dsar_${IP_ADDRESS}_$(date +%Y%m%d)"

mkdir -p "$OUTPUT_DIR"

# Search Kong logs for the IP
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | \
    grep "$IP_ADDRESS" > "$OUTPUT_DIR/kong_logs.txt"

# Search threat detection logs
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | \
    grep -i "threat_detected.*$IP_ADDRESS" > "$OUTPUT_DIR/threat_events.txt"

# Search enforcement actions
kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | \
    grep -i "enforcement.*$IP_ADDRESS" > "$OUTPUT_DIR/enforcement_actions.txt"

# Generate summary report
cat > "$OUTPUT_DIR/dsar_summary.txt" << EOF
Data Subject Access Request Summary
====================================

IP Address: $IP_ADDRESS
Request Date: $(date)
Data Retention Period: 30 days

Data Categories Found:
- Request logs: $(wc -l < "$OUTPUT_DIR/kong_logs.txt") entries
- Threat events: $(wc -l < "$OUTPUT_DIR/threat_events.txt") entries  
- Enforcement actions: $(wc -l < "$OUTPUT_DIR/enforcement_actions.txt") entries

Legal Basis: Legitimate Interest (Cybersecurity)
Retention: Automated deletion after 30 days

Rights Available:
- Right to rectification
- Right to erasure
- Right to restrict processing
- Right to object
- Right to data portability

Contact: privacy@yourcompany.com
EOF

echo "DSAR package created in $OUTPUT_DIR"
```

### Right to Rectification (Article 16)

Since Kong Guard AI primarily processes technical data (IP addresses, request patterns), rectification typically involves:

1. **IP Address Corrections**
   - Update IP whitelist/blacklist if incorrect
   - Correct geolocation data if inaccurate

2. **Threat Classification Corrections**
   - Update false positive records
   - Reclassify legitimate traffic incorrectly flagged

### Right to Erasure (Article 17)

Implementing the "right to be forgotten":

```bash
#!/bin/bash
# Data erasure script for specific IP address

IP_ADDRESS="$1"
CONFIRMATION="$2"

if [[ "$CONFIRMATION" != "CONFIRMED" ]]; then
    echo "This will permanently delete all data for IP $IP_ADDRESS"
    echo "Usage: $0 <IP_ADDRESS> CONFIRMED"
    exit 1
fi

# Remove from IP blacklist
curl -X PATCH http://kong-admin:8001/plugins/kong-guard-ai \
    --data "config.ip_blacklist[]=" \
    --data "config.ip_blacklist[]=$(curl -s http://kong-admin:8001/plugins/kong-guard-ai | jq -r '.config.ip_blacklist[]' | grep -v "$IP_ADDRESS")"

# Clear threat cache entries
kubectl exec -n kong-guard-ai deployment/kong-gateway -- \
    lua -e "
        local shared = ngx.shared.kong_guard_ai_cache
        local keys = shared:get_keys(0)
        for _, key in ipairs(keys) do
            if key:match('$IP_ADDRESS') then
                shared:delete(key)
            end
        end
    "

# Remove from rate limiting cache
kubectl exec -n kong-guard-ai deployment/kong-gateway -- \
    lua -e "
        local shared = ngx.shared.kong_guard_ai_rate_limit
        local keys = shared:get_keys(0)
        for _, key in ipairs(keys) do
            if key:match('$IP_ADDRESS') then
                shared:delete(key)
            end
        end
    "

# Archive logs before deletion (for audit trail)
ARCHIVE_DIR="/var/backups/gdpr-deletions/$(date +%Y%m%d)"
mkdir -p "$ARCHIVE_DIR"

kubectl logs -n kong-guard-ai -l app.kubernetes.io/name=kong-gateway --since=720h | \
    grep "$IP_ADDRESS" > "$ARCHIVE_DIR/deleted_logs_${IP_ADDRESS}_$(date +%Y%m%d_%H%M%S).txt"

# Log the deletion action
echo "$(date): GDPR deletion executed for IP $IP_ADDRESS by $(whoami)" >> /var/log/gdpr-deletions.log

echo "Data erasure completed for IP $IP_ADDRESS"
echo "Archived logs available in $ARCHIVE_DIR"
```

### Right to Restrict Processing (Article 18)

Implementing processing restrictions:

```lua
-- Configuration for restricted processing
local restricted_ips = {
    ["192.168.1.100"] = {
        restriction_type = "processing_only", -- or "no_processing", "logging_only"
        reason = "gdpr_restriction_request",
        applied_date = "2024-01-15",
        expiry_date = "2024-07-15" -- 6 months maximum
    }
}

-- Check if IP processing is restricted
local function is_processing_restricted(ip)
    local restriction = restricted_ips[ip]
    if restriction then
        local current_date = os.date("%Y-%m-%d")
        if restriction.expiry_date and current_date > restriction.expiry_date then
            -- Restriction expired, remove it
            restricted_ips[ip] = nil
            return false
        end
        return restriction.restriction_type
    end
    return false
end
```

### Right to Object (Article 21)

Handling objections to processing:

```yaml
# Configuration for processing objections
objection_handling:
  legitimate_interest_balancing:
    factors_considered:
      - "Cybersecurity risk assessment"
      - "Public safety considerations"
      - "Technical necessity for service operation"
      - "Data subject's fundamental rights"
    
  objection_responses:
    accepted:
      action: "restrict_processing"
      notification: "Processing restricted per GDPR Article 21"
    
    overridden:
      action: "continue_processing"
      justification: "Compelling legitimate grounds override objection"
      notification: "Objection noted but processing continues due to security requirements"
```

## Technical Compliance Measures

### Privacy by Design

Kong Guard AI implements privacy by design principles:

1. **Default Security Settings**
```lua
-- Secure defaults
local default_config = {
    dry_run_mode = true,           -- No enforcement by default
    anonymize_ip = true,           -- IP anonymization enabled
    log_level = "info",            -- Minimal logging
    max_payload_size = 8192,       -- Limit data processed
    threat_threshold = 8.0,        -- Conservative threshold
    enable_learning = false,       -- No learning by default
    notification_threshold = 9.0   -- Only critical alerts
}
```

2. **Data Protection Impact Assessment (DPIA)**

Kong Guard AI supports DPIA requirements:

```yaml
dpia_assessment:
  high_risk_processing: false
  reasons:
    - "Automated threat detection"
    - "IP address processing"
    - "Security monitoring"
  
  risk_mitigation:
    - "IP anonymization"
    - "Data minimization"
    - "Purpose limitation"
    - "Storage limitation"
    - "Encryption at rest and in transit"
  
  necessity_test:
    purpose: "Cybersecurity protection"
    proportionality: "Minimal data processing"
    effectiveness: "Proven threat detection"
```

### Consent Management

For enhanced features requiring consent:

```lua
-- Consent management
local consent_manager = {
    check_consent = function(ip, purpose)
        -- Check if consent exists for this purpose
        local consent_key = "consent:" .. ip .. ":" .. purpose
        local consent = ngx.shared.kong_guard_ai_cache:get(consent_key)
        
        if consent then
            local consent_data = cjson.decode(consent)
            local current_time = ngx.time()
            
            -- Check if consent is still valid
            if consent_data.expiry and current_time > consent_data.expiry then
                ngx.shared.kong_guard_ai_cache:delete(consent_key)
                return false
            end
            
            return consent_data.granted
        end
        
        return false
    end,
    
    record_consent = function(ip, purpose, granted, expiry)
        local consent_key = "consent:" .. ip .. ":" .. purpose
        local consent_data = {
            granted = granted,
            timestamp = ngx.time(),
            expiry = expiry,
            purpose = purpose
        }
        
        ngx.shared.kong_guard_ai_cache:set(consent_key, cjson.encode(consent_data), expiry)
    end
}
```

## Audit and Compliance Monitoring

### GDPR Compliance Dashboard

Monitor GDPR compliance metrics:

```yaml
# Grafana dashboard metrics
gdpr_metrics:
  - name: "data_subject_requests"
    description: "Number of data subject requests processed"
    type: "counter"
    
  - name: "data_retention_compliance"
    description: "Percentage of data within retention limits"
    type: "gauge"
    
  - name: "anonymization_rate"
    description: "Percentage of IP addresses anonymized"
    type: "gauge"
    
  - name: "consent_compliance"
    description: "Compliance with consent requirements"
    type: "gauge"
```

### Audit Trail

Comprehensive audit logging:

```lua
-- GDPR audit logging
local function log_gdpr_action(action_type, ip, details)
    local audit_entry = {
        timestamp = ngx.utctime(),
        action_type = action_type, -- "access", "rectification", "erasure", "restriction"
        ip_address = ip,
        details = details,
        operator = ngx.var.http_x_operator_id or "system",
        request_id = ngx.var.request_id
    }
    
    -- Log to dedicated GDPR audit log
    ngx.log(ngx.INFO, "GDPR_AUDIT: " .. cjson.encode(audit_entry))
end
```

## Incident Response Procedures

### Data Breach Response

In case of a personal data breach:

1. **Immediate Response (within 1 hour)**
   - Identify scope of breach
   - Contain the incident
   - Assess risk to data subjects

2. **Authority Notification (within 72 hours)**
   - Prepare breach notification for supervisory authority
   - Include required information per Article 33

3. **Data Subject Notification (without undue delay)**
   - If high risk to rights and freedoms
   - Provide information per Article 34

```bash
#!/bin/bash
# GDPR breach response script

BREACH_ID="BREACH_$(date +%Y%m%d_%H%M%S)"
BREACH_DIR="/var/security/gdpr-breaches/$BREACH_ID"

mkdir -p "$BREACH_DIR"

# Collect breach information
cat > "$BREACH_DIR/breach_assessment.txt" << EOF
GDPR Data Breach Assessment
===========================

Breach ID: $BREACH_ID
Date Discovered: $(date)
Reported By: $(whoami)

Nature of Breach:
[ ] Confidentiality breach (unauthorized access)
[ ] Integrity breach (unauthorized alteration)
[ ] Availability breach (loss of data)

Categories of Data Affected:
[ ] IP addresses
[ ] Request data
[ ] Threat detection logs
[ ] Other: _______________

Number of Data Subjects Affected: ___________
Risk Assessment: [ ] Low [ ] Medium [ ] High

Immediate Actions Taken:
- 
- 
- 

Next Steps:
- [ ] Notify supervisory authority (within 72h)
- [ ] Notify data subjects (if high risk)
- [ ] Update security measures
- [ ] Review and update procedures
EOF

echo "Breach assessment template created: $BREACH_DIR/breach_assessment.txt"
```

## Implementation Checklist

### Pre-Deployment GDPR Compliance

- [ ] Data Protection Impact Assessment completed
- [ ] Legal basis for processing documented
- [ ] Privacy notice updated
- [ ] Data retention policies configured
- [ ] IP anonymization enabled
- [ ] Encryption configured for all data
- [ ] Access controls implemented
- [ ] Audit logging enabled
- [ ] Incident response procedures documented
- [ ] Staff training completed

### Operational GDPR Compliance

- [ ] Regular compliance audits scheduled
- [ ] Data subject request procedures operational
- [ ] Breach response procedures tested
- [ ] Vendor agreements updated
- [ ] Cross-border transfer safeguards implemented
- [ ] Consent management system operational
- [ ] Data retention automated
- [ ] Security monitoring active

### Ongoing Compliance

- [ ] Monthly compliance reviews
- [ ] Quarterly privacy impact assessments
- [ ] Annual compliance training
- [ ] Regular penetration testing
- [ ] Vendor compliance monitoring
- [ ] Regulatory change monitoring
- [ ] Documentation updates

This GDPR compliance guide ensures Kong Guard AI meets all requirements for processing personal data in the European Union while maintaining effective cybersecurity protection.