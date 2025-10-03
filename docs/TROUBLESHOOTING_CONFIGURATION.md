# Kong Guard AI - Configuration Troubleshooting Guide

This guide helps diagnose and resolve common configuration issues with the Kong Guard AI plugin across different deployment scenarios.

## Quick Diagnosis

### Health Check Commands

```bash
# Check Kong status
curl http://localhost:8001/status

# List available plugins
curl http://localhost:8001/plugins/available | jq '.available_plugins[]' | grep kong-guard-ai

# Check plugin instances
curl http://localhost:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'

# Validate specific plugin configuration
curl http://localhost:8001/plugins/PLUGIN_ID
```

### Log Analysis

```bash
# Kong error logs
docker logs kong-gateway 2>&1 | grep -i "kong-guard-ai\|error"

# Plugin-specific logs (if structured logging enabled)
docker logs kong-gateway 2>&1 | grep "kong-guard-ai" | tail -20

# Access logs with plugin info
tail -f /var/log/kong/access.log | grep "kong-guard-ai"
```

## Common Configuration Issues

### 1. Plugin Not Loading

**Symptoms:**
- Plugin not in available plugins list
- "plugin not found" errors
- 404 responses when configuring plugin

**Diagnosis:**
```bash
# Check if plugin files exist
ls -la /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/

# Verify Kong configuration includes plugin path
kong config | grep plugins
```

**Solutions:**

#### For Local Development
```bash
# Ensure plugin is in Kong's plugin path
export KONG_PLUGINS="bundled,kong-guard-ai"
export KONG_LUA_PACKAGE_PATH="/path/to/plugins/?.lua;;"

# Restart Kong
kong restart
```

#### For Docker
```yaml
# docker-compose.yml
environment:
  KONG_PLUGINS: bundled,kong-guard-ai
  KONG_LUA_PACKAGE_PATH: "/opt/kong/plugins/?.lua;;"
volumes:
  - ./kong/plugins:/opt/kong/plugins
```

#### For Konnect
- Ensure plugin is available in your Konnect environment
- Contact Kong support if custom plugin deployment is needed

### 2. Schema Validation Errors

**Symptoms:**
- "schema violation" errors
- Configuration rejected by Admin API
- Invalid field type errors

**Common Schema Issues:**

#### Boolean Field Errors
```bash
# Incorrect
{
  "config": {
    "dry_run": "true" # String instead of boolean
  }
}

# Correct
{
  "config": {
    "dry_run": true
  }
}
```

#### Array Field Errors
```bash
# Incorrect
{
  "config": {
    "threat_detection": {
      "rules": {
        "suspicious_patterns": "SELECT.*FROM" # String instead of array
      }
    }
  }
}

# Correct
{
  "config": {
    "threat_detection": {
      "rules": {
        "suspicious_patterns": ["SELECT.*FROM", "<script"]
      }
    }
  }
}
```

#### Missing Required Fields
```bash
# Validate configuration before applying
curl -X POST http://localhost:8001/schemas/plugins/validate \
  -H "Content-Type: application/json" \
  -d '{
    "name": "kong-guard-ai",
    "config": {
      "dry_run": true,
      "log_level": "info"
    }
  }'
```

### 3. Dry Run Mode Issues

**Symptoms:**
- Requests blocked when dry_run is true
- No logs generated in dry run mode
- Inconsistent behavior between dry run and active mode

**Diagnosis:**
```bash
# Check current dry_run setting
curl http://localhost:8001/plugins/PLUGIN_ID | jq '.config.dry_run'

# Test with dry run enabled
curl -X PATCH http://localhost:8001/plugins/PLUGIN_ID \
  -H "Content-Type: application/json" \
  -d '{"config": {"dry_run": true}}'

# Send test request and check response
curl -v http://localhost:8000/your-route
```

**Solutions:**

#### Enable Structured Logging
```json
{
  "config": {
    "logging": {
      "enabled": true,
      "structured_logging": true,
      "log_requests": true
    }
  }
}
```

#### Verify Log Output
```bash
# Check Kong error log for plugin messages
docker logs kong-gateway 2>&1 | grep "kong-guard-ai.*dry_run"

# Check access logs for threat detection info
tail -f /var/log/kong/access.log | jq '.kong_guard_ai'
```

### 4. Performance Issues

**Symptoms:**
- High response times
- Kong worker process CPU usage
- Memory consumption growth

**Diagnosis:**
```bash
# Check plugin processing time
curl http://localhost:8000/_guard_ai/metrics

# Monitor Kong worker processes
ps aux | grep kong
top -p $(pgrep -f "kong worker")

# Check for memory leaks
watch -n 5 'ps -eo pid,ppid,cmd,%mem --sort=-%mem | grep kong'
```

**Solutions:**

#### Optimize Configuration
```json
{
  "config": {
    "performance": {
      "max_processing_time": 5, // Reduce from default 10ms
      "enable_caching": true,
      "cache_size": 500, // Reduce if memory constrained
      "sampling_rate": 0.1 // Process only 10% of requests
    },
    "threat_detection": {
      "rules": {
        "max_payload_size": 65536 // Reduce payload analysis size
      }
    }
  }
}
```

#### Enable Async Processing
```json
{
  "config": {
    "performance": {
      "async_processing": true
    }
  }
}
```

### 5. Hot Reload Problems

**Symptoms:**
- Configuration changes not taking effect
- Requires Kong restart for changes
- Inconsistent configuration across workers

**Diagnosis:**
```bash
# Check Kong configuration reload
kong health

# Verify configuration propagation
for i in {1..5}; do
  curl -s http://localhost:8001/plugins/PLUGIN_ID | jq '.config.dry_run'
  sleep 1
done
```

**Solutions:**

#### Force Configuration Reload
```bash
# Send SIGUSR1 to Kong master process
sudo kill -USR1 $(cat /var/run/kong/nginx.pid)

# Or use Kong reload command
kong reload
```

#### Check Worker Process Sync
```bash
# Ensure all workers have same configuration
curl http://localhost:8001/status | jq '.database.reachable'
```

### 6. Notification Failures

**Symptoms:**
- Webhook notifications not sent
- Email notifications failing
- Slack integration not working

**Diagnosis:**
```bash
# Test webhook endpoint
curl -X POST http://your-webhook-endpoint/test \
  -H "Content-Type: application/json" \
  -d '{"test": "kong-guard-ai webhook test"}'

# Check notification configuration
curl http://localhost:8001/plugins/PLUGIN_ID | jq '.config.notifications'

# Monitor notification attempts in logs
docker logs kong-gateway 2>&1 | grep "notification\|webhook"
```

**Solutions:**

#### Webhook Configuration
```json
{
  "config": {
    "notifications": {
      "webhook_url": "https://your-endpoint.com/webhook",
      "notification_cooldown": 60,
      "max_notifications_per_hour": 10
    }
  }
}
```

#### Email Configuration
```json
{
  "config": {
    "notifications": {
      "email_config": {
        "enabled": true,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_user": "your-email@gmail.com",
        "smtp_password": "your-app-password",
        "from_email": "your-email@gmail.com",
        "to_emails": ["admin@company.com"]
      }
    }
  }
}
```

### 7. AI Gateway Integration Issues

**Symptoms:**
- AI analysis not working
- Timeouts on AI requests
- Invalid AI model responses

**Diagnosis:**
```bash
# Test AI Gateway connectivity
curl -X POST $AI_GATEWAY_ENDPOINT/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "test"}]}'

# Check AI Gateway configuration
curl http://localhost:8001/plugins/PLUGIN_ID | jq '.config.ai_gateway'
```

**Solutions:**

#### Update AI Configuration
```json
{
  "config": {
    "ai_gateway": {
      "enabled": true,
      "model_endpoint": "https://api.openai.com/v1",
      "model_name": "gpt-3.5-turbo",
      "api_key": "your-api-key",
      "analysis_timeout": 10000, // Increase timeout
      "cache_results": true,
      "cache_ttl": 300
    }
  }
}
```

## Deployment-Specific Issues

### Kong Gateway (Traditional)

#### Database Connection Issues
```bash
# Check database connectivity
kong health

# Verify database schema
kong migrations status

# Reset if needed
kong migrations reset --yes
kong migrations bootstrap
```

#### Plugin File Permissions
```bash
# Ensure Kong can read plugin files
sudo chown -R kong:kong /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/
sudo chmod -R 755 /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/
```

### Kong Konnect

#### Declarative Configuration Issues
```bash
# Validate declarative config format
./scripts/validate-konnect-compatibility.sh

# Check for Konnect-specific constraints
grep -i "localhost" kong.yml # Should be empty
grep "http://" kong.yml # Should prefer HTTPS
```

#### Environment Variable Issues
```yaml
# Ensure environment variables are set in Konnect
config:
  webhook_url: "${WEBHOOK_URL}" # Must be set in Konnect environment
  api_key: "${AI_API_KEY}" # Must be configured as secret
```

### Docker Deployment

#### Container Issues
```bash
# Check container logs
docker logs kong-gateway

# Verify volume mounts
docker inspect kong-gateway | jq '.[].Mounts'

# Test plugin loading in container
docker exec kong-gateway kong plugins
```

#### Network Issues
```bash
# Test inter-container connectivity
docker exec kong-gateway ping webhook-service
docker exec kong-gateway nslookup redis
```

## Monitoring and Debugging

### Enable Debug Logging

```json
{
  "config": {
    "log_level": "debug",
    "logging": {
      "enabled": true,
      "structured_logging": true,
      "log_requests": true,
      "log_responses": true,
      "log_headers": true
    }
  }
}
```

### Performance Monitoring

```bash
# Create monitoring script
cat > monitor_plugin.sh << 'EOF'
#!/bin/bash
while true; do
  echo "=== $(date) ==="
  curl -s http://localhost:8000/_guard_ai/metrics | jq '.'
  curl -s http://localhost:8000/_guard_ai/status | jq '.'
  sleep 30
done
EOF

chmod +x monitor_plugin.sh
./monitor_plugin.sh
```

### Configuration Backup and Restore

```bash
# Backup current configuration
curl http://localhost:8001/config > kong_backup_$(date +%Y%m%d_%H%M%S).json

# Restore configuration
curl -X POST http://localhost:8001/config \
  -H "Content-Type: application/json" \
  -d @kong_backup_20240819_120000.json
```

## Getting Help

### Diagnostic Information to Collect

When reporting issues, include:

1. **Kong Version and Plugin Info**
   ```bash
   kong version
   curl http://localhost:8001/plugins/available | jq '.available_plugins[]' | grep kong-guard-ai
   ```

2. **Plugin Configuration**
   ```bash
   curl http://localhost:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'
   ```

3. **Error Logs**
   ```bash
   docker logs kong-gateway --tail 100 2>&1 | grep -i error
   ```

4. **System Information**
   ```bash
   uname -a
   docker version
   docker-compose version
   ```

### Support Channels

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check latest documentation for updates
- **Community**: Kong Community forums and Slack
- **Kong Support**: For Konnect-related issues

### Emergency Procedures

#### Quick Disable Plugin
```bash
# Disable plugin on all services
curl -X PATCH http://localhost:8001/plugins/PLUGIN_ID \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Or delete plugin entirely
curl -X DELETE http://localhost:8001/plugins/PLUGIN_ID
```

#### Rollback Configuration
```bash
# Restore from backup
curl -X POST http://localhost:8001/config \
  -H "Content-Type: application/json" \
  -d @kong_backup.json

# Or restart Kong with previous config
kong restart -c /etc/kong/kong.conf.backup
```

---

This troubleshooting guide covers the most common configuration issues. For deployment-specific problems, also refer to the respective deployment guides and Kong's official documentation.