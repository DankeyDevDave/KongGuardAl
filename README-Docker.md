# Kong Guard AI - Docker Development Environment

This directory contains the Docker Compose stack for local development of the Kong Guard AI plugin.

## 🚀 Quick Start

1. **Start the development stack:**
   ```bash
   ./docker-start.sh
   ```

2. **Configure Kong services and routes:**
   ```bash
   ./setup-kong.sh
   ```

3. **Test the setup:**
   ```bash
   # Test Kong Gateway
   curl http://localhost:8001/status
   
   # Test Demo API through Kong
   curl http://localhost:8000/demo/status/200
   
   # Test Mock Attacker through Kong
   curl http://localhost:8000/attack/health
   ```

## 📊 Services Overview

| Service | Port | URL | Description |
|---------|------|-----|-------------|
| Kong Gateway (Proxy) | 8000 | http://localhost:8000 | Main API gateway endpoint |
| Kong Gateway (Admin) | 8001 | http://localhost:8001 | Kong Admin API |
| Kong Gateway (SSL Proxy) | 8443 | https://localhost:8443 | SSL proxy endpoint |
| Kong Gateway (SSL Admin) | 8444 | https://localhost:8444 | SSL admin endpoint |
| Demo API (httpbin) | 8080 | http://localhost:8080 | Testing API service |
| Mock Attacker | 8090 | http://localhost:8090 | Simulated malicious traffic |
| PostgreSQL | 5432 | localhost:5432 | Kong database |
| Redis | 6379 | localhost:6379 | Plugin state storage |

## 🔧 Management Scripts

- **`./docker-start.sh`** - Start the complete development stack
- **`./docker-stop.sh`** - Stop all services (preserves data)
- **`./docker-reset.sh`** - Stop and remove all data (complete reset)
- **`./setup-kong.sh`** - Configure Kong services, routes, and plugins

## 📁 Directory Structure

```
.
├── docker-compose.yml          # Main Docker Compose configuration
├── kong.conf                   # Kong Gateway configuration
├── .env.docker                 # Environment variables
├── plugins/
│   └── kong-guard-ai/          # Plugin development directory
│       ├── handler.lua         # Plugin handler (placeholder)
│       └── schema.lua          # Plugin configuration schema
├── mock-attacker/              # Mock malicious service
│   ├── nginx.conf              # Nginx configuration
│   └── html/
│       └── index.html          # Attack simulation endpoints
├── docker-start.sh             # Start script
├── docker-stop.sh              # Stop script
├── docker-reset.sh             # Reset script
└── setup-kong.sh               # Kong configuration script
```

## 🛡️ Plugin Development

The Kong Guard AI plugin files are located in `plugins/kong-guard-ai/`:

- **`handler.lua`** - Main plugin logic (currently placeholder)
- **`schema.lua`** - Plugin configuration schema

### Plugin Development Workflow

1. Modify plugin files in `plugins/kong-guard-ai/`
2. Restart Kong container: `docker-compose restart kong`
3. Re-run Kong configuration: `./setup-kong.sh`
4. Test plugin functionality

### Plugin Configuration

The plugin supports various configuration options defined in `schema.lua`:

- **Basic Settings**: dry_run, log_level
- **Rate Limiting**: rate_limit_enabled, rate_limit_threshold
- **IP Blocking**: ip_blocking_enabled, blocked_ips
- **AI Detection**: ai_detection_enabled, ai_api_endpoint
- **Notifications**: notifications_enabled, slack_webhook_url
- **Payload Analysis**: payload_analysis_enabled, suspicious_patterns

## 🧪 Testing Scenarios

### 1. Rate Limiting Test
```bash
# Rapid requests to trigger rate limiting
for i in {1..150}; do
    curl -s http://localhost:8000/demo/status/200 > /dev/null
    echo "Request $i"
done
```

### 2. Suspicious Access Test
```bash
# Try accessing admin endpoints
curl http://localhost:8000/attack/admin
curl http://localhost:8000/attack/.env
curl http://localhost:8000/attack/config
```

### 3. Error Pattern Test
```bash
# Generate various error responses
curl http://localhost:8000/attack/api/error/400
curl http://localhost:8000/attack/api/error/401
curl http://localhost:8000/attack/api/error/403
curl http://localhost:8000/attack/api/error/500
```

### 4. Large Payload Test
```bash
# Send large POST request
curl -X POST http://localhost:8000/attack/api/upload \
     -H "Content-Type: application/json" \
     -d '{"data": "'$(head -c 1000000 /dev/zero | base64)'"}'
```

## 📊 Monitoring and Logs

### View Service Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f kong
docker-compose logs -f kong-database
docker-compose logs -f demo-api
docker-compose logs -f mock-attacker
```

### Kong Admin API Queries
```bash
# View services
curl http://localhost:8001/services

# View routes
curl http://localhost:8001/routes

# View plugins
curl http://localhost:8001/plugins

# View consumers
curl http://localhost:8001/consumers

# Kong status
curl http://localhost:8001/status
```

## 🔍 Troubleshooting

### Common Issues

1. **Kong fails to start**
   - Check database connection: `docker-compose logs kong-database`
   - Verify migrations: `docker-compose logs kong-migrations`

2. **Plugin not loading**
   - Check plugin directory permissions
   - Verify Lua syntax: `luac -p plugins/kong-guard-ai/*.lua`
   - Check Kong logs for plugin errors

3. **Services unreachable**
   - Verify all containers are running: `docker-compose ps`
   - Check network connectivity: `docker network ls`

### Reset Environment
```bash
# Complete reset (removes all data)
./docker-reset.sh

# Start fresh
./docker-start.sh
./setup-kong.sh
```

## 🌐 External Dependencies

- **Docker & Docker Compose** - Container orchestration
- **Kong Gateway 3.8.0** - API Gateway
- **PostgreSQL 13** - Kong database
- **Redis 7** - Plugin state storage
- **httpbin** - Demo API service
- **Nginx** - Mock attacker service

## 📚 Useful Resources

- [Kong Gateway Documentation](https://docs.konghq.com/gateway/)
- [Kong Plugin Development Guide](https://docs.konghq.com/gateway/latest/plugin-development/)
- [Kong Admin API Reference](https://docs.konghq.com/gateway/api/admin-oss/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)

---

**Next Steps:**
1. Develop the Kong Guard AI plugin logic in `plugins/kong-guard-ai/`
2. Implement threat detection algorithms
3. Add AI integration capabilities
4. Test with various attack scenarios
5. Implement notification systems