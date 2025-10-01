# Kong Guard AI Launch Scripts

## Quick Start

### Launch the Complete Stack
```bash
./launch-kong-guard.sh
```

This will:
1. Check Docker and docker-compose availability
2. Stop any existing containers
3. Start all services (PostgreSQL, Redis, Kong, Demo API)
4. Wait for services to be healthy
5. Configure Kong Guard AI plugin
6. Open Kong Admin UI in your browser
7. Provide Claude assistance if errors occur

### Stop All Services
```bash
./stop-kong-guard.sh
```

Stop and clean volumes:
```bash
./stop-kong-guard.sh --clean
```

## Launch Options

### Command Line Arguments
```bash
# Show help
./launch-kong-guard.sh --help

# Clean volumes before starting (fresh start)
./launch-kong-guard.sh --clean

# Don't open browser UI
./launch-kong-guard.sh --no-ui

# Skip Claude assistance on errors
./launch-kong-guard.sh --skip-claude

# Show container logs after startup
./launch-kong-guard.sh --logs

# Combine options
./launch-kong-guard.sh --clean --logs --no-ui
```

### Environment Variables
```bash
# Clean volumes before starting
CLEAN_VOLUMES=true ./launch-kong-guard.sh

# Don't open UI
OPEN_UI=false ./launch-kong-guard.sh

# Disable Claude assistance
CLAUDE_ASSIST=false ./launch-kong-guard.sh
```

## Service URLs

After launching, services are available at:

- **Konga UI**: http://localhost:1337 (Web-based Kong Admin GUI)
- **Kong Admin API**: http://localhost:18001
- **Kong Proxy**: http://localhost:18000
- **Demo API**: http://localhost:18085
- **Redis**: redis://localhost:16379
- **PostgreSQL**: postgresql://kong:kongpass@localhost:15432/kong

## First Time Setup - Konga UI

When you first access Konga at http://localhost:1337:

1. **Create an Admin Account**:
   - Username: admin (or your choice)
   - Email: your-email@example.com
   - Password: (choose a secure password)

2. **Connect to Kong**:
   - Click "Connections" → "New Connection"
   - Name: `Local Kong`
   - Kong Admin URL: `http://kong:8001` (internal Docker network)
   - Click "Create Connection"

3. **Activate Connection**:
   - Click on your new connection to activate it
   - You should now see the Kong dashboard with services, routes, and plugins

## Testing the Stack

### Test Kong Proxy
```bash
# Test through Kong proxy
curl http://localhost:18000/demo/status/200
```

### Check Kong Admin API
```bash
# List services
curl http://localhost:18001/services

# List plugins
curl http://localhost:18001/plugins

# Check Kong Guard AI plugin
curl http://localhost:18001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'
```

### Simulate Attacks
```bash
# SQL Injection attempt
curl "http://localhost:18000/demo/anything?id=1' OR '1'='1"

# XSS attempt
curl "http://localhost:18000/demo/anything?search=<script>alert('xss')</script>"

# Path traversal attempt
curl "http://localhost:18000/demo/../../../etc/passwd"
```

## Troubleshooting

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f kong-gateway
docker compose logs -f kong-database
docker compose logs -f redis
```

### Check Service Health
```bash
# Check all containers
docker ps

# Check specific service health
docker exec kong-gateway kong health
docker exec kong-database pg_isready -U kong
docker exec kong-redis redis-cli ping
```

### Manual Claude Assistance

If the automatic Claude assistance doesn't trigger:

1. Check the diagnostics file:
```bash
cat diagnostics.txt
```

2. Manually call Claude:
```bash
claude -p "Kong Guard AI services are failing. Here are the diagnostics: $(cat diagnostics.txt)"
```

### Common Issues

#### Port Conflicts
The scripts use non-standard ports to avoid conflicts:
- Kong Admin: 18001 (instead of 8001)
- Kong Proxy: 18000 (instead of 8000)
- PostgreSQL: 15432 (instead of 5432)
- Redis: 16379 (instead of 6379)

#### Docker Not Running
```bash
# Start Docker Desktop on macOS
open -a Docker

# Start Docker on Linux
sudo systemctl start docker
```

#### Permission Issues
```bash
# Make scripts executable
chmod +x launch-kong-guard.sh
chmod +x stop-kong-guard.sh
chmod +x quick-start.sh
```

#### Clean Start
If services are in a bad state:
```bash
# Stop everything and clean volumes
./stop-kong-guard.sh --clean

# Fresh start
./launch-kong-guard.sh --clean
```

## Advanced Usage

### Custom Configuration

Edit `docker-compose.yml` to modify:
- Service configurations
- Port mappings
- Environment variables
- Volume mounts

### Plugin Configuration

The launch script automatically configures Kong Guard AI with default settings. To modify:

```bash
# Update plugin configuration
curl -X PATCH http://localhost:18001/plugins/{plugin-id} \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "log_level": "DEBUG",
      "threat_detection": {
        "ml_threshold": 0.8
      }
    }
  }'
```

### Development Mode

For development with live plugin reloading:
```bash
# Mount local plugin directory
docker compose up -d --volume ./kong-plugin:/usr/local/share/lua/5.1/kong/plugins
```

## Integration with CI/CD

### GitHub Actions
```yaml
- name: Launch Kong Guard AI
  run: |
    ./launch-kong-guard.sh --no-ui --skip-claude
    
- name: Run tests
  run: |
    npm test
    
- name: Stop services
  run: |
    ./stop-kong-guard.sh
```

### Jenkins
```groovy
stage('Start Kong Guard AI') {
    sh './launch-kong-guard.sh --no-ui --skip-claude'
}

stage('Test') {
    sh 'npm test'
}

stage('Cleanup') {
    sh './stop-kong-guard.sh'
}
```

## Support

If you encounter issues:

1. Check the launch log: `cat launch.log`
2. Check error log: `cat errors.log`
3. Review diagnostics: `cat diagnostics.txt`
4. Let Claude assist: Run the script without `--skip-claude`
5. Check Docker logs: `docker compose logs`

## Quick Commands Reference

```bash
# Launch
./launch-kong-guard.sh

# Launch with fresh start
./launch-kong-guard.sh --clean

# Launch without UI
./launch-kong-guard.sh --no-ui

# Stop
./stop-kong-guard.sh

# Stop and clean
./stop-kong-guard.sh --clean

# View help
./launch-kong-guard.sh --help
```