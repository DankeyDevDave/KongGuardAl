# Kong Guard AI - Unified Stack

## Everything in One Location

All Kong Guard AI components are now managed through a single Docker Compose stack for easier management and maintenance.

## Complete Stack Components

| Service | Port | Purpose |
|---------|------|---------|
| **Kong Gateway** | 18000 (HTTP), 18443 (HTTPS) | API Gateway |
| **Kong Admin API** | 18001 (HTTP), 18444 (HTTPS) | Kong Management |
| **Konga** | 1337 | Kong Admin GUI |
| **Grafana** | 3000 | Monitoring Dashboard |
| **Prometheus** | 9090 | Metrics Collection |
| **Cloud AI Service** | 18002 | AI-powered threat detection |
| **Ollama AI Service** | 18003 | Local LLM protection |
| **Web Dashboard** | 8080 | Real-time threat dashboard |
| **PostgreSQL** | 15432 | Kong database |
| **Redis** | 16379 | Cache and state |

## Quick Start

### Start Everything
```bash
./manage-stack.sh start
```

This single command:
- Stops any standalone services
- Starts all Docker containers
- Configures networking between services
- Sets up metrics collection
- Initializes databases

### Stop Everything
```bash
./manage-stack.sh stop
```

### Check Status
```bash
./manage-stack.sh status
```

### View Logs
```bash
# All services
./manage-stack.sh logs

# Specific service
./manage-stack.sh logs grafana
```

## Access Points

### Monitoring & Dashboards
- **Grafana**: http://localhost:3000
  - Username: `admin`
  - Password: `KongGuard2024!`
  - Pre-configured Kong Guard AI dashboard

- **Web Dashboard**: http://localhost:8080
  - Real-time threat detection
  - WebSocket updates
  - Three-tier protection status

### API Endpoints
- **Kong Gateway**: http://localhost:18000
- **Kong Admin API**: http://localhost:18001
- **Cloud AI API**: http://localhost:18002
- **Ollama AI API**: http://localhost:18003

### Admin Interfaces
- **Konga**: http://localhost:1337
  - Kong administration GUI
  - Route and service management

- **Prometheus**: http://localhost:9090
  - Direct metrics queries
  - Target health monitoring

## Configuration

### Environment Variables
Create a `.env` file for API keys:
```bash
# AI Provider Keys
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=your-key-here

# Database Passwords (optional, defaults provided)
KONG_PG_PASSWORD=kongpass
KONGA_DB_PASSWORD=kongapass
```

### Ollama Configuration
The Ollama service connects to your local Ollama installation:
- Ensure Ollama is running: `ollama serve`
- Default model: `llama3.2:3b`
- Host: `http://host.docker.internal:11434`

## Metrics & Monitoring

### Prometheus Targets
- `ai-service-cloud:8000/metrics` - Cloud AI metrics
- `ai-service-ollama:8000/metrics` - Ollama AI metrics
- `kong:8001/metrics` - Kong Gateway metrics
- `prometheus:9090/metrics` - Self monitoring

### Grafana Datasources
Pre-configured datasources:
1. Prometheus (local) - http://prometheus:9090
2. Direct AI metrics - http://ai-service-cloud:8000
3. Production Prometheus - http://192.168.0.225:9090 (optional)

## Management Commands

```bash
# Start the stack
./manage-stack.sh start

# Stop the stack
./manage-stack.sh stop

# Restart all services
./manage-stack.sh restart

# Check service health
./manage-stack.sh status

# View logs
./manage-stack.sh logs [service-name]

# Display current metrics
./manage-stack.sh metrics

# Clean all data and volumes
./manage-stack.sh clean

# Rebuild AI service images
./manage-stack.sh build
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Docker Network: kong-net │
├─────────────────────────────────────────────────────────┤
│ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│ │ Kong │ │ Cloud │ │ Ollama │ │ Web │ │
│ │ Gateway │──│ AI │ │ AI │ │Dashboard│ │
│ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
│ │ │ │ │ │
│ └──────────────┴──────────────┴────────────┘ │
│ │ │
│ ┌───────────────┐ │
│ │ Prometheus │ │
│ └───────────────┘ │
│ │ │
│ ┌───────────────┐ │
│ │ Grafana │ │
│ └───────────────┘ │
│ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│ │PostgreSQL│ │ Redis │ │ Konga │ │ Demo │ │
│ │ x2 │ │ │ │ │ │ API │ │
│ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Services Not Starting
```bash
# Check Docker logs
docker-compose logs [service-name]

# Verify port availability
lsof -i :3000 # Check if Grafana port is free
```

### Metrics Not Showing
```bash
# Test metrics endpoints
curl http://localhost:18002/metrics
curl http://localhost:18003/metrics

# Check Prometheus targets
open http://localhost:9090/targets
```

### Ollama Connection Issues
```bash
# Verify Ollama is running
ollama list

# Test Ollama API
curl http://localhost:11434/api/tags
```

## Security Notes

- Change default passwords in production
- Use environment variables for API keys
- Configure firewall rules for production deployment
- Enable TLS/SSL for external access
- Regularly update Docker images

## Notes

- All services restart automatically on failure
- Data persists in Docker volumes
- Logs are stored in `./logs/` directory
- Grafana dashboards are pre-provisioned
- Health checks ensure service availability

---

**Single Command Management**: `./manage-stack.sh` handles everything!