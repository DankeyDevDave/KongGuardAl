# Kong Guard AI - Network Access Configuration

## Network Architecture

Your Kong Guard AI stack needs to be accessible from your network, not just localhost.

### Current Network Layout:
- **Production Server**: 192.168.0.228 (where Docker stack runs)
- **Your Mac (Dev)**: 192.168.0.84 (with Ollama)
- **Network Range**: 192.168.0.0/24

## Access URLs from Network

When deployed on production server (192.168.0.228), access services from ANY device on your network:

### Core Services
| Service | Network URL | Purpose |
|---------|------------|---------|
| **Kong Gateway** | http://192.168.0.228:8000 | Main API Gateway |
| **Kong Admin** | http://192.168.0.228:8001 | Kong Management API |
| **Konga UI** | http://192.168.0.228:1337 | Web-based Kong Admin |

### Monitoring & Dashboards
| Service | Network URL | Credentials |
|---------|------------|-------------|
| **Grafana** | http://192.168.0.228:3000 | admin / KongGuard2024! |
| **Web Dashboard** | http://192.168.0.228:8080 | No auth required |
| **Prometheus** | http://192.168.0.228:9090 | No auth required |

### AI Services
| Service | Network URL | Description |
|---------|------------|-------------|
| **Cloud AI** | http://192.168.0.228:18002 | Cloud-based AI protection |
| **Ollama AI** | http://192.168.0.228:18003 | Local Ollama (via your Mac) |

## Docker Compose Configuration

The key difference for network access is using `0.0.0.0` instead of default binding:

### Development (localhost only):
```yaml
ports:
  - "3000:3000" # Only accessible on localhost
```

### Production (network accessible):
```yaml
ports:
  - "0.0.0.0:3000:3000" # Accessible from entire network
```

## Deployment Steps

### 1. On Production Server (192.168.0.228)

```bash
# Copy the project to production server
scp -r /Users/jacques/DevFolder/KongGuardAI user@192.168.0.228:/home/user/

# SSH to production server
ssh user@192.168.0.228

# Navigate to project
cd /home/user/KongGuardAI

# Use production compose file
docker-compose -f docker-compose.production.yml up -d
```

### 2. Configure Ollama Connection

The production stack connects to Ollama on your Mac (192.168.0.84):

```yaml
ai-service-ollama:
  environment:
    - OLLAMA_HOST=http://192.168.0.84:11434
```

**On your Mac**, ensure Ollama is accessible:
```bash
# Start Ollama with network binding
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

## Grafana Dashboard Configuration

Update Grafana datasources for network access:

```yaml
# grafana-local/provisioning/datasources/datasources.yml
datasources:
  - name: Prometheus
    type: prometheus
    url: http://prometheus:9090 # Internal Docker network
    
  - name: Kong-AI-Cloud
    type: prometheus
    url: http://ai-service-cloud:8000 # Internal Docker network
    
  - name: Kong-AI-Ollama
    type: prometheus
    url: http://ai-service-ollama:8000 # Internal Docker network
```

## Security Considerations

### Firewall Rules (Production Server)
```bash
# Allow Kong Gateway
sudo ufw allow 8000/tcp
sudo ufw allow 8443/tcp

# Allow Admin interfaces (restrict to local network)
sudo ufw allow from 192.168.0.0/24 to any port 8001
sudo ufw allow from 192.168.0.0/24 to any port 1337
sudo ufw allow from 192.168.0.0/24 to any port 3000
sudo ufw allow from 192.168.0.0/24 to any port 9090
```

### Ollama Security (Your Mac)
```bash
# Only allow local network access to Ollama
# In System Preferences > Security & Privacy > Firewall
# Add rule: Allow connections from 192.168.0.0/24 to port 11434
```

## Access from Different Devices

### From your Mac (192.168.0.84):
- Grafana: http://192.168.0.228:3000
- Dashboard: http://192.168.0.228:8080
- Kong Admin: http://192.168.0.228:8001

### From iPhone/iPad on same network:
- Dashboard: http://192.168.0.228:8080
- Grafana Mobile: http://192.168.0.228:3000

### From another computer on network:
- All services accessible via http://192.168.0.228:PORT

## Mobile Dashboard Access

The web dashboard at http://192.168.0.228:8080 is mobile-responsive and provides:
- Real-time threat detection status
- AI service health monitoring
- Attack statistics
- WebSocket updates

## Environment Variables

Create `.env` file on production server:

```bash
# Network Configuration
EXTERNAL_HOST=192.168.0.228
OLLAMA_MAC_IP=192.168.0.84

# API Keys
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=your-key-here

# Kong Database
KONG_PG_PASSWORD=strongpassword
KONGA_DB_PASSWORD=strongpassword

# Grafana
GF_SECURITY_ADMIN_PASSWORD=StrongPassword2024!
```

## Quick Test Commands

### From any machine on network:
```bash
# Test Kong Gateway
curl http://192.168.0.228:8000

# Test AI Services
curl http://192.168.0.228:18002/health
curl http://192.168.0.228:18003/health

# Test Grafana
curl http://192.168.0.228:3000/api/health

# Test Dashboard
curl http://192.168.0.228:8080
```

### From production server itself:
```bash
# Check all containers
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f grafana

# Check network connectivity to Mac's Ollama
curl http://192.168.0.84:11434/api/tags
```

## Troubleshooting Network Access

### Can't access from network?

1. **Check Docker port binding:**
   ```bash
   docker ps --format "table {{.Names}}\t{{.Ports}}"
   ```
   Should show `0.0.0.0:PORT->PORT/tcp` not `127.0.0.1:PORT->PORT/tcp`

2. **Check firewall:**
   ```bash
   sudo ufw status numbered
   ```

3. **Test from production server:**
   ```bash
   curl -I http://localhost:3000
   curl -I http://192.168.0.228:3000
   ```

4. **Check network interface:**
   ```bash
   ip addr show | grep 192.168
   ```

### Ollama connection failing?

1. **On Mac, check Ollama binding:**
   ```bash
   lsof -i :11434
   ```
   Should show `*:11434` not `localhost:11434`

2. **Test from production server:**
   ```bash
   curl http://192.168.0.84:11434/api/tags
   ```

3. **Check Mac firewall settings:**
   System Preferences > Security & Privacy > Firewall Options

---

**Remember**: When deploying to production (192.168.0.228), all services become accessible from your entire network, not just localhost!