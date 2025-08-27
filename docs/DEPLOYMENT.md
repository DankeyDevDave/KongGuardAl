# Kong Guard AI - Remote Docker Deployment Guide

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Security](#security)
- [Monitoring](#monitoring)
- [Backup & Recovery](#backup--recovery)
- [Troubleshooting](#troubleshooting)
- [CI/CD Pipeline](#cicd-pipeline)

## Prerequisites

### Local Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Git
- SSH client
- OpenSSL (for certificate generation)

### Remote Server Requirements
- Ubuntu 20.04+ or Debian 11+
- Docker and Docker Compose installed
- Minimum 4GB RAM, 2 CPUs
- 20GB available disk space
- Open ports: 80, 443, 8000, 8443 (public), 22 (SSH)

### Recommended Production Specs
- 8GB+ RAM
- 4+ CPUs
- 50GB+ SSD storage
- Network: 100Mbps+
- OS: Ubuntu 22.04 LTS

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourorg/kong-guard-ai.git
cd kong-guard-ai
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Set your domain and credentials
DOMAIN=your-domain.com
KONG_PG_PASSWORD=secure-password-here
API_SECRET_KEY=your-secret-key-here
```

### 3. Deploy to Remote Server
```bash
# Set remote server details
export REMOTE_HOST=your-server.com
export REMOTE_USER=ubuntu

# Run deployment
./scripts/deploy.sh deploy
```

## Production Deployment

### Step 1: Server Preparation

#### Install Docker on Remote Server
```bash
# SSH into server
ssh ubuntu@your-server.com

# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose plugin
# Method 1: Via package manager (recommended)
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Method 2: Manual installation (if needed)
# mkdir -p ~/.docker/cli-plugins/
# curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o ~/.docker/cli-plugins/docker-compose
# chmod +x ~/.docker/cli-plugins/docker-compose

# Verify installation
docker --version
docker compose version
```

#### Configure Firewall
```bash
# Allow necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8000/tcp  # Kong Proxy
sudo ufw allow 8443/tcp  # Kong Proxy SSL

# Block admin ports from external access
sudo ufw deny 8001/tcp   # Kong Admin
sudo ufw deny 8444/tcp   # Kong Admin SSL
sudo ufw deny 9090/tcp   # Prometheus
sudo ufw deny 3000/tcp   # Grafana

# Enable firewall
sudo ufw enable
```

### Step 2: Generate Secrets

```bash
# Create secrets directory
mkdir -p secrets
chmod 700 secrets

# Generate passwords
openssl rand -base64 32 > secrets/kong_postgres_password.txt
openssl rand -base64 32 > secrets/api_postgres_password.txt
openssl rand -base64 32 > secrets/redis_password.txt
openssl rand -hex 32 > secrets/api_secret_key.txt
openssl rand -base64 20 > secrets/grafana_password.txt

# For AI Gateway (optional)
echo "your-openai-api-key" > secrets/ai_gateway_key.txt

# Set proper permissions
chmod 600 secrets/*.txt
```

### Step 3: SSL Certificate Setup

#### Option A: Let's Encrypt (Production)
```bash
# The deployment script will automatically set up Let's Encrypt
# Just ensure your domain points to the server IP
```

#### Option B: Self-Signed (Development)
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout secrets/server.key \
    -out secrets/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

### Step 4: Deploy Application

```bash
# Full deployment with all options
REMOTE_HOST=your-server.com \
REMOTE_USER=ubuntu \
DEPLOYMENT_ENV=production \
./scripts/deploy.sh deploy

# The script will:
# 1. Check prerequisites
# 2. Generate missing secrets
# 3. Build Docker images
# 4. Create backup of existing deployment
# 5. Deploy to remote server
# 6. Run health checks
# 7. Configure firewall
# 8. Set up SSL (if configured)
```

### Step 5: Verify Deployment

```bash
# Check health locally
./scripts/health-check.sh

# Check services on remote
ssh ubuntu@your-server.com "cd /opt/kong-guard-ai && docker-compose -f docker-compose.production.yml ps"

# Test endpoints
curl https://your-domain.com/health
curl https://your-domain.com/api/health
```

## Configuration

### Environment Variables

Key configuration in `.env.production`:

```bash
# Deployment
DEPLOYMENT_ENV=production
DOMAIN=your-domain.com

# Kong Settings
KONG_REPLICAS=2                    # Number of Kong instances
KONG_PG_DATABASE=kong
KONG_PG_USER=kong
KONG_LOG_LEVEL=info

# API Settings
API_REPLICAS=2                     # Number of FastAPI instances
API_WORKERS=4                      # Uvicorn workers per instance
API_PORT=8080
LOG_LEVEL=info

# AI Gateway (optional)
AI_GATEWAY_ENABLED=false
AI_GATEWAY_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
GRAFANA_USER=admin

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
EMAIL_TO=admin@your-domain.com
```

### Kong Plugin Configuration

Configure via Admin API:
```bash
# Enable plugin globally
curl -X POST http://localhost:8001/plugins \
  --data "name=kong-guard-ai" \
  --data "config.dry_run_mode=false" \
  --data "config.threat_threshold=7.0" \
  --data "config.enable_auto_blocking=true"

# Or via declarative config
cat > kong.yml << EOF
plugins:
- name: kong-guard-ai
  config:
    dry_run_mode: false
    threat_threshold: 7.0
    enable_auto_blocking: true
    block_duration_seconds: 3600
    ai_gateway_enabled: true
    ai_gateway_model: gpt-4o-mini
EOF

# Apply configuration
curl -X POST http://localhost:8001/config \
  --data @kong.yml
```

## Security

### 1. Secrets Management

```bash
# Never commit secrets to git
echo "secrets/" >> .gitignore
echo ".env" >> .gitignore

# Use Docker secrets in production
docker secret create kong_postgres_password secrets/kong_postgres_password.txt

# Or use environment variable files
docker run --env-file .env.production ...
```

### 2. Network Security

```yaml
# docker-compose.production.yml
networks:
  kong-net:
    driver: bridge
    internal: true  # Isolate internal services
    
  public-net:
    driver: bridge  # For public-facing services
```

### 3. SSL/TLS Configuration

```nginx
# nginx/nginx.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:...;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
```

### 4. Access Control

```bash
# SSH access via key only
ssh-copy-id -i ~/.ssh/id_rsa.pub ubuntu@your-server.com

# Disable password authentication
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Admin API access via SSH tunnel only
ssh -L 8001:localhost:8001 ubuntu@your-server.com
```

## Monitoring

### Access Monitoring Dashboards

```bash
# Create SSH tunnel for admin interfaces
ssh -L 8001:localhost:8001 \
    -L 3000:localhost:3000 \
    -L 9090:localhost:9090 \
    ubuntu@your-server.com

# Access locally
open http://localhost:8001  # Kong Admin
open http://localhost:3000  # Grafana (admin/[password])
open http://localhost:9090  # Prometheus
```

### Grafana Dashboards

Pre-configured dashboards:
- **Kong Guard AI Overview**: Real-time threat monitoring
- **Performance Metrics**: Latency, throughput, errors
- **Resource Usage**: CPU, memory, disk, network
- **Security Events**: Threats, blocks, incidents

### Prometheus Metrics

Key metrics to monitor:
```promql
# Request rate
rate(kong_http_requests_total[5m])

# Error rate
rate(kong_http_requests_total{status=~"5.."}[5m])

# P95 latency
histogram_quantile(0.95, kong_latency_bucket)

# Threat detection rate
rate(kong_guard_ai_threats_detected_total[5m])
```

### Alerting Rules

Configure in `monitoring/prometheus/alerts.yml`:
```yaml
groups:
- name: kong_guard_ai
  rules:
  - alert: HighErrorRate
    expr: rate(kong_http_requests_total{status=~"5.."}[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: High error rate detected
      
  - alert: HighThreatLevel
    expr: kong_guard_ai_threat_level > 8
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: High threat level detected
```

## Backup & Recovery

### Automated Backups

```bash
# Run backup manually
./scripts/backup.sh

# Schedule daily backups via cron
crontab -e
# Add:
0 2 * * * cd /opt/kong-guard-ai && ./scripts/backup.sh

# Configure S3 backup
export S3_ENABLED=true
export S3_BUCKET=your-backup-bucket
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
./scripts/backup.sh
```

### Restore from Backup

```bash
# List available backups
./scripts/backup.sh list

# Restore specific backup
./scripts/restore.sh /path/to/backup.tar.gz

# Restore latest backup
./scripts/restore.sh latest
```

### Disaster Recovery

1. **Database Recovery**:
```bash
# Restore Kong database
docker exec -i kong-database pg_restore \
    -U kong -d kong < kong_backup.dump

# Restore API database
docker exec -i api-database pg_restore \
    -U kongguard -d kongguard < api_backup.dump
```

2. **Volume Recovery**:
```bash
# Restore Docker volume
docker run --rm \
    -v kong_data:/restore \
    -v $(pwd):/backup \
    alpine tar xzf /backup/volume_backup.tar.gz -C /restore
```

## Troubleshooting

### Common Issues

#### 1. Services Not Starting
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs -f kong

# Check container status
docker ps -a

# Restart services
docker-compose -f docker-compose.production.yml restart
```

#### 2. Database Connection Issues
```bash
# Test database connection
docker exec kong-database pg_isready -U kong

# Check database logs
docker logs kong-database

# Reset database
docker-compose -f docker-compose.production.yml down
docker volume rm kongguardai_kong_data
docker-compose -f docker-compose.production.yml up -d
```

#### 3. High Memory Usage
```bash
# Check memory usage
docker stats

# Limit container memory
# Edit docker-compose.production.yml:
services:
  kong:
    deploy:
      resources:
        limits:
          memory: 2G
```

#### 4. SSL Certificate Issues
```bash
# Renew Let's Encrypt certificate
docker-compose -f docker-compose.production.yml run --rm certbot renew

# Check certificate expiry
openssl x509 -in /etc/letsencrypt/live/your-domain.com/cert.pem -noout -dates
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
export KONG_LOG_LEVEL=debug

# Deploy with debug
./scripts/deploy.sh deploy

# View detailed logs
docker-compose -f docker-compose.production.yml logs -f --tail=100
```

## CI/CD Pipeline

### GitHub Actions Setup

1. **Add Secrets to GitHub**:
   - Go to Settings → Secrets → Actions
   - Add required secrets:
     - `STAGING_HOST`: Staging server IP/domain
     - `STAGING_SSH_KEY`: Private SSH key for staging
     - `PRODUCTION_HOST`: Production server IP/domain
     - `PRODUCTION_SSH_KEY`: Private SSH key for production
     - `SLACK_WEBHOOK`: Slack notification webhook
     - Database passwords and API keys

2. **Deployment Workflow**:
   - Push to `main` → Deploy to staging
   - Push to `production` or tag `v*` → Deploy to production
   - Manual deployment via Actions UI

3. **Rollback on Failure**:
   ```bash
   # Automatic rollback in workflow
   ./scripts/deploy.sh rollback
   
   # Manual rollback
   ssh ubuntu@your-server.com "cd /opt/kong-guard-ai && ./scripts/deploy.sh rollback"
   ```

### Manual Deployment

```bash
# Deploy specific version
VERSION=v1.2.3 ./scripts/deploy.sh deploy

# Deploy to staging
DEPLOYMENT_ENV=staging \
REMOTE_HOST=staging.your-domain.com \
./scripts/deploy.sh deploy

# Deploy to production
DEPLOYMENT_ENV=production \
REMOTE_HOST=your-domain.com \
./scripts/deploy.sh deploy
```

## Scaling

### Horizontal Scaling

```bash
# Scale Kong instances
docker-compose -f docker-compose.production.yml up -d --scale kong=3

# Scale FastAPI instances
docker-compose -f docker-compose.production.yml up -d --scale fastapi=3
```

### Load Balancing

Configure nginx upstream:
```nginx
upstream kong_proxy {
    least_conn;
    server kong1:8000;
    server kong2:8000;
    server kong3:8000;
    keepalive 32;
}
```

### Database Scaling

```yaml
# Use PostgreSQL replication
services:
  postgres-primary:
    image: postgres:16
    environment:
      POSTGRES_REPLICATION_MODE: master
      
  postgres-replica:
    image: postgres:16
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_HOST: postgres-primary
```

## Performance Tuning

### Kong Optimization
```bash
# kong.conf
nginx_worker_processes = auto
nginx_worker_connections = 16384
mem_cache_size = 256m
database_cache_ttl = 120
```

### FastAPI Optimization
```python
# Increase workers
WORKERS=8

# Enable response caching
CACHE_TTL_SECONDS=300

# Database connection pooling
DB_POOL_SIZE=40
DB_MAX_OVERFLOW=80
```

### System Tuning
```bash
# Increase file descriptors
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
sysctl -p
```

## Support

- **Documentation**: [Kong Guard AI Docs](https://docs.kongguard.ai)
- **Issues**: [GitHub Issues](https://github.com/yourorg/kong-guard-ai/issues)
- **Discord**: [Join Discord](https://discord.gg/kongguard)
- **Email**: support@kongguard.ai

---

**Last Updated**: 2024-01-20
**Version**: 1.0.0