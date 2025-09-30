# Kong Guard AI Configuration Files

This directory contains all configuration files for Kong Guard AI, organized by component.

## 📁 Directory Structure

### 🐳 Docker Compose (`docker/`)
Docker Compose configuration files for different deployment scenarios:
- `docker-compose.yml` - Main/default configuration
- `docker-compose.production.yml` - Production deployment
- `docker-compose.demo.yml` - Demo environment with attack scenarios
- `docker-compose.presentation.yml` - Presentation/showcase environment
- `docker-compose.simple.yml` - Minimal setup for testing
- `docker-compose.with-ai.yml` - Configuration with AI services enabled
- `docker-compose.deploy.yml` - Deployment-specific configuration
- `docker-compose.zapvend-integration.yml` - ZapVend integration setup

**Note:** Symlinks exist in root directory for convenience:
- `/docker-compose.yml` → `config/docker/docker-compose.yml`
- `/docker-compose.production.yml` → `config/docker/docker-compose.production.yml`

### 🦍 Kong Gateway (`kong/`)
Kong Gateway configuration files:
- `kong.conf` - Main Kong configuration
- `kong-config.yml` - Kong declarative configuration
- `kong-simple.yml` - Simplified Kong setup

### 📊 Prometheus (`prometheus/`)
Prometheus monitoring configuration:
- `prometheus-config.yml` - Main Prometheus configuration
- `prometheus-local.yml` - Local development configuration
- `prometheus-production-config.yml` - Production monitoring setup

### 🌐 Nginx (`nginx/`)
Nginx web server configuration:
- `nginx-dashboard.conf` - Dashboard proxy configuration

### 🤖 Ollama (`ollama/`)
Ollama AI service configuration:
- `ollama-models.conf` - AI model configuration

### 📈 Grafana (`grafana/`)
Grafana dashboard configuration:
- `grafana-dashboard.json` - Dashboard definition

### ⚙️ Environment Files
Environment variable configurations:
- `.env.docker` - Docker-specific environment variables
- `.env.example` - Example environment configuration template
- `env_example` - Alternative example configuration

## 🚀 Usage

### Starting with Different Configurations

**Default setup:**
```bash
docker-compose up -d
# OR from root:
cd /path/to/KongGuardAI
docker-compose up -d  # Uses symlink
```

**Production deployment:**
```bash
docker-compose -f config/docker/docker-compose.production.yml up -d
# OR from root:
docker-compose -f docker-compose.production.yml up -d  # Uses symlink
```

**Demo environment:**
```bash
docker-compose -f config/docker/docker-compose.demo.yml up -d
```

**Simple/minimal setup:**
```bash
docker-compose -f config/docker/docker-compose.simple.yml up -d
```

### Environment Configuration

1. Copy environment template:
```bash
cp config/.env.example .env
```

2. Edit with your values:
```bash
# API Keys
GEMINI_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here

# Database
SUPABASE_URL=your_url
SUPABASE_KEY=your_key
```

### Kong Configuration

Edit Kong settings in `config/kong/kong.conf` for production deployments.

For declarative configuration, modify `config/kong/kong-config.yml`.

## 🔍 Configuration Tips

### Docker Compose
- Use `docker-compose config` to validate syntax
- Use `docker-compose -f <file> config` to see final merged configuration
- Environment variables override compose file settings

### Kong
- Test configuration changes in simple environment first
- Use `kong check` to validate configuration syntax
- Backup existing configuration before making changes

### Prometheus
- Adjust scrape intervals based on load
- Configure retention based on available disk space
- Add custom alerting rules in `prometheus-config.yml`

## 🔗 Related Documentation

- [Deployment Guide](../docs/deployment/deploy-to-production.md)
- [Docker Setup](../docs/user/readme-docker.md)
- [Stack Architecture](../docs/development/stack-architecture.md)
- [Operations Runbook](../docs/operations/operational-runbook.md)

---

**Note:** Always review configuration files before deploying to production. Ensure API keys and secrets are properly secured.
