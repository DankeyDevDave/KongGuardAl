# Kong Guard AI Deployment Files

This directory contains deployment artifacts for Kong Guard AI.

## 📁 Directory Structure

### 🐳 Docker (`docker/`)
Dockerfile definitions for building Kong Guard AI images:
- `Dockerfile` - Main application Dockerfile
- `Dockerfile.production` - Production-optimized image
- `Dockerfile.ollama-service` - Ollama AI service image

## 🚀 Building Images

### Main Application Image
```bash
docker build -f deployments/docker/Dockerfile -t kong-guard-ai:latest .
```

### Production Image
```bash
docker build -f deployments/docker/Dockerfile.production -t kong-guard-ai:production .
```

### Ollama Service Image
```bash
docker build -f deployments/docker/Dockerfile.ollama-service -t kong-guard-ai-ollama:latest .
```

## 📦 Multi-Stage Builds

The production Dockerfile uses multi-stage builds for optimal image size:
1. **Build stage** - Compiles and prepares application
2. **Production stage** - Minimal runtime image with only necessary files

## 🔧 Build Arguments

**Production Dockerfile supports:**
```bash
docker build \
  --build-arg VERSION=1.0.0 \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  -f deployments/docker/Dockerfile.production \
  -t kong-guard-ai:1.0.0 .
```

## 📝 Image Tags

**Tagging strategy:**
```bash
# Version tag
docker tag kong-guard-ai:latest kong-guard-ai:v1.0.0

# Environment tags
docker tag kong-guard-ai:latest kong-guard-ai:production
docker tag kong-guard-ai:latest kong-guard-ai:staging
docker tag kong-guard-ai:latest kong-guard-ai:dev
```

## 🚢 Deployment Workflows

### Using Docker Compose
Docker Compose files reference these Dockerfiles:
```yaml
services:
  kong-guard-ai:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.production
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Build Docker image
  run: |
    docker build \
      -f deployments/docker/Dockerfile.production \
      -t ${{ secrets.DOCKER_REGISTRY }}/kong-guard-ai:${{ github.sha }} \
      .
```

## 🔐 Security Best Practices

1. **Multi-stage builds** - Minimize attack surface
2. **Non-root user** - Run as unprivileged user
3. **Minimal base images** - Use alpine or distroless
4. **Layer caching** - Optimize build times
5. **Secrets management** - Never bake secrets into images

## 📊 Image Size Optimization

**Tips for smaller images:**
- Use `.dockerignore` file
- Combine RUN commands
- Remove build dependencies
- Use multi-stage builds
- Leverage layer caching

## 🔗 Related Documentation

- [Deployment Guide](../docs/deployment/deploy-to-production.md)
- [Docker Setup](../docs/user/readme-docker.md)
- [Stack Architecture](../docs/development/stack-architecture.md)

## 🛠️ Troubleshooting

**Build fails:**
```bash
# Check build context
docker build --no-cache -f deployments/docker/Dockerfile .

# Inspect intermediate layers
docker build --rm=false -f deployments/docker/Dockerfile .
```

**Image size too large:**
```bash
# Analyze layers
docker history kong-guard-ai:latest

# Use dive tool
dive kong-guard-ai:latest
```

---

**Note:** Always test images locally before pushing to registry or deploying to production.
