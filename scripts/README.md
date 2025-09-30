# Kong Guard AI Scripts

This directory contains all operational scripts for Kong Guard AI, organized by function.

## 📁 Directory Structure

### 🔧 Setup (`setup/`)
Installation and configuration scripts
- `setup-kong.sh` - Kong Gateway setup
- `setup-api-keys.sh` - API key configuration
- `setup-github-runner.sh` - GitHub Actions runner setup
- `setup-proxmox-ssh.sh` - Proxmox SSH configuration
- `configure-kong-guard-ai.sh` - Plugin configuration
- `configure-zapvend-kong.sh` - ZapVend integration
- `configure-three-tier.sh` - Three-tier Kong setup
- `add-kong-ssh-alias.sh` - SSH alias creation
- `proxmox-container-setup.sh` - Proxmox container setup
- `quick-proxmox-setup.sh` - Quick Proxmox setup

### 🚀 Deployment (`deployment/`)
Production deployment and packaging scripts
- `deploy-grafana.sh` - Grafana dashboard deployment
- `deploy-to-kong-container.sh` - Deploy plugin to Kong container
- `deploy-with-cloudflare.sh` - Cloudflare tunnel deployment
- `production-deployment-package.sh` - Production package creation
- `production-ollama-config.sh` - Ollama production configuration
- `transfer-to-production.sh` - Production environment transfer
- `cloudflare-tunnel-setup.sh` - Cloudflare tunnel setup

### 🐳 Docker (`docker/`)
Docker environment management
- `docker-start.sh` - Start Docker Compose stack
- `docker-stop.sh` - Stop Docker Compose stack
- `docker-reset.sh` - Reset Docker environment

### 🧪 Testing (`testing/`)
Test execution and validation
- `run-tests.sh` - Main test runner
- `run-integration-tests.sh` - Integration test suite
- `test-error-handling.sh` - Error handling tests
- `test_ai_detection.sh` - AI detection tests
- `test_ai_enterprise.sh` - Enterprise AI tests
- `start-testing.sh` - Testing environment setup

### ✅ Validation (`validation/`)
System validation and security audits
- `security_audit.sh` - Security audit script
- See also: `scripts/` directory for additional validation scripts

### 🎯 Management (`management/`)
Stack management and operations
- `launch-kong-guard.sh` - Launch Kong Guard AI
- `stop-kong-guard.sh` - Stop Kong Guard AI
- `manage-stack.sh` - Stack management operations
- `integrated-stack-status.sh` - Check stack status
- `start-grafana-local.sh` - Local Grafana startup
- `start-local-ollama-service.sh` - Local Ollama service
- `update-grafana-datasource.sh` - Update Grafana datasource

### 🏃 Quick Start
- `quick-start.sh` - Quick start script (root of scripts/)

## 🔍 Finding Scripts

### By Task

**Initial Setup:**
```bash
./scripts/setup/setup-kong.sh
./scripts/setup/setup-api-keys.sh
./scripts/setup/configure-kong-guard-ai.sh
```

**Start Stack:**
```bash
./scripts/docker/docker-start.sh
# OR
./scripts/management/launch-kong-guard.sh
```

**Run Tests:**
```bash
./scripts/testing/run-tests.sh
./scripts/testing/run-integration-tests.sh
```

**Deploy to Production:**
```bash
./scripts/deployment/production-deployment-package.sh
./scripts/deployment/transfer-to-production.sh
```

## 📝 Script Conventions

- All scripts use `#!/usr/bin/env bash` shebang
- Error handling with `set -e` where appropriate
- Color-coded output for better readability
- Environment variable support via `.env` files
- Logging to appropriate log files

## 🔗 Related Documentation

- [Main README](../README.md)
- [Deployment Guide](../docs/deployment/deploy-to-production.md)
- [Testing Guide](../docs/user/readme-tests.md)
- [Operations Runbook](../docs/operations/operational-runbook.md)

---

**Note:** Always review scripts before execution, especially in production environments.
