# Kong Guard AI - GitHub Actions Runner Setup Guide

## Overview

Kong Guard AI uses a self-hosted GitHub Actions runner deployed on a Proxmox LXC container for CI/CD workflows. This provides better performance, control, and integration with the local infrastructure.

## Runner Infrastructure

### Container Details
- **Container ID**: 201 (git-worker-01)
- **Host Server**: Proxmox VE at `203.0.113.200`
- **Container Type**: LXC (Linux Container)
- **Runner Name**: proxmox-runner-201
- **Labels**: `self-hosted`, `proxmox`, `Linux`, `X64`, `kong-guard-ai`

### Network Architecture
```
GitHub Actions
      ↓
[Internet/VPN]
      ↓
Proxmox Host (203.0.113.200)
      ↓
LXC Container 201
      ↓
GitHub Runner Service
      ↓
Kong Guard AI Workflows
```

## Quick Start

### 1. Initial Setup (One-time)

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run the setup script
./scripts/setup-runner.sh
```

This will:
- Check prerequisites (GitHub CLI, SSH access)
- Get a registration token from GitHub
- Install the runner in container 201
- Configure it for Kong Guard AI
- Verify the registration

### 2. Health Check

```bash
# Quick health check
./scripts/check-runner-health.sh

# Detailed status
./scripts/runner-management.sh status
```

### 3. Management Interface

```bash
# Interactive management menu
./scripts/runner-management.sh

# Or use direct commands:
./scripts/runner-management.sh status    # Check status
./scripts/runner-management.sh logs      # View logs
./scripts/runner-management.sh restart   # Restart service
./scripts/runner-management.sh cancel    # Cancel stuck workflows
```

## Workflow Configuration

### Basic CI/CD Workflow

```yaml
name: Kong Guard AI CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    name: Test Kong Guard AI
    runs-on: [self-hosted, proxmox]  # Use labels, not runner name
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build and Test
        run: |
          docker-compose build
          docker-compose up -d
          ./scripts/test-kong-guard.sh
          
      - name: Cleanup
        if: always()
        run: docker-compose down -v
```

### Advanced Deployment Workflow

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    name: Deploy Kong Guard AI
    runs-on: [self-hosted, proxmox, kong-guard-ai]
    environment: production
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker Images
        run: |
          docker build -t kong-guard-ai:latest .
          docker tag kong-guard-ai:latest registry.local/kong-guard-ai:latest
          
      - name: Push to Registry
        run: docker push registry.local/kong-guard-ai:latest
        
      - name: Deploy to Kong Cluster
        run: |
          ssh kong-server "docker pull registry.local/kong-guard-ai:latest"
          ssh kong-server "docker-compose up -d"
          
      - name: Health Check
        run: |
          sleep 30
          curl -f http://kong-server:8001/plugins/kong-guard-ai
```

## Troubleshooting

### Common Issues and Solutions

#### Runner Shows Offline

1. **Check container status**:
   ```bash
   ssh root@203.0.113.200 "pct status 201"
   ```

2. **Restart runner service**:
   ```bash
   ./scripts/runner-management.sh restart
   ```

3. **Check logs**:
   ```bash
   ./scripts/runner-management.sh logs
   ```

#### Workflows Stuck in Queue

1. **Check runner availability**:
   ```bash
   gh api /repos/jlwainwright/KongGuardAl/actions/runners
   ```

2. **Cancel stuck workflows**:
   ```bash
   ./scripts/runner-management.sh cancel
   ```

3. **Verify labels match**:
   - Workflow must use: `runs-on: [self-hosted, proxmox]`
   - NOT: `runs-on: proxmox-runner-201`

#### Permission Errors

1. **Runner runs as 'runner' user**, not root
2. **For Docker access**, add runner to docker group:
   ```bash
   ssh root@203.0.113.200
   pct enter 201
   usermod -aG docker runner
   systemctl restart actions.runner.*.service
   ```

### Manual Container Access

```bash
# SSH to Proxmox host
ssh root@203.0.113.200

# Enter container
pct enter 201

# Navigate to runner directory
cd /home/runner
ls -la actions-runner-*

# Check service status
systemctl status 'actions.runner.*.service'

# View logs
journalctl -u 'actions.runner.*.service' -n 100
```

## Security Considerations

### Best Practices

1. **Use Secrets for Sensitive Data**:
   ```yaml
   - name: Deploy
     env:
       DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
       API_TOKEN: ${{ secrets.API_TOKEN }}
   ```

2. **Limit Runner Access**:
   - Runner uses dedicated 'runner' user
   - No root access unless explicitly needed
   - Use SSH keys for deployments

3. **Network Isolation**:
   - Runner in isolated LXC container
   - Firewall rules on Proxmox host
   - VPN for remote access

### SSH Key Management

```bash
# Generate deployment key (on runner)
ssh root@203.0.113.200
pct enter 201
su - runner
ssh-keygen -t ed25519 -C "github-runner-deploy"

# Add public key to target servers
cat ~/.ssh/id_ed25519.pub
# Copy to target server's authorized_keys
```

## Monitoring and Maintenance

### Automated Health Checks

Create a cron job for regular health checks:

```bash
# Add to crontab
crontab -e

# Add health check every 15 minutes
*/15 * * * * /path/to/kong-guard-ai/scripts/check-runner-health.sh > /tmp/runner-health.log 2>&1
```

### Log Rotation

Runner logs are managed by systemd journal. Configure retention:

```bash
# On container 201
echo "MaxRetentionSec=7d" >> /etc/systemd/journald.conf
systemctl restart systemd-journald
```

### Performance Tuning

1. **Container Resources**:
   ```bash
   # Check current limits
   ssh root@203.0.113.200 "pct config 201 | grep -E 'cores|memory'"
   
   # Adjust if needed
   ssh root@203.0.113.200 "pct set 201 -cores 4 -memory 8192"
   ```

2. **Concurrent Jobs**:
   - Default: 1 job at a time
   - Can run multiple runners for parallel jobs

## Integration with Kong Guard AI

### Plugin Testing Workflow

```yaml
name: Test Kong Guard AI Plugin

on:
  push:
    paths:
      - 'kong/plugins/**'
      - 'tests/**'

jobs:
  plugin-test:
    runs-on: [self-hosted, proxmox]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Start Kong with Plugin
        run: |
          docker-compose -f docker-compose.test.yml up -d
          sleep 30
          
      - name: Configure Test Service
        run: |
          ./scripts/configure-test-service.sh
          
      - name: Run Plugin Tests
        run: |
          ./tests/run-plugin-tests.sh
          
      - name: Collect Logs
        if: failure()
        run: |
          docker-compose logs > test-failure.log
          
      - name: Upload Logs
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: test-logs
          path: test-failure.log
```

### Deployment Pipeline

```yaml
name: Deploy Kong Guard AI

on:
  release:
    types: [published]

jobs:
  deploy:
    runs-on: [self-hosted, proxmox, kong-guard-ai]
    
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.release.tag_name }}
          
      - name: Build Release
        run: |
          ./scripts/build-release.sh ${{ github.event.release.tag_name }}
          
      - name: Deploy to Kong Cluster
        run: |
          ./scripts/deploy-to-production.sh
          
      - name: Verify Deployment
        run: |
          ./scripts/verify-deployment.sh
```

## Useful Commands Reference

```bash
# Check all runners for repository
gh api /repos/jlwainwright/KongGuardAl/actions/runners

# List recent workflow runs
gh run list --repo jlwainwright/KongGuardAl --limit 10

# Watch workflow in progress
gh run watch --repo jlwainwright/KongGuardAl

# Trigger workflow manually
gh workflow run ci.yml --repo jlwainwright/KongGuardAl

# Download workflow artifacts
gh run download <run-id> --repo jlwainwright/KongGuardAl

# View workflow logs
gh run view <run-id> --log --repo jlwainwright/KongGuardAl
```

## Support and Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Self-hosted Runners Guide](https://docs.github.com/en/actions/hosting-your-own-runners)
- [Kong Plugin Development](https://docs.konghq.com/gateway/latest/plugin-development/)
- [Proxmox LXC Documentation](https://pve.proxmox.com/wiki/Linux_Container)

## Appendix: Environment Variables

The runner has access to these environment variables:

```bash
# GitHub-provided
GITHUB_ACTIONS=true
GITHUB_WORKFLOW=<workflow-name>
GITHUB_RUN_ID=<run-id>
GITHUB_REPOSITORY=jlwainwright/KongGuardAl
GITHUB_SHA=<commit-sha>
GITHUB_REF=<ref>

# Custom for Kong Guard AI
KONG_GUARD_ENV=production
RUNNER_CONTAINER_ID=201
RUNNER_HOST=203.0.113.200
```

---

*Last Updated: 2025*
*Runner Version: 2.319.1*
*Container: Proxmox LXC 201*