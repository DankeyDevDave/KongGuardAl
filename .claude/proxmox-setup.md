# Proxmox Runner Setup for Kong Guard AI

## Configuration Complete ✅

### Default Runner Configuration
- **Runner Name**: `proxmox-runner-201`
- **Labels**: `[self-hosted, Linux, x64, proxmox]`
- **Target**: Kong Guard AI deployment to Proxmox

### Files Created/Updated
- ✅ `.claude/github-actions-config.json` - Runner configuration
- ✅ `.github/workflows/deploy-proxmox.yml` - Already configured for proxmox-runner-201
- ✅ `.claude/proxmox-setup.md` - This documentation

### Current Workflow Status
The deployment workflow is configured to use `proxmox-runner-201` and will deploy:
- Kong Gateway 3.x with Kong Guard AI plugin
- Claude-Flow v2.0.0 Alpha coordination system
- Neural threat prediction models
- Docker Compose production stack

### Monitoring Endpoints
Once deployed, monitor via:
- **Status**: `http://localhost:8001/_guard_ai/status`
- **Metrics**: `http://localhost:8001/_guard_ai/metrics`
- **Claude-Flow**: `npx claude-flow@alpha swarm status`

### Deployment Triggers
Automatic deployment on:
- Push to `main` or `master` branches
- Pull requests to `main` or `master`
- Manual workflow dispatch

### Runner Requirements
The `proxmox-runner-201` runner should have:
- Docker installed and running
- Node.js 18+ for Claude-Flow
- Network access to deployment targets
- Sufficient resources for Kong Gateway + AI processing

## Quick Commands

### Check Runner Status
```bash
gh api /repos/jlwainwright/KongGuardAl/actions/runners
```

### Trigger Manual Deployment
```bash
gh workflow run "Deploy Kong Guard AI to Proxmox" --repo jlwainwright/KongGuardAl
```

### Monitor Deployment
```bash
gh run watch --repo jlwainwright/KongGuardAl
```

## Project Ready for Hackathon 🚀

Your Kong Guard AI project is now fully configured for:
- ✅ Production deployment via Proxmox
- ✅ AI-enhanced security with Claude-Flow
- ✅ Kong API Summit Hackathon submission
- ✅ Enterprise-grade performance monitoring