# Check GitHub Actions Runner Status

Quick health check for the Proxmox self-hosted runner.

## Run These Commands

1. **Check runner registration in GitHub**:
```bash
gh api /repos/jlwainwright/KongGuardAl/actions/runners --jq '.runners[] | select(.labels[] | .name=="proxmox") | {name, status, busy, labels: [.labels[].name]}'
```

2. **Check recent workflow runs**:
```bash
gh run list --repo jlwainwright/KongGuardAl --limit 5
```

3. **Check if runner service is active** (requires SSH):
```bash
ssh root@198.51.100.201 "pct enter 201 -- systemctl --user is-active actions.runner.*"
```

4. **View runner logs** (last 10 lines):
```bash
ssh root@198.51.100.201 "pct enter 201 -- journalctl --user -n 10 --no-pager | grep runner"
```

5. **Check container status**:
```bash
ssh root@198.51.100.201 "pct status 201"
```

## Quick Status Script

Save this as `check-proxmox-runner.sh`:

```bash
#!/bin/bash
echo "=== Proxmox Container Status ==="
ssh root@198.51.100.201 "pct status 201" 2>/dev/null || echo "Cannot connect to Proxmox node"

echo -e "\n=== GitHub Runner Registration ==="
gh api /repos/jlwainwright/KongGuardAl/actions/runners --jq '.runners[] | select(.labels[] | .name=="proxmox")' | jq '{name, status, busy}' 2>/dev/null || echo "No proxmox runners found"

echo -e "\n=== Runner Service Status ==="
ssh root@198.51.100.201 "pct enter 201 -- systemctl --user is-active actions.runner.*" 2>/dev/null || echo "Cannot check service status"

echo -e "\n=== Recent Workflows ==="
gh run list --repo jlwainwright/KongGuardAl --limit 3

echo -e "\n=== Queued Jobs ==="
gh run list --repo jlwainwright/KongGuardAl --status queued --limit 5
```

## Expected Output

When healthy:
- **Container**: "running"
- **Runner Status**: "online" 
- **Busy**: false (when idle) or true (when running job)
- **Service**: "active"
- **Recent workflows**: Should show "completed" with "success" or "in_progress"
- **No queued jobs** staying in "queued" state for long

## If Unhealthy

- **Container "stopped"**: Start with `ssh root@198.51.100.201 "pct start 201"`
- **Status "offline"**: Runner needs restart - enter container and restart service
- **Many queued jobs**: Runner not picking up - check workflow labels match `[self-hosted, proxmox]`
- **Service "inactive"**: Service stopped - restart GitHub Actions runner service

## Container Details

- **Proxmox Host**: 198.51.100.201
- **Container ID**: 201
- **Access**: `ssh root@198.51.100.201 "pct enter 201"`
- **Runner Location**: `/home/runner/actions-runner/` (typical path)

## Troubleshooting Commands

```bash
# Enter container directly
ssh root@198.51.100.201 "pct enter 201"

# Check runner directory
ssh root@198.51.100.201 "pct enter 201 -- ls -la /home/runner/"

# View all running services
ssh root@198.51.100.201 "pct enter 201 -- systemctl --user list-units --type=service --state=running"

# Check runner configuration
ssh root@198.51.100.201 "pct enter 201 -- cat /home/runner/actions-runner/.runner"
```

## Quick Fixes

### Restart Container
```bash
ssh root@198.51.100.201 "pct stop 201 && pct start 201"
```

### Restart Runner Service
```bash
ssh root@198.51.100.201 "pct enter 201 -- systemctl --user restart actions.runner.*"
```

### Check Runner Registration Token
```bash
# If runner needs re-registration, get new token from:
# GitHub repo → Settings → Actions → Runners → New self-hosted runner
```