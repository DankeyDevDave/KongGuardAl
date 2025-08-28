# Global Proxmox Runner Setup

Set up proxmox-runner-201 as the default runner for the current project and automatically register the GitHub Actions runner.

## Steps:

1. Create `.github/workflows/` directory if it doesn't exist
2. Add a workflow file with `runs-on: proxmox-runner-201`
3. Create `.claude/github-actions-config.json` with runner config
4. Update any existing workflows to use the Proxmox runner
5. **Check Proxmox container status and runner connectivity**
6. **Automatically configure and register GitHub Actions runner**
7. **Verify queued actions start processing**

## Commands to run:

```bash
# Create directories
mkdir -p .github/workflows .claude

# Create config
cat > .claude/github-actions-config.json << 'EOF'
{
  "defaultRunner": "proxmox-runner-201",
  "workflowDefaults": {
    "runs-on": "proxmox-runner-201"
  },
  "proxmoxConfig": {
    "host": "203.0.113.200",
    "container": "201",
    "runnerName": "proxmox-runner-201"
  }
}
EOF

# Update existing workflows
find .github/workflows -name "*.yml" -o -name "*.yaml" | while read file; do
  sed -i.bak 's/runs-on:.*/runs-on: proxmox-runner-201/' "$file"
done

echo "=== Proxmox Container Status Check ==="
ssh root@203.0.113.200 "pct status 201" 2>/dev/null || echo "❌ Cannot connect to Proxmox host or container not found"

echo -e "\n=== Container Details ==="
ssh root@203.0.113.200 "pct config 201" 2>/dev/null | grep -E "hostname|net0|cores|memory" || echo "❌ Cannot retrieve container config"

echo -e "\n=== GitHub Runner Service Status ==="
ssh root@203.0.113.200 "pct exec 201 -- systemctl --user list-units --type=service | grep actions.runner" 2>/dev/null || echo "❌ Cannot check runner service status"

echo -e "\n=== GitHub Repository Runner Registration ==="
gh api /repos/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions/runners --jq '.runners[] | select(.name=="proxmox-runner-201") | {name, status, busy}' 2>/dev/null || echo "❌ No runner named proxmox-runner-201 found"

echo -e "\n=== Current Workflow Queue Status ==="
gh run list --status queued --limit 5 2>/dev/null || echo "❌ Cannot check workflow queue"

echo -e "\n=== Runner Connectivity Test ==="
if ssh root@203.0.113.200 "pct exec 201 -- ping -c 1 8.8.8.8 >/dev/null 2>&1"; then
    echo "✅ Container has internet connectivity"
else
    echo "❌ Container network connectivity issues"
fi

echo -e "\n=== Docker Status in Container ==="
ssh root@203.0.113.200 "pct exec 201 -- docker --version" 2>/dev/null && echo "✅ Docker available" || echo "❌ Docker not found or not running"

echo -e "\n=== Node.js Status in Container ==="
ssh root@203.0.113.200 "pct exec 201 -- node --version" 2>/dev/null && echo "✅ Node.js available" || echo "❌ Node.js not found"

# Step 6: Automatic GitHub Runner Registration
echo -e "\n=== Preparing Container for GitHub Runner ==="
ssh root@203.0.113.200 "pct exec 201 -- bash -c '
    # Create runner user if not exists
    if ! id -u runner >/dev/null 2>&1; then
        useradd -m -s /bin/bash runner
        echo \"✅ Created runner user\"
    fi
    
    # Install required packages
    apt-get update -qq
    apt-get install -y curl wget tar docker.io nodejs npm jq >/dev/null 2>&1
    systemctl enable docker >/dev/null 2>&1
    systemctl start docker >/dev/null 2>&1
    usermod -aG docker runner
    echo \"✅ Installed required packages\"
    
    # Create runner directory
    mkdir -p /home/runner/actions-runner
    chown runner:runner /home/runner/actions-runner
    echo \"✅ Created runner directory\"
'"

echo -e "\n=== Getting GitHub Registration Token ==="
# Get repository info
REPO_OWNER=$(git config --get remote.origin.url | sed 's/.*github.com[:/]\([^/]*\)\/.*/\1/')
REPO_NAME=$(git config --get remote.origin.url | sed 's/.*github.com[:/][^/]*\/\([^.]*\).*/\1/')
echo "Repository: $REPO_OWNER/$REPO_NAME"

# Get registration token (requires gh auth)
REG_TOKEN=$(gh api --method POST -H "Accept: application/vnd.github+json" /repos/$REPO_OWNER/$REPO_NAME/actions/runners/registration-token --jq .token 2>/dev/null)

if [ -z "$REG_TOKEN" ]; then
    echo "❌ Failed to get registration token. Please ensure 'gh auth login' is configured with repo permissions"
    echo "Manual setup required:"
    echo "1. Visit: https://github.com/$REPO_OWNER/$REPO_NAME/settings/actions/runners"
    echo "2. Click 'New self-hosted runner'"
    echo "3. Follow the setup instructions"
    exit 1
fi

echo "✅ Retrieved registration token"

echo -e "\n=== Downloading and Configuring GitHub Runner ==="
ssh root@203.0.113.200 "pct exec 201 -- su - runner -c '
    cd /home/runner/actions-runner
    
    # Download runner if not already present
    if [ ! -f \"./config.sh\" ]; then
        echo \"📥 Downloading GitHub Actions runner...\"
        curl -o actions-runner-linux-x64-2.311.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz >/dev/null 2>&1
        tar xzf ./actions-runner-linux-x64-2.311.0.tar.gz
        rm actions-runner-linux-x64-2.311.0.tar.gz
        echo \"✅ Downloaded and extracted runner\"
    fi
    
    # Configure runner with registration token
    echo \"🔧 Configuring runner...\"
    ./config.sh --url https://github.com/$REPO_OWNER/$REPO_NAME --token $REG_TOKEN --name proxmox-runner-201 --labels self-hosted,Linux,X64,proxmox --work _work --replace --unattended
    
    # Install and start as service
    echo \"🚀 Installing runner service...\"
    sudo ./svc.sh install
    sudo ./svc.sh start
    
    echo \"✅ GitHub Actions runner configured and started\"
'"

echo -e "\n=== Verifying Runner Registration ==="
sleep 5  # Give runner time to register
RUNNER_STATUS=$(gh api /repos/$REPO_OWNER/$REPO_NAME/actions/runners --jq '.runners[] | select(.name=="proxmox-runner-201") | {name, status, busy}' 2>/dev/null)

if [ -n "$RUNNER_STATUS" ]; then
    echo "✅ Runner successfully registered:"
    echo "$RUNNER_STATUS"
else
    echo "⏳ Runner registration in progress... Check status in a moment"
fi

echo -e "\n=== Checking Workflow Queue ==="
QUEUED_COUNT=$(gh run list --status queued --limit 10 --json id | jq '. | length')
echo "Queued workflows: $QUEUED_COUNT"

if [ "$QUEUED_COUNT" -gt 0 ]; then
    echo "🚀 Queued workflows should start processing shortly!"
    echo "Monitor with: gh run watch"
fi

echo "✅ Proxmox runner setup and registration complete"
echo "🎯 Kong Guard AI deployment will start automatically"
```

## Expected Healthy Output:

```
=== Proxmox Container Status Check ===
running

=== Container Details ===
hostname: git-worker-01
net0: name=eth0,bridge=vmbr0,ip=dhcp
cores: 4
memory: 8192

=== GitHub Runner Service Status ===
actions.runner.user-repo.proxmox-runner-201.service active running

=== GitHub Repository Runner Registration ===
{
  "name": "proxmox-runner-201",
  "status": "online",
  "busy": false
}

=== Current Workflow Queue Status ===
No queued workflows (or currently processing)

=== Runner Connectivity Test ===
✅ Container has internet connectivity

=== Docker Status in Container ===
✅ Docker available

=== Node.js Status in Container ===
✅ Node.js available
```

## Troubleshooting Common Issues:

### Container Not Running
```bash
ssh root@203.0.113.200 "pct start 201"
```

### Runner Service Not Active
```bash
ssh root@203.0.113.200 "pct exec 201 -- systemctl --user start actions.runner.*"
```

### Runner Not Registered
1. Go to GitHub repo → Settings → Actions → Runners
2. Add new self-hosted runner
3. Follow registration commands in container 201

### Network Issues
```bash
ssh root@203.0.113.200 "pct exec 201 -- ip addr show"
ssh root@203.0.113.200 "pct exec 201 -- cat /etc/resolv.conf"
```

## Post-Setup Verification:

After running this command, check if your queued workflows start processing:
```bash
# Monitor workflow progress
gh run watch

# Check runner is picking up jobs
gh api /repos/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions/runners --jq '.runners[] | select(.name=="proxmox-runner-201")'
```