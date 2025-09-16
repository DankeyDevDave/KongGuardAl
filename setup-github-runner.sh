#!/bin/bash
# Setup GitHub Actions Runner on Proxmox Container 201

echo "🚀 Setting up GitHub Actions Runner: proxmox-runner-201"

# Step 1: Enter the container and create runner directory
ssh root@203.0.113.200 "pct exec 201 -- bash -c '
    # Create runner user if not exists
    id -u runner >/dev/null 2>&1 || useradd -m -s /bin/bash runner

    # Create runner directory
    mkdir -p /home/runner/actions-runner
    chown runner:runner /home/runner/actions-runner

    # Install required packages
    apt-get update
    apt-get install -y curl wget tar docker.io nodejs npm
    systemctl enable docker
    systemctl start docker
    usermod -aG docker runner
'"

echo "📋 Next steps (manual):"
echo "1. Go to: https://github.com/jlwainwright/KongGuardAl/settings/actions/runners"
echo "2. Click 'New self-hosted runner'"
echo "3. Select 'Linux' and copy the download/config commands"
echo "4. Run the commands in container 201 as user 'runner'"

echo "🔧 Example commands to run in container:"
echo "ssh root@203.0.113.200 \"pct exec 201 -- su - runner\""
echo "# Then run the GitHub-provided download and config commands"
echo "# Make sure to use runner name: proxmox-runner-201"
echo "# Use labels: self-hosted,Linux,X64,proxmox"

echo "✅ Container prepared for GitHub Actions runner setup"
