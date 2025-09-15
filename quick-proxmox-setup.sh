#!/bin/bash

# Quick setup for Proxmox Container 998 on 192.168.0.202

echo "🚀 Quick Proxmox Container 998 Setup"
echo "===================================="
echo ""

# Get your public key
PUBLIC_KEY=$(cat ~/.ssh/id_ed25519.pub)
echo "Using your existing SSH key:"
echo "$PUBLIC_KEY"
echo ""

echo "📡 Connecting to Proxmox (192.168.0.202)..."
echo "You'll need to enter the root password for Proxmox"
echo ""

# Single command to set everything up
ssh root@192.168.0.202 "
echo '=== Setting up Container 998 ==='

# Start container if needed
pct status 998
if ! pct status 998 | grep -q running; then
    echo 'Starting container...'
    pct start 998
    sleep 3
fi

# Quick setup in container
pct exec 998 -- bash -c '
    # Update and install SSH
    apt-get update -qq && apt-get install -y openssh-server
    
    # Configure SSH for key-based auth
    sed -i \"s/#PermitRootLogin.*/PermitRootLogin prohibit-password/\" /etc/ssh/sshd_config
    sed -i \"s/#PubkeyAuthentication.*/PubkeyAuthentication yes/\" /etc/ssh/sshd_config
    
    # Setup SSH directory and key
    mkdir -p /root/.ssh
    echo \"$PUBLIC_KEY\" > /root/.ssh/authorized_keys
    chmod 700 /root/.ssh
    chmod 600 /root/.ssh/authorized_keys
    
    # Start SSH service
    systemctl enable ssh
    systemctl restart ssh
'

# Get container IP
CONTAINER_IP=\$(pct exec 998 -- hostname -I | awk '{print \$1}')
echo ''
echo '✅ Container 998 is configured!'
echo \"Container IP: \$CONTAINER_IP\"
echo ''
echo 'You can now SSH directly to:'
echo \"  ssh root@\$CONTAINER_IP\"
"

# Get the container IP for local use
echo ""
echo "Getting container IP..."
CONTAINER_IP=$(ssh root@192.168.0.202 "pct exec 998 -- hostname -I | awk '{print \$1}'" 2>/dev/null)

if [ ! -z "$CONTAINER_IP" ]; then
    echo ""
    echo "========================================="
    echo "✅ Setup Complete!"
    echo "========================================="
    echo ""
    echo "Container 998 is now accessible via SSH:"
    echo "  ssh root@$CONTAINER_IP"
    echo ""
    
    # Add to SSH config for easy access
    if ! grep -q "Host ct998" ~/.ssh/config 2>/dev/null; then
        echo "Adding to SSH config for easy access..."
        echo "" >> ~/.ssh/config
        echo "Host ct998" >> ~/.ssh/config
        echo "    HostName $CONTAINER_IP" >> ~/.ssh/config
        echo "    User root" >> ~/.ssh/config
        echo "    IdentityFile ~/.ssh/id_ed25519" >> ~/.ssh/config
        echo ""
        echo "You can also connect using:"
        echo "  ssh ct998"
    fi
    
    # Test connection
    echo ""
    echo "Testing SSH connection..."
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@$CONTAINER_IP "echo '✅ SSH connection successful!'; uname -a" || echo "⚠️  SSH may need a moment to initialize. Try again in a few seconds."
else
    echo "⚠️  Could not get container IP. Please check Proxmox connection."
fi