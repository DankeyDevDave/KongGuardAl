#!/bin/bash

# Quick Proxmox Container 998 SSH Setup
# Run this from your Mac

echo "🔐 Setting up SSH access to Proxmox Container 998"
echo "================================================="
echo ""

# Generate SSH key if needed
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "Generating SSH keypair..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
fi

echo "Your SSH public key:"
cat ~/.ssh/id_rsa.pub
echo ""

# Connect to Proxmox and setup container
echo "Connecting to Proxmox host..."
echo "Password for root@192.168.0.202 will be required"
echo ""

ssh root@192.168.0.202 << 'PROXMOX_COMMANDS'
echo "Connected to Proxmox host"
echo ""

# Check container 998 status
echo "Checking container 998..."
pct status 998

# Start container if needed
if ! pct status 998 | grep -q "running"; then
    echo "Starting container 998..."
    pct start 998
    sleep 5
fi

# Install SSH server in container
echo "Installing SSH server in container 998..."
pct exec 998 -- bash -c "
    apt-get update -qq
    apt-get install -y openssh-server
    
    # Configure SSH
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    
    # Create SSH directory
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # Enable and start SSH
    systemctl enable ssh
    systemctl restart ssh
"

# Get container IP
CONTAINER_IP=$(pct exec 998 -- hostname -I | awk '{print $1}')
echo ""
echo "✅ Container 998 is ready"
echo "Container IP: $CONTAINER_IP"
echo ""
echo "Now run this command to add your SSH key:"
echo "pct exec 998 -- bash -c 'echo \"YOUR_PUBLIC_KEY\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys'"
PROXMOX_COMMANDS

# Now add the SSH key
echo ""
echo "Adding your SSH key to container..."
PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)

ssh root@192.168.0.202 "pct exec 998 -- bash -c 'echo \"$PUBLIC_KEY\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys'"

# Get the container IP for direct SSH
CONTAINER_IP=$(ssh root@192.168.0.202 "pct exec 998 -- hostname -I | awk '{print \$1}'")

echo ""
echo "========================================="
echo "✅ Setup Complete!"
echo "========================================="
echo ""
echo "Container 998 IP: $CONTAINER_IP"
echo ""
echo "You can now SSH directly to the container:"
echo "  ssh root@$CONTAINER_IP"
echo ""
echo "Or through Proxmox:"
echo "  ssh root@192.168.0.202 'pct exec 998 -- bash'"
echo ""

# Test SSH connection
echo "Testing SSH connection to container..."
ssh -o ConnectTimeout=5 root@$CONTAINER_IP "echo 'SSH connection successful!'" || echo "Note: Direct SSH may need a moment to initialize"