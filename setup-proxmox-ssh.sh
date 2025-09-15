#!/bin/bash

# Setup SSH Keypair for Proxmox Container 998
# This script helps you connect to Proxmox and set up SSH access

set -e

# Configuration
PROXMOX_HOST="192.168.0.202"
PROXMOX_USER="root"
CONTAINER_ID="998"
LOCAL_USER=$(whoami)

echo "🔐 SSH Keypair Setup for Proxmox Container $CONTAINER_ID"
echo "======================================================"
echo ""
echo "Proxmox Host: $PROXMOX_USER@$PROXMOX_HOST"
echo "Container ID: $CONTAINER_ID"
echo ""

# Step 1: Generate SSH keypair if it doesn't exist
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "📝 Generating SSH keypair..."
    ssh-keygen -t rsa -b 4096 -C "$LOCAL_USER@kong-guard-ai" -f ~/.ssh/id_rsa -N ""
    echo "✅ SSH keypair generated"
else
    echo "✅ SSH keypair already exists"
fi

echo ""
echo "Your public key:"
echo "----------------"
cat ~/.ssh/id_rsa.pub
echo ""

# Step 2: Create script to run on Proxmox host
cat > /tmp/setup-container-ssh.sh << 'SCRIPT'
#!/bin/bash

CONTAINER_ID="998"
echo "Setting up SSH in container $CONTAINER_ID..."

# Check if container is running
if pct status $CONTAINER_ID | grep -q "running"; then
    echo "✅ Container $CONTAINER_ID is running"
else
    echo "Starting container $CONTAINER_ID..."
    pct start $CONTAINER_ID
    sleep 5
fi

# Install openssh-server in container if needed
echo "Installing SSH server in container..."
pct exec $CONTAINER_ID -- bash -c "apt-get update && apt-get install -y openssh-server"

# Configure SSH in container
echo "Configuring SSH..."
pct exec $CONTAINER_ID -- bash -c "
    # Enable root login with SSH key
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    
    # Create .ssh directory
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # Restart SSH service
    systemctl restart sshd
    systemctl enable sshd
"

# Get container IP
CONTAINER_IP=$(pct exec $CONTAINER_ID -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo ""
echo "✅ SSH server installed and configured"
echo "Container IP: $CONTAINER_IP"
echo ""
echo "Now you can add your SSH public key to the container."
SCRIPT

# Step 3: Connect to Proxmox and setup container
echo "📡 Connecting to Proxmox host..."
echo ""
echo "This will:"
echo "1. Connect to your Proxmox host"
echo "2. Set up SSH in container $CONTAINER_ID"
echo "3. Add your SSH key to the container"
echo ""

# Create a command to run everything
cat > /tmp/proxmox-setup-commands.txt << 'COMMANDS'
# On Proxmox host, run these commands:

# 1. Check container status
pct status 998

# 2. Start container if needed
pct start 998

# 3. Install SSH server
pct exec 998 -- apt-get update
pct exec 998 -- apt-get install -y openssh-server nano

# 4. Configure SSH
pct exec 998 -- bash -c "sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config"
pct exec 998 -- bash -c "sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"
pct exec 998 -- mkdir -p /root/.ssh
pct exec 998 -- chmod 700 /root/.ssh

# 5. Add your public key (paste your key here)
pct exec 998 -- bash -c "echo 'YOUR_PUBLIC_KEY_HERE' >> /root/.ssh/authorized_keys"
pct exec 998 -- chmod 600 /root/.ssh/authorized_keys

# 6. Start SSH service
pct exec 998 -- systemctl restart sshd
pct exec 998 -- systemctl enable sshd

# 7. Get container IP
pct exec 998 -- ip -4 addr show eth0

# 8. Test SSH from Proxmox host
ssh root@CONTAINER_IP
COMMANDS

echo "🎯 Quick Connection Command:"
echo "=============================="
echo ""
echo "Option 1: Direct to Proxmox (you'll be prompted for password):"
echo "  ssh $PROXMOX_USER@$PROXMOX_HOST"
echo ""
echo "Option 2: Connect and enter container:"
echo "  ssh $PROXMOX_USER@$PROXMOX_HOST 'pct exec $CONTAINER_ID -- bash'"
echo ""
echo "Option 3: Run setup script on Proxmox:"
echo "  cat /tmp/setup-container-ssh.sh | ssh $PROXMOX_USER@$PROXMOX_HOST 'bash -s'"
echo ""

# Try to connect and set up
read -p "Do you want to connect to Proxmox now and set up the container? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Connecting to Proxmox..."
    echo "You'll be prompted for the root password for Proxmox."
    echo ""
    
    # Copy and run setup script
    scp /tmp/setup-container-ssh.sh $PROXMOX_USER@$PROXMOX_HOST:/tmp/
    ssh $PROXMOX_USER@$PROXMOX_HOST "bash /tmp/setup-container-ssh.sh"
    
    # Now add the SSH key
    echo ""
    echo "Adding your SSH public key to container..."
    PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)
    ssh $PROXMOX_USER@$PROXMOX_HOST "pct exec $CONTAINER_ID -- bash -c \"echo '$PUBLIC_KEY' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys\""
    
    # Get container IP
    echo ""
    echo "Getting container IP address..."
    CONTAINER_IP=$(ssh $PROXMOX_USER@$PROXMOX_HOST "pct exec $CONTAINER_ID -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
    echo "Container IP: $CONTAINER_IP"
    
    # Save connection info
    echo ""
    echo "Saving connection information..."
    cat > ~/.ssh/config.d/kong-guard-ct998 << EOF
Host kong-guard-ct998
    HostName $CONTAINER_IP
    User root
    IdentityFile ~/.ssh/id_rsa
    StrictHostKeyChecking no
    
Host proxmox-kong
    HostName $PROXMOX_HOST
    User root
    StrictHostKeyChecking no
EOF
    
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "You can now connect directly to the container:"
    echo "  ssh root@$CONTAINER_IP"
    echo "Or use the saved config:"
    echo "  ssh kong-guard-ct998"
else
    echo ""
    echo "📋 Manual Setup Instructions:"
    echo "=============================="
    echo ""
    echo "1. Connect to Proxmox:"
    echo "   ssh $PROXMOX_USER@$PROXMOX_HOST"
    echo ""
    echo "2. Enter the container:"
    echo "   pct exec $CONTAINER_ID -- bash"
    echo ""
    echo "3. Inside the container, run:"
    echo "   apt-get update && apt-get install -y openssh-server"
    echo "   mkdir -p /root/.ssh"
    echo "   echo '$(cat ~/.ssh/id_rsa.pub)' >> /root/.ssh/authorized_keys"
    echo "   chmod 600 /root/.ssh/authorized_keys"
    echo "   systemctl enable ssh && systemctl start ssh"
    echo ""
    echo "4. Get the container IP:"
    echo "   ip addr show eth0"
    echo ""
    echo "5. Exit and test SSH:"
    echo "   ssh root@<container-ip>"
fi

echo ""
echo "📝 Commands Reference saved to: /tmp/proxmox-setup-commands.txt"
echo "📜 Setup script saved to: /tmp/setup-container-ssh.sh"