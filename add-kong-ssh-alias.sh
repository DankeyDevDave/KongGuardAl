#!/bin/bash

# Add 'kong' as an SSH alias for the Kong Guard AI container

echo "🔐 Adding 'kong' SSH shortcut"
echo "============================="
echo ""

# Check if the alias already exists
if grep -q "Host kong$" ~/.ssh/config 2>/dev/null; then
    echo "⚠️  'kong' alias already exists in SSH config"
    echo ""
    echo "Current configuration:"
    grep -A 4 "Host kong$" ~/.ssh/config
else
    # Add the kong alias
    echo "Adding 'kong' alias to SSH config..."
    cat >> ~/.ssh/config << 'EOF'

Host kong
    HostName 192.168.0.228
    User root
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
    
EOF
    echo "✅ Added 'kong' SSH shortcut"
fi

# Also add some useful related shortcuts
echo ""
echo "📝 Adding additional useful shortcuts..."

# Kong production server
if ! grep -q "Host kong-prod" ~/.ssh/config 2>/dev/null; then
    cat >> ~/.ssh/config << 'EOF'
Host kong-prod
    HostName 192.168.0.228
    User root
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
    
EOF
    echo "✅ Added 'kong-prod' (same as kong)"
fi

# Proxmox host
if ! grep -q "Host proxmox" ~/.ssh/config 2>/dev/null; then
    cat >> ~/.ssh/config << 'EOF'
Host proxmox
    HostName 192.168.0.202
    User root
    StrictHostKeyChecking no
    
EOF
    echo "✅ Added 'proxmox' shortcut"
fi

echo ""
echo "========================================="
echo "✅ SSH Shortcuts Configured!"
echo "========================================="
echo ""
echo "You can now use these shortcuts:"
echo ""
echo "  ssh kong          # Kong Guard AI container (192.168.0.228)"
echo "  ssh kong-prod     # Same as above"
echo "  ssh ct998         # Container 998 (already exists)"
echo "  ssh proxmox       # Proxmox host (192.168.0.202)"
echo ""
echo "Test the new shortcut:"
echo "  ssh kong 'hostname && uname -a'"
echo ""