#!/bin/bash

# Kong Guard AI - Runner Workspace Cleanup Script
# Fixes permission issues and cleans up the runner workspace

set -e

# Configuration
RUNNER_HOST="203.0.113.200"
RUNNER_CONTAINER="201"
REPO="jlwainwright/KongGuardAl"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}===================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================${NC}"
}

print_error() {
    echo -e "${RED}Error: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Clean local workspace (if running locally)
clean_local() {
    print_header "Cleaning Local Workspace"
    
    # Directories that might have permission issues
    PROBLEM_DIRS=(
        "redis-data"
        "postgres-data"
        "kong-data"
        "_work"
        ".git/objects"
    )
    
    for dir in "${PROBLEM_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo "Cleaning $dir..."
            sudo rm -rf "$dir" 2>/dev/null || {
                print_warning "Could not remove $dir, trying with force..."
                sudo chmod -R 777 "$dir" 2>/dev/null || true
                sudo rm -rf "$dir" || print_error "Failed to remove $dir"
            }
        fi
    done
    
    print_success "Local workspace cleaned"
}

# Clean runner workspace on Proxmox
clean_runner() {
    print_header "Cleaning Runner Workspace on Container $RUNNER_CONTAINER"
    
    echo "Connecting to Proxmox container..."
    
    # Create cleanup script
    cat > /tmp/runner-cleanup.sh << 'SCRIPT_END'
#!/bin/bash

echo "Cleaning runner workspace..."

# Find all runner work directories
RUNNER_DIRS=$(find /home/runner -type d -name "_work" 2>/dev/null)

for work_dir in $RUNNER_DIRS; do
    echo "Cleaning $work_dir..."
    
    # Find the repository directory
    REPO_DIR=$(find "$work_dir" -maxdepth 2 -type d -name "KongGuardAl" 2>/dev/null | head -1)
    
    if [ -n "$REPO_DIR" ]; then
        echo "Found repository at: $REPO_DIR"
        
        # Clean problematic directories
        for dir in redis-data postgres-data kong-data; do
            if [ -d "$REPO_DIR/$dir" ]; then
                echo "  Removing $dir..."
                sudo rm -rf "$REPO_DIR/$dir" || {
                    echo "  Permission denied, changing ownership..."
                    sudo chown -R runner:runner "$REPO_DIR/$dir" 2>/dev/null || true
                    sudo chmod -R 777 "$REPO_DIR/$dir" 2>/dev/null || true
                    sudo rm -rf "$REPO_DIR/$dir" || echo "  Failed to remove $dir"
                }
            fi
        done
        
        # Clean git objects if needed
        if [ -d "$REPO_DIR/.git/objects" ]; then
            echo "  Fixing git permissions..."
            sudo chown -R runner:runner "$REPO_DIR/.git" 2>/dev/null || true
            sudo chmod -R 755 "$REPO_DIR/.git" 2>/dev/null || true
        fi
    fi
done

# Also clean any docker volumes that might be lingering
echo "Cleaning Docker volumes..."
docker volume prune -f 2>/dev/null || true

# Clean up any stopped containers
echo "Cleaning stopped containers..."
docker container prune -f 2>/dev/null || true

echo "✓ Cleanup complete"
SCRIPT_END
    
    # Execute cleanup on runner
    echo "Executing cleanup script..."
    scp -o StrictHostKeyChecking=no /tmp/runner-cleanup.sh root@${RUNNER_HOST}:/tmp/ 2>/dev/null || {
        print_error "Failed to copy cleanup script"
        echo "Manual cleanup required:"
        echo "  ssh root@${RUNNER_HOST}"
        echo "  pct enter ${RUNNER_CONTAINER}"
        echo "  sudo rm -rf /home/runner/actions-runner/_work/KongGuardAl/KongGuardAl/redis-data"
        return 1
    }
    
    ssh root@${RUNNER_HOST} "pct push ${RUNNER_CONTAINER} /tmp/runner-cleanup.sh /tmp/runner-cleanup.sh" 2>/dev/null
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- chmod +x /tmp/runner-cleanup.sh" 2>/dev/null
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- /tmp/runner-cleanup.sh" 2>/dev/null || {
        print_warning "Cleanup script had some errors, but continuing..."
    }
    
    # Cleanup temp files
    rm -f /tmp/runner-cleanup.sh
    ssh root@${RUNNER_HOST} "rm -f /tmp/runner-cleanup.sh" 2>/dev/null
    
    print_success "Runner workspace cleaned"
}

# Fix permissions permanently
fix_permissions() {
    print_header "Fixing Runner Permissions"
    
    cat > /tmp/fix-permissions.sh << 'SCRIPT_END'
#!/bin/bash

# Add runner to docker group if not already
if ! groups runner | grep -q docker; then
    echo "Adding runner to docker group..."
    usermod -aG docker runner
fi

# Ensure runner owns its workspace
chown -R runner:runner /home/runner/actions-runner 2>/dev/null || true

# Set proper permissions on work directories
find /home/runner -type d -name "_work" -exec chmod 755 {} \; 2>/dev/null || true

echo "✓ Permissions fixed"
SCRIPT_END
    
    echo "Applying permission fixes..."
    scp -o StrictHostKeyChecking=no /tmp/fix-permissions.sh root@${RUNNER_HOST}:/tmp/ 2>/dev/null
    ssh root@${RUNNER_HOST} "pct push ${RUNNER_CONTAINER} /tmp/fix-permissions.sh /tmp/fix-permissions.sh" 2>/dev/null
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- chmod +x /tmp/fix-permissions.sh" 2>/dev/null
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- /tmp/fix-permissions.sh" 2>/dev/null
    
    # Cleanup
    rm -f /tmp/fix-permissions.sh
    ssh root@${RUNNER_HOST} "rm -f /tmp/fix-permissions.sh" 2>/dev/null
    
    print_success "Permissions fixed"
}

# Restart runner after cleanup
restart_runner() {
    print_header "Restarting Runner Service"
    
    echo "Restarting runner service..."
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- systemctl restart 'actions.runner.*.service'" 2>/dev/null && {
        print_success "Runner service restarted"
    } || {
        print_warning "Could not restart runner service automatically"
        echo "Manual restart may be required"
    }
}

# Main menu
show_menu() {
    print_header "Runner Workspace Cleanup"
    echo "This script fixes permission issues with the GitHub Actions runner"
    echo
    echo "1) Quick cleanup (runner only)"
    echo "2) Full cleanup (runner + permissions)"
    echo "3) Clean local workspace only"
    echo "4) Fix permissions only"
    echo "q) Quit"
    echo
    read -p "Select option: " option
    
    case $option in
        1)
            clean_runner
            restart_runner
            ;;
        2)
            clean_runner
            fix_permissions
            restart_runner
            ;;
        3)
            clean_local
            ;;
        4)
            fix_permissions
            restart_runner
            ;;
        q|Q)
            exit 0
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# Main execution
main() {
    # Check if we can connect to Proxmox
    if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@${RUNNER_HOST} "echo connected" &> /dev/null; then
        print_warning "Cannot connect to Proxmox host ${RUNNER_HOST}"
        echo "Running local cleanup only..."
        clean_local
        exit 0
    fi
    
    # If no arguments, show menu
    if [ $# -eq 0 ]; then
        show_menu
    else
        case "$1" in
            quick)
                clean_runner
                restart_runner
                ;;
            full)
                clean_runner
                fix_permissions
                restart_runner
                ;;
            local)
                clean_local
                ;;
            fix)
                fix_permissions
                restart_runner
                ;;
            *)
                echo "Usage: $0 [quick|full|local|fix]"
                echo "  quick - Clean runner workspace only"
                echo "  full  - Clean workspace and fix permissions"
                echo "  local - Clean local workspace only"
                echo "  fix   - Fix permissions only"
                exit 1
                ;;
        esac
    fi
    
    echo
    print_success "Cleanup complete!"
    echo "You can now retry your GitHub Actions workflow"
}

# Run main function
main "$@"