#!/usr/bin/env bash

# Kong Guard AI - GitHub Actions Runner Setup Script
# Sets up a new runner on Proxmox container 201 for Kong Guard AI

set -Eeuo pipefail

# Configuration
REPO="jlwainwright/KongGuardAl"
RUNNER_HOST="203.0.113.200"
RUNNER_CONTAINER="201"
RUNNER_NAME="proxmox-runner-201"
RUNNER_VERSION="2.319.1"

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

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check GitHub CLI
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed"
        echo "Install with: brew install gh"
        exit 1
    fi

    # Check GitHub authentication
    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI is not authenticated"
        echo "Run: gh auth login"
        exit 1
    fi

    print_success "GitHub CLI is installed and authenticated"

    # Check SSH access to Proxmox
    if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@${RUNNER_HOST} "echo connected" &> /dev/null; then
        print_error "Cannot SSH to Proxmox host ${RUNNER_HOST}"
        echo "Check your SSH key or network connection"
        exit 1
    fi

    print_success "SSH access to Proxmox confirmed"

    # Check container exists
    if ! ssh root@${RUNNER_HOST} "pct status ${RUNNER_CONTAINER}" &> /dev/null; then
        print_error "Container ${RUNNER_CONTAINER} does not exist"
        exit 1
    fi

    print_success "Container ${RUNNER_CONTAINER} exists"
}

# Get registration token
get_registration_token() {
    print_header "Getting Registration Token"

    TOKEN=$(gh api -X POST /repos/${REPO}/actions/runners/registration-token --jq .token 2>/dev/null) || {
        print_error "Failed to get registration token"
        echo "Make sure you have admin access to ${REPO}"
        exit 1
    }

    if [ -z "$TOKEN" ]; then
        print_error "Registration token is empty"
        exit 1
    fi

    print_success "Registration token obtained"
}

# Setup runner on container
setup_runner() {
    print_header "Setting Up Runner on Container ${RUNNER_CONTAINER}"

    echo "Connecting to container..."

    # Create setup script
    cat > /tmp/setup-runner.sh << 'SCRIPT_END'
#!/bin/bash
set -e

REPO="__REPO__"
TOKEN="__TOKEN__"
RUNNER_NAME="__RUNNER_NAME__"
RUNNER_VERSION="__RUNNER_VERSION__"

echo "Setting up runner in container..."

# Create runner user if doesn't exist
if ! id -u runner &>/dev/null; then
    useradd -m -s /bin/bash runner
    echo "Created runner user"
fi

# Switch to runner home
cd /home/runner

# Create runner directory
RUNNER_DIR="actions-runner-$(echo $REPO | tr '/' '-')"
if [ -d "$RUNNER_DIR" ]; then
    echo "Runner directory already exists: $RUNNER_DIR"
    echo "Removing old runner..."
    cd "$RUNNER_DIR"
    ./svc.sh stop || true
    ./svc.sh uninstall || true
    ./config.sh remove --token "$TOKEN" || true
    cd ..
    rm -rf "$RUNNER_DIR"
fi

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

# Download runner
echo "Downloading runner version ${RUNNER_VERSION}..."
curl -o actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz -L \
    https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz

# Extract runner
echo "Extracting runner..."
tar xzf ./actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz
rm actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz

# Set ownership
chown -R runner:runner /home/runner/"$RUNNER_DIR"

# Configure runner as runner user
echo "Configuring runner..."
sudo -u runner ./config.sh \
    --url https://github.com/${REPO} \
    --token ${TOKEN} \
    --name ${RUNNER_NAME} \
    --labels self-hosted,proxmox,Linux,X64,kong-guard-ai \
    --work _work \
    --unattended \
    --replace

# Install as service
echo "Installing runner service..."
./svc.sh install runner
./svc.sh start

# Check service status
if systemctl is-active --quiet "actions.runner.*.service"; then
    echo "✓ Runner service is active"
else
    echo "⚠ Runner service may not be active"
fi

echo "Runner setup complete!"
SCRIPT_END

    # Replace placeholders
    sed -i.bak "s|__REPO__|${REPO}|g" /tmp/setup-runner.sh
    sed -i.bak "s|__TOKEN__|${TOKEN}|g" /tmp/setup-runner.sh
    sed -i.bak "s|__RUNNER_NAME__|${RUNNER_NAME}|g" /tmp/setup-runner.sh
    sed -i.bak "s|__RUNNER_VERSION__|${RUNNER_VERSION}|g" /tmp/setup-runner.sh

    # Copy script to container and execute
    echo "Copying setup script to container..."
    scp -o StrictHostKeyChecking=no /tmp/setup-runner.sh root@${RUNNER_HOST}:/tmp/

    echo "Executing setup script in container..."
    ssh root@${RUNNER_HOST} "pct push ${RUNNER_CONTAINER} /tmp/setup-runner.sh /tmp/setup-runner.sh"
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- chmod +x /tmp/setup-runner.sh"
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- /tmp/setup-runner.sh" || {
        print_error "Setup script failed"
        exit 1
    }

    # Cleanup
    rm -f /tmp/setup-runner.sh /tmp/setup-runner.sh.bak
    ssh root@${RUNNER_HOST} "rm -f /tmp/setup-runner.sh"

    print_success "Runner installed and started"
}

# Verify runner registration
verify_runner() {
    print_header "Verifying Runner Registration"

    echo "Waiting for runner to register..."
    sleep 5

    # Check GitHub API for runner
    runner_status=$(gh api /repos/${REPO}/actions/runners --jq '.runners[] | select(.name=="'${RUNNER_NAME}'") | .status' 2>/dev/null || echo "not_found")

    if [ "$runner_status" = "online" ]; then
        print_success "Runner is ONLINE and registered with GitHub"

        # Show runner details
        echo -e "\n${GREEN}Runner Details:${NC}"
        gh api /repos/${REPO}/actions/runners --jq '.runners[] | select(.name=="'${RUNNER_NAME}'") | {
            name: .name,
            status: .status,
            os: .os,
            labels: [.labels[].name] | join(", ")
        }' 2>/dev/null

    elif [ "$runner_status" = "offline" ]; then
        print_warning "Runner is registered but OFFLINE"
        echo "The runner may need a moment to connect..."
    else
        print_error "Runner not found in GitHub"
        echo "Check the container logs for errors"
    fi
}

# Create test workflow
create_test_workflow() {
    print_header "Creating Test Workflow"

    read -p "Create a test workflow? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping test workflow"
        return
    fi

    # Create test workflow file
    mkdir -p .github/workflows
    cat > .github/workflows/test-runner.yml << 'EOF'
name: Test Runner
on:
  workflow_dispatch:

jobs:
  test:
    name: Test Kong Guard AI Runner
    runs-on: [self-hosted, proxmox, kong-guard-ai]

    steps:
      - name: Check runner info
        run: |
          echo "Runner name: ${{ runner.name }}"
          echo "Runner OS: ${{ runner.os }}"
          echo "Working directory: $(pwd)"

      - name: Check tools
        run: |
          echo "Docker version:"
          docker --version || echo "Docker not available"
          echo "Git version:"
          git --version

      - name: Test complete
        run: echo "✓ Runner is working correctly!"
EOF

    print_success "Test workflow created"
    echo "To run the test: gh workflow run test-runner.yml --repo ${REPO}"
}

# Main setup flow
main() {
    print_header "Kong Guard AI - GitHub Actions Runner Setup"
    echo "Repository: ${REPO}"
    echo "Container: ${RUNNER_CONTAINER} on ${RUNNER_HOST}"
    echo "Runner Name: ${RUNNER_NAME}"
    echo

    read -p "Continue with setup? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled"
        exit 0
    fi

    check_prerequisites
    get_registration_token
    setup_runner
    verify_runner
    create_test_workflow

    print_header "Setup Complete!"
    echo -e "${GREEN}✓ Runner '${RUNNER_NAME}' is set up and ready${NC}"
    echo
    echo "Next steps:"
    echo "1. Update your workflows to use: runs-on: [self-hosted, proxmox]"
    echo "2. Test the runner: gh workflow run test-runner.yml --repo ${REPO}"
    echo "3. Monitor runner: ./scripts/check-runner-health.sh"
    echo
    echo "Runner management:"
    echo "  ./scripts/runner-management.sh       # Interactive management"
    echo "  ./scripts/check-runner-health.sh     # Quick health check"
}

# Run main function
main
