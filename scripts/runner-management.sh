#!/bin/bash

# Kong Guard AI - GitHub Actions Runner Management Script
# Manages self-hosted runners on Proxmox container 201

set -e

# Configuration
RUNNER_HOST="203.0.113.200"
RUNNER_CONTAINER="201"
REPO="jlwainwright/KongGuardAl"  # Your repository
RUNNER_NAME="proxmox-runner-201"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "${GREEN}===================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}===================================${NC}"
}

print_error() {
    echo -e "${RED}Error: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}Warning: $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed"
        echo "Install with: brew install gh"
        exit 1
    fi
    
    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI is not authenticated"
        echo "Run: gh auth login"
        exit 1
    fi
    
    echo "✓ GitHub CLI is installed and authenticated"
}

# Check runner status
check_runner_status() {
    print_header "Checking Runner Status for $REPO"
    
    echo "Fetching runner information from GitHub..."
    gh api /repos/${REPO}/actions/runners --jq '.runners[] | select(.name=="'${RUNNER_NAME}'") | {name, status, busy, labels}' 2>/dev/null || {
        print_warning "No runner found or API error"
        echo "Checking all runners for the repository..."
        gh api /repos/${REPO}/actions/runners --jq '.runners[] | {name, status, busy}' 2>/dev/null || print_error "Failed to fetch runners"
    }
    
    echo -e "\n${GREEN}Recent Workflow Runs:${NC}"
    gh run list --repo ${REPO} --limit 5 2>/dev/null || print_warning "No recent runs found"
}

# Check runner service on Proxmox
check_runner_service() {
    print_header "Checking Runner Service on Proxmox Container"
    
    echo "Connecting to Proxmox container ${RUNNER_CONTAINER}..."
    
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- systemctl is-active 'actions.runner.*.service'" 2>/dev/null && {
        echo "✓ Runner service is active"
    } || {
        print_warning "Runner service may not be active"
    }
    
    echo -e "\n${GREEN}Runner processes:${NC}"
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- ps aux | grep -i runner | grep -v grep" 2>/dev/null || print_warning "No runner processes found"
}

# View runner logs
view_runner_logs() {
    print_header "Runner Logs (Last 50 lines)"
    
    echo "Fetching logs from Proxmox container..."
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- journalctl -u 'actions.runner.*' -n 50 --no-pager" 2>/dev/null || {
        print_error "Failed to fetch logs"
        echo "Try connecting manually: ssh root@${RUNNER_HOST}"
        echo "Then: pct enter ${RUNNER_CONTAINER}"
    }
}

# Restart runner service
restart_runner() {
    print_header "Restarting Runner Service"
    
    read -p "Are you sure you want to restart the runner? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Restart cancelled"
        return
    fi
    
    echo "Restarting runner service..."
    ssh root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- systemctl restart 'actions.runner.*.service'" 2>/dev/null && {
        echo "✓ Runner service restarted successfully"
        sleep 5
        check_runner_status
    } || {
        print_error "Failed to restart runner service"
        echo "Try manual restart:"
        echo "  ssh root@${RUNNER_HOST}"
        echo "  pct enter ${RUNNER_CONTAINER}"
        echo "  systemctl restart 'actions.runner.*.service'"
    }
}

# Cancel stuck workflows
cancel_stuck_workflows() {
    print_header "Cancelling Stuck Workflows"
    
    echo "Checking for queued workflows..."
    queued_runs=$(gh run list --repo ${REPO} --status queued --json databaseId --jq '.[].databaseId' 2>/dev/null)
    
    if [ -z "$queued_runs" ]; then
        echo "No queued workflows found"
    else
        echo "Found queued workflows:"
        echo "$queued_runs"
        read -p "Cancel all queued workflows? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "$queued_runs" | while read id; do
                echo "Cancelling run $id..."
                gh run cancel $id --repo ${REPO} 2>/dev/null && echo "✓ Cancelled run $id" || print_error "Failed to cancel run $id"
            done
        fi
    fi
    
    echo -e "\nChecking for in-progress workflows..."
    in_progress=$(gh run list --repo ${REPO} --status in_progress --json databaseId --jq '.[].databaseId' 2>/dev/null)
    
    if [ -z "$in_progress" ]; then
        echo "No in-progress workflows found"
    else
        echo "Found in-progress workflows:"
        echo "$in_progress"
        read -p "Cancel all in-progress workflows? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "$in_progress" | while read id; do
                echo "Cancelling run $id..."
                gh run cancel $id --repo ${REPO} 2>/dev/null && echo "✓ Cancelled run $id" || print_error "Failed to cancel run $id"
            done
        fi
    fi
}

# Trigger workflow manually
trigger_workflow() {
    print_header "Trigger Workflow Manually"
    
    echo "Available workflows:"
    gh workflow list --repo ${REPO} 2>/dev/null || {
        print_error "Failed to list workflows"
        return
    }
    
    echo -e "\nEnter workflow name or ID to trigger (or press Enter to cancel):"
    read workflow_input
    
    if [ -z "$workflow_input" ]; then
        echo "Cancelled"
        return
    fi
    
    echo "Triggering workflow: $workflow_input"
    gh workflow run "$workflow_input" --repo ${REPO} 2>/dev/null && {
        echo "✓ Workflow triggered successfully"
        echo "View at: https://github.com/${REPO}/actions"
    } || {
        print_error "Failed to trigger workflow"
    }
}

# Show menu
show_menu() {
    print_header "Kong Guard AI Runner Management"
    echo "Repository: ${REPO}"
    echo "Runner: ${RUNNER_NAME}"
    echo "Container: ${RUNNER_CONTAINER} on ${RUNNER_HOST}"
    echo
    echo "1) Check runner status"
    echo "2) Check runner service (Proxmox)"
    echo "3) View runner logs"
    echo "4) Restart runner service"
    echo "5) Cancel stuck workflows"
    echo "6) Trigger workflow manually"
    echo "7) Full health check"
    echo "q) Quit"
    echo
    read -p "Select option: " option
    
    case $option in
        1) check_runner_status ;;
        2) check_runner_service ;;
        3) view_runner_logs ;;
        4) restart_runner ;;
        5) cancel_stuck_workflows ;;
        6) trigger_workflow ;;
        7) 
            check_runner_status
            echo
            check_runner_service
            ;;
        q|Q) exit 0 ;;
        *) print_error "Invalid option" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
}

# Main execution
main() {
    check_prerequisites
    
    # If arguments provided, run specific command
    case "${1:-}" in
        status)
            check_runner_status
            ;;
        service)
            check_runner_service
            ;;
        logs)
            view_runner_logs
            ;;
        restart)
            restart_runner
            ;;
        cancel)
            cancel_stuck_workflows
            ;;
        trigger)
            trigger_workflow
            ;;
        health)
            check_runner_status
            echo
            check_runner_service
            ;;
        *)
            # Interactive menu
            while true; do
                clear
                show_menu
            done
            ;;
    esac
}

# Run main function
main "$@"