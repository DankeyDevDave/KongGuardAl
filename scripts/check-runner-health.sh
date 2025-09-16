#!/usr/bin/env bash

# Kong Guard AI - Quick Runner Health Check Script
# Provides a comprehensive health check for GitHub Actions runner

set -euo pipefail
IFS=$'\n\t'

# Configuration
REPO="${1:-jlwainwright/KongGuardAl}"
RUNNER_HOST="203.0.113.200"
RUNNER_CONTAINER="201"
RUNNER_NAME="proxmox-runner-201"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Status icons
CHECK="✓"
CROSS="✗"
WARN="⚠"

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}     Kong Guard AI - GitHub Runner Health Check${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo

# Check GitHub CLI - strict preflight
echo -e "${GREEN}[1/6] Checking GitHub CLI...${NC}"
if ! command -v gh >/dev/null 2>&1; then
    echo -e "  ${RED}${CROSS}${NC} GitHub CLI is not installed"
    echo -e "  ${YELLOW}${WARN}${NC} Install with: brew install gh (macOS) or apt install gh (Ubuntu)"
    exit 1
elif ! gh auth status >/dev/null 2>&1; then
    echo -e "  ${RED}${CROSS}${NC} GitHub CLI is not authenticated"
    echo -e "  ${YELLOW}${WARN}${NC} Run: gh auth login"
    exit 1
else
    echo -e "  ${GREEN}${CHECK}${NC} GitHub CLI authenticated"
fi

# Check GitHub runner status
echo -e "\n${GREEN}[2/6] Checking GitHub Runner Status...${NC}"
runner_status=$(gh api /repos/${REPO}/actions/runners 2>/dev/null | jq -r '.runners[] | select(.name=="'${RUNNER_NAME}'") | .status' || echo "offline")

if [ "$runner_status" = "online" ]; then
    echo -e "  ${GREEN}${CHECK}${NC} Runner is ONLINE in GitHub"

    # Get runner details
    gh api /repos/${REPO}/actions/runners 2>/dev/null | jq -r '.runners[] | select(.name=="'${RUNNER_NAME}'") | "  Labels: \(.labels[].name)"' | head -4

    # Check if runner is busy
    is_busy=$(gh api /repos/${REPO}/actions/runners 2>/dev/null | jq -r '.runners[] | select(.name=="'${RUNNER_NAME}'") | .busy' || echo "false")
    if [ "$is_busy" = "true" ]; then
        echo -e "  ${YELLOW}${WARN}${NC} Runner is currently BUSY (running a job)"
    else
        echo -e "  ${GREEN}${CHECK}${NC} Runner is IDLE (ready for jobs)"
    fi
else
    echo -e "  ${RED}${CROSS}${NC} Runner is OFFLINE or not found in GitHub"
    echo -e "  ${YELLOW}${WARN}${NC} Repository: ${REPO}"
fi

# Check Proxmox container
echo -e "\n${GREEN}[3/6] Checking Proxmox Container...${NC}"
if ping -c 1 ${RUNNER_HOST} &> /dev/null; then
    echo -e "  ${GREEN}${CHECK}${NC} Proxmox host reachable (${RUNNER_HOST})"

    # Check container status
    container_status=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@${RUNNER_HOST} "pct status ${RUNNER_CONTAINER}" 2>/dev/null | grep -o "running\|stopped" || echo "unknown")

    if [ "$container_status" = "running" ]; then
        echo -e "  ${GREEN}${CHECK}${NC} Container ${RUNNER_CONTAINER} is RUNNING"

        # Check runner service
        service_status=$(ssh -o ConnectTimeout=5 root@${RUNNER_HOST} "pct exec ${RUNNER_CONTAINER} -- systemctl is-active 'actions.runner.*.service' 2>/dev/null" || echo "inactive")

        if [ "$service_status" = "active" ]; then
            echo -e "  ${GREEN}${CHECK}${NC} Runner service is ACTIVE"
        else
            echo -e "  ${RED}${CROSS}${NC} Runner service is INACTIVE"
        fi
    else
        echo -e "  ${RED}${CROSS}${NC} Container ${RUNNER_CONTAINER} is NOT running"
    fi
else
    echo -e "  ${RED}${CROSS}${NC} Cannot reach Proxmox host (${RUNNER_HOST})"
    echo -e "  ${YELLOW}${WARN}${NC} Check network connection or VPN"
fi

# Check recent workflow runs
echo -e "\n${GREEN}[4/6] Recent Workflow Runs...${NC}"
recent_runs=$(gh run list --repo ${REPO} --limit 5 --json status,conclusion,name,createdAt 2>/dev/null)

if [ -n "$recent_runs" ] && [ "$recent_runs" != "[]" ]; then
    echo "$recent_runs" | jq -r '.[] |
        (if .conclusion == "success" then "  ✓"
         elif .conclusion == "failure" then "  ✗"
         elif .status == "in_progress" then "  ⟳"
         elif .status == "queued" then "  ⏸"
         else "  ?" end) +
        " " + (.name | .[0:40]) +
        " (" + (.createdAt | split("T")[0]) + ")"' 2>/dev/null || echo "  No recent runs"
else
    echo "  No workflow runs found"
fi

# Check for stuck workflows
echo -e "\n${GREEN}[5/6] Checking for Stuck Workflows...${NC}"
queued=$(gh run list --repo ${REPO} --status queued --json databaseId 2>/dev/null | jq -r '. | length' || echo "0")
in_progress=$(gh run list --repo ${REPO} --status in_progress --json databaseId 2>/dev/null | jq -r '. | length' || echo "0")

if [ "$queued" -gt 0 ]; then
    echo -e "  ${YELLOW}${WARN}${NC} ${queued} workflow(s) QUEUED"
else
    echo -e "  ${GREEN}${CHECK}${NC} No queued workflows"
fi

if [ "$in_progress" -gt 0 ]; then
    echo -e "  ${BLUE}⟳${NC} ${in_progress} workflow(s) IN PROGRESS"
else
    echo -e "  ${GREEN}${CHECK}${NC} No in-progress workflows"
fi

# Overall health summary
echo -e "\n${GREEN}[6/6] Overall Health Summary${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

health_score=0
max_score=5

# Calculate health score
[ "$runner_status" = "online" ] && ((health_score++))
[ "$container_status" = "running" ] && ((health_score++))
[ "$service_status" = "active" ] && ((health_score++))
[ "$queued" -eq 0 ] && ((health_score++))
[ "$is_busy" != "true" ] && ((health_score++))

# Display health status
if [ $health_score -eq $max_score ]; then
    echo -e "${GREEN}${CHECK} HEALTHY${NC} - All systems operational (${health_score}/${max_score})"
elif [ $health_score -ge 3 ]; then
    echo -e "${YELLOW}${WARN} WARNING${NC} - Some issues detected (${health_score}/${max_score})"
else
    echo -e "${RED}${CROSS} CRITICAL${NC} - Multiple issues found (${health_score}/${max_score})"
fi

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

# Provide recommendations if issues found
if [ $health_score -lt $max_score ]; then
    echo -e "\n${YELLOW}Recommendations:${NC}"

    [ "$runner_status" != "online" ] && echo "  • Restart runner service: ./scripts/runner-management.sh restart"
    [ "$container_status" != "running" ] && echo "  • Start container: ssh root@${RUNNER_HOST} 'pct start ${RUNNER_CONTAINER}'"
    [ "$service_status" != "active" ] && echo "  • Start service: ssh root@${RUNNER_HOST} 'pct exec ${RUNNER_CONTAINER} -- systemctl start actions.runner.*.service'"
    [ "$queued" -gt 0 ] && echo "  • Cancel stuck workflows: ./scripts/runner-management.sh cancel"
fi

echo
echo "Repository: ${REPO}"
echo "Runner: ${RUNNER_NAME} on container ${RUNNER_CONTAINER}"
echo "Checked at: $(date '+%Y-%m-%d %H:%M:%S')"
