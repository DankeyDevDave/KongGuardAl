#!/bin/bash

# ===============================================
# Kong Guard AI - Complete Stack Launch Script
# ===============================================
# This script starts all Kong Guard AI services, checks their health,
# and opens the management UI. If errors occur, it can call Claude for assistance.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_FILE="$SCRIPT_DIR/launch.log"
ERROR_LOG="$SCRIPT_DIR/errors.log"
CLAUDE_ASSIST=${CLAUDE_ASSIST:-true}
OPEN_UI=${OPEN_UI:-true}
MAX_RETRIES=30
RETRY_DELAY=2

# Service URLs
KONG_ADMIN_URL="http://localhost:18001"
KONG_PROXY_URL="http://localhost:18000"
DEMO_API_URL="http://localhost:18085"
REDIS_URL="localhost:16379"
POSTGRES_URL="localhost:15432"

# Konga UI URL
KONGA_URL="http://localhost:1337"

# Kong Manager URL (if installed)
KONG_MANAGER_URL="http://localhost:18002"

# Function: Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -c, --clean          Clean volumes before starting"
    echo "  -n, --no-ui          Don't open UI in browser"
    echo "  -s, --skip-claude    Don't offer Claude assistance on errors"
    echo "  -l, --logs           Show container logs after startup"
    echo ""
    echo "Environment variables:"
    echo "  CLEAN_VOLUMES=true   Clean volumes before starting"
    echo "  OPEN_UI=false        Don't open UI in browser"
    echo "  CLAUDE_ASSIST=false  Don't offer Claude assistance"
}

# Check for help argument first
for arg in "$@"; do
    if [[ "$arg" == "-h" ]] || [[ "$arg" == "--help" ]]; then
        show_usage
        exit 0
    fi
done

# Initialize logs
echo "Kong Guard AI Launch - $(date)" > "$LOG_FILE"
echo "" > "$ERROR_LOG"

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Function: Print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Function: Show spinner for long operations
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⣾⣽⣻⢿⡿⣟⣯⣷'
    local temp
    echo -n " "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Function: Progress bar
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))

    printf "\r["
    printf "%${filled}s" | tr ' ' '='
    printf "%$((width - filled))s" | tr ' ' '>'
    printf "] %d%%" $percentage
}

# Function: Animated waiting dots
wait_with_dots() {
    local message=$1
    local max_dots=3
    local dots=0

    while true; do
        printf "\r${message}"
        for ((i=0; i<dots; i++)); do
            printf "."
        done
        for ((i=dots; i<max_dots; i++)); do
            printf " "
        done
        dots=$(((dots + 1) % (max_dots + 1)))
        sleep 0.5
    done
}

# Function: Cleanup on exit
cleanup() {
    # Only trigger Claude assist if there are actual errors and script failed
    if [ -s "$ERROR_LOG" ] && [ "$CLAUDE_ASSIST" = true ] && [ "${SCRIPT_SUCCESS:-false}" = false ]; then
        print_status "$YELLOW" "\n📋 Errors detected. Preparing Claude assistance..."
        prepare_claude_assist
    fi
}

# Function: Check if Docker is running
check_docker() {
    print_status "$BLUE" "🐳 Checking Docker..."
    if ! docker info >/dev/null 2>&1; then
        print_status "$RED" "❌ Docker is not running!"
        echo "Docker daemon is not running" >> "$ERROR_LOG"
        return 1
    fi
    print_status "$GREEN" "✅ Docker is running"
    return 0
}

# Function: Check if docker-compose is available
check_docker_compose() {
    print_status "$BLUE" "📦 Checking docker-compose..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_status "$RED" "❌ docker-compose is not installed!"
        echo "docker-compose is not installed" >> "$ERROR_LOG"
        return 1
    fi
    print_status "$GREEN" "✅ docker-compose is available"
    return 0
}

# Function: Stop existing containers
stop_existing() {
    print_status "$BLUE" "🛑 Stopping existing containers..."
    cd "$SCRIPT_DIR"
    if docker compose version &> /dev/null; then
        docker compose down 2>&1 | tee -a "$LOG_FILE" || true
    else
        docker-compose down 2>&1 | tee -a "$LOG_FILE" || true
    fi
    sleep 2
}

# Function: Clean up volumes if requested
clean_volumes() {
    if [ "${CLEAN_VOLUMES:-false}" = true ]; then
        print_status "$YELLOW" "🗑️  Cleaning volumes..."
        cd "$SCRIPT_DIR"
        if docker compose version &> /dev/null; then
            docker compose down -v 2>&1 | tee -a "$LOG_FILE" || true
        else
            docker-compose down -v 2>&1 | tee -a "$LOG_FILE" || true
        fi
    fi
}

# Function: Start services
start_services() {
    print_status "$BLUE" "🚀 Starting Kong Guard AI services..."
    echo ""
    print_status "$YELLOW" "📦 Launching containers:"
    cd "$SCRIPT_DIR"

    # Start with visual feedback
    echo "  ├─ PostgreSQL database (Kong)"
    echo "  ├─ PostgreSQL database (Konga)"
    echo "  ├─ Redis cache"
    echo "  ├─ Kong Gateway"
    echo "  ├─ Konga UI"
    echo "  ├─ Demo API service"
    echo "  └─ Mock attacker service"
    echo ""

    print_status "$BLUE" "🐳 Docker Compose starting services..."

    if docker compose version &> /dev/null; then
        if ! docker compose up -d 2>&1 | tee -a "$LOG_FILE" | while IFS= read -r line; do
            if [[ "$line" == *"Creating"* ]]; then
                echo "  ✓ $line"
            elif [[ "$line" == *"Starting"* ]]; then
                echo "  ✓ $line"
            elif [[ "$line" == *"Started"* ]]; then
                echo "  ✓ $line"
            fi
        done; then
            print_status "$RED" "❌ Failed to start services"
            echo "Docker compose up failed" >> "$ERROR_LOG"
            return 1
        fi
    else
        if ! docker-compose up -d 2>&1 | tee -a "$LOG_FILE" | while IFS= read -r line; do
            if [[ "$line" == *"Creating"* ]]; then
                echo "  ✓ $line"
            elif [[ "$line" == *"Starting"* ]]; then
                echo "  ✓ $line"
            elif [[ "$line" == *"Started"* ]]; then
                echo "  ✓ $line"
            fi
        done; then
            print_status "$RED" "❌ Failed to start services"
            echo "Docker compose up failed" >> "$ERROR_LOG"
            return 1
        fi
    fi

    echo ""
    print_status "$GREEN" "✅ All containers launched successfully"
    return 0
}

# Function: Wait for service to be healthy
wait_for_service() {
    local service_name=$1
    local check_command=$2
    local retries=0

    printf "⏳ Waiting for %-20s " "$service_name"

    # Show progress with visual indicator
    while [ $retries -lt $MAX_RETRIES ]; do
        if eval "$check_command" 2>/dev/null; then
            printf " ✅ Ready!\n"
            return 0
        fi
        retries=$((retries + 1))

        # Show progress indicator
        local progress=$((retries * 100 / MAX_RETRIES))
        if [ $((retries % 3)) -eq 0 ]; then
            printf "\r⏳ Waiting for %-20s [%3d%%]" "$service_name" "$progress"
        fi

        sleep $RETRY_DELAY
    done

    printf " ❌ Failed\n"
    print_status "$RED" "   └─ $service_name health check failed after $MAX_RETRIES attempts"
    echo "$service_name health check failed" >> "$ERROR_LOG"
    return 1
}

# Function: Check PostgreSQL
check_postgres() {
    wait_for_service "PostgreSQL" "docker exec kong-database pg_isready -U kong"
}

# Function: Check Redis
check_redis() {
    wait_for_service "Redis" "docker exec kong-redis redis-cli ping | grep -q PONG"
}

# Function: Check Kong Admin API
check_kong_admin() {
    wait_for_service "Kong Admin API" "curl -s -o /dev/null -w '%{http_code}' $KONG_ADMIN_URL | grep -q '200'"
}

# Function: Check Kong Proxy
check_kong_proxy() {
    wait_for_service "Kong Proxy" "curl -s -o /dev/null -w '%{http_code}' $KONG_PROXY_URL | grep -q '404\|200'"
}

# Function: Check Demo API
check_demo_api() {
    wait_for_service "Demo API" "curl -s -o /dev/null -w '%{http_code}' $DEMO_API_URL/status/200 | grep -q '200'"
}

# Function: Check Konga UI
check_konga() {
    wait_for_service "Konga UI" "curl -s -o /dev/null -w '%{http_code}' $KONGA_URL | grep -q '200\|302'"
}

# Function: Configure Kong Guard AI plugin
configure_plugin() {
    print_status "$BLUE" "🔧 Configuring Kong Guard AI plugin..."

    # Check if plugin is already configured
    if curl -s "$KONG_ADMIN_URL/plugins" | grep -q "kong-guard-ai"; then
        print_status "$GREEN" "✅ Kong Guard AI plugin already configured"
        return 0
    fi

    # Create a test service if it doesn't exist
    curl -s -X POST "$KONG_ADMIN_URL/services" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "demo-service",
            "url": "http://demo-api"
        }' 2>&1 | tee -a "$LOG_FILE" || true

    # Create a route for the service
    curl -s -X POST "$KONG_ADMIN_URL/services/demo-service/routes" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "demo-route",
            "paths": ["/demo"]
        }' 2>&1 | tee -a "$LOG_FILE" || true

    # Enable Kong Guard AI plugin globally
    curl -s -X POST "$KONG_ADMIN_URL/plugins" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "kong-guard-ai",
            "config": {
                "enabled": true,
                "log_level": "INFO",
                "threat_detection": {
                    "enabled": true,
                    "ml_threshold": 0.7,
                    "patterns": {
                        "sql_injection": true,
                        "xss": true,
                        "command_injection": true,
                        "path_traversal": true
                    }
                },
                "rate_limiting": {
                    "enabled": true,
                    "requests_per_minute": 100,
                    "requests_per_hour": 1000
                },
                "auto_response": {
                    "enabled": true,
                    "block_duration": 300,
                    "escalation_threshold": 5
                }
            }
        }' 2>&1 | tee -a "$LOG_FILE"

    if [ $? -eq 0 ]; then
        print_status "$GREEN" "✅ Kong Guard AI plugin configured"
    else
        print_status "$YELLOW" "⚠️  Plugin configuration may have failed - check logs"
        echo "Plugin configuration failed" >> "$ERROR_LOG"
    fi
}

# Function: Show service status
show_status() {
    print_status "$BLUE" "\n📊 Service Status:"
    echo "-------------------"

    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "kong|redis|demo|mock|konga" || true

    echo -e "\n🔗 Service URLs:"
    echo "  🌐 Konga UI: $KONGA_URL"
    echo "  📡 Kong Admin API: $KONG_ADMIN_URL"
    echo "  🔌 Kong Proxy: $KONG_PROXY_URL"
    echo "  🧪 Demo API: $DEMO_API_URL"
    echo "  💾 Redis: redis://localhost:16379"
    echo "  🗄️  PostgreSQL: postgresql://kong:kongpass@localhost:15432/kong"

    # Check if Kong Manager is available
    if curl -s -o /dev/null -w "%{http_code}" "$KONG_MANAGER_URL" | grep -q "200\|302"; then
        echo "  Kong Manager: $KONG_MANAGER_URL"
    fi
}

# Function: Open UI in browser
open_ui() {
    if [ "$OPEN_UI" = true ]; then
        print_status "$BLUE" "🌐 Opening Konga UI in browser..."

        # Wait a moment for Konga to be fully ready
        sleep 2

        # Detect OS and open browser
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS - Open Konga UI
            if curl -s -o /dev/null -w "%{http_code}" "$KONGA_URL" | grep -q "200\|302"; then
                print_status "$GREEN" "🚀 Launching Konga UI at $KONGA_URL"
                open "$KONGA_URL"
            else
                print_status "$YELLOW" "⚠️  Konga UI not ready yet. You can manually open: $KONGA_URL"
                print_status "$BLUE" "   Opening Kong Admin API instead: $KONG_ADMIN_URL"
                open "$KONG_ADMIN_URL"
            fi

            # If Kong Manager is available
            if curl -s -o /dev/null -w "%{http_code}" "$KONG_MANAGER_URL" | grep -q "200\|302"; then
                open "$KONG_MANAGER_URL"
            fi
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Linux
            if command -v xdg-open &> /dev/null; then
                if curl -s -o /dev/null -w "%{http_code}" "$KONGA_URL" | grep -q "200\|302"; then
                    print_status "$GREEN" "🚀 Launching Konga UI at $KONGA_URL"
                    xdg-open "$KONGA_URL"
                else
                    xdg-open "$KONG_ADMIN_URL"
                fi
            elif command -v gnome-open &> /dev/null; then
                if curl -s -o /dev/null -w "%{http_code}" "$KONGA_URL" | grep -q "200\|302"; then
                    print_status "$GREEN" "🚀 Launching Konga UI at $KONGA_URL"
                    gnome-open "$KONGA_URL"
                else
                    gnome-open "$KONG_ADMIN_URL"
                fi
            fi
        else
            print_status "$BLUE" "📝 Please open your browser and navigate to:"
            echo "   Konga UI: $KONGA_URL"
        fi
    fi
}

# Function: Run health checks
run_health_checks() {
    print_status "$BLUE" "\n🏥 Running health checks..."

    local all_healthy=true

    # Check each service
    if ! docker exec kong-database pg_isready -U kong &>/dev/null; then
        print_status "$RED" "  ❌ PostgreSQL is unhealthy"
        echo "PostgreSQL unhealthy" >> "$ERROR_LOG"
        all_healthy=false
    else
        print_status "$GREEN" "  ✅ PostgreSQL is healthy"
    fi

    if ! docker exec kong-redis redis-cli ping &>/dev/null; then
        print_status "$RED" "  ❌ Redis is unhealthy"
        echo "Redis unhealthy" >> "$ERROR_LOG"
        all_healthy=false
    else
        print_status "$GREEN" "  ✅ Redis is healthy"
    fi

    if ! curl -s -o /dev/null "$KONG_ADMIN_URL"; then
        print_status "$RED" "  ❌ Kong Admin API is unreachable"
        echo "Kong Admin API unreachable" >> "$ERROR_LOG"
        all_healthy=false
    else
        print_status "$GREEN" "  ✅ Kong Admin API is healthy"
    fi

    if ! curl -s -o /dev/null "$KONG_PROXY_URL"; then
        print_status "$RED" "  ❌ Kong Proxy is unreachable"
        echo "Kong Proxy unreachable" >> "$ERROR_LOG"
        all_healthy=false
    else
        print_status "$GREEN" "  ✅ Kong Proxy is healthy"
    fi

    if ! curl -s -o /dev/null "$KONGA_URL"; then
        print_status "$RED" "  ❌ Konga UI is unreachable"
        echo "Konga UI unreachable" >> "$ERROR_LOG"
        all_healthy=false
    else
        print_status "$GREEN" "  ✅ Konga UI is healthy"
    fi

    if [ "$all_healthy" = true ]; then
        print_status "$GREEN" "\n🎉 All services are healthy!"
        return 0
    else
        print_status "$YELLOW" "\n⚠️  Some services are unhealthy"
        return 1
    fi
}

# Function: Prepare Claude assistance
prepare_claude_assist() {
    if [ ! -s "$ERROR_LOG" ]; then
        return
    fi

    print_status "$BLUE" "\n🤖 Analyzing errors and preparing diagnostics..."
    echo ""

    # Show progress for diagnostic collection
    print_status "$YELLOW" "📊 Collecting diagnostic information:"

    # Collect diagnostic information with progress indicators
    local diagnostics=""
    diagnostics+="Kong Guard AI Launch Errors:\n"
    diagnostics+="========================\n\n"

    # Step 1: Error log
    printf "  ├─ Reading error log"
    diagnostics+="Errors encountered:\n"
    diagnostics+=$(cat "$ERROR_LOG")
    printf " ✓\n"

    # Step 2: Container status
    printf "  ├─ Checking container status"
    diagnostics+="\n\nDocker container status:\n"
    diagnostics+=$(docker ps -a --format "table {{.Names}}\t{{.Status}}" | grep -E "kong|redis|demo|mock" || echo "No containers found")
    printf " ✓\n"

    # Step 3: Container logs
    printf "  └─ Collecting container logs"
    diagnostics+="\n\nRecent Docker logs:\n"

    # Get logs from failed containers with progress
    local containers=("kong-gateway" "kong-database" "kong-redis" "demo-api")
    local total=${#containers[@]}
    local current=0

    echo ""
    for container in "${containers[@]}"; do
        current=$((current + 1))
        printf "     Checking %s" "$container"
        if docker ps -a --format "{{.Names}}" | grep -q "^$container$"; then
            diagnostics+="\n--- $container logs ---\n"
            diagnostics+=$(docker logs --tail 50 "$container" 2>&1 || echo "Could not get logs")
            printf " ✓\n"
        else
            printf " (not found)\n"
        fi
    done

    # Save diagnostics to file
    echo -e "$diagnostics" > "$SCRIPT_DIR/diagnostics.txt"

    print_status "$GREEN" "\n✅ Diagnostics collected and saved to: $SCRIPT_DIR/diagnostics.txt"

    # Offer to call Claude with visual feedback
    echo ""
    print_status "$BLUE" "🤔 Would you like AI assistance to fix these issues? (y/n)"

    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        # Call Claude with the errors
        if command -v claude &> /dev/null; then
            echo ""
            print_status "$GREEN" "🚀 Initiating Claude AI assistance..."
            echo ""

            # Show what Claude will analyze
            print_status "$BLUE" "📋 Claude will analyze:"
            echo "  • Error logs and diagnostics"
            echo "  • Container health status"
            echo "  • Service configuration issues"
            echo "  • Potential fixes and solutions"
            echo ""

            # Visual indicator for LLM processing
            print_status "$YELLOW" "🧠 Processing with Claude AI..."
            echo "  ├─ Sending diagnostic data"
            echo "  ├─ Analyzing error patterns"
            echo "  └─ Generating solutions"
            echo ""

            # Create a concise prompt for Claude
            local prompt="Kong Guard AI services are failing to start. Please analyze these errors and provide specific fixes:\n\n"
            prompt+="=== ERRORS ===\n$(cat "$ERROR_LOG")\n\n"
            prompt+="=== CONTAINER STATUS ===\n"
            prompt+=$(docker ps -a --format "{{.Names}}: {{.Status}}" | grep -E "kong|redis|demo|mock" || echo "No containers")
            prompt+="\n\n=== RECENT LOGS ===\n"

            # Get only the most relevant error logs
            for container in kong-gateway kong-database; do
                if docker ps -a --format "{{.Names}}" | grep -q "^$container$"; then
                    prompt+="\n$container errors:\n"
                    prompt+=$(docker logs --tail 20 "$container" 2>&1 | grep -E "ERROR|FATAL|Failed" || echo "No errors in log tail")
                fi
            done

            prompt+="\n\nPlease provide:\n1. Root cause of the failure\n2. Step-by-step fix\n3. Commands to verify the fix worked"

            # Show launching indicator
            print_status "$GREEN" "🎯 Launching Claude with collected diagnostics..."
            echo ""
            echo "────────────────────────────────────────────────"
            echo ""

            # Call Claude
            claude -p "$prompt"

        else
            print_status "$YELLOW" "\n⚠️  Claude CLI is not installed"
            echo ""
            print_status "$BLUE" "To install Claude CLI:"
            echo "  npm install -g @anthropic-ai/claude-cli"
            echo ""
            print_status "$BLUE" "For manual analysis, review:"
            echo "  • Diagnostics: $SCRIPT_DIR/diagnostics.txt"
            echo "  • Error log: $SCRIPT_DIR/errors.log"
            echo "  • Launch log: $SCRIPT_DIR/launch.log"
        fi
    else
        print_status "$BLUE" "\n📚 For manual troubleshooting:"
        echo "  • View diagnostics: cat $SCRIPT_DIR/diagnostics.txt"
        echo "  • Check logs: docker compose logs"
        echo "  • Restart clean: ./launch-kong-guard.sh --clean"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -c|--clean)
            CLEAN_VOLUMES=true
            shift
            ;;
        -n|--no-ui)
            OPEN_UI=false
            shift
            ;;
        -s|--skip-claude)
            CLAUDE_ASSIST=false
            shift
            ;;
        -l|--logs)
            SHOW_LOGS=true
            shift
            ;;
        *)
            print_status "$RED" "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_status "$BLUE" "🚀 Kong Guard AI Launch Script"
    print_status "$BLUE" "================================\n"

    # Pre-flight checks
    check_docker || exit 1
    check_docker_compose || exit 1

    # Stop existing containers
    stop_existing

    # Clean volumes if requested
    clean_volumes

    # Start services
    start_services || exit 1

    # Wait for services to be ready
    print_status "$BLUE" "\n⏳ Waiting for services to be ready..."
    check_postgres
    check_redis
    check_kong_admin
    check_kong_proxy
    check_demo_api
    check_konga

    # Configure plugin
    configure_plugin

    # Show status
    show_status

    # Run health checks
    run_health_checks

    # Open UI
    open_ui

    # Show logs if requested
    if [ "${SHOW_LOGS:-false}" = true ]; then
        print_status "$BLUE" "\n📜 Container logs:"
        docker compose logs --tail 50
    fi

    print_status "$GREEN" "\n✅ Kong Guard AI stack is ready!"
    print_status "$BLUE" "\n🌐 Access Points:"
    echo "  Konga UI:         http://localhost:1337"
    echo "  Kong Admin API:   http://localhost:18001"
    echo "  Kong Proxy:       http://localhost:18000"
    echo ""
    print_status "$BLUE" "📚 Quick commands:"
    echo "  View logs:        docker compose logs -f"
    echo "  Stop services:    docker compose down"
    echo "  Test endpoint:    curl http://localhost:18000/demo/status/200"
    echo ""
    print_status "$YELLOW" "💡 First time using Konga?"
    echo "  1. Open http://localhost:1337"
    echo "  2. Create an admin account"
    echo "  3. Add connection: Name='Local Kong', Kong Admin URL='http://kong:8001'"
    echo ""

    # Mark script as successful to prevent false error triggers
    SCRIPT_SUCCESS=true
}

# Run main function
main
