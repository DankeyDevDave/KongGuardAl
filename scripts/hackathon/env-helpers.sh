#!/bin/bash
# Environment Setup Helper Functions

# Start all services
start_services() {
    echo_info "Starting Kong Guard AI services..."
    
    # Find docker-compose file
    local compose_file=""
    if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
        compose_file="$DOCKER_COMPOSE_FILE"
    elif [[ -f "$DOCKER_COMPOSE_FALLBACK" ]]; then
        compose_file="$DOCKER_COMPOSE_FALLBACK"
        echo_warning "Using fallback compose file: $compose_file"
    else
        echo_error "No docker-compose file found"
        return 1
    fi
    
    echo_info "Using: $compose_file"
    
    docker-compose -f "$compose_file" up -d
    
    if [[ $? -eq 0 ]]; then
        echo_success "Services started successfully!"
        echo_info "Waiting $SERVICE_STARTUP_WAIT seconds for initialization..."
        sleep "$SERVICE_STARTUP_WAIT"
        check_services_status
        return 0
    else
        echo_error "Failed to start services"
        return 1
    fi
}

# Stop all services
stop_services() {
    echo_info "Stopping Kong Guard AI services..."
    
    local compose_file=""
    if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
        compose_file="$DOCKER_COMPOSE_FILE"
    elif [[ -f "$DOCKER_COMPOSE_FALLBACK" ]]; then
        compose_file="$DOCKER_COMPOSE_FALLBACK"
    else
        echo_warning "No docker-compose file found, trying default docker-compose down"
        docker-compose down 2>/dev/null
        return $?
    fi
    
    docker-compose -f "$compose_file" down
    
    if [[ $? -eq 0 ]]; then
        echo_success "Services stopped successfully!"
        return 0
    else
        echo_error "Failed to stop services"
        return 1
    fi
}

# Check service status
check_services_status() {
    echo_info "Checking service status..."
    echo ""
    
    # Check Docker
    if ! command_exists docker; then
        echo_error "Docker not installed"
        return 1
    fi
    
    # Check docker-compose
    if ! command_exists docker-compose; then
        echo_error "docker-compose not installed"
        return 1
    fi
    
    # Show running containers
    local containers=$(docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(kong|guard|ai|visualization|nginx)" || true)
    
    if [[ -z "$containers" ]]; then
        echo_warning "No Kong Guard AI services running"
        echo_info "Start services with: $0 --start-services"
        return 1
    fi
    
    echo "$containers"
    echo ""
    
    # Check dashboard accessibility
    check_dashboard_access
    
    return 0
}

# Check dashboard access
check_dashboard_access() {
    echo_info "Checking dashboard accessibility..."
    
    local url="$DASHBOARD_URL"
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    
    if [[ "$status_code" == "200" || "$status_code" == "304" ]]; then
        echo_success "Dashboard accessible at: $url"
        return 0
    else
        echo_warning "Dashboard not accessible at: $url (Status: $status_code)"
        
        # Check if file exists locally
        if [[ -f "$DASHBOARD_LOCAL_PATH" ]]; then
            echo_info "Local dashboard available: file://$(pwd)/$DASHBOARD_LOCAL_PATH"
        fi
        
        return 1
    fi
}

# Reset environment
reset_environment() {
    echo_warning "This will stop all services and remove containers/volumes"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo_info "Reset cancelled"
        return 0
    fi
    
    echo_info "Resetting environment..."
    
    # Stop services
    stop_services
    
    # Remove volumes
    echo_info "Removing volumes..."
    docker volume prune -f
    
    # Remove networks
    echo_info "Removing networks..."
    docker network prune -f
    
    echo_success "Environment reset complete!"
    echo_info "Start fresh with: $0 --start-services"
}

# Check dependencies
check_dependencies() {
    echo_info "Checking dependencies..."
    echo ""
    
    local all_good=true
    
    # Python
    if command_exists "$PYTHON_CMD"; then
        local py_version=$($PYTHON_CMD --version 2>&1)
        echo_success "✓ Python: $py_version"
    else
        echo_error "✗ Python not found (command: $PYTHON_CMD)"
        all_good=false
    fi
    
    # Playwright
    if $PYTHON_CMD -c "from playwright.async_api import async_playwright" 2>/dev/null; then
        echo_success "✓ Playwright installed"
    else
        echo_error "✗ Playwright not installed"
        echo_info "  Install with: pip install playwright && playwright install"
        all_good=false
    fi
    
    # Docker
    if command_exists docker; then
        local docker_version=$(docker --version)
        echo_success "✓ Docker: $docker_version"
    else
        echo_error "✗ Docker not installed"
        all_good=false
    fi
    
    # docker-compose
    if command_exists docker-compose; then
        local compose_version=$(docker-compose --version)
        echo_success "✓ docker-compose: $compose_version"
    else
        echo_error "✗ docker-compose not installed"
        all_good=false
    fi
    
    # ffmpeg (optional)
    if command_exists ffmpeg; then
        local ffmpeg_version=$(ffmpeg -version 2>&1 | head -1)
        echo_success "✓ ffmpeg: $ffmpeg_version"
    else
        echo_warning "⚠ ffmpeg not installed (needed for MP4 conversion)"
        echo_info "  Install with: brew install ffmpeg (macOS) or apt install ffmpeg (Linux)"
    fi
    
    # Check required files
    echo ""
    echo_info "Checking required files..."
    
    [[ -f "$RECORDER_SCRIPT" ]] && echo_success "✓ $RECORDER_SCRIPT" || { echo_error "✗ $RECORDER_SCRIPT"; all_good=false; }
    [[ -f "$TIMING_CONFIG" ]] && echo_success "✓ $TIMING_CONFIG" || { echo_error "✗ $TIMING_CONFIG"; all_good=false; }
    [[ -f "$VISUAL_EFFECTS" ]] && echo_success "✓ $VISUAL_EFFECTS" || { echo_error "✗ $VISUAL_EFFECTS"; all_good=false; }
    
    echo ""
    
    if $all_good; then
        echo_success "All dependencies satisfied!"
        return 0
    else
        echo_error "Some dependencies missing"
        return 1
    fi
}

# Check disk space
check_disk_space() {
    echo_info "Checking disk space..."
    echo ""
    
    local available=$(df -h . | awk 'NR==2 {print $4}')
    local used=$(df -h . | awk 'NR==2 {print $5}')
    
    echo_info "Available: $available | Used: $used"
    
    # Check if we have at least 1GB free
    local available_mb=$(df -m . | awk 'NR==2 {print $4}')
    
    if [[ $available_mb -lt 1024 ]]; then
        echo_warning "Low disk space! Recommended: >1GB free"
        return 1
    else
        echo_success "Sufficient disk space available"
        return 0
    fi
}

# View logs
view_logs() {
    local service="${1:-all}"
    
    echo_info "Viewing logs for: $service"
    echo ""
    
    local compose_file=""
    if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
        compose_file="$DOCKER_COMPOSE_FILE"
    elif [[ -f "$DOCKER_COMPOSE_FALLBACK" ]]; then
        compose_file="$DOCKER_COMPOSE_FALLBACK"
    fi
    
    if [[ -n "$compose_file" ]]; then
        if [[ "$service" == "all" ]]; then
            docker-compose -f "$compose_file" logs --tail=50
        else
            docker-compose -f "$compose_file" logs --tail=50 "$service"
        fi
    else
        echo_warning "No docker-compose file found, showing all docker logs"
        docker logs $(docker ps -q) 2>&1 | tail -50
    fi
}

# Test connections
test_connections() {
    echo_info "Testing network connections..."
    echo ""
    
    # Test dashboard
    local urls=(
        "$DASHBOARD_URL"
        "http://localhost:8001"
        "http://localhost:8000"
    )
    
    for url in "${urls[@]}"; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        
        if [[ "$status" == "200" || "$status" == "304" ]]; then
            echo_success "✓ $url (Status: $status)"
        else
            echo_error "✗ $url (Status: $status)"
        fi
    done
}
