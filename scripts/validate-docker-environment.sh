#!/bin/bash

# Docker Environment Validation Script
# Validates the complete Docker stack for Kong Guard AI

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[DOCKER]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Docker installation
check_docker_installation() {
    log_info "Checking Docker installation..."
    
    if command -v docker > /dev/null 2>&1; then
        local docker_version=$(docker --version)
        log_success "Docker is installed: $docker_version"
        return 0
    else
        log_error "Docker is not installed"
        return 1
    fi
}

# Check Docker Compose installation
check_docker_compose() {
    log_info "Checking Docker Compose installation..."
    
    if command -v docker-compose > /dev/null 2>&1; then
        local compose_version=$(docker-compose --version)
        log_success "Docker Compose is installed: $compose_version"
        return 0
    elif docker compose version > /dev/null 2>&1; then
        local compose_version=$(docker compose version)
        log_success "Docker Compose (v2) is installed: $compose_version"
        return 0
    else
        log_error "Docker Compose is not installed"
        return 1
    fi
}

# Check if Docker daemon is running
check_docker_daemon() {
    log_info "Checking Docker daemon status..."
    
    if docker info > /dev/null 2>&1; then
        log_success "Docker daemon is running"
        return 0
    else
        log_error "Docker daemon is not running"
        return 1
    fi
}

# Check for docker-compose.yml file
check_compose_file() {
    log_info "Checking for docker-compose.yml..."
    
    if [ -f "docker-compose.yml" ]; then
        log_success "docker-compose.yml found"
        
        # Validate compose file syntax
        if docker-compose config > /dev/null 2>&1 || docker compose config > /dev/null 2>&1; then
            log_success "docker-compose.yml syntax is valid"
            return 0
        else
            log_error "docker-compose.yml has syntax errors"
            return 1
        fi
    else
        log_warning "docker-compose.yml not found (will be created by other agents)"
        return 1
    fi
}

# Check for required Docker images
check_required_images() {
    log_info "Checking for required Docker images..."
    
    local required_images=("kong:latest" "postgres:13")
    local missing_images=()
    
    for image in "${required_images[@]}"; do
        if docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "$image"; then
            log_success "$image is available locally"
        else
            log_warning "$image not found locally, will be pulled during startup"
            missing_images+=("$image")
        fi
    done
    
    if [ ${#missing_images[@]} -eq 0 ]; then
        return 0
    else
        log_info "Missing images: ${missing_images[*]}"
        return 1
    fi
}

# Check container startup
check_container_startup() {
    log_info "Checking container startup capability..."
    
    if [ ! -f "docker-compose.yml" ]; then
        log_warning "Cannot test container startup without docker-compose.yml"
        return 1
    fi
    
    # Try to validate the compose file can start (dry run)
    if docker-compose config --services > /dev/null 2>&1 || docker compose config --services > /dev/null 2>&1; then
        log_success "Compose services configuration is valid"
        return 0
    else
        log_error "Compose services configuration has issues"
        return 1
    fi
}

# Check network configuration
check_network_configuration() {
    log_info "Checking Docker network configuration..."
    
    # Check if the default bridge network is available
    if docker network ls | grep -q bridge; then
        log_success "Docker bridge network is available"
    else
        log_error "Docker bridge network not found"
        return 1
    fi
    
    # Check if ports 8000 and 8001 are available
    check_port_availability 8000 "Kong Proxy"
    check_port_availability 8001 "Kong Admin API"
    check_port_availability 5432 "PostgreSQL"
    
    return 0
}

# Check if a port is available
check_port_availability() {
    local port=$1
    local service_name=$2
    
    if lsof -i :$port > /dev/null 2>&1; then
        log_warning "Port $port ($service_name) is already in use"
        local process=$(lsof -i :$port | tail -1 | awk '{print $1, $2}')
        log_info "Process using port $port: $process"
        return 1
    else
        log_success "Port $port ($service_name) is available"
        return 0
    fi
}

# Check disk space
check_disk_space() {
    log_info "Checking available disk space..."
    
    local available_space=$(df -h . | awk 'NR==2 {print $4}' | sed 's/G\|M\|K//')
    local space_unit=$(df -h . | awk 'NR==2 {print $4}' | sed 's/[0-9.]*//g')
    
    log_info "Available space: ${available_space}${space_unit}"
    
    # Check if we have at least 2GB available
    if [[ "$space_unit" == "G" && "${available_space%.*}" -ge 2 ]]; then
        log_success "Sufficient disk space available"
        return 0
    elif [[ "$space_unit" == "M" && "${available_space%.*}" -ge 2048 ]]; then
        log_success "Sufficient disk space available"
        return 0
    else
        log_warning "Low disk space, may cause issues during image pulls"
        return 1
    fi
}

# Check system resources
check_system_resources() {
    log_info "Checking system resources..."
    
    # Check available memory
    if command -v free > /dev/null 2>&1; then
        local available_mem=$(free -h | awk '/^Mem/ {print $7}')
        log_info "Available memory: $available_mem"
    elif command -v vm_stat > /dev/null 2>&1; then
        # macOS
        local free_pages=$(vm_stat | grep "Pages free" | awk '{print $3}' | sed 's/\.//')
        local available_mem=$(echo "$free_pages * 4096 / 1024 / 1024" | bc)
        log_info "Available memory: ~${available_mem}MB"
    fi
    
    # Check CPU cores
    if command -v nproc > /dev/null 2>&1; then
        local cpu_cores=$(nproc)
        log_info "CPU cores: $cpu_cores"
    elif command -v sysctl > /dev/null 2>&1; then
        # macOS
        local cpu_cores=$(sysctl -n hw.ncpu)
        log_info "CPU cores: $cpu_cores"
    fi
    
    return 0
}

# Test Docker Compose operations
test_compose_operations() {
    log_info "Testing Docker Compose operations..."
    
    if [ ! -f "docker-compose.yml" ]; then
        log_warning "Cannot test compose operations without docker-compose.yml"
        return 1
    fi
    
    # Test compose config
    if docker-compose config > /dev/null 2>&1 || docker compose config > /dev/null 2>&1; then
        log_success "Compose configuration is valid"
    else
        log_error "Compose configuration is invalid"
        return 1
    fi
    
    # Test compose pull (dry run)
    log_info "Testing image pull capability..."
    if docker-compose pull --help > /dev/null 2>&1 || docker compose pull --help > /dev/null 2>&1; then
        log_success "Compose pull command is available"
    else
        log_error "Compose pull command not available"
        return 1
    fi
    
    return 0
}

# Wait for environment to be ready
wait_for_environment() {
    log_info "Waiting for Docker environment to be set up by other agents..."
    
    local max_wait=60  # Wait up to 1 minute
    local wait_count=0
    
    while [ $wait_count -lt $max_wait ]; do
        if [ -f "docker-compose.yml" ]; then
            log_success "Docker environment files detected"
            return 0
        fi
        
        sleep 1
        ((wait_count++))
        
        if [ $((wait_count % 10)) -eq 0 ]; then
            log_info "Still waiting for environment files... (${wait_count}s)"
        fi
    done
    
    log_warning "Timeout waiting for environment files"
    return 1
}

# Create validation report
create_validation_report() {
    log_info "Creating Docker environment validation report..."
    
    local report_file="docker-validation-report.md"
    
    cat > "$report_file" << EOF
# Docker Environment Validation Report

Generated: $(date)

## Environment Check Results

### Docker Installation
- Docker: $(docker --version 2>/dev/null || echo "Not installed")
- Docker Compose: $(docker-compose --version 2>/dev/null || docker compose version 2>/dev/null || echo "Not installed")
- Docker Daemon: $(docker info > /dev/null 2>&1 && echo "Running" || echo "Not running")

### System Resources
- Available Disk Space: $(df -h . | awk 'NR==2 {print $4}')
- CPU Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")

### Network Ports
- Port 8000 (Kong Proxy): $(lsof -i :8000 > /dev/null 2>&1 && echo "In use" || echo "Available")
- Port 8001 (Kong Admin): $(lsof -i :8001 > /dev/null 2>&1 && echo "In use" || echo "Available")
- Port 5432 (PostgreSQL): $(lsof -i :5432 > /dev/null 2>&1 && echo "In use" || echo "Available")

### Docker Images
$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep -E "(kong|postgres)" || echo "No Kong/Postgres images found locally")

### Validation Status
- Docker Ready: $(docker info > /dev/null 2>&1 && echo "✅ Yes" || echo "❌ No")
- Compose Ready: $(command -v docker-compose > /dev/null 2>&1 || docker compose version > /dev/null 2>&1 && echo "✅ Yes" || echo "❌ No")
- Environment Ready: $([ -f "docker-compose.yml" ] && echo "✅ Yes" || echo "⏳ Waiting")

## Recommendations

1. Ensure Docker daemon is running before starting containers
2. Pull required images if not available locally: \`docker-compose pull\`
3. Monitor resource usage during startup
4. Check Kong logs for plugin loading confirmation

## Next Steps

1. Start the Docker stack: \`docker-compose up -d\`
2. Verify Kong connectivity: \`curl http://localhost:8001/status\`
3. Run plugin integration tests
4. Monitor system performance

EOF

    log_success "Validation report created: $report_file"
}

# Main validation function
main() {
    echo "============================================="
    echo "Docker Environment Validation"
    echo "============================================="
    
    local failed_tests=0
    
    # Core Docker checks
    check_docker_installation || ((failed_tests++))
    check_docker_compose || ((failed_tests++))
    check_docker_daemon || ((failed_tests++))
    
    # System resources
    check_disk_space || ((failed_tests++))
    check_system_resources
    check_network_configuration || ((failed_tests++))
    
    # Environment-specific checks
    check_compose_file || log_info "Environment files not yet ready"
    check_required_images || log_info "Images will be pulled during startup"
    test_compose_operations || log_info "Compose operations will be tested when files are ready"
    
    # Create validation report
    create_validation_report
    
    echo "============================================="
    if [ $failed_tests -eq 0 ]; then
        log_success "Docker environment validation passed!"
        log_info "Environment is ready for Kong Guard AI deployment"
    else
        log_warning "$failed_tests validation check(s) failed or pending"
        log_info "Some components may need attention before deployment"
    fi
    
    return $failed_tests
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi