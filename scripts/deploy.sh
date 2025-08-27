#!/bin/bash

# Kong Guard AI Remote Docker Deployment Script
# Production deployment with health checks and rollback capability

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
BACKUP_ENABLED="${BACKUP_ENABLED:-true}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-10}"
HEALTH_CHECK_DELAY="${HEALTH_CHECK_DELAY:-30}"

# Remote server configuration (can be overridden by environment variables)
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-ubuntu}"
REMOTE_PORT="${REMOTE_PORT:-22}"
REMOTE_PATH="${REMOTE_PATH:-/opt/kong-guard-ai}"
SSH_KEY="${SSH_KEY:-~/.ssh/id_rsa}"

# Function to print colored output
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for required commands
    local required_commands=("docker" "docker-compose" "ssh" "rsync" "git")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd is not installed"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check remote host configuration
    if [ -z "$REMOTE_HOST" ]; then
        log_error "REMOTE_HOST is not set. Please configure the remote server."
        echo "Usage: REMOTE_HOST=your-server.com $0"
        exit 1
    fi
    
    # Test SSH connection
    if ! ssh -o ConnectTimeout=5 -p "$REMOTE_PORT" -i "$SSH_KEY" \
         "$REMOTE_USER@$REMOTE_HOST" "echo 'SSH connection successful'" &> /dev/null; then
        log_error "Cannot connect to remote host $REMOTE_HOST"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Function to generate secrets
generate_secrets() {
    log_info "Generating secrets..."
    
    local secrets_dir="$PROJECT_ROOT/secrets"
    mkdir -p "$secrets_dir"
    chmod 700 "$secrets_dir"
    
    # Generate passwords if they don't exist
    [ ! -f "$secrets_dir/kong_postgres_password.txt" ] && \
        openssl rand -base64 32 > "$secrets_dir/kong_postgres_password.txt"
    
    [ ! -f "$secrets_dir/api_postgres_password.txt" ] && \
        openssl rand -base64 32 > "$secrets_dir/api_postgres_password.txt"
    
    [ ! -f "$secrets_dir/redis_password.txt" ] && \
        openssl rand -base64 32 > "$secrets_dir/redis_password.txt"
    
    [ ! -f "$secrets_dir/api_secret_key.txt" ] && \
        openssl rand -hex 32 > "$secrets_dir/api_secret_key.txt"
    
    [ ! -f "$secrets_dir/grafana_password.txt" ] && \
        openssl rand -base64 20 > "$secrets_dir/grafana_password.txt"
    
    # Generate self-signed SSL certificate if not exists
    if [ ! -f "$secrets_dir/server.crt" ] || [ ! -f "$secrets_dir/server.key" ]; then
        log_info "Generating self-signed SSL certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$secrets_dir/server.key" \
            -out "$secrets_dir/server.crt" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$REMOTE_HOST"
    fi
    
    chmod 600 "$secrets_dir"/*
    log_success "Secrets generated"
}

# Function to create environment file
create_env_file() {
    log_info "Creating environment configuration..."
    
    cat > "$PROJECT_ROOT/.env.production" << EOF
# Kong Guard AI Production Environment Configuration
# Generated: $(date)

# Deployment
DEPLOYMENT_ENV=production
DOMAIN=${REMOTE_HOST}

# Kong Configuration
KONG_PG_DATABASE=kong
KONG_PG_USER=kong
KONG_REPLICAS=2
KONG_PROXY_PORT=8000
KONG_PROXY_SSL_PORT=8443
KONG_ADMIN_PORT=127.0.0.1:8001
KONG_ADMIN_SSL_PORT=127.0.0.1:8444

# API Configuration
API_PG_DATABASE=kongguard
API_PG_USER=kongguard
API_REPLICAS=2
API_PORT=8080
API_WORKERS=4

# Monitoring
PROMETHEUS_PORT=127.0.0.1:9090
GRAFANA_PORT=127.0.0.1:3000
GRAFANA_USER=admin
LOKI_PORT=127.0.0.1:3100

# Logging
LOG_LEVEL=info

# AI Gateway (optional)
AI_GATEWAY_ENABLED=false
AI_GATEWAY_MODEL=gpt-4o-mini
EOF
    
    log_success "Environment configuration created"
}

# Function to build Docker images
build_images() {
    log_info "Building Docker images..."
    
    cd "$PROJECT_ROOT"
    
    # Build production images
    docker build -f Dockerfile.production --target kong-production -t kong-guard-ai:kong-latest .
    docker build -f Dockerfile.production --target fastapi-production -t kong-guard-ai:api-latest .
    
    # Tag images for registry
    # Conditionally tag with registry prefix only if not localhost
    if [ -n "${DOCKER_REGISTRY:-}" ] && [ "${DOCKER_REGISTRY}" != "localhost" ]; then
        REGISTRY_PREFIX="${DOCKER_REGISTRY}/"
    else
        REGISTRY_PREFIX=""
    fi
    
    docker tag kong-guard-ai:kong-latest "${REGISTRY_PREFIX}kong-guard-ai:kong-${VERSION:-latest}"
    docker tag kong-guard-ai:api-latest "${REGISTRY_PREFIX}kong-guard-ai:api-${VERSION:-latest}"
    
    log_success "Docker images built successfully"
}

# Function to backup existing deployment
backup_deployment() {
    if [ "$BACKUP_ENABLED" != "true" ]; then
        log_warning "Backup is disabled, skipping..."
        return
    fi
    
    log_info "Creating backup of existing deployment..."
    
    local backup_name="backup-$(date +%Y%m%d-%H%M%S)"
    
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" << EOF
        if [ -d "$REMOTE_PATH" ]; then
            mkdir -p "$REMOTE_PATH/../backups"
            cd "$REMOTE_PATH/.."
            tar czf "backups/${backup_name}.tar.gz" kong-guard-ai/
            echo "Backup created: ${backup_name}.tar.gz"
            
            # Keep only last 5 backups
            ls -t backups/*.tar.gz | tail -n +6 | xargs -r rm
        fi
EOF
    
    log_success "Backup completed"
}

# Function to deploy to remote server
deploy_to_remote() {
    log_info "Deploying to remote server $REMOTE_HOST..."
    
    # Create remote directory
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" \
        "mkdir -p $REMOTE_PATH"
    
    # Sync files to remote server
    log_info "Synchronizing files..."
    rsync -avz --delete \
        -e "ssh -p $REMOTE_PORT -i $SSH_KEY" \
        --exclude='.git' \
        --exclude='*.log' \
        --exclude='__pycache__' \
        --exclude='node_modules' \
        --exclude='.pytest_cache' \
        --exclude='venv' \
        "$PROJECT_ROOT/" \
        "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/"
    
    log_success "Files synchronized"
}

# Function to start services on remote
start_remote_services() {
    log_info "Starting services on remote server..."
    
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" << 'ENDSSH'
        cd "$REMOTE_PATH"
        
        # Stop existing services
        docker-compose -f docker-compose.production.yml down --remove-orphans || true
        
        # Pull latest images (if using registry)
        # docker-compose -f docker-compose.production.yml pull
        
        # Start services
        docker-compose -f docker-compose.production.yml up -d
        
        # Wait for services to start
        sleep 10
        
        # Show service status
        docker-compose -f docker-compose.production.yml ps
ENDSSH
    
    log_success "Services started"
}

# Function to perform health checks
health_check() {
    log_info "Performing health checks..."
    
    local retry_count=0
    local all_healthy=false
    
    while [ $retry_count -lt $HEALTH_CHECK_RETRIES ]; do
        log_info "Health check attempt $((retry_count + 1))/$HEALTH_CHECK_RETRIES"
        
        # Check Kong health
        if ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" \
           "curl -sf http://localhost:8001/status" &> /dev/null; then
            log_success "Kong is healthy"
            
            # Check FastAPI health
            if ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" \
               "curl -sf http://localhost:8080/health" &> /dev/null; then
                log_success "FastAPI is healthy"
                all_healthy=true
                break
            else
                log_warning "FastAPI is not healthy yet"
            fi
        else
            log_warning "Kong is not healthy yet"
        fi
        
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $HEALTH_CHECK_RETRIES ]; then
            log_info "Waiting ${HEALTH_CHECK_DELAY} seconds before next check..."
            sleep $HEALTH_CHECK_DELAY
        fi
    done
    
    if [ "$all_healthy" = true ]; then
        log_success "All services are healthy"
        return 0
    else
        log_error "Health checks failed after $HEALTH_CHECK_RETRIES attempts"
        return 1
    fi
}

# Function to setup SSL with Let's Encrypt
setup_ssl() {
    log_info "Setting up SSL with Let's Encrypt..."
    
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" << ENDSSH
        cd "$REMOTE_PATH"
        
        # Initialize Let's Encrypt certificates
        docker-compose -f docker-compose.production.yml run --rm certbot certonly \
            --webroot --webroot-path=/var/www/certbot \
            --email admin@$REMOTE_HOST \
            --agree-tos \
            --no-eff-email \
            -d $REMOTE_HOST \
            -d www.$REMOTE_HOST
        
        # Reload nginx to use new certificates
        docker-compose -f docker-compose.production.yml exec nginx nginx -s reload
ENDSSH
    
    log_success "SSL setup completed"
}

# Function to setup firewall rules
setup_firewall() {
    log_info "Setting up firewall rules..."
    
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" << 'ENDSSH'
        # Allow SSH
        sudo ufw allow 22/tcp
        
        # Allow HTTP and HTTPS
        sudo ufw allow 80/tcp
        sudo ufw allow 443/tcp
        
        # Allow Kong proxy ports
        sudo ufw allow 8000/tcp
        sudo ufw allow 8443/tcp
        
        # Block Kong Admin API from external access
        sudo ufw deny 8001/tcp
        sudo ufw deny 8444/tcp
        
        # Block monitoring ports from external access
        sudo ufw deny 9090/tcp  # Prometheus
        sudo ufw deny 3000/tcp  # Grafana
        sudo ufw deny 3100/tcp  # Loki
        
        # Enable firewall
        sudo ufw --force enable
        
        # Show status
        sudo ufw status verbose
ENDSSH
    
    log_success "Firewall configured"
}

# Function to display deployment info
display_info() {
    log_success "Deployment completed successfully!"
    echo ""
    echo "=========================================="
    echo "Kong Guard AI Deployment Information"
    echo "=========================================="
    echo "Server: $REMOTE_HOST"
    echo "Kong Proxy: http://$REMOTE_HOST:8000"
    echo "Kong Proxy SSL: https://$REMOTE_HOST:8443"
    echo "FastAPI Management: http://$REMOTE_HOST:8080"
    echo "FastAPI Docs: http://$REMOTE_HOST:8080/docs"
    echo ""
    echo "To access admin interfaces via SSH tunnel:"
    echo "ssh -L 8001:localhost:8001 -L 3000:localhost:3000 -L 9090:localhost:9090 $REMOTE_USER@$REMOTE_HOST"
    echo ""
    echo "Then access:"
    echo "Kong Admin: http://localhost:8001"
    echo "Grafana: http://localhost:3000 (admin/[check secrets/grafana_password.txt])"
    echo "Prometheus: http://localhost:9090"
    echo "=========================================="
}

# Function to rollback deployment
rollback() {
    log_warning "Rolling back deployment..."
    
    local latest_backup=$(ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" \
        "find \$(dirname '$REMOTE_PATH')/backups -name '*.tar.gz' -type f | sort -r | head -1 2>/dev/null")
    
    if [ -z "$latest_backup" ]; then
        log_error "No backup found for rollback"
        exit 1
    fi
    
    # Validate backup path and extract safely
    ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" << EOF
        set -euo pipefail
        
        # Resolve absolute paths
        BACKUP_FILE="\$(realpath '$latest_backup')"
        DEPLOY_DIR="\$(realpath '$REMOTE_PATH')"
        PARENT_DIR="\$(dirname '\$DEPLOY_DIR')"
        
        # Validate paths
        if [[ "\$BACKUP_FILE" != "\$PARENT_DIR/backups/"* ]]; then
            echo "Invalid backup path: \$BACKUP_FILE"
            exit 1
        fi
        
        # Stop services and clean up
        cd "\$DEPLOY_DIR"
        docker-compose -f docker-compose.production.yml down 2>/dev/null || true
        
        # Extract to temporary directory first
        TEMP_DIR="\$(mktemp -d)"
        cd "\$TEMP_DIR"
        tar xzf "\$BACKUP_FILE" --strip-components=0
        
        # Verify extraction contains expected directory structure
        if [ ! -d "kong-guard-ai" ]; then
            echo "Invalid backup structure - no kong-guard-ai directory found"
            rm -rf "\$TEMP_DIR"
            exit 1
        fi
        
        # Replace deployment directory
        rm -rf "\$DEPLOY_DIR"
        mv "kong-guard-ai" "\$DEPLOY_DIR"
        
        # Start services
        cd "\$DEPLOY_DIR"
        docker-compose -f docker-compose.production.yml up -d
        
        # Cleanup temp directory
        rm -rf "\$TEMP_DIR"
EOF
    
    log_success "Rollback completed"
}

# Main deployment flow
main() {
    log_info "Starting Kong Guard AI deployment..."
    
    # Parse command line arguments
    case "${1:-deploy}" in
        deploy)
            check_prerequisites
            generate_secrets
            create_env_file
            build_images
            backup_deployment
            deploy_to_remote
            start_remote_services
            
            if health_check; then
                setup_firewall
                # Optionally setup SSL if domain is configured
                # setup_ssl
                display_info
            else
                log_error "Deployment failed health checks"
                rollback
                exit 1
            fi
            ;;
        rollback)
            rollback
            ;;
        health)
            health_check
            ;;
        *)
            echo "Usage: $0 {deploy|rollback|health}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"