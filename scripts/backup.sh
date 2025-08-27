#!/bin/bash

# Kong Guard AI Backup Script
# Comprehensive backup solution for production deployments

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="kong-guard-ai-backup-${TIMESTAMP}"

# S3 Configuration (optional)
S3_ENABLED="${S3_ENABLED:-false}"
S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"
S3_PREFIX="${S3_PREFIX:-kong-guard-ai-backups}"

# Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Create backup directory
create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

# Backup Kong database
backup_kong_database() {
    log_info "Backing up Kong database..."
    
    docker exec kong-database pg_dump \
        -U kong \
        -d kong \
        --no-password \
        --verbose \
        --format=custom \
        --file=/tmp/kong_backup.dump || { log_error "Failed to dump Kong database"; return 1; }
    
    docker cp kong-database:/tmp/kong_backup.dump "$BACKUP_DIR/${BACKUP_NAME}_kong.dump" || { log_error "Failed to copy Kong database dump"; return 1; }
    docker exec kong-database rm /tmp/kong_backup.dump || { log_error "Failed to cleanup Kong database dump"; return 1; }
    
    log_success "Kong database backed up"
    return 0
}

# Backup API database
backup_api_database() {
    log_info "Backing up API database..."
    
    docker exec api-database pg_dump \
        -U kongguard \
        -d kongguard \
        --no-password \
        --verbose \
        --format=custom \
        --file=/tmp/api_backup.dump || { log_error "Failed to dump API database"; return 1; }
    
    docker cp api-database:/tmp/api_backup.dump "$BACKUP_DIR/${BACKUP_NAME}_api.dump" || { log_error "Failed to copy API database dump"; return 1; }
    docker exec api-database rm /tmp/api_backup.dump || { log_error "Failed to cleanup API database dump"; return 1; }
    
    log_success "API database backed up"
    return 0
}

# Backup Redis data
backup_redis() {
    log_info "Backing up Redis data..."
    
    # Configure timeout for Redis save operation
    local MAX_WAIT_SECONDS="${REDIS_BACKUP_TIMEOUT:-300}"  # Default 5 minutes
    
    # Trigger Redis save
    docker exec redis redis-cli BGSAVE || { log_error "Failed to trigger Redis save"; return 1; }
    
    # Wait for save to complete with timeout
    local prev_lastsave
    prev_lastsave=$(docker exec redis redis-cli LASTSAVE) || { log_error "Failed to get initial Redis LASTSAVE"; return 1; }
    
    local start_time=$(date +%s)
    local current_lastsave
    
    while true; do
        # Check if we've exceeded the timeout
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        
        if [ $elapsed_time -ge $MAX_WAIT_SECONDS ]; then
            log_error "Redis BGSAVE operation timed out after ${MAX_WAIT_SECONDS} seconds"
            return 1
        fi
        
        # Get current LASTSAVE value
        current_lastsave=$(docker exec redis redis-cli LASTSAVE 2>/dev/null)
        if [ $? -ne 0 ]; then
            log_error "Failed to check Redis LASTSAVE status during polling"
            return 1
        fi
        
        # Check if save has completed (LASTSAVE value changed)
        if [ "$prev_lastsave" != "$current_lastsave" ]; then
            log_info "Redis save completed after $elapsed_time seconds"
            break
        fi
        
        sleep 1
    done
    
    # Copy dump file
    docker cp redis:/data/dump.rdb "$BACKUP_DIR/${BACKUP_NAME}_redis.rdb" || { log_error "Failed to copy Redis dump file"; return 1; }
    
    log_success "Redis data backed up"
    return 0
}

# Backup configuration files
backup_configs() {
    log_info "Backing up configuration files..."
    
    local config_backup="$BACKUP_DIR/${BACKUP_NAME}_configs"
    mkdir -p "$config_backup" || { log_error "Failed to create config backup directory"; return 1; }
    
    # Copy important config files
    cp -r "$PROJECT_ROOT/kong-guard-ai/kong/plugins/kong-guard-ai" "$config_backup/plugin" 2>/dev/null || true
    cp "$PROJECT_ROOT/.env"* "$config_backup/" 2>/dev/null || true
    cp "$PROJECT_ROOT/docker-compose"*.yml "$config_backup/" 2>/dev/null || true
    cp -r "$PROJECT_ROOT/nginx" "$config_backup/" 2>/dev/null || true
    cp -r "$PROJECT_ROOT/monitoring" "$config_backup/" 2>/dev/null || true
    
    # Exclude secrets from config backup safely
    find "$config_backup" -type f \( -iname "*.key" -o -iname "*.pem" -o -iname "*password*.*" \) -print0 | xargs -0 rm -f 2>/dev/null || true
    
    # Create tarball
    tar czf "$BACKUP_DIR/${BACKUP_NAME}_configs.tar.gz" -C "$BACKUP_DIR" "$(basename "$config_backup")" || { log_error "Failed to create config tarball"; return 1; }
    rm -rf "$config_backup"
    
    log_success "Configuration files backed up"
    return 0
}

# Backup Docker volumes
backup_volumes() {
    log_info "Backing up Docker volumes..."
    
    local volumes=("kong_data" "api_data" "kong_prefix" "prometheus_data" "grafana_data" "loki_data")
    local failed_volumes=0
    
    for volume in "${volumes[@]}"; do
        if docker volume inspect "$volume" >/dev/null 2>&1; then
            log_info "Backing up volume: $volume"
            
            # Create temporary container to access volume
            if ! docker run --rm \
                -v "$volume":/backup-volume \
                -v "$BACKUP_DIR":/backup \
                alpine tar czf "/backup/${BACKUP_NAME}_volume_${volume}.tar.gz" -C /backup-volume .; then
                log_error "Failed to backup volume: $volume"
                ((failed_volumes++))
            fi
        else
            log_warning "Volume $volume not found, skipping"
        fi
    done
    
    if [ $failed_volumes -gt 0 ]; then
        log_error "Failed to backup $failed_volumes volume(s)"
        return 1
    fi
    
    log_success "Docker volumes backed up"
    return 0
}

# Backup Grafana dashboards
backup_grafana() {
    log_info "Backing up Grafana dashboards..."
    
    if docker ps --format "{{.Names}}" | grep -q "^grafana$"; then
        # Export dashboards via API
        mkdir -p "$BACKUP_DIR/${BACKUP_NAME}_grafana" || { log_error "Failed to create Grafana backup directory"; return 1; }
        
        # Get all dashboards
        dashboards=$(docker exec grafana curl -s \
            -u admin:${GRAFANA_PASSWORD:-admin} \
            http://localhost:3000/api/search?type=dash-db 2>/dev/null || echo "[]")
        
        if [ "$dashboards" != "[]" ]; then
            echo "$dashboards" | jq -r '.[].uid' | while read -r uid; do
                if [ -n "$uid" ]; then
                    docker exec grafana curl -s \
                        -u admin:${GRAFANA_PASSWORD:-admin} \
                        "http://localhost:3000/api/dashboards/uid/${uid}" \
                        > "$BACKUP_DIR/${BACKUP_NAME}_grafana/dashboard_${uid}.json" 2>/dev/null || true
                fi
            done
        fi
        
        # Create tarball
        tar czf "$BACKUP_DIR/${BACKUP_NAME}_grafana.tar.gz" -C "$BACKUP_DIR" "${BACKUP_NAME}_grafana" || { log_error "Failed to create Grafana tarball"; return 1; }
        rm -rf "$BACKUP_DIR/${BACKUP_NAME}_grafana"
        
        log_success "Grafana dashboards backed up"
        return 0
    else
        log_warning "Grafana not running, skipping dashboard backup"
        return 0
    fi
}

# Create master backup archive
create_archive() {
    log_info "Creating master backup archive..."
    
    # Ensure we're in the backup directory
    if ! cd "$BACKUP_DIR"; then
        log_error "Failed to change to backup directory: $BACKUP_DIR"
        exit 1
    fi
    
    # Create archive with proper error handling
    if tar czf "${BACKUP_NAME}.tar.gz" --warning=no-file-changed \
        "${BACKUP_NAME}_kong.dump" \
        "${BACKUP_NAME}_api.dump" \
        "${BACKUP_NAME}_redis.rdb" \
        "${BACKUP_NAME}_configs.tar.gz" \
        "${BACKUP_NAME}_volume_"*.tar.gz \
        "${BACKUP_NAME}_grafana.tar.gz" 2>/dev/null; then
        
        # Remove individual backup files only if archive was successful
        rm -f "${BACKUP_NAME}_"*.dump
        rm -f "${BACKUP_NAME}_"*.rdb
        rm -f "${BACKUP_NAME}_"*.tar.gz
        
        # Calculate backup size only if archive exists
        if [ -f "${BACKUP_NAME}.tar.gz" ]; then
            backup_size=$(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
            log_success "Master backup created: ${BACKUP_NAME}.tar.gz (${backup_size})"
        else
            log_error "Archive file was not created successfully"
            exit 1
        fi
    else
        log_error "Failed to create backup archive"
        exit 1
    fi
}

# Upload to S3 (optional)
upload_to_s3() {
    if [ "$S3_ENABLED" != "true" ]; then
        return
    fi
    
    if [ -z "$S3_BUCKET" ]; then
        log_warning "S3_BUCKET not configured, skipping S3 upload"
        return
    fi
    
    log_info "Uploading backup to S3..."
    
    if command -v aws >/dev/null 2>&1; then
        aws s3 cp \
            "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" \
            "s3://${S3_BUCKET}/${S3_PREFIX}/${BACKUP_NAME}.tar.gz" \
            --region "$S3_REGION"
        
        log_success "Backup uploaded to S3: s3://${S3_BUCKET}/${S3_PREFIX}/${BACKUP_NAME}.tar.gz"
    else
        log_error "AWS CLI not installed, cannot upload to S3"
    fi
}

# Clean old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups..."
    
    # Clean local backups
    find "$BACKUP_DIR" -name "kong-guard-ai-backup-*.tar.gz" -type f -mtime +${BACKUP_RETENTION_DAYS} -delete
    
    local remaining=$(ls -1 "$BACKUP_DIR"/kong-guard-ai-backup-*.tar.gz 2>/dev/null | wc -l)
    log_info "Kept $remaining backup(s) (retention: ${BACKUP_RETENTION_DAYS} days)"
    
    # Clean S3 backups
    if [ "$S3_ENABLED" = "true" ] && [ -n "$S3_BUCKET" ] && command -v aws >/dev/null 2>&1; then
        log_info "Cleaning old S3 backups..."
        
        aws s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}/" --region "$S3_REGION" | \
            awk '{print $4}' | \
            while read -r file; do
                if [[ "$file" =~ kong-guard-ai-backup-.*\.tar\.gz ]]; then
                    file_date=$(echo "$file" | grep -oE '[0-9]{8}')
                    cutoff_date=$(date -d "${BACKUP_RETENTION_DAYS} days ago" +%Y%m%d)
                    
                    if [ "$file_date" -lt "$cutoff_date" ] 2>/dev/null; then
                        aws s3 rm "s3://${S3_BUCKET}/${S3_PREFIX}/${file}" --region "$S3_REGION"
                        log_info "Deleted old S3 backup: $file"
                    fi
                fi
            done
    fi
}

# Verify backup
verify_backup() {
    log_info "Verifying backup integrity..."
    
    if tar tzf "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" >/dev/null 2>&1; then
        log_success "Backup integrity verified"
        return 0
    else
        log_error "Backup integrity check failed"
        return 1
    fi
}

# Send notification
send_notification() {
    local status=$1
    local message=$2
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"Kong Guard AI Backup ${status}: ${message}\"}" \
            2>/dev/null || true
    fi
    
    # Email notification (requires mail command)
    if [ -n "${EMAIL_TO:-}" ] && command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "Kong Guard AI Backup ${status}" "$EMAIL_TO"
    fi
}

# Main backup process
main() {
    log_info "Starting Kong Guard AI backup..."
    log_info "Backup name: ${BACKUP_NAME}"
    
    # Check if running in Docker environment
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running or not accessible"
        exit 1
    fi
    
    # Create backup directory
    create_backup_dir
    
    # Perform critical backups - fail fast on errors
    if ! backup_kong_database; then
        log_error "Kong database backup failed - aborting"
        exit 1
    fi
    
    if ! backup_api_database; then
        log_error "API database backup failed - aborting"
        exit 1
    fi
    
    if ! backup_redis; then
        log_error "Redis backup failed - aborting"
        exit 1
    fi
    backup_configs
    backup_volumes
    backup_grafana
    
    # Create archive
    create_archive
    
    # Verify backup
    if verify_backup; then
        # Upload to S3
        upload_to_s3
        
        # Clean old backups
        cleanup_old_backups
        
        log_success "Backup completed successfully"
        send_notification "SUCCESS" "Backup ${BACKUP_NAME} completed successfully"
    else
        log_error "Backup verification failed"
        send_notification "FAILED" "Backup ${BACKUP_NAME} failed verification"
        exit 1
    fi
    
    echo ""
    echo "=========================================="
    echo "Backup Summary"
    echo "=========================================="
    echo "Backup File: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
    echo "Backup Size: $(du -h "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)"
    echo "Timestamp: $(date)"
    echo "=========================================="
}

# Parse command line arguments
case "${1:-backup}" in
    backup)
        main
        ;;
    list)
        log_info "Available backups:"
        ls -lh "$BACKUP_DIR"/kong-guard-ai-backup-*.tar.gz 2>/dev/null || echo "No backups found"
        ;;
    *)
        echo "Usage: $0 {backup|list}"
        exit 1
        ;;
esac