#!/bin/bash

# Kong Guard AI - Automated Backup Script
# Enterprise-grade backup automation with rotation, compression, and monitoring

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/backup-config.conf"
LOG_FILE="/var/log/kong-guard-ai-backup.log"
BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/var/backups/kong-guard-ai}"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS="${RETENTION_DAYS:-30}"
COMPRESSION_LEVEL="${COMPRESSION_LEVEL:-6}"

# AWS Configuration
AWS_REGION="${AWS_REGION:-us-west-2}"
S3_BACKUP_BUCKET="${S3_BACKUP_BUCKET:-kong-guard-ai-backups}"
S3_BACKUP_PREFIX="${S3_BACKUP_PREFIX:-production}"

# Kubernetes Configuration
NAMESPACE="${NAMESPACE:-kong-guard-ai}"
KUBECTL_CONFIG="${KUBECTL_CONFIG:-~/.kube/config}"

# Database Configuration
DB_HOST="${DB_HOST:-}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-kong}"
DB_USER="${DB_USER:-kong}"
DB_PASSWORD_FILE="${DB_PASSWORD_FILE:-/etc/kong-guard-ai/db-password}"

# Notification Configuration
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
EMAIL_RECIPIENTS="${EMAIL_RECIPIENTS:-}"
SMTP_SERVER="${SMTP_SERVER:-localhost}"

# Load configuration if exists
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $*" | tee -a "$LOG_FILE"
}

# Notification functions
send_slack_notification() {
    local message="$1"
    local status="${2:-info}"
    
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local color="good"
        local emoji="ℹ️"
        
        case "$status" in
            error)
                color="danger"
                emoji="❌"
                ;;
            success)
                color="good"
                emoji="✅"
                ;;
            warning)
                color="warning"
                emoji="⚠️"
                ;;
        esac
        
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-type: application/json' \
            --data "{
                \"text\": \"${emoji} Kong Guard AI Backup\",
                \"attachments\": [
                    {
                        \"color\": \"${color}\",
                        \"fields\": [
                            {
                                \"title\": \"Message\",
                                \"value\": \"${message}\",
                                \"short\": false
                            },
                            {
                                \"title\": \"Timestamp\",
                                \"value\": \"$(date)\",
                                \"short\": true
                            },
                            {
                                \"title\": \"Environment\",
                                \"value\": \"${S3_BACKUP_PREFIX}\",
                                \"short\": true
                            }
                        ]
                    }
                ]
            }" 2>/dev/null || log_error "Failed to send Slack notification"
    fi
}

send_email_notification() {
    local subject="$1"
    local message="$2"
    
    if [[ -n "$EMAIL_RECIPIENTS" && -n "$SMTP_SERVER" ]]; then
        echo -e "Subject: $subject\n\n$message\n\nTimestamp: $(date)\nEnvironment: $S3_BACKUP_PREFIX" | \
            sendmail -S "$SMTP_SERVER" "$EMAIL_RECIPIENTS" 2>/dev/null || \
            log_error "Failed to send email notification"
    fi
}

# Utility functions
check_dependencies() {
    local deps=("kubectl" "pg_dump" "aws" "gzip" "tar")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' is not installed"
            return 1
        fi
    done
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        return 1
    fi
    
    # Check Kubernetes access
    if ! kubectl --kubeconfig="$KUBECTL_CONFIG" get namespaces &> /dev/null; then
        log_error "Kubernetes access not configured or invalid"
        return 1
    fi
    
    log "All dependencies verified"
    return 0
}

create_backup_directories() {
    local dirs=(
        "$BACKUP_BASE_DIR"
        "$BACKUP_BASE_DIR/database"
        "$BACKUP_BASE_DIR/configuration"
        "$BACKUP_BASE_DIR/logs"
        "$BACKUP_BASE_DIR/certificates"
        "$BACKUP_BASE_DIR/monitoring"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
    
    log "Backup directories created"
}

# Database backup functions
backup_database() {
    log "Starting database backup..."
    
    local backup_file="$BACKUP_BASE_DIR/database/kong-db-${DATE}.sql"
    local compressed_file="${backup_file}.gz"
    
    # Get database credentials if not provided
    if [[ -z "$DB_HOST" ]]; then
        DB_HOST=$(kubectl --kubeconfig="$KUBECTL_CONFIG" get secret postgres-secret -n "$NAMESPACE" -o jsonpath='{.data.POSTGRES_HOST}' | base64 -d 2>/dev/null || echo "")
    fi
    
    if [[ -z "$DB_HOST" ]]; then
        # Try to get RDS endpoint from Terraform output
        DB_HOST=$(terraform output -raw rds_endpoint 2>/dev/null || echo "")
    fi
    
    if [[ -z "$DB_HOST" ]]; then
        log_error "Database host not configured"
        return 1
    fi
    
    # Get database password
    local db_password=""
    if [[ -f "$DB_PASSWORD_FILE" ]]; then
        db_password=$(cat "$DB_PASSWORD_FILE")
    else
        db_password=$(kubectl --kubeconfig="$KUBECTL_CONFIG" get secret postgres-secret -n "$NAMESPACE" -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d 2>/dev/null || echo "")
    fi
    
    if [[ -z "$db_password" ]]; then
        log_error "Database password not found"
        return 1
    fi
    
    # Create database dump
    export PGPASSWORD="$db_password"
    
    if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        --verbose \
        --clean \
        --if-exists \
        --create \
        --format=plain \
        --no-owner \
        --no-privileges > "$backup_file" 2>/dev/null; then
        
        # Compress the backup
        gzip -"$COMPRESSION_LEVEL" "$backup_file"
        
        local file_size=$(du -h "$compressed_file" | cut -f1)
        log_success "Database backup completed: $compressed_file ($file_size)"
        
        # Verify backup integrity
        if verify_database_backup "$compressed_file"; then
            log_success "Database backup integrity verified"
            echo "$compressed_file"
        else
            log_error "Database backup integrity verification failed"
            return 1
        fi
    else
        log_error "Database backup failed"
        return 1
    fi
    
    unset PGPASSWORD
}

verify_database_backup() {
    local backup_file="$1"
    
    # Basic verification - check if file is a valid gzip and contains expected content
    if gzip -t "$backup_file" 2>/dev/null; then
        if zcat "$backup_file" | head -n 10 | grep -q "PostgreSQL database dump"; then
            return 0
        fi
    fi
    
    return 1
}

# Configuration backup functions
backup_kubernetes_configuration() {
    log "Starting Kubernetes configuration backup..."
    
    local config_dir="$BACKUP_BASE_DIR/configuration"
    local config_archive="$config_dir/k8s-config-${DATE}.tar.gz"
    
    # Create temporary directory for configuration files
    local temp_dir=$(mktemp -d)
    
    # Backup ConfigMaps
    kubectl --kubeconfig="$KUBECTL_CONFIG" get configmaps -n "$NAMESPACE" -o yaml > "$temp_dir/configmaps.yaml"
    
    # Backup Secrets (excluding sensitive data, just structure)
    kubectl --kubeconfig="$KUBECTL_CONFIG" get secrets -n "$NAMESPACE" -o yaml | \
        grep -v "data:" | grep -v "  [a-zA-Z0-9+/]*=" > "$temp_dir/secrets-structure.yaml"
    
    # Backup Deployments
    kubectl --kubeconfig="$KUBECTL_CONFIG" get deployments -n "$NAMESPACE" -o yaml > "$temp_dir/deployments.yaml"
    
    # Backup Services
    kubectl --kubeconfig="$KUBECTL_CONFIG" get services -n "$NAMESPACE" -o yaml > "$temp_dir/services.yaml"
    
    # Backup Ingress
    kubectl --kubeconfig="$KUBECTL_CONFIG" get ingress -n "$NAMESPACE" -o yaml > "$temp_dir/ingress.yaml" 2>/dev/null || true
    
    # Backup PersistentVolumeClaims
    kubectl --kubeconfig="$KUBECTL_CONFIG" get pvc -n "$NAMESPACE" -o yaml > "$temp_dir/pvc.yaml"
    
    # Backup Network Policies
    kubectl --kubeconfig="$KUBECTL_CONFIG" get networkpolicies -n "$NAMESPACE" -o yaml > "$temp_dir/networkpolicies.yaml" 2>/dev/null || true
    
    # Backup ServiceMonitors (if Prometheus operator is used)
    kubectl --kubeconfig="$KUBECTL_CONFIG" get servicemonitors -n "$NAMESPACE" -o yaml > "$temp_dir/servicemonitors.yaml" 2>/dev/null || true
    
    # Create archive
    tar -czf "$config_archive" -C "$temp_dir" . 2>/dev/null
    
    # Cleanup
    rm -rf "$temp_dir"
    
    local file_size=$(du -h "$config_archive" | cut -f1)
    log_success "Kubernetes configuration backup completed: $config_archive ($file_size)"
    
    echo "$config_archive"
}

backup_kong_configuration() {
    log "Starting Kong configuration backup..."
    
    local config_dir="$BACKUP_BASE_DIR/configuration"
    local kong_config_file="$config_dir/kong-config-${DATE}.json"
    local compressed_file="${kong_config_file}.gz"
    
    # Get Kong Admin API endpoint
    local admin_api_url=""
    
    # Try to get admin API URL from service
    local admin_service=$(kubectl --kubeconfig="$KUBECTL_CONFIG" get svc -n "$NAMESPACE" -l app.kubernetes.io/component=admin -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")
    
    if [[ -n "$admin_service" ]]; then
        admin_api_url="http://${admin_service}:8001"
    else
        # Try port-forward as fallback
        kubectl --kubeconfig="$KUBECTL_CONFIG" port-forward svc/kong-admin 8001:8001 -n "$NAMESPACE" &
        local port_forward_pid=$!
        sleep 5
        admin_api_url="http://localhost:8001"
    fi
    
    # Backup Kong configuration
    local config_data=$(curl -s "$admin_api_url/config" 2>/dev/null || echo "{}")
    
    if [[ "$config_data" != "{}" ]]; then
        echo "$config_data" | jq . > "$kong_config_file"
        gzip -"$COMPRESSION_LEVEL" "$kong_config_file"
        
        local file_size=$(du -h "$compressed_file" | cut -f1)
        log_success "Kong configuration backup completed: $compressed_file ($file_size)"
        echo "$compressed_file"
    else
        log_error "Failed to retrieve Kong configuration"
        return 1
    fi
    
    # Cleanup port-forward if used
    if [[ -n "${port_forward_pid:-}" ]]; then
        kill "$port_forward_pid" 2>/dev/null || true
    fi
}

# Logs backup functions
backup_application_logs() {
    log "Starting application logs backup..."
    
    local logs_dir="$BACKUP_BASE_DIR/logs"
    local logs_archive="$logs_dir/app-logs-${DATE}.tar.gz"
    
    # Create temporary directory for logs
    local temp_dir=$(mktemp -d)
    
    # Get Kong Gateway logs
    kubectl --kubeconfig="$KUBECTL_CONFIG" logs -n "$NAMESPACE" -l app.kubernetes.io/name=kong-gateway --since=24h > "$temp_dir/kong-gateway.log" 2>/dev/null || true
    
    # Get Kong Guard AI specific logs
    kubectl --kubeconfig="$KUBECTL_CONFIG" logs -n "$NAMESPACE" -l app.kubernetes.io/name=kong-gateway --since=24h | \
        grep -i "kong-guard-ai\|threat_detected\|enforcement_action" > "$temp_dir/kong-guard-ai.log" 2>/dev/null || true
    
    # Get database logs if available
    kubectl --kubeconfig="$KUBECTL_CONFIG" logs -n "$NAMESPACE" -l app.kubernetes.io/name=postgres --since=24h > "$temp_dir/postgres.log" 2>/dev/null || true
    
    # Get events
    kubectl --kubeconfig="$KUBECTL_CONFIG" get events -n "$NAMESPACE" --sort-by='.lastTimestamp' > "$temp_dir/k8s-events.log" 2>/dev/null || true
    
    # Create archive
    tar -czf "$logs_archive" -C "$temp_dir" . 2>/dev/null
    
    # Cleanup
    rm -rf "$temp_dir"
    
    local file_size=$(du -h "$logs_archive" | cut -f1)
    log_success "Application logs backup completed: $logs_archive ($file_size)"
    
    echo "$logs_archive"
}

# Certificates backup functions
backup_certificates() {
    log "Starting certificates backup..."
    
    local certs_dir="$BACKUP_BASE_DIR/certificates"
    local certs_archive="$certs_dir/certificates-${DATE}.tar.gz"
    
    # Create temporary directory for certificates
    local temp_dir=$(mktemp -d)
    
    # Backup TLS secrets
    kubectl --kubeconfig="$KUBECTL_CONFIG" get secrets -n "$NAMESPACE" -o yaml | \
        grep -A 20 "type: kubernetes.io/tls" > "$temp_dir/tls-secrets.yaml" 2>/dev/null || true
    
    # Backup certificate issuer configurations (if cert-manager is used)
    kubectl --kubeconfig="$KUBECTL_CONFIG" get clusterissuers -o yaml > "$temp_dir/clusterissuers.yaml" 2>/dev/null || true
    kubectl --kubeconfig="$KUBECTL_CONFIG" get issuers -n "$NAMESPACE" -o yaml > "$temp_dir/issuers.yaml" 2>/dev/null || true
    kubectl --kubeconfig="$KUBECTL_CONFIG" get certificates -n "$NAMESPACE" -o yaml > "$temp_dir/certificates.yaml" 2>/dev/null || true
    
    # Create archive
    tar -czf "$certs_archive" -C "$temp_dir" . 2>/dev/null
    
    # Cleanup
    rm -rf "$temp_dir"
    
    local file_size=$(du -h "$certs_archive" | cut -f1)
    log_success "Certificates backup completed: $certs_archive ($file_size)"
    
    echo "$certs_archive"
}

# Monitoring backup functions
backup_monitoring_configuration() {
    log "Starting monitoring configuration backup..."
    
    local monitoring_dir="$BACKUP_BASE_DIR/monitoring"
    local monitoring_archive="$monitoring_dir/monitoring-config-${DATE}.tar.gz"
    
    # Create temporary directory for monitoring config
    local temp_dir=$(mktemp -d)
    
    # Backup Prometheus configuration
    kubectl --kubeconfig="$KUBECTL_CONFIG" get configmaps -n monitoring -o yaml > "$temp_dir/prometheus-config.yaml" 2>/dev/null || true
    
    # Backup Grafana dashboards
    kubectl --kubeconfig="$KUBECTL_CONFIG" get configmaps -n monitoring -l grafana_dashboard=1 -o yaml > "$temp_dir/grafana-dashboards.yaml" 2>/dev/null || true
    
    # Backup AlertManager configuration
    kubectl --kubeconfig="$KUBECTL_CONFIG" get secrets -n monitoring alertmanager-main -o yaml > "$temp_dir/alertmanager-config.yaml" 2>/dev/null || true
    
    # Backup ServiceMonitors
    kubectl --kubeconfig="$KUBECTL_CONFIG" get servicemonitors -n monitoring -o yaml > "$temp_dir/servicemonitors.yaml" 2>/dev/null || true
    
    # Backup PrometheusRules
    kubectl --kubeconfig="$KUBECTL_CONFIG" get prometheusrules -n monitoring -o yaml > "$temp_dir/prometheusrules.yaml" 2>/dev/null || true
    
    # Create archive
    tar -czf "$monitoring_archive" -C "$temp_dir" . 2>/dev/null
    
    # Cleanup
    rm -rf "$temp_dir"
    
    local file_size=$(du -h "$monitoring_archive" | cut -f1)
    log_success "Monitoring configuration backup completed: $monitoring_archive ($file_size)"
    
    echo "$monitoring_archive"
}

# Upload to S3
upload_to_s3() {
    local file_path="$1"
    local s3_key="$2"
    
    log "Uploading $file_path to S3..."
    
    if aws s3 cp "$file_path" "s3://$S3_BACKUP_BUCKET/$S3_BACKUP_PREFIX/$s3_key" \
        --storage-class STANDARD_IA \
        --server-side-encryption AES256; then
        
        log_success "Successfully uploaded to S3: s3://$S3_BACKUP_BUCKET/$S3_BACKUP_PREFIX/$s3_key"
        
        # Verify upload
        local s3_size=$(aws s3 ls "s3://$S3_BACKUP_BUCKET/$S3_BACKUP_PREFIX/$s3_key" | awk '{print $3}')
        local local_size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path")
        
        if [[ "$s3_size" == "$local_size" ]]; then
            log_success "Upload verification successful"
            return 0
        else
            log_error "Upload verification failed: size mismatch"
            return 1
        fi
    else
        log_error "Failed to upload $file_path to S3"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log "Cleaning up old local backups..."
    
    # Remove local backups older than retention period
    find "$BACKUP_BASE_DIR" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    
    log "Cleaning up old S3 backups..."
    
    # Remove S3 backups older than retention period
    local cutoff_date=$(date -d "$RETENTION_DAYS days ago" +%Y-%m-%d)
    
    aws s3 ls "s3://$S3_BACKUP_BUCKET/$S3_BACKUP_PREFIX/" --recursive | \
        awk '$1 < "'$cutoff_date'" {print $4}' | \
        while read -r key; do
            if [[ -n "$key" ]]; then
                aws s3 rm "s3://$S3_BACKUP_BUCKET/$key"
                log "Removed old backup: $key"
            fi
        done
}

# Generate backup report
generate_backup_report() {
    local backup_files=("$@")
    
    local report_file="$BACKUP_BASE_DIR/backup-report-${DATE}.txt"
    
    cat > "$report_file" << EOF
Kong Guard AI Backup Report
===========================

Date: $(date)
Environment: $S3_BACKUP_PREFIX
Retention Period: $RETENTION_DAYS days
Compression Level: $COMPRESSION_LEVEL

Backup Files:
EOF
    
    local total_size=0
    for file in "${backup_files[@]}"; do
        if [[ -f "$file" ]]; then
            local size=$(du -b "$file" | cut -f1)
            local human_size=$(du -h "$file" | cut -f1)
            echo "  - $(basename "$file"): $human_size" >> "$report_file"
            total_size=$((total_size + size))
        fi
    done
    
    local total_human_size=$(numfmt --to=iec "$total_size")
    echo "" >> "$report_file"
    echo "Total backup size: $total_human_size" >> "$report_file"
    echo "" >> "$report_file"
    echo "S3 Location: s3://$S3_BACKUP_BUCKET/$S3_BACKUP_PREFIX/" >> "$report_file"
    
    log_success "Backup report generated: $report_file"
    
    # Upload report to S3
    upload_to_s3 "$report_file" "reports/backup-report-${DATE}.txt"
    
    echo "$report_file"
}

# Main backup function
main() {
    log "Starting Kong Guard AI backup process..."
    
    # Initialize
    if ! check_dependencies; then
        send_slack_notification "Backup failed: Missing dependencies" "error"
        exit 1
    fi
    
    create_backup_directories
    
    # Array to store backup file paths
    local backup_files=()
    
    # Perform backups
    local db_backup
    if db_backup=$(backup_database); then
        backup_files+=("$db_backup")
        upload_to_s3 "$db_backup" "database/$(basename "$db_backup")"
    else
        send_slack_notification "Database backup failed" "error"
        exit 1
    fi
    
    local k8s_config_backup
    if k8s_config_backup=$(backup_kubernetes_configuration); then
        backup_files+=("$k8s_config_backup")
        upload_to_s3 "$k8s_config_backup" "configuration/$(basename "$k8s_config_backup")"
    fi
    
    local kong_config_backup
    if kong_config_backup=$(backup_kong_configuration); then
        backup_files+=("$kong_config_backup")
        upload_to_s3 "$kong_config_backup" "configuration/$(basename "$kong_config_backup")"
    fi
    
    local logs_backup
    if logs_backup=$(backup_application_logs); then
        backup_files+=("$logs_backup")
        upload_to_s3 "$logs_backup" "logs/$(basename "$logs_backup")"
    fi
    
    local certs_backup
    if certs_backup=$(backup_certificates); then
        backup_files+=("$certs_backup")
        upload_to_s3 "$certs_backup" "certificates/$(basename "$certs_backup")"
    fi
    
    local monitoring_backup
    if monitoring_backup=$(backup_monitoring_configuration); then
        backup_files+=("$monitoring_backup")
        upload_to_s3 "$monitoring_backup" "monitoring/$(basename "$monitoring_backup")"
    fi
    
    # Generate report
    local report_file
    report_file=$(generate_backup_report "${backup_files[@]}")
    
    # Cleanup old backups
    cleanup_old_backups
    
    # Send success notification
    local total_files=${#backup_files[@]}
    send_slack_notification "Backup completed successfully: $total_files files backed up" "success"
    send_email_notification "Kong Guard AI Backup Successful" "$(cat "$report_file")"
    
    log_success "Kong Guard AI backup process completed successfully"
}

# Error handling
trap 'log_error "Backup process failed with exit code $?"; send_slack_notification "Backup process failed unexpectedly" "error"; exit 1' ERR

# Run main function
main "$@"