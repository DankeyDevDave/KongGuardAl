#!/bin/bash

# Kong Guard AI - Security Issues Fix Script
# This script addresses the critical security issues found in the security audit

set -e

echo "🔒 Kong Guard AI - Security Issues Fix Script"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the project root
if [ ! -f "README.md" ] || [ ! -f "docker-compose.yml" ]; then
    print_error "This script must be run from the Kong Guard AI project root directory"
    exit 1
fi

print_status "Starting security fixes..."

# 1. Create .env file from template if it doesn't exist
if [ ! -f ".env" ]; then
    print_status "Creating .env file from template..."
    cp env_example .env
    print_success "Created .env file - please update with your actual values"
else
    print_warning ".env file already exists - skipping creation"
fi

# 2. Update .gitignore to ensure sensitive files are ignored
print_status "Updating .gitignore..."
cat >> .gitignore << 'EOF'

# Security - Environment files
.env
.env.local
.env.production
.env.staging

# Security - Database files
*.db
*.sqlite
*.sqlite3
attack_metrics.db

# Security - Log files
*.log
logs/
attack_flood.log

# Security - Certificate files
*.pem
*.key
*.crt
*.p12
*.pfx

# Security - Configuration files with secrets
supabase_config.py
config.json
secrets.json

# Security - Backup files
*.bak
*.backup
backup/

# Security - Test results with sensitive data
test-results/
validation-report-*.md

# Security - Temporary files
*.tmp
*.temp
temp/
tmp/

# Security - IDE files that might contain sensitive data
.vscode/settings.json
.idea/workspace.xml
*.swp
*.swo

# Security - OS files
.DS_Store
Thumbs.db

# Security - Package manager files
package-lock.json
yarn.lock
poetry.lock
EOF

print_success "Updated .gitignore with security exclusions"

# 3. Create a security configuration template
print_status "Creating security configuration template..."
mkdir -p config/security

cat > config/security/security-config.template.yml << 'EOF'
# Kong Guard AI Security Configuration Template
# Copy this file to security-config.yml and update with your values

# Database Security
database:
  encryption_enabled: true
  ssl_required: true
  connection_pool_size: 10
  max_connections: 50

# API Security
api:
  rate_limit_enabled: true
  rate_limit_requests: 100
  rate_limit_window: 60
  cors_enabled: true
  allowed_origins:
    - "https://yourdomain.com"
    - "https://api.yourdomain.com"

# Authentication & Authorization
auth:
  jwt_secret: "your_jwt_secret_here"
  jwt_expiry: 3600
  refresh_token_expiry: 86400
  password_min_length: 12
  require_special_chars: true
  require_numbers: true
  require_uppercase: true

# Network Security
network:
  trusted_ips:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  block_suspicious_ips: true
  enable_ddos_protection: true
  max_connections_per_ip: 100

# Logging & Monitoring
logging:
  level: "info"
  sensitive_data_masking: true
  log_retention_days: 90
  audit_log_enabled: true

# SSL/TLS Configuration
ssl:
  enabled: true
  cert_path: "/path/to/your/certificate.crt"
  key_path: "/path/to/your/private.key"
  min_tls_version: "1.2"
  cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384"

# AI Service Security
ai_service:
  api_key_required: true
  request_validation: true
  response_sanitization: true
  max_payload_size: 1048576  # 1MB

# Backup & Recovery
backup:
  enabled: true
  encryption: true
  retention_days: 30
  backup_path: "/secure/backup/location"
EOF

print_success "Created security configuration template"

# 4. Create a security checklist
print_status "Creating security checklist..."
cat > SECURITY_CHECKLIST.md << 'EOF'
# Kong Guard AI Security Checklist

## Pre-Deployment Security Checks

### ✅ Environment Configuration
- [ ] All sensitive data moved to environment variables
- [ ] .env file created and configured
- [ ] .env file added to .gitignore
- [ ] No hardcoded passwords in configuration files
- [ ] No hardcoded API keys in source code

### ✅ Database Security
- [ ] Database passwords are environment variables
- [ ] Database connections use SSL/TLS
- [ ] Database user has minimal required privileges
- [ ] Database backups are encrypted
- [ ] No sensitive data in test databases

### ✅ Network Security
- [ ] All private IP addresses replaced with test IPs
- [ ] Firewall rules configured
- [ ] Rate limiting enabled
- [ ] DDoS protection configured
- [ ] SSL/TLS certificates installed

### ✅ Application Security
- [ ] Input validation enabled
- [ ] Output sanitization enabled
- [ ] CORS properly configured
- [ ] Authentication required for sensitive endpoints
- [ ] Authorization checks implemented

### ✅ Logging & Monitoring
- [ ] Sensitive data masked in logs
- [ ] Audit logging enabled
- [ ] Log retention policy configured
- [ ] Monitoring alerts configured
- [ ] Error handling doesn't expose sensitive data

### ✅ Code Security
- [ ] No hardcoded credentials
- [ ] No hardcoded IP addresses
- [ ] No sensitive data in comments
- [ ] Dependencies updated to latest secure versions
- [ ] Security headers configured

## Post-Deployment Security Checks

### ✅ Runtime Security
- [ ] Application runs with minimal privileges
- [ ] File permissions properly set
- [ ] Network access restricted
- [ ] Health checks implemented
- [ ] Graceful error handling

### ✅ Monitoring & Alerting
- [ ] Security events logged
- [ ] Alerts configured for suspicious activity
- [ ] Performance monitoring active
- [ ] Error rate monitoring active
- [ ] Resource usage monitoring active

## Regular Security Maintenance

### Monthly
- [ ] Update dependencies
- [ ] Review security logs
- [ ] Check for new security advisories
- [ ] Review access logs
- [ ] Update security documentation

### Quarterly
- [ ] Security audit
- [ ] Penetration testing
- [ ] Backup restoration test
- [ ] Incident response drill
- [ ] Security training review

### Annually
- [ ] Full security assessment
- [ ] Compliance review
- [ ] Disaster recovery test
- [ ] Security policy review
- [ ] Risk assessment update
EOF

print_success "Created security checklist"

# 5. Create a security monitoring script
print_status "Creating security monitoring script..."
cat > scripts/security_monitor.sh << 'EOF'
#!/bin/bash

# Kong Guard AI Security Monitor
# Monitors for potential security issues

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔒 Kong Guard AI Security Monitor"
echo "================================="

# Check for .env file
if [ ! -f ".env" ]; then
    print_error ".env file not found - create one from env_example"
    exit 1
fi

# Check for hardcoded passwords
print_status "Checking for hardcoded passwords..."
if grep -r "password.*=.*['\"]kongpass['\"]" . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git; then
    print_warning "Found hardcoded passwords"
else
    print_success "No hardcoded passwords found"
fi

# Check for hardcoded IP addresses
print_status "Checking for hardcoded private IP addresses..."
if grep -r "192\.168\." . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git --exclude-dir=archived-plugins; then
    print_warning "Found hardcoded private IP addresses"
else
    print_success "No hardcoded private IP addresses found"
fi

# Check for API keys in code
print_status "Checking for API keys in source code..."
if grep -r "sk-[a-zA-Z0-9]" . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git; then
    print_error "Found potential API keys in source code"
else
    print_success "No API keys found in source code"
fi

# Check file permissions
print_status "Checking file permissions..."
if [ -f ".env" ] && [ "$(stat -c %a .env 2>/dev/null || stat -f %Lp .env 2>/dev/null)" != "600" ]; then
    print_warning ".env file should have 600 permissions"
    chmod 600 .env
    print_success "Fixed .env file permissions"
fi

# Check for sensitive files in git
print_status "Checking for sensitive files in git..."
if git ls-files | grep -E "\.(key|pem|crt|p12|pfx)$"; then
    print_error "Found sensitive files in git repository"
else
    print_success "No sensitive files found in git repository"
fi

# Check for large files that might contain sensitive data
print_status "Checking for large files..."
find . -type f -size +10M -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./supabase_env/*" | while read file; do
    print_warning "Large file found: $file"
done

print_success "Security monitoring complete"
EOF

chmod +x scripts/security_monitor.sh
print_success "Created security monitoring script"

# 6. Update the main security audit script
print_status "Updating security audit script..."
cat > security_audit.sh << 'EOF'
#!/bin/bash

# Kong Guard AI Security Audit
# Enhanced version with better reporting and fixes

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔒 Kong Guard AI Security Audit"
echo "================================"

# Initialize counters
CRITICAL_ISSUES=0
WARNINGS=0

# Function to increment counters
increment_critical() {
    ((CRITICAL_ISSUES++))
}

increment_warning() {
    ((WARNINGS++))
}

echo ""
echo "Checking for sensitive data..."

# 1. Check for API keys
print_status "1. Checking for API keys..."
if grep -r "sk-[a-zA-Z0-9]" . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git 2>/dev/null; then
    print_error "Found API keys"
    increment_critical
else
    print_success "No API keys found"
fi

# 2. Check for passwords
print_status "2. Checking for passwords..."
if grep -r "password.*=.*['\"]kongpass['\"]" . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git 2>/dev/null; then
    print_error "Found hardcoded passwords"
    increment_critical
else
    print_success "No hardcoded passwords found"
fi

# 3. Check for database credentials
print_status "3. Checking for database credentials..."
if grep -r "postgres://.*:.*@" . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git 2>/dev/null; then
    print_error "Found database connection strings"
    increment_critical
else
    print_success "No database connection strings found"
fi

# 4. Check for private IP addresses
print_status "4. Checking for private IP addresses..."
if grep -r "192\.168\." . --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git --exclude-dir=archived-plugins 2>/dev/null; then
    print_warning "Found private IP addresses (may need sanitization)"
    increment_warning
else
    print_success "No private IP addresses found"
fi

# 5. Check for .env files
print_status "5. Checking for .env files..."
if find . -name ".env" -not -path "./.git/*" 2>/dev/null | grep -q .; then
    print_warning "Found .env files"
    increment_warning
else
    print_success "No .env files found"
fi

# 6. Check for private keys
print_status "6. Checking for private keys..."
if find . -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | grep -v node_modules | grep -v __pycache__ | grep -v supabase_env | grep -v .git; then
    print_error "Found private key files"
    increment_critical
else
    print_success "No private key files found"
fi

# 7. Check for Supabase credentials
print_status "7. Checking for Supabase credentials..."
if find . -name "supabase_config.py" 2>/dev/null | grep -q .; then
    print_error "Found supabase_config.py"
    increment_critical
else
    print_success "No supabase_config.py found"
fi

# 8. Check .gitignore
print_status "8. Checking .gitignore..."
if [ -f ".gitignore" ]; then
    if grep -q "\.env" .gitignore && grep -q "\.key" .gitignore && grep -q "\.pem" .gitignore; then
        print_success ".gitignore exists and covers sensitive files"
    else
        print_warning ".gitignore exists but may not cover all sensitive files"
        increment_warning
    fi
else
    print_error ".gitignore does not exist"
    increment_critical
fi

# 9. Check for copyright notices
print_status "9. Checking for copyright notices..."
if grep -r "Copyright.*Kong Guard AI" . --include="*.py" --include="*.lua" --include="*.js" --include="*.ts" --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=supabase_env --exclude-dir=.git 2>/dev/null | head -5; then
    print_success "Copyright notices found in source files"
else
    print_warning "Copyright notices may be missing from some files"
    increment_warning
fi

# 10. Check for LICENSE file
print_status "10. Checking for LICENSE file..."
if [ -f "LICENSE" ]; then
    print_success "LICENSE file exists"
else
    print_error "LICENSE file does not exist"
    increment_critical
fi

echo ""
echo "================================"
echo "Security Audit Summary"
echo "================================"
echo "Found $CRITICAL_ISSUES critical issues"
echo "Found $WARNINGS warnings"

if [ $CRITICAL_ISSUES -gt 0 ]; then
    echo ""
    print_error "Please fix critical issues before making repository public!"
    exit 1
else
    echo ""
    print_success "No critical security issues found!"
fi

echo ""
echo "Additional manual checks recommended:"
echo "  - Review all configuration files"
echo "  - Check for any personal information"
echo "  - Ensure all test data is sanitized"
echo "  - Verify no internal network details exposed"
echo "  - Run: ./scripts/security_monitor.sh"
EOF

chmod +x security_audit.sh
print_success "Updated security audit script"

# 7. Create a quick fix script for common issues
print_status "Creating quick fix script..."
cat > scripts/quick_security_fix.sh << 'EOF'
#!/bin/bash

# Kong Guard AI Quick Security Fix
# Automatically fixes common security issues

set -e

echo "🔧 Kong Guard AI Quick Security Fix"
echo "==================================="

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp env_example .env
    echo "✅ Created .env file - please update with your values"
fi

# Fix file permissions
echo "Fixing file permissions..."
chmod 600 .env 2>/dev/null || true
chmod 644 *.md 2>/dev/null || true
chmod 644 *.yml 2>/dev/null || true
chmod 644 *.yaml 2>/dev/null || true
echo "✅ Fixed file permissions"

# Remove any accidentally committed sensitive files
echo "Checking for sensitive files in git..."
git rm --cached .env 2>/dev/null || true
git rm --cached *.key 2>/dev/null || true
git rm --cached *.pem 2>/dev/null || true
git rm --cached supabase_config.py 2>/dev/null || true
echo "✅ Removed sensitive files from git tracking"

# Run the sanitization script
echo "Running test data sanitization..."
python scripts/sanitize_test_data.py 2>/dev/null || echo "⚠️  Sanitization script not available"

echo "✅ Quick security fix complete!"
echo "Please review the changes and update your .env file with actual values."
EOF

chmod +x scripts/quick_security_fix.sh
print_success "Created quick fix script"

print_status "Security fixes complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Update .env file with your actual values"
echo "2. Review SECURITY_CHECKLIST.md"
echo "3. Run: ./scripts/security_monitor.sh"
echo "4. Run: ./security_audit.sh"
echo "5. Test your application with the new configuration"
echo ""
echo "🔒 Your Kong Guard AI project is now more secure!"
