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
# More specific API key patterns to avoid false positives
if grep -r -E "(sk-[a-zA-Z0-9]{20,}|pk_[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9]{35})" . \
    --exclude-dir=node_modules \
    --exclude-dir=__pycache__ \
    --exclude-dir=supabase_env \
    --exclude-dir=.git \
    --exclude-dir=.taskmaster \
    --exclude-dir=.claude \
    --exclude-dir=.cursor \
    --exclude="*.md" \
    --exclude="*.txt" \
    --exclude="*.json" \
    --exclude="*.yaml" \
    --exclude="*.yml" 2>/dev/null; then
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
if grep -r "postgres://.*:.*@" . \
    --exclude-dir=node_modules \
    --exclude-dir=__pycache__ \
    --exclude-dir=supabase_env \
    --exclude-dir=.git \
    --exclude-dir=scripts \
    --exclude="*.sh" \
    --exclude="*.md" \
    --exclude="*.txt" \
    --exclude="*.json" \
    --exclude="*.yaml" \
    --exclude="*.yml" 2>/dev/null; then
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
