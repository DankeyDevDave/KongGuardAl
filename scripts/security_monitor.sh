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
    --exclude="*.yml"; then
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
