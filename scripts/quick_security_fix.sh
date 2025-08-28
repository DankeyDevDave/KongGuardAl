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
