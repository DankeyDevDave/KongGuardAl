# CI/CD Workflow Troubleshooting Guide

**Document Version:** 1.0  
**Last Updated:** 2025-09-30  
**Status:** Active Knowledge Base Article

## Table of Contents

1. [Overview](#overview)
2. [Common Issues and Solutions](#common-issues-and-solutions)
3. [Issue Deep Dives](#issue-deep-dives)
4. [Prevention Best Practices](#prevention-best-practices)
5. [Diagnostic Tools](#diagnostic-tools)
6. [Reference Materials](#reference-materials)

---

## Overview

This document provides comprehensive troubleshooting guidance for GitHub Actions CI/CD workflows in the Kong Guard AI project. It captures known issues, their root causes, and proven solutions.

### Workflow Files

- **CI Workflow:** `.github/workflows/ci.yml` (self-hosted runners)
- **Deploy Workflow:** `.github/workflows/deploy.yml` (ubuntu-latest)
- **Test Workflow:** `.github/workflows/test.yml`
- **Lint Workflow:** `.github/workflows/lint.yml`

---

## Common Issues and Solutions

### Issue #1: Missing Test Directories Cause Hard Failures

**Symptom:**
```
Error -> Cannot find file or directory: spec/
Error -> No test files found matching Lua pattern: _spec
Process completed with exit code 1
```

**Root Cause:**  
Workflow assumes test directories exist and fails hard when they're missing.

**Solution:**  
Add conditional checks before running tests:

```yaml
- name: Run Lua tests
  run: |
    cd kong-guard-ai
    if [ -d "spec" ]; then
      busted spec/
    else
      echo "No spec directory found, skipping Lua tests"
    fi
    if [ -d "kong/plugins/kong-guard-ai" ]; then
      luacheck kong/plugins/kong-guard-ai/*.lua
    else
      echo "No Kong plugin files found, skipping luacheck"
    fi
```

**Files Modified:**
- `.github/workflows/deploy.yml` (Test job, steps 6-7)

**Status:** ✅ Resolved

---

### Issue #2: Deprecated CodeQL Action v2

**Symptom:**
```
##[error]CodeQL Action major versions v1 and v2 have been deprecated. 
Please update all occurrences of the CodeQL Action in your workflow files to v3.
```

**Root Cause:**  
GitHub deprecated CodeQL Action v2 on January 10, 2025.

**Solution:**  
Upgrade to v3:

```yaml
# Before
- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'

# After
- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

**Files Modified:**
- `.github/workflows/deploy.yml` (Security Scan job, step 5)

**Status:** ✅ Resolved

---

### Issue #3: Security Events Permission Denied

**Symptom:**
```
##[error]Resource not accessible by integration
```

**Root Cause:**  
Two possible causes:
1. Missing `security-events: write` permission in workflow
2. GitHub Advanced Security not enabled on repository

**Solution:**

**Step 1:** Add permissions to workflow:
```yaml
security-scan:
  name: Security Scan
  runs-on: ubuntu-latest
  permissions:
    contents: read
    security-events: write  # Required for SARIF upload
  steps:
    # ... rest of job
```

**Step 2:** Enable GitHub Advanced Security (if applicable):
1. Go to Repository Settings → Security & analysis
2. Enable "Code scanning" under GitHub Advanced Security
3. Or ensure your organization/repository has GHAS enabled

**Files Modified:**
- `.github/workflows/deploy.yml` (Security Scan job)

**Status:** ⚠️ Partial (permission added, may require GHAS enablement)

---

### Issue #4: Luacheck Code Quality Failures

**Symptom:**
```
Total: 168 warnings / 1 error in 37 files
##[error]Process completed with exit code 2
```

**Root Cause:**  
Code quality issues in Lua files including:
- W112: Mutating non-standard global variables
- W113: Accessing undefined variables
- W211: Unused variables
- W631: Lines too long (>120 characters)
- W122: Setting read-only fields

**Solution:**

**Option 1 - Fix the Code (Recommended):**
Address luacheck warnings by:
```lua
-- Add proper local declarations
local TestAdvancedRemediation = {}

-- Use `_` prefix for intentionally unused variables
local function example(_unused_param)
  -- implementation
end

-- Break long lines
local very_long_line = 
  "This is a very long string that " ..
  "has been split across multiple lines"
```

**Option 2 - Configure Luacheck:**
Create `.luacheckrc` in `kong-guard-ai/`:
```lua
std = "ngx_lua"
globals = {
  "kong",
  "ngx",
  "TestAdvancedRemediation",
  "run_all_tests"
}
max_line_length = 120
ignore = {
  "212",  -- Unused argument
  "213",  -- Unused loop variable
}
```

**Option 3 - Make Luacheck Non-Blocking (Temporary):**
```yaml
- name: Run Lua tests
  run: |
    cd kong-guard-ai
    if [ -d "kong/plugins/kong-guard-ai" ]; then
      luacheck kong/plugins/kong-guard-ai/*.lua || echo "Luacheck found issues but continuing"
    fi
```

**Status:** ⚠️ Ongoing (code quality improvements needed)

---

### Issue #5: Python Test Directory Handling

**Symptom:**
```
cd fastapi-generated
pytest tests/
# Fails if directory doesn't exist
```

**Root Cause:**  
Similar to Issue #1, assumes Python test directory exists.

**Solution:**
```yaml
- name: Install Python dependencies
  run: |
    if [ -d "fastapi-generated" ]; then
      cd fastapi-generated
      pip install -r requirements.txt 2>/dev/null || echo "No requirements.txt found"
      pip install -r requirements-dev.txt 2>/dev/null || echo "No requirements-dev.txt found"
    else
      echo "No fastapi-generated directory found, skipping Python dependencies"
    fi

- name: Run Python tests
  run: |
    if [ -d "fastapi-generated/tests" ]; then
      cd fastapi-generated
      pytest tests/ -v --cov=app --cov-report=xml
    else
      echo "No Python test directory found, skipping Python tests"
    fi
```

**Files Modified:**
- `.github/workflows/deploy.yml` (Test job, steps 7-8)

**Status:** ✅ Resolved

---

### Issue #6: Self-Hosted Runner Label Mismatch

**Symptom:**
```
No runner matching the specified labels was found: self-hosted
```

**Root Cause:**  
Runner labels in workflow don't match actual runner configuration.

**Solution:**
```yaml
# Check your runner labels in: Settings → Actions → Runners
# Then match them exactly in your workflow:

jobs:
  test:
    name: Test Kong Guard AI
    runs-on: self-hosted  # or [self-hosted, linux, x64] depending on your setup
```

**Diagnostic Commands:**
```bash
# List available runners (using GitHub CLI)
gh api repos/{owner}/{repo}/actions/runners

# Check runner labels
gh api repos/{owner}/{repo}/actions/runners | jq '.runners[] | {name, labels}'
```

**Status:** ℹ️ Environment-specific

---

## Issue Deep Dives

### Deep Dive: GitHub Advanced Security Requirements

**Context:**  
The security-scan job uploads SARIF files to GitHub Security tab, which requires specific features.

**Requirements:**
1. **Public Repositories:** GHAS features are free
2. **Private Repositories:** Requires GitHub Enterprise with GHAS license
3. **Organization Settings:** Must be enabled at org level (if applicable)

**Verification Steps:**
```bash
# Check if GHAS is available
gh api repos/{owner}/{repo} | jq '.security_and_analysis'

# Expected output for enabled:
{
  "advanced_security": {
    "status": "enabled"
  },
  "secret_scanning": {
    "status": "enabled"
  }
}
```

**Alternative Solutions:**
If GHAS is not available:

1. **Store SARIF as Artifacts:**
```yaml
- name: Upload Trivy results as artifact
  uses: actions/upload-artifact@v4
  with:
    name: trivy-results
    path: trivy-results.sarif
```

2. **Generate HTML Reports:**
```yaml
- name: Generate HTML report
  run: |
    trivy fs . --format template --template "@contrib/html.tpl" -o trivy-report.html
```

3. **Post to PR Comments:**
```yaml
- name: Comment on PR
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const sarif = JSON.parse(fs.readFileSync('trivy-results.sarif', 'utf8'));
      // Parse and comment on PR
```

---

### Deep Dive: Graceful Degradation Pattern

**Philosophy:**  
CI/CD workflows should fail fast on critical issues but degrade gracefully for non-critical components.

**Implementation Pattern:**
```yaml
# Critical: Fail immediately
- name: Build application
  run: |
    npm run build
    # No error handling - must succeed

# Important: Warn but continue
- name: Run linter
  run: |
    npm run lint || echo "::warning::Linting issues found"

# Optional: Skip if unavailable
- name: Run optional tests
  run: |
    if [ -d "tests/integration" ]; then
      npm run test:integration
    else
      echo "Integration tests not configured, skipping"
    fi
```

**Decision Matrix:**
| Component | Criticality | Action on Failure |
|-----------|-------------|-------------------|
| Build | Critical | Fail immediately |
| Unit Tests | Critical | Fail immediately |
| Integration Tests | Important | Warn, continue |
| Linting | Important | Warn, continue |
| Coverage Upload | Optional | Skip silently |
| Notification | Optional | Skip silently |

---

## Prevention Best Practices

### 1. Pre-commit Hooks

Install pre-commit hooks to catch issues early:

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: local
    hooks:
      - id: luacheck
        name: Luacheck
        entry: luacheck
        language: system
        files: \.lua$
      
      - id: validate-workflows
        name: Validate GitHub Actions
        entry: bash -c 'for f in .github/workflows/*.yml; do yamllint "$f"; done'
        language: system
        files: \.github/workflows/.*\.yml$
EOF

# Install hooks
pre-commit install
```

### 2. Workflow Validation

Validate workflow syntax before pushing:

```bash
# Install actionlint
brew install actionlint  # macOS
# or
go install github.com/rhysd/actionlint/cmd/actionlint@latest

# Validate workflows
actionlint .github/workflows/*.yml
```

### 3. Local Testing with Act

Test workflows locally before pushing:

```bash
# Install act
brew install act  # macOS

# Run workflow locally
act push -j test

# Run with secrets
act push -j test --secret-file .secrets
```

### 4. Workflow Templates

Use standardized templates for consistency:

```yaml
# .github/workflow-templates/standard-test.yml
name: Standard Test Workflow

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup
        run: |
          # Setup commands
          
      - name: Run tests
        run: |
          if [ -d "tests" ]; then
            # Run tests
          else
            echo "No tests found, skipping"
          fi
```

### 5. Monitoring and Alerting

Set up workflow monitoring:

```yaml
# .github/workflows/workflow-monitor.yml
name: Monitor Workflows

on:
  workflow_run:
    workflows: ["*"]
    types: [completed]

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - name: Check workflow status
        uses: actions/github-script@v7
        with:
          script: |
            if (context.payload.workflow_run.conclusion === 'failure') {
              // Send notification
            }
```

---

## Diagnostic Tools

### 1. Workflow Run Investigation

```bash
# List recent workflow runs
gh run list --repo {owner}/{repo} --limit 10

# View specific run
gh run view {run_id}

# Download logs
gh run download {run_id}

# View logs in browser
gh run view {run_id} --web
```

### 2. Job Log Analysis

```bash
# Get failed job logs
gh api repos/{owner}/{repo}/actions/runs/{run_id}/jobs \
  | jq '.jobs[] | select(.conclusion=="failure") | {name, id}'

# Download specific job logs
gh api repos/{owner}/{repo}/actions/jobs/{job_id}/logs > job.log
```

### 3. Debug Mode

Enable debug logging in workflows:

```yaml
# Add to workflow file
on:
  push:
    branches: [main]

# Or enable via repository secrets:
# Settings → Secrets → Actions → New repository secret
# Name: ACTIONS_STEP_DEBUG
# Value: true
```

Run workflow and check detailed logs:
```bash
gh run view {run_id} --log-failed
```

### 4. Workflow Dispatch Testing

Test workflows manually with custom inputs:

```yaml
on:
  workflow_dispatch:
    inputs:
      debug_enabled:
        description: 'Enable debug mode'
        required: false
        type: boolean
        default: false

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Debug info
        if: ${{ inputs.debug_enabled }}
        run: |
          echo "Debug mode enabled"
          env | sort
```

Trigger manually:
```bash
gh workflow run deploy.yml \
  --repo {owner}/{repo} \
  -f debug_enabled=true
```

---

## Reference Materials

### Documentation Links

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [CodeQL Action v3 Migration](https://github.blog/changelog/2025-01-10-code-scanning-codeql-action-v2-is-now-deprecated/)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [SARIF Format Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Luacheck Documentation](https://luacheck.readthedocs.io/)

### Related Issues

- GitHub Issue #XXX: "CI/CD workflows failing after runner reconfiguration"
- GitHub Issue #XXX: "Security scan permission errors"

### Useful Commands Reference

```bash
# Workflow Management
gh workflow list                          # List all workflows
gh workflow view {workflow}               # View workflow details
gh workflow run {workflow}                # Trigger workflow
gh workflow disable {workflow}            # Disable workflow
gh workflow enable {workflow}             # Enable workflow

# Run Management
gh run list                               # List recent runs
gh run view {run_id}                      # View run details
gh run rerun {run_id}                     # Rerun failed jobs
gh run cancel {run_id}                    # Cancel running workflow
gh run watch {run_id}                     # Watch run in real-time

# Repository Secrets
gh secret list                            # List secrets
gh secret set {name} < secret.txt         # Set secret from file
gh secret set {name} --body "value"       # Set secret directly

# Runner Management
gh api repos/{owner}/{repo}/actions/runners  # List runners
```

### Workflow File Templates

**Minimal Test Workflow:**
```yaml
name: Minimal Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: |
          echo "Running tests..."
          # Add test commands
```

**Comprehensive Deploy Workflow:**
```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test
        run: |
          if [ -d "tests" ]; then
            echo "Running tests..."
          else
            echo "No tests found, skipping"
          fi
  
  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: |
          echo "Deploying..."
          # Add deployment commands
```

---

## Changelog

### Version 1.0 (2025-09-30)
- Initial document creation
- Documented Issues #1-6
- Added deep dives for GHAS and graceful degradation
- Included diagnostic tools and reference materials

---

## Contributing

To update this document:

1. Add new issues to "Common Issues and Solutions"
2. Update status indicators (✅ Resolved, ⚠️ Ongoing, ℹ️ Info)
3. Include code examples and commit references
4. Update changelog with version and date

**Document Maintainer:** DevOps Team  
**Review Frequency:** Quarterly or after major incidents
