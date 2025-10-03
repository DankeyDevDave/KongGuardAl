# CI/CD Quick Reference Guide

Quick access guide for common CI/CD operations and troubleshooting.

## Emergency Response

### Workflow Failures
```bash
# Check status
gh run list --limit 5

# View failed run
gh run view {run_id} --log-failed

# Rerun failed jobs
gh run rerun {run_id} --failed
```

### Cancel Runaway Workflows
```bash
# Cancel specific run
gh run cancel {run_id}

# Cancel all runs for a workflow
gh run list --workflow=deploy.yml | awk '{print $7}' | xargs -I {} gh run cancel {}
```

## Common Fixes

### Fix #1: Missing Test Directories
```yaml
if [ -d "tests" ]; then
  pytest tests/
else
  echo "No tests found, skipping"
fi
```

### Fix #2: Upgrade Deprecated Actions
```yaml
# CodeQL v2 → v3
- uses: github/codeql-action/upload-sarif@v3 # was @v2
```

### Fix #3: Add Security Permissions
```yaml
jobs:
  security-scan:
    permissions:
      contents: read
      security-events: write # Add this
```

## Status Checks

### Check Workflow Health
```bash
# List workflows with status
gh workflow list

# View specific workflow runs
gh run list --workflow=deploy.yml --limit 10

# Check runner availability
gh api repos/{owner}/{repo}/actions/runners | jq '.runners[] | {name, status, labels}'
```

### Monitor Active Runs
```bash
# Watch run in real-time
gh run watch

# Get run status
gh run view {run_id}
```

## Local Testing

### Validate Workflows
```bash
# Install actionlint
brew install actionlint

# Validate all workflows
actionlint .github/workflows/*.yml
```

### Test Locally with Act
```bash
# Install act
brew install act

# Run workflow
act push -j test

# Run with secrets
act push --secret-file .secrets
```

## Quick Commands

### Workflow Management
| Command | Description |
|---------|-------------|
| `gh workflow list` | List all workflows |
| `gh workflow run {workflow}` | Trigger workflow |
| `gh workflow disable {workflow}` | Disable workflow |
| `gh workflow enable {workflow}` | Enable workflow |

### Run Management
| Command | Description |
|---------|-------------|
| `gh run list --limit 10` | Recent runs |
| `gh run view {id}` | View details |
| `gh run rerun {id}` | Rerun workflow |
| `gh run cancel {id}` | Cancel run |
| `gh run watch` | Watch active run |

### Secrets Management
| Command | Description |
|---------|-------------|
| `gh secret list` | List secrets |
| `gh secret set NAME` | Set secret |
| `gh secret remove NAME` | Delete secret |

## Quick Links

- **Full Guide:** [CICD_WORKFLOW_TROUBLESHOOTING.md](./CICD_WORKFLOW_TROUBLESHOOTING.md)
- **GitHub Actions Docs:** https://docs.github.com/en/actions
- **Organization Runners:** Settings → Actions → Runners

## Issue Lookup Table

| Symptom | Issue # | Fix |
|---------|---------|-----|
| "Cannot find directory: spec/" | #1 | Add conditional checks |
| "CodeQL Action v2 deprecated" | #2 | Upgrade to v3 |
| "Resource not accessible" | #3 | Add permissions |
| "168 warnings / 1 error" | #4 | Fix luacheck issues |
| "No runner matching labels" | #6 | Check runner config |

## Common Workflows

### Deploy to Production
```bash
# Trigger deploy workflow
gh workflow run deploy.yml -f environment=production

# Monitor deployment
gh run watch
```

### Run Tests Manually
```bash
# Trigger test workflow
gh workflow run test.yml

# View results
gh run view --log
```

### Check Security Scan
```bash
# View latest security scan
gh run list --workflow=deploy.yml --json conclusion,databaseId,displayTitle | \
  jq '.[] | select(.displayTitle | contains("security"))'
```

## Pro Tips

1. **Enable Debug Mode:**
   ```bash
   # Add repo secret: ACTIONS_STEP_DEBUG = true
   gh secret set ACTIONS_STEP_DEBUG --body "true"
   ```

2. **Download Artifacts:**
   ```bash
   gh run download {run_id}
   ```

3. **Workflow Dispatch with Inputs:**
   ```bash
   gh workflow run deploy.yml \
     -f environment=staging \
     -f version=v1.2.3
   ```

4. **Check Permissions:**
   ```bash
   gh api repos/{owner}/{repo} | jq '.permissions'
   ```

5. **View Workflow YAML:**
   ```bash
   gh workflow view deploy.yml --yaml
   ```

## Escalation

If issues persist after trying these fixes:
1. Check full troubleshooting guide: `docs/CICD_WORKFLOW_TROUBLESHOOTING.md`
2. Review workflow logs: `gh run view {run_id} --log`
3. Check GitHub Status: https://www.githubstatus.com/
4. Contact: DevOps Team

---

**Last Updated:** 2025-09-30  
**Related Docs:** [CICD_WORKFLOW_TROUBLESHOOTING.md](./CICD_WORKFLOW_TROUBLESHOOTING.md)
