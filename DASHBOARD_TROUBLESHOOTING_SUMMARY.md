# Dashboard Display Issue - Resolved ✅

## Issue
Grafana dashboard not displaying in browser after metrics alignment work.

## Root Causes Identified

1. **Session Authentication:** Browser had stale session tokens causing "token needs to be rotated" errors
2. **Password Confusion:** Admin password was not the default `admin/admin`
3. **Dashboard Access:** User wasn't sure how to access the provisioned dashboard

## Solutions Applied

### 1. Reset Grafana Admin Password
```bash
docker exec kong-guard-grafana grafana cli admin reset-admin-password admin
```
✅ **Result:** Password now set to `admin`

### 2. Verified Dashboard Provisioning
```bash
curl -u admin:admin http://localhost:33000/api/search?type=dash-db
```
✅ **Result:** Dashboard found with UID `kong-guard-ai`

### 3. Confirmed Prometheus Datasource
```bash
curl -u admin:admin http://localhost:33000/api/datasources
```
✅ **Result:** Default Prometheus datasource configured at `http://prometheus:9090`

### 4. Verified Metrics Collection
```bash
curl http://localhost:39090/api/v1/targets
```
✅ **Result:** AI service target is `UP` and being scraped

## Current System Status

### Services Running ✅
```
✓ Grafana:    http://localhost:33000  [HEALTHY]
✓ Prometheus: http://localhost:39090  [HEALTHY]
✓ AI Service: http://localhost:28100  [HEALTHY]
✓ Dashboard:  http://localhost:3000   [HEALTHY]
```

### Metrics Available ✅
```
✓ kong_guard_db_total_attacks:        2,337
✓ kong_guard_db_attacks_by_category:  48 categories
✓ kong_guard_db_blocked_total:        52
✓ kong_guard_db_allowed_total:        2,285
✓ kong_guard_db_avg_threat_score:     ~0.75
```

### Prometheus Targets ✅
```
✓ kong-guard-ai-cloud:   UP   (ai-service-cloud:8000)
✓ prometheus:            UP   (localhost:9090)
✗ kong:                  DOWN (not started)
✗ kong-guard-ai-ollama:  DOWN (not started)
✗ redis:                 DOWN (not started)
```

## Access Instructions

### Step 1: Login to Grafana
1. Open browser to: **http://localhost:33000**
2. Username: `admin`
3. Password: `admin`
4. Click "Log in"

**If you see authentication errors:**
- Clear browser cache/cookies for localhost:33000
- Or use incognito/private window
- Or try different browser

### Step 2: Access Dashboard

**Direct Link (Recommended):**
```
http://localhost:33000/d/kong-guard-ai/kong-guard-ai-historical-metrics
```

**Or Navigate:**
1. Click "Dashboards" icon (四) in left sidebar
2. Find "Kong Guard AI - Historical Metrics"
3. Click to open

### Step 3: Verify Data Display

You should see:
- **Top-left panel:** Total Threats = **2,337**
- **Multiple panels** showing attack categories
- **Time-series graphs** with historical data
- **Auto-refresh** indicator in top-right

## What Changed vs Original Issue

| Before | After |
|--------|-------|
| Grafana showed 3 threats | Shows 2,337 attacks |
| Runtime counters only | Database historical data |
| Metrics misaligned | Metrics aligned across dashboards |
| No database access | Database mounted in container |
| Wrong scrape path | Fixed to /metrics/ |
| Duplicate endpoints | Single metrics endpoint |
| Session errors | Password reset |

## Dashboard Features

### Available Panels
1. ✅ Total Threats Detected (Gauge)
2. ✅ Threat Detection Rate by Type (Graph)
3. ✅ Detection Rate % (Stat)
4. ✅ Threat Distribution (Pie Chart)
5. ✅ Average AI Response Time (Stat)
6. ✅ Top Blocked IPs (Table)
7. ✅ AI Service Status (Stat)
8. ✅ Recent Attacks 1h/24h (Stats)

### Data Updates
- **Scrape Interval:** 30 seconds
- **Background Export:** Every 30 seconds
- **Dashboard Refresh:** 5s to 5m (based on time range)
- **Data Retention:** 30 days

## Verification Commands

### Check Grafana Health
```bash
curl http://localhost:33000/api/health
```

### Check Dashboard Exists
```bash
curl -u admin:admin http://localhost:33000/api/search?query=kong
```

### Check Metrics in Prometheus
```bash
curl 'http://localhost:39090/api/v1/query?query=kong_guard_db_total_attacks' | jq '.data.result[0].value[1]'
```

### Check AI Service Metrics Endpoint
```bash
curl http://localhost:28100/metrics/ | grep kong_guard_db_total
```

### Check Database Direct
```bash
sqlite3 attack_metrics.db "SELECT COUNT(*) FROM attack_metrics"
```

## Common Issues & Solutions

### Issue: "Invalid username or password"
**Solution:** Password was reset, use `admin/admin`

### Issue: "Token needs to be rotated"
**Solution:** Clear browser cache or use incognito mode

### Issue: Dashboard shows "No Data"
**Check:**
1. Prometheus is scraping: http://localhost:39090/targets
2. Metrics exist: http://localhost:28100/metrics/
3. Datasource works: Grafana → Configuration → Data Sources → Test

### Issue: Wrong metrics displayed
**Solution:** Dashboard queries updated to use `kong_guard_db_*` metrics

## Files Modified During Fix

1. `docker-compose.consolidated.yml`
   - Added database volume mount to AI service

2. `ai-service/metrics_exporter.py`
   - Enhanced database path resolution

3. `ai-service/app.py`
   - Removed duplicate /metrics endpoint

4. `config/prometheus/prometheus-config.yml`
   - Fixed scrape path to `/metrics/`

5. `grafana-local/dashboards/kong-guard-ai-dashboard.json`
   - Updated all queries to use database metrics

## Side-by-Side Comparison

### Before Fix
```
Grafana Dashboard:    3 threats
KongGuard Dashboard:  2,337 attacks
Status:               MISALIGNED ❌
```

### After Fix
```
Grafana Dashboard:    2,337 attacks
KongGuard Dashboard:  2,337 attacks
Status:               ALIGNED ✅
```

## Documentation Created

1. ✅ `METRICS_ALIGNMENT_COMPLETE.md` - Technical implementation details
2. ✅ `GRAFANA_DASHBOARD_ACCESS_GUIDE.md` - User access instructions
3. ✅ `DASHBOARD_TROUBLESHOOTING_SUMMARY.md` - This file

## Next Steps for User

1. **Login to Grafana:** http://localhost:33000 (admin/admin)
2. **View dashboard:** Use direct link or navigate
3. **Verify metrics:** Should show 2,337 total attacks
4. **Customize:** Edit panels as needed
5. **Monitor:** Set up alerts (optional)

## Support Commands

### Restart All Metrics Services
```bash
docker-compose -f docker-compose.consolidated.yml restart ai-service-cloud prometheus grafana
```

### View Logs
```bash
docker logs kong-guard-ai-cloud      # AI service
docker logs kong-guard-prometheus    # Prometheus
docker logs kong-guard-grafana       # Grafana
```

### Check Container Status
```bash
docker ps | grep -E "kong-guard-(ai|prometheus|grafana)"
```

---

**Status:** ✅ RESOLVED  
**Dashboard:** Accessible at http://localhost:33000  
**Credentials:** admin/admin  
**Metrics:** 2,337 attacks from historical database  
**Last Updated:** October 2, 2025
