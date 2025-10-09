# Grafana Dashboard Access Guide

## Current Status ✅

- **Grafana is running:** `http://localhost:33000`
- **Dashboard is provisioned:** "Kong Guard AI - Historical Metrics"
- **Prometheus datasource:** Configured and working
- **Metrics available:** 2,337 total attacks from database

## Access Instructions

### 1. Login to Grafana

**URL:** http://localhost:33000

**Credentials:**
- Username: `admin`
- Password: `admin`

**Note:** If you're already logged in but seeing authentication errors, you need to **refresh your browser session**:
1. Clear browser cache/cookies for localhost:33000
2. Or use an incognito/private window
3. Or restart your browser

### 2. Access the Dashboard

After logging in, you have two options:

**Option A: Direct URL**
```
http://localhost:33000/d/kong-guard-ai/kong-guard-ai-historical-metrics
```

**Option B: Navigate through UI**
1. Click on **"Dashboards"** in the left sidebar (or press `g` then `d`)
2. Look for **"Kong Guard AI - Historical Metrics"** in the list
3. Click to open

### 3. Verify Metrics Display

The dashboard should show:
- **Total Threats Detected:** 2,337
- **Attack Categories:** 48 different types
- **Blocked Attacks:** 52
- **Allowed Attacks:** 2,285
- **Real-time updates:** Every 30 seconds

## Troubleshooting

### Problem: "Unauthorized" or "Token needs to be rotated" errors

**Solution:**
1. Log out of Grafana
2. Clear browser cache/cookies
3. Log back in with `admin/admin`
4. Navigate to dashboard

### Problem: Dashboard shows "No Data"

**Verification Steps:**

1. **Check Prometheus is running:**
   ```bash
   curl http://localhost:39090/-/healthy
   # Should return: "Prometheus Server is Healthy."
   ```

2. **Check metrics are available in Prometheus:**
   ```bash
   curl 'http://localhost:39090/api/v1/query?query=kong_guard_db_total_attacks'
   # Should show: "value": [timestamp, "2337"]
   ```

3. **Check AI service metrics endpoint:**
   ```bash
   curl http://localhost:28100/metrics/ | grep kong_guard_db_total_attacks
   # Should show: kong_guard_db_total_attacks 2337.0
   ```

4. **Check Prometheus datasource in Grafana:**
   - Go to: Configuration → Data Sources
   - Click on "Prometheus"
   - Click "Test" button
   - Should show green "Data source is working"

### Problem: Dashboard not in list

**Solution:**
```bash
# Restart Grafana to reload provisioned dashboards
docker-compose -f docker-compose.consolidated.yml restart grafana
```

Then wait 10 seconds and refresh browser.

### Problem: Panels show "Bad Gateway" or query errors

**Check Prometheus URL in datasource:**
1. Go to Configuration → Data Sources → Prometheus
2. Verify URL is: `http://prometheus:9090`
3. Click "Save & Test"

## Dashboard Panels Explained

### Top Row
1. **Total Threats Detected** (Gauge)
   - Shows total attacks from database
   - Query: `kong_guard_db_total_attacks`

2. **Attack Categories** (Table)
   - Breakdown by attack type
   - Query: `kong_guard_db_attacks_by_category`

3. **Blocked vs Allowed** (Pie Chart)
   - Distribution of blocked/allowed
   - Queries: `kong_guard_db_blocked_total`, `kong_guard_db_allowed_total`

### Middle Row
4. **Attack Trend Over Time** (Graph)
   - Recent attack activity
   - Query: `rate(kong_guard_db_attacks_by_category[5m])`

5. **Average Threat Score** (Stat)
   - Mean threat score from ML models
   - Query: `kong_guard_db_avg_threat_score`

### Bottom Row
6. **Recent Attacks (1h)** (Stat)
   - Attacks in last hour
   - Query: `kong_guard_db_recent_attacks_1h`

7. **Recent Attacks (24h)** (Stat)
   - Attacks in last 24 hours
   - Query: `kong_guard_db_recent_attacks_24h`

## Comparing with KongGuard Dashboard

Both dashboards now show aligned metrics:

| Metric | Grafana | KongGuard Dashboard |
|--------|---------|---------------------|
| Total Attacks | 2,337 | 2,337 |
| Data Source | Prometheus ← SQLite | SQLite direct |
| Update Frequency | 30 seconds | Real-time WebSocket |
| Historical Data | ✅ Yes | ✅ Yes |

## API Access (Alternative)

If you prefer API access to metrics:

### Grafana API
```bash
# List all dashboards
curl -u admin:admin http://localhost:33000/api/search?type=dash-db

# Get dashboard JSON
curl -u admin:admin http://localhost:33000/api/dashboards/uid/kong-guard-ai
```

### Prometheus API
```bash
# Query total attacks
curl 'http://localhost:39090/api/v1/query?query=kong_guard_db_total_attacks'

# Query attacks by category
curl 'http://localhost:39090/api/v1/query?query=kong_guard_db_attacks_by_category'

# Query with time range
curl 'http://localhost:39090/api/v1/query_range?query=kong_guard_db_total_attacks&start=2024-01-01T00:00:00Z&end=2024-12-31T23:59:59Z&step=1h'
```

### Direct Metrics Endpoint
```bash
# Raw Prometheus format
curl http://localhost:28100/metrics/ | grep kong_guard_db
```

## Service URLs Summary

| Service | URL | Purpose |
|---------|-----|---------|
| Grafana | http://localhost:33000 | Visualization dashboard |
| Prometheus | http://localhost:39090 | Metrics database |
| KongGuard Dashboard | http://localhost:3000 | Primary UI |
| AI Service Metrics | http://localhost:28100/metrics/ | Raw metrics endpoint |
| AI Service Health | http://localhost:28100/health | Health check |

## Refresh Time Settings

The dashboard auto-refreshes based on the time range:
- **Last 5 minutes:** Refresh every 5s
- **Last 15 minutes:** Refresh every 10s
- **Last 1 hour:** Refresh every 30s
- **Last 6 hours:** Refresh every 1m
- **Last 24 hours:** Refresh every 5m

You can change this in the top-right dropdown.

## Custom Query Examples

In Grafana, you can create custom queries:

### Attack Rate Per Minute
```promql
rate(kong_guard_db_total_attacks[1m]) * 60
```

### Top 5 Attack Categories
```promql
topk(5, kong_guard_db_attacks_by_category)
```

### Blocked Percentage
```promql
(kong_guard_db_blocked_total / kong_guard_db_total_attacks) * 100
```

### Attacks in Last Hour vs Day
```promql
kong_guard_db_recent_attacks_1h / kong_guard_db_recent_attacks_24h
```

## Next Steps

1. **Login to Grafana** at http://localhost:33000 (admin/admin)
2. **Navigate to dashboard** or use direct link
3. **Verify metrics** show 2,337 total attacks
4. **Customize panels** as needed (edit button on each panel)
5. **Set alerts** (optional) for anomaly detection

## Need Help?

If dashboard still not displaying:
1. Check all services are running: `docker ps | grep kong-guard`
2. Check Grafana logs: `docker logs kong-guard-grafana`
3. Check Prometheus targets: http://localhost:39090/targets
4. Verify metrics in Prometheus: http://localhost:39090/graph

---

**Status:** ✅ Dashboard provisioned and accessible  
**Metrics:** ✅ 2,337 attacks from database  
**Datasource:** ✅ Prometheus configured  
**Authentication:** ✅ Password reset to admin/admin
