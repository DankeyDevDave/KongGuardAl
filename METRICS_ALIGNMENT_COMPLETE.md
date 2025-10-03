# Grafana and KongGuard Dashboard Metrics Alignment - COMPLETE ✅

## Summary

Successfully aligned Grafana dashboard metrics with KongGuard dashboard by bridging the SQLite database to Prometheus. Both dashboards now show **2,337 total attacks** from the historical database.

## Problem Solved

**Before:**
- **Grafana Dashboard:** Showed 3 threats (runtime counters that reset on service restart)
- **KongGuard Dashboard:** Showed 2,337 attacks (from SQLite database)
- **Root Cause:** Different data sources - Prometheus tracked only new threats since restart, while dashboard read from persistent database

**After:**
- **Both Dashboards:** Show 2,337 total attacks
- **Data Source:** Unified metrics from SQLite database exported to Prometheus
- **Updates:** Real-time (30-second scrape interval)

## Changes Implemented

### 1. Database Mount (docker-compose.consolidated.yml)
```yaml
ai-service-cloud:
  volumes:
    - ./ai-service:/app
    - ./logs/cloud-ai:/app/logs
    - ./attack_metrics.db:/app/attack_metrics.db:ro  # ← Added read-only database mount
```

### 2. Metrics Exporter Path Resolution (ai-service/metrics_exporter.py)
Updated to search multiple locations for the database:
- `/app/attack_metrics.db` (Docker mount)
- `./attack_metrics.db` (Same directory)
- `../attack_metrics.db` (Parent directory)

### 3. Removed Duplicate /metrics Endpoint (ai-service/app.py)
- Removed conflicting route handler
- Now using `make_asgi_app()` mount exclusively
- All Prometheus metrics automatically collected

### 4. Fixed Prometheus Scrape Path (config/prometheus/prometheus-config.yml)
```yaml
scrape_configs:
  - job_name: 'kong-guard-ai-cloud'
    metrics_path: '/metrics/'  # ← Added trailing slash
    scrape_interval: 30s
```

### 5. Updated Grafana Dashboard Queries (grafana-local/dashboards/kong-guard-ai-dashboard.json)
Replaced runtime metrics with database metrics:
- `kong_guard_threats_detected_total` → `kong_guard_db_total_attacks`
- `kong_guard_threats_by_type` → `kong_guard_db_attacks_by_category`
- `kong_guard_blocked_ips` → `kong_guard_db_blocked_total`
- `kong_guard_false_positives_total` → `kong_guard_db_allowed_total`

## Metrics Exported

The AI service now exports these database metrics to Prometheus:

| Metric Name | Description | Current Value |
|-------------|-------------|---------------|
| `kong_guard_db_total_attacks` | Total attacks in database | 2,337 |
| `kong_guard_db_attacks_by_category` | Attacks grouped by category | 48 categories |
| `kong_guard_db_blocked_total` | Total blocked attacks | 52 |
| `kong_guard_db_allowed_total` | Total allowed attacks | 2,285 |
| `kong_guard_db_avg_threat_score` | Average threat score | ~0.75 |
| `kong_guard_db_avg_response_time_ms` | Avg response time | Variable |
| `kong_guard_db_recent_attacks_1h` | Attacks in last hour | Real-time |
| `kong_guard_db_recent_attacks_24h` | Attacks in last 24h | Real-time |
| `kong_guard_db_unique_source_ips` | Unique attacker IPs | Variable |
| `kong_guard_db_attack_runs_total` | Total simulation runs | Variable |

## Verification Commands

### Check Prometheus has database metrics:
```bash
curl 'http://localhost:39090/api/v1/query?query=kong_guard_db_total_attacks' | jq '.data.result[0].value[1]'
# Output: "2337"
```

### Check database count:
```bash
sqlite3 attack_metrics.db "SELECT COUNT(*) FROM attack_metrics"
# Output: 2337
```

### View metrics endpoint directly:
```bash
curl http://localhost:28100/metrics/ | grep kong_guard_db
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   attack_metrics.db                          │
│                    (2,337 attacks)                           │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Mounted read-only
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              AI Service (kong-guard-ai-cloud)                │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  metrics_exporter.py                                 │   │
│  │  - Queries database every 30s                        │   │
│  │  - Updates Prometheus Gauges                         │   │
│  │  - Exports kong_guard_db_* metrics                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                            ↓                                 │
│                  /metrics/ endpoint                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Scraped every 30s
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    Prometheus                                │
│              http://localhost:39090                          │
│          (30-day data retention)                             │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Data source
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     Grafana                                  │
│              http://localhost:33000                          │
│        Displays: 2,337 total attacks                         │
│        Updates: Every 30 seconds                             │
└─────────────────────────────────────────────────────────────┘
```

## Access Information

### Grafana Dashboard
- **URL:** http://localhost:33000
- **Credentials:** admin / admin
- **Dashboard:** "Kong Guard AI - Historical Metrics"

### Prometheus
- **URL:** http://localhost:39090
- **Query Example:** `kong_guard_db_total_attacks`

### KongGuard Dashboard
- **URL:** http://localhost:3000
- **Shows:** Same 2,337 attacks from database

## Background Task

The metrics exporter runs as a background task in the AI service:
```python
async def export_database_metrics():
    """Periodically export metrics from SQLite database"""
    while True:
        try:
            if metrics_exporter:
                result = metrics_exporter.export_metrics()
                logger.debug(f"Exported database metrics: {result.get('total_attacks', 0)} attacks")
        except Exception as e:
            logger.error(f"Error exporting database metrics: {e}")
        
        await asyncio.sleep(30)  # Export every 30 seconds
```

## Benefits

1. **Unified Metrics:** Both dashboards show the same numbers
2. **Historical Data:** Metrics persist across service restarts
3. **Real-time Updates:** 30-second refresh rate
4. **Scalable:** Database can grow without impacting performance
5. **Observability:** Full Prometheus integration for alerting and monitoring

## Testing

All metrics verified:
- ✅ Database mounted in container: `/app/attack_metrics.db`
- ✅ Metrics exporter finds database: 2,337 attacks
- ✅ Prometheus scrapes metrics: `kong_guard_db_total_attacks = 2337`
- ✅ Grafana dashboard updated with database queries
- ✅ Both dashboards show aligned metrics

## Next Steps (Optional)

1. **Add Alerting:** Configure Prometheus alerts for anomaly detection
2. **Dashboard Polish:** Customize panels with attack trend graphs
3. **Rate Analysis:** Add attack rate per minute panels
4. **Category Breakdown:** Enhanced visualizations by attack category
5. **Historical Trends:** Time-series graphs showing attack patterns

## Files Modified

- `docker-compose.consolidated.yml` - Added database volume mount
- `ai-service/metrics_exporter.py` - Enhanced path resolution
- `ai-service/app.py` - Removed duplicate metrics endpoint
- `config/prometheus/prometheus-config.yml` - Fixed scrape path
- `grafana-local/dashboards/kong-guard-ai-dashboard.json` - Updated queries

## Maintenance

- **Database Updates:** Automatically reflected in Prometheus within 30 seconds
- **Service Restarts:** Metrics persist, no data loss
- **Scaling:** Can add multiple AI services, each exporting its own metrics

---

**Status:** ✅ COMPLETE  
**Date:** October 1, 2025  
**Metrics Aligned:** Grafana ↔ KongGuard Dashboard  
**Total Attacks Displayed:** 2,337
