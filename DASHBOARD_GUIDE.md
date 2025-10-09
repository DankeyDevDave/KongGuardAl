# KongGuardAI Dashboard Guide

## You Have TWO Separate Dashboards! 🎯

### 1️⃣ Next.js Real-Time Dashboard (Your Main Dashboard)

**URL:** http://localhost:3000

**Purpose:** Live attack monitoring and demonstration

**Data Source:** 
- WebSocket connection to AI service
- SQLite database (`attack_metrics.db`)
- Real-time attack simulations

**Updates:** Instantly via WebSocket as attacks happen

**To Populate This Dashboard:**

Run any of these attack simulation scripts:

```bash
# Quick flood attack (generates lots of traffic)
python3 attack_flood_simulator.py

# Enterprise-grade attacks (realistic scenarios)
python3 enterprise_attacks_demo.py

# Industry-specific attack patterns
python3 industry_attack_scenarios.py

# Automated presentation demo
python3 automated_presentation_demo.py
```

**What You'll See:**
- Total threats detected counter
- Detection rate percentage
- Threat distribution pie charts
- Top blocked IPs
- Service status indicators
- Real-time threat analysis
- Tier performance comparison

---

### 2️⃣ Grafana Metrics Dashboard (New - Just Added)

**URL:** http://localhost:33000/d/kong-guard-ai

**Login:** 
- Username: `admin`
- Password: `KongGuard2024!`

**Purpose:** Historical metrics and time-series analysis

**Data Source:**
- Prometheus time-series database
- 30-day retention
- 15-second scrape interval

**Updates:** Every 15 seconds from Prometheus

**To Populate This Dashboard:**

The Grafana dashboard automatically collects metrics from:
1. The `/metrics` endpoint on the AI service
2. Background tasks exporting database metrics
3. Any traffic processed by the AI service

**What You'll See:**
- `kong_guard_ai_up` - Service health status
- `kong_guard_threats_detected_total` - Cumulative threat count
- `kong_guard_threats_by_type` - Threats by category (SQL injection, XSS, etc.)
- `kong_guard_blocked_ips_total` - Number of blocked IPs
- Historical trends and patterns

---

## Quick Start

### For Next.js Dashboard (Port 3000):

```bash
# 1. Make sure services are running
docker ps | grep "kong-guard"

# 2. Open dashboard
open http://localhost:3000

# 3. Run attack simulation
python3 attack_flood_simulator.py

# 4. Watch real-time updates!
```

### For Grafana Dashboard (Port 33000):

```bash
# 1. Open Grafana
open http://localhost:33000

# 2. Login with admin / KongGuard2024!

# 3. Navigate to Kong Guard AI dashboard
# (Should auto-load or go to Dashboards menu)

# 4. Data is already being collected!
# Run attack simulations to see more activity
```

---

## Differences

| Feature | Next.js Dashboard | Grafana Dashboard |
|---------|------------------|-------------------|
| **Port** | 3000 | 33000 |
| **Login** | None | admin/KongGuard2024! |
| **Updates** | Real-time WebSocket | 15-second intervals |
| **Data Source** | Direct DB + WebSocket | Prometheus TSDB |
| **Purpose** | Live demos & monitoring | Historical analysis |
| **Retention** | SQLite database | 30 days |
| **Best For** | Presentations, demos | Trend analysis, ops |

---

## Troubleshooting

### Next.js Dashboard Not Updating?

1. **Check if services are running:**
   ```bash
   docker ps | grep kong-guard-dashboard
   docker ps | grep kong-guard-ai-websocket
   ```

2. **Run an attack simulation:**
   ```bash
   python3 attack_flood_simulator.py
   ```

3. **Check WebSocket connection:**
   - Open browser console (F12)
   - Look for WebSocket errors
   - Should see connection to `ws://192.168.0.228:28100/ws`

4. **Verify database has data:**
   ```bash
   sqlite3 attack_metrics.db "SELECT COUNT(*) FROM attack_metrics"
   ```

### Grafana Dashboard Not Showing Data?

1. **Check Prometheus is scraping:**
   ```bash
   curl -s http://localhost:39090/api/v1/targets | grep kong-guard
   ```

2. **Verify metrics endpoint:**
   ```bash
   curl http://localhost:28100/metrics | grep kong_guard
   ```

3. **Check datasource connection:**
   ```bash
   curl -s http://localhost:33000/api/datasources/1 \
     -u 'admin:KongGuard2024!' | python3 -m json.tool
   ```

4. **Query Prometheus directly:**
   ```bash
   curl -s 'http://localhost:39090/api/v1/query?query=kong_guard_ai_up'
   ```

---

## Which Dashboard Should I Use?

### Use Next.js Dashboard (Port 3000) when:
- Giving presentations or demos
- Showing real-time threat detection
- Running attack simulations
- Need immediate visual feedback
- Want to impress stakeholders 😎

### Use Grafana Dashboard (Port 33000) when:
- Analyzing historical patterns
- Creating operational reports
- Setting up alerts and monitoring
- Need time-series analysis
- Building SRE/DevOps workflows
- Want industry-standard tooling

---

## Summary

✅ **Next.JS Dashboard** (port 3000) - Your existing real-time demo dashboard  
✅ **Grafana Dashboard** (port 33000) - New metrics visualization system  
✅ **Both are operational and serve different purposes!**  
✅ **Run attack simulations to populate both dashboards**  

Both dashboards complement each other:
- Next.js for real-time demos
- Grafana for historical analysis

🚀 **Ready to use!**
