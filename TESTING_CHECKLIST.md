# Kong Guard AI - Testing Checklist

**Date**: September 30, 2025  
**Purpose**: Pre-submission testing before video creation  
**Status**: Ready to Execute

---

## 🎯 Testing Priority

### Priority 1: Critical (Must Pass) ✅
- [ ] Core Kong Gateway operational
- [ ] Plugin loads successfully
- [ ] Threat detection working
- [ ] Dashboard accessible
- [ ] Basic attack simulation

### Priority 2: Important (Should Pass) ⚠️
- [ ] ML models loading
- [ ] AI service responding
- [ ] Cache functioning
- [ ] Rate limiting working
- [ ] WebSocket real-time updates

### Priority 3: Nice-to-Have (Can Demo) 📊
- [ ] Advanced visualizations
- [ ] All attack types
- [ ] Performance metrics
- [ ] Full demo workflow

---

## 📋 Test Execution Plan

### Phase 1: Infrastructure Health (5 min)

#### 1.1 Docker Services ✅
```bash
# Check all containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Expected services:
# - kong-gateway (ports 8000, 8001)
# - kong-database (postgres)
# - kong-redis
# - kong-guard-dashboard (port 3000)
# - mock-attacker
```

**Current Status**: 
- ✅ kong-database (healthy)
- ✅ kong-redis (healthy)
- ✅ mock-attacker (healthy)
- ⚠️ kong-guard-dashboard (unhealthy) ← NEEDS FIX
- ✅ Others up

**Action Required**: Fix dashboard health

#### 1.2 Port Availability ✅
```bash
# Test critical ports
curl -I http://localhost:8000  # Kong Gateway
curl -I http://localhost:8001  # Kong Admin
curl -I http://localhost:3000  # Dashboard
```

**Expected**:
- 8000: Kong proxy (should respond)
- 8001: Kong admin (should respond)
- 3000: Dashboard (should respond)

#### 1.3 Database Connectivity ✅
```bash
# Test Redis
redis-cli -h localhost -p 6379 ping

# Test Postgres (if accessible)
docker exec kong-database pg_isready
```

---

### Phase 2: Kong Plugin Testing (10 min)

#### 2.1 Plugin Loaded ✅
```bash
# Check plugin is loaded
curl http://localhost:8001 | jq '.plugins.available_on_server."kong-guard-ai"'

# Should show: true or plugin info
```

#### 2.2 Plugin Configuration ✅
```bash
# List routes
curl http://localhost:8001/routes | jq '.data[] | {name, paths}'

# Check if Kong Guard AI plugin enabled on any routes
curl http://localhost:8001/plugins | jq '.data[] | select(.name == "kong-guard-ai")'
```

#### 2.3 Enable Plugin on Test Route ✅
```bash
# Create test service
curl -X POST http://localhost:8001/services \
  --data "name=test-service" \
  --data "url=http://httpbin.org"

# Create test route
curl -X POST http://localhost:8001/services/test-service/routes \
  --data "name=test-route" \
  --data "paths[]=/test"

# Enable Kong Guard AI plugin
curl -X POST http://localhost:8001/routes/test-route/plugins \
  --data "name=kong-guard-ai" \
  --data "config.enable_ai_analysis=true" \
  --data "config.block_threshold=0.8"
```

---

### Phase 3: Threat Detection Testing (15 min)

#### 3.1 Normal Request (Should Pass) ✅
```bash
# Send normal request
curl -i http://localhost:8000/test/api/users

# Expected:
# - Status: 200 OK
# - Header: X-GuardAI-Score: <low value>
# - Header: X-GuardAI-Action: allow
```

#### 3.2 SQL Injection Attack (Should Block) ✅
```bash
# Send SQL injection
curl -i "http://localhost:8000/test/api/users?id=1' OR '1'='1"

# Expected:
# - Status: 403 Forbidden (or as configured)
# - Header: X-GuardAI-Score: >0.8
# - Header: X-GuardAI-Action: block
# - Header: X-GuardAI-Type: sql_injection
```

#### 3.3 XSS Attack (Should Block) ✅
```bash
# Send XSS attempt
curl -i "http://localhost:8000/test/api/search?q=<script>alert('xss')</script>"

# Expected:
# - Status: 403 Forbidden
# - Header: X-GuardAI-Type: xss
# - High threat score
```

#### 3.4 Command Injection (Should Block) ✅
```bash
# Send command injection
curl -i "http://localhost:8000/test/api/exec?cmd=ls;cat%20/etc/passwd"

# Expected:
# - Status: 403 Forbidden
# - Header: X-GuardAI-Type: command_injection
```

#### 3.5 Check Response Headers ✅
For any blocked request, verify all headers present:
```bash
# Should include:
X-GuardAI-Score: 0.XXX
X-GuardAI-Action: block
X-GuardAI-Type: [attack_type]
X-GuardAI-Severity: high
X-GuardAI-Policy: /test
X-GuardAI-FP-ID: [request_id]
X-GuardAI-FP-URL: [feedback_url]
```

---

### Phase 4: Dashboard Testing (10 min)

#### 4.1 Dashboard Loads ✅
```bash
# Access dashboard
open http://localhost:3000

# Or test with curl
curl -I http://localhost:3000
```

**Expected**:
- Page loads without errors
- Login screen (if auth enabled)
- Main dashboard visible

#### 4.2 Dashboard Shows Data ✅
**Manual Check**:
- [ ] Threat score metrics visible
- [ ] Recent attacks list populated
- [ ] Real-time updates working
- [ ] Graphs/charts rendering
- [ ] No console errors

#### 4.3 WebSocket Connection ✅
**Browser Console Check**:
```javascript
// Should see WebSocket connection
// ws://localhost:8080 or similar
```

---

### Phase 5: Security Features Testing (15 min)

#### 5.1 PII Scrubbing ✅
```bash
# Send request with PII
curl -i "http://localhost:8000/test/api/users?email=test@example.com&phone=555-123-4567"

# Check logs - PII should be scrubbed:
# email: <EMAIL_REDACTED>
# phone: <PHONE_REDACTED>
```

#### 5.2 Rate Limiting ✅
```bash
# Send multiple requests quickly
for i in {1..20}; do
  curl -i "http://localhost:8000/test/api/users"
  sleep 0.1
done

# Should eventually see:
# X-GuardAI-RateLimit: exceeded
# Or 429 status
```

#### 5.3 Cache Performance ✅
```bash
# First request (cache miss)
time curl "http://localhost:8000/test/api/users?id=1' OR '1'='1"

# Second identical request (cache hit)
time curl "http://localhost:8000/test/api/users?id=1' OR '1'='1"

# Expected:
# - Second request much faster
# - Header: X-GuardAI-Cache: hit-signature
```

#### 5.4 Dry-Run Mode ✅
```bash
# Enable dry-run header
curl -i -H "X-GuardAI-DryRun: true" \
  "http://localhost:8000/test/api/users?id=1' OR '1'='1"

# Expected:
# - Status: 200 OK (not blocked)
# - Header: X-GuardAI-DryRun: true
# - Header: X-GuardAI-WouldBlock: true
# - Still analyzed, just not blocked
```

---

### Phase 6: Performance Testing (10 min)

#### 6.1 Latency Test ✅
```bash
# Measure request latency
for i in {1..10}; do
  curl -w "@curl-format.txt" -o /dev/null -s "http://localhost:8000/test/api/users"
done

# Create curl-format.txt:
echo 'time_total: %{time_total}s\n' > curl-format.txt

# Expected: <100ms for cached, <2s for uncached
```

#### 6.2 Load Test (Optional) ✅
```bash
# Simple load test with Apache Bench (if installed)
ab -n 100 -c 10 http://localhost:8000/test/api/users

# Or with curl loop
time for i in {1..100}; do
  curl -s http://localhost:8000/test/api/users > /dev/null
done
```

#### 6.3 Memory Usage ✅
```bash
# Check Docker container memory
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}"

# Expected: Reasonable memory (<2GB per container)
```

---

### Phase 7: Demo Preparation (5 min)

#### 7.1 Demo Scripts Exist ✅
```bash
ls -lh hackathon_demo_recorder.py
ls -lh generate_scene_voice.py
ls -lh demo_narrator.py
ls -lh narrator_timing.json
```

#### 7.2 Test Demo Script ✅
```bash
# Dry run of demo script
python3 hackathon_demo_recorder.py --help

# Should show usage without errors
```

#### 7.3 Dependencies Installed ✅
```bash
# Check Python dependencies
pip3 list | grep -E "playwright|fastapi|httpx|redis"

# Check Playwright browsers
python3 -m playwright --help
```

---

## 🚨 Known Issues & Fixes

### Issue 1: Dashboard Unhealthy ⚠️
**Status**: DETECTED  
**Impact**: Medium - dashboard may not load  
**Fix**:
```bash
# Check dashboard logs
docker logs kong-guard-dashboard

# Restart dashboard
docker restart kong-guard-dashboard

# Or rebuild
cd dashboard
docker-compose up -d --build
```

### Issue 2: Kong Gateway Not Responding
**Symptoms**: Connection refused on port 8000  
**Fix**:
```bash
# Check Kong status
docker ps | grep kong

# Restart Kong
docker restart kong-gateway

# Check migrations
docker exec kong-gateway kong migrations list
```

### Issue 3: Plugin Not Loading
**Symptoms**: Plugin not in available list  
**Fix**:
```bash
# Check plugin path
docker exec kong-gateway ls -la /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/

# Restart Kong after plugin changes
docker restart kong-gateway
```

---

## ✅ Pre-Video Checklist

Before recording video, ensure:

### Infrastructure ✅
- [ ] All Docker containers healthy
- [ ] Kong Gateway responding (8000, 8001)
- [ ] Dashboard loading (3000)
- [ ] No error logs in containers

### Functionality ✅
- [ ] Plugin loaded and enabled
- [ ] Normal requests pass through
- [ ] Attack requests blocked
- [ ] Headers present in responses
- [ ] Dashboard shows real-time data

### Demo Ready ✅
- [ ] Demo scripts tested
- [ ] Attack scenarios prepared
- [ ] Dashboard visualizations working
- [ ] Playwright installed and working
- [ ] Recording environment clean (no popups/notifications)

### Documentation ✅
- [ ] README.md updated
- [ ] LICENSE enhanced with authorship
- [ ] SECURITY.md created
- [ ] All credits show "DankeyDevDave"
- [ ] All dates show "2025"

---

## 🎬 Video Recording Checklist

### Pre-Recording ✅
- [ ] Close unnecessary applications
- [ ] Clear browser history/cache
- [ ] Disable notifications
- [ ] Set up external mic (if available)
- [ ] Good lighting
- [ ] Quiet environment

### Recording Sections ✅
1. **Introduction** (30 sec)
   - Project name and purpose
   - Your name: DankeyDevDave
   - Kong Agentic AI Hackathon 2025

2. **Architecture Overview** (1 min)
   - Show architecture diagram
   - Explain components
   - Highlight AI/ML integration

3. **Live Demo** (3-4 min)
   - Dashboard overview
   - Send normal request (passes)
   - Send SQL injection (blocked)
   - Send XSS attack (blocked)
   - Show real-time dashboard updates
   - Explain threat scoring

4. **Key Features** (1-2 min)
   - Multi-tier caching
   - LLM analysis
   - Response headers
   - Dry-run mode
   - PII scrubbing

5. **Security Hardening** (1 min)
   - Circuit breakers
   - GDPR compliance
   - Operator feedback
   - Policy engine

6. **Conclusion** (30 sec)
   - Summary of value
   - Thank judges
   - Contact: dankeydevdave@gmail.com

**Total**: 7-9 minutes (within limits)

---

## 🛠️ Quick Test Commands

### One-Liner Health Check
```bash
curl -s http://localhost:8001 > /dev/null && echo "✅ Kong Admin OK" || echo "❌ Kong Admin DOWN"
curl -s http://localhost:8000 > /dev/null && echo "✅ Kong Proxy OK" || echo "❌ Kong Proxy DOWN"
curl -s http://localhost:3000 > /dev/null && echo "✅ Dashboard OK" || echo "❌ Dashboard DOWN"
```

### One-Liner Attack Test
```bash
curl -i "http://localhost:8000/test/api/users?id=1' OR '1'='1" | grep -E "X-GuardAI|HTTP/"
```

### One-Liner Demo Start
```bash
docker-compose up -d && sleep 10 && echo "System ready for demo!"
```

---

## 📊 Testing Status Template

Use this to track progress:

```
┌─────────────────────────────────────────┐
│ KONG GUARD AI - TEST STATUS             │
├─────────────────────────────────────────┤
│ Infrastructure:     [ ] Pass  [ ] Fail  │
│ Plugin Loading:     [ ] Pass  [ ] Fail  │
│ Threat Detection:   [ ] Pass  [ ] Fail  │
│ Dashboard:          [ ] Pass  [ ] Fail  │
│ Security Features:  [ ] Pass  [ ] Fail  │
│ Performance:        [ ] Pass  [ ] Fail  │
│ Demo Scripts:       [ ] Pass  [ ] Fail  │
├─────────────────────────────────────────┤
│ Overall Status:     [ ] READY           │
│                     [ ] NEEDS WORK      │
└─────────────────────────────────────────┘

Tested By: DankeyDevDave
Date: September 30, 2025
Ready for Video: [ ] YES  [ ] NO
```

---

## 🚀 Next Steps After Testing

1. **If All Tests Pass**:
   - Proceed to video recording
   - Use demo scripts
   - Record in 1-2 takes

2. **If Tests Fail**:
   - Fix issues first
   - Re-test
   - Document workarounds

3. **After Video**:
   - Final git commit
   - Push to GitHub
   - Submit to hackathon
   - Celebrate! 🎉

---

**Testing begins NOW!** 🧪
