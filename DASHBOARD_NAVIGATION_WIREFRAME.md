# 📊 Kong Guard AI - Dashboard Navigation & Wireframe

## 🗺️ Dashboard Ecosystem Overview

Kong Guard AI has **multiple dashboard implementations** for different purposes and environments.

---

## 📁 Dashboard File Structure

```
KongGuardAI/
├── visualization/                    [PRIMARY DASHBOARDS]
│   ├── index.html                   ⭐ Main React Dashboard (407 lines)
│   ├── fixed-dashboard.html         🔧 Stable Version
│   ├── simple-ai-dashboard.html     📊 Simplified View
│   └── ai-insights.html             🧠 AI Analysis Focus
│
├── public/dashboards/               [PUBLIC FACING]
│   ├── kong-dashboard.html          🎯 Testing Dashboard (641 lines)
│   ├── unified_dashboard.html       🔄 Unified View
│   ├── enterprise_demo_dashboard.html    💼 Enterprise Demo
│   ├── enterprise_attack_dashboard.html  ⚠️ Attack Visualization
│   └── enterprise_attack_dashboard_with_protection.html
│
├── dashboards/                      [LEGACY/ARCHIVED]
│   ├── index.html                   📜 Original Dashboard
│   ├── enterprise_demo_dashboard.html
│   ├── kong-dashboard.html
│   └── test-dashboard.html
│
├── shadcn-dashboard/                [MODERN UI]
│   └── (Next.js/React shadcn/ui implementation)
│
├── kong-guard-ai/branding/         [BRANDED VERSION]
│   └── dashboard.html
│
├── testing-ui/                      [TEST INTERFACE]
│   └── index.html
│
└── kong-local-testing/              [LOCAL DEV]
    └── dashboard.html
```

---

## 🎯 Primary Dashboards

### 1️⃣ Main React Dashboard (Primary)
**File**: `visualization/index.html`  
**Lines**: 407  
**Technology**: React 18 + Chart.js + TailwindCSS

```
┌─────────────────────────────────────────────────────────┐
│  KONG GUARD AI - Live Threat Detection                 │
│  File: visualization/index.html                         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🔴 Status Bar                                           │
│ ┌─────────┬─────────┬─────────┬─────────┬──────────┐   │
│ │ Total   │ Threats │ Allowed │ Avg     │ Current  │   │
│ │ Req     │ Blocked │         │ Latency │ RPS      │   │
│ │ 0       │ 0       │ 0       │ 0ms     │ 0 req/s  │   │
│ └─────────┴─────────┴─────────┴─────────┴──────────┘   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📊 Metrics Overview                                     │
│                                                         │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│ │ Total Reqs   │  │ Threats      │  │ AI Accuracy  │  │
│ │   0          │  │ Blocked: 0   │  │   95.5%      │  │
│ │              │  │ Allowed: 0   │  │              │  │
│ └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🎯 Threat Flow Visualization                           │
│                                                         │
│  [Request] → [AI Guard] → [Decision] → [Action]       │
│                                                         │
│  Green Particles = Safe                                │
│  Red Particles = Threat                                │
│  Blue Glow = AI Analyzing                              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📈 Charts                                               │
│ ┌────────────────┐  ┌────────────────┐                │
│ │ Request Rate   │  │ Latency        │                │
│ │   (Chart.js)   │  │   (Chart.js)   │                │
│ └────────────────┘  └────────────────┘                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🔴 Live Event Feed                                      │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ [Time] IP: xxx.xxx → Path: /api/... → BLOCKED      │ │
│ │ [Time] IP: xxx.xxx → Path: /api/... → ALLOWED      │ │
│ │ [Time] IP: xxx.xxx → Path: /api/... → RATE_LIMITED │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🧠 AI Thinking (When Active)                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Analyzing request from 192.168.1.100...            │ │
│ │ Pattern: SQL Injection Attempt                      │ │
│ │ Confidence: 94.5%                                   │ │
│ │ Decision: BLOCK                                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🗺️ Threat Map (Geographic)                            │
│                                                         │
│  [Interactive Map showing threat sources]              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Features**:
- ✅ Real-time WebSocket updates
- ✅ Live metrics counters
- ✅ Animated threat flow
- ✅ AI thinking visualization
- ✅ Interactive charts
- ✅ Event feed
- ✅ Geographic threat map

**WebSocket**: `ws://localhost:8000/ws`  
**API**: REST endpoints for historical data

**Navigation**: Single-page application (no navigation)

---

### 2️⃣ Testing Dashboard
**File**: `public/dashboards/kong-dashboard.html`  
**Lines**: 641  
**Technology**: Vanilla JS + Custom Animations

```
┌─────────────────────────────────────────────────────────┐
│  KONG GUARD AI - Testing Dashboard                     │
│  File: public/dashboards/kong-dashboard.html           │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📊 Status Bar                                           │
│ ┌──────────────┬──────────────┬──────────────┐         │
│ │ Kong Gateway │ AI Service   │ Dashboard    │         │
│ │ 🟢 Online    │ 🟢 Online    │ 🟢 Connected │         │
│ └──────────────┴──────────────┴──────────────┘         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🧪 Attack Simulator                                     │
│ ┌─────────────────────────────────────────────────────┐ │
│ │                                                     │ │
│ │ [ Normal Request ]  Test normal traffic            │ │
│ │                                                     │ │
│ │ [ SQL Injection ]   Test database attack           │ │
│ │                                                     │ │
│ │ [ XSS Attack ]      Test script injection          │ │
│ │                                                     │ │
│ │ [ DDoS Burst ]      Test rapid requests            │ │
│ │                                                     │ │
│ │ [ Path Traversal ]  Test directory access          │ │
│ │                                                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📊 Results Display                                      │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Request: GET /api/users?id=1' OR '1'='1            │ │
│ │ Status: BLOCKED                                     │ │
│ │ Threat: SQL Injection                               │ │
│ │ Confidence: 98.3%                                   │ │
│ │ Response Time: 15ms                                 │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📈 Test Statistics                                      │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Total Tests Run: 0                                  │ │
│ │ Attacks Blocked: 0                                  │ │
│ │ False Positives: 0                                  │ │
│ │ Detection Rate: 0%                                  │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🔄 Actions                                              │
│ [ Clear Results ] [ Export Report ] [ View Logs ]      │
└─────────────────────────────────────────────────────────┘
```

**Features**:
- ✅ Interactive attack simulator
- ✅ Real-time test execution
- ✅ Visual result display
- ✅ Statistics tracking
- ✅ Export functionality

**API**: Direct HTTP requests to Kong Gateway  
**Navigation**: Single-page with sections

---

### 3️⃣ Fixed Dashboard (Stable)
**File**: `visualization/fixed-dashboard.html`  
**Lines**: ~300  
**Technology**: HTML + CSS + Vanilla JS

```
┌─────────────────────────────────────────────────────────┐
│  Kong Guard AI - Stable Dashboard                      │
│  File: visualization/fixed-dashboard.html               │
└─────────────────────────────────────────────────────────┘

[Similar layout to Main Dashboard but with simplified features]

- Static/mock data
- No WebSocket dependency
- Simplified animations
- Fallback for demo purposes
```

---

### 4️⃣ Enterprise Demo Dashboard
**File**: `public/dashboards/enterprise_demo_dashboard.html`  
**Technology**: Advanced visualizations

```
┌─────────────────────────────────────────────────────────┐
│  Kong Guard AI - Enterprise Edition                    │
│  File: public/dashboards/enterprise_demo_dashboard.html│
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🏢 Enterprise Metrics                                   │
│                                                         │
│ ┌────────────┬────────────┬────────────┬────────────┐  │
│ │ Multi-DC   │ Global     │ Compliance │ SLA        │  │
│ │ Status     │ Traffic    │ Score      │ Uptime     │  │
│ │ 🟢 Active  │ 1.2M req/s │ 99.7%      │ 99.99%     │  │
│ └────────────┴────────────┴────────────┴────────────┘  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🌍 Global Threat Map                                    │
│                                                         │
│  [World map with threat indicators by region]          │
│                                                         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 📊 Advanced Analytics                                   │
│ ┌────────────────┐  ┌────────────────┐                │
│ │ Attack Trends  │  │ AI Performance │                │
│ │ (7-day view)   │  │ (Real-time)    │                │
│ └────────────────┘  └────────────────┘                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🔐 Security Posture                                     │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Critical Threats:   0                               │ │
│ │ High Priority:      2                               │ │
│ │ Medium Priority:    8                               │ │
│ │ Low Priority:       15                              │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features**:
- ✅ Multi-datacenter support
- ✅ Global threat intelligence
- ✅ Compliance reporting
- ✅ SLA monitoring
- ✅ Advanced analytics

---

### 5️⃣ shadcn/ui Dashboard (Modern)
**File**: `shadcn-dashboard/` (Next.js App)  
**Technology**: Next.js + React + shadcn/ui + TailwindCSS

```
┌─────────────────────────────────────────────────────────┐
│  🎨 Kong Guard AI - Modern UI Dashboard                │
│  Directory: shadcn-dashboard/                           │
└─────────────────────────────────────────────────────────┘

Navigation: Multi-page with routing

┌────────────────────────────────────┐
│  SIDEBAR NAVIGATION                │
├────────────────────────────────────┤
│  🏠 Dashboard                      │
│  📊 Analytics                      │
│  ⚠️ Threats                        │
│  🔒 Security                       │
│  ⚙️ Settings                       │
│  📚 Documentation                  │
│  👤 Profile                        │
└────────────────────────────────────┘

Main Dashboard View:
┌─────────────────────────────────────────────────────────┐
│ Header: Kong Guard AI                    [User] [🔔]   │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────┬─────────────┬─────────────┬──────────┐ │
│ │ Card        │ Card        │ Card        │ Card     │ │
│ │ Metric 1    │ Metric 2    │ Metric 3    │ Metric 4 │ │
│ └─────────────┴─────────────┴─────────────┴──────────┘ │
│                                                         │
│ ┌──────────────────────────┐  ┌──────────────────────┐ │
│ │ Chart Component          │  │ Recent Activity      │ │
│ │                          │  │                      │ │
│ └──────────────────────────┘  └──────────────────────┘ │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Data Table: Recent Threats                          │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Features**:
- ✅ Modern shadcn/ui components
- ✅ Multi-page routing
- ✅ Dark/Light mode
- ✅ Responsive design
- ✅ Enterprise branding

**Routes**:
```
/ (Home)
├─ /dashboard
├─ /analytics
├─ /threats
├─ /security
├─ /settings
└─ /docs
```

---

## 🔄 Dashboard Navigation Flow

### Single-Page Dashboards (No Navigation)

Most dashboards are **single-page applications** with no internal navigation:

```
visualization/index.html
└─ No navigation (single page with real-time updates)

public/dashboards/kong-dashboard.html
└─ No navigation (single page with test sections)

visualization/fixed-dashboard.html
└─ No navigation (single page, static/demo)
```

### Multi-Page Dashboard (shadcn-dashboard)

Only the shadcn-dashboard has internal navigation:

```
shadcn-dashboard/
│
├─ Home (/)
│  └─ Landing page
│
├─ Dashboard (/dashboard)
│  ├─ Overview metrics
│  ├─ Real-time charts
│  └─ Quick actions
│
├─ Analytics (/analytics)
│  ├─ Historical data
│  ├─ Trend analysis
│  └─ Custom reports
│
├─ Threats (/threats)
│  ├─ Active threats
│  ├─ Blocked requests
│  └─ Threat intelligence
│
├─ Security (/security)
│  ├─ Security posture
│  ├─ Compliance status
│  └─ Audit logs
│
├─ Settings (/settings)
│  ├─ Configuration
│  ├─ API keys
│  └─ User preferences
│
└─ Documentation (/docs)
   ├─ API reference
   ├─ Integration guides
   └─ Troubleshooting
```

---

## 🎨 Visual Wireframe Comparison

### Main Dashboard (visualization/index.html)

```
┌─────────────────────────────────────────────────────────────┐
│ Header Bar                                                  │
│ Kong Guard AI - Live Threat Detection    🟢 Connected      │
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ METRICS OVERVIEW                                        ┃ │
│ ┣━━━━━━━━━┯━━━━━━━━━┯━━━━━━━━━┯━━━━━━━━━┯━━━━━━━━━━━━┫ │
│ ┃ Total   │ Threats │ Allowed │ Latency │ RPS        ┃ │
│ ┃ 12,450  │ 234     │ 12,216  │ 8ms     │ 125 req/s  ┃ │
│ ┗━━━━━━━━━┷━━━━━━━━━┷━━━━━━━━━┷━━━━━━━━━┷━━━━━━━━━━━━┛ │
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ THREAT FLOW VISUALIZATION                               ┃ │
│ ┃                                                         ┃ │
│ ┃  🌐 → [AI GUARD] → ✓ Safe     → 🟢 Allowed           ┃ │
│ ┃  🌐 → [AI GUARD] → ⚠️ Threat  → 🔴 Blocked           ┃ │
│ ┃  🌐 → [AI GUARD] → ⏱️ Slow    → ⏸️ Rate Limited      ┃ │
│ ┃                                                         ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
├───────────────────────────────┬─────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓│┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓│
│ ┃ REQUEST RATE CHART       ┃│┃ LATENCY CHART            ┃│
│ ┃                          ┃│┃                          ┃│
│ ┃ [Chart.js Line Chart]    ┃│┃ [Chart.js Line Chart]    ┃│
│ ┃                          ┃│┃                          ┃│
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛│┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛│
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ LIVE EVENT FEED                                         ┃ │
│ ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│ ┃ 14:23:45 │ 192.168.1.100 │ /api/users   │ 🔴 BLOCKED ┃ │
│ ┃ 14:23:44 │ 192.168.1.101 │ /api/login   │ 🟢 ALLOWED ┃ │
│ ┃ 14:23:43 │ 192.168.1.102 │ /api/data    │ ⏸️ RATE_LIM┃ │
│ ┃ 14:23:42 │ 192.168.1.103 │ /api/search  │ 🟢 ALLOWED ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ AI THINKING (When Active)                               ┃ │
│ ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│ ┃ 🧠 Analyzing: 192.168.1.105                            ┃ │
│ ┃ Pattern: SQL Injection - DROP TABLE                     ┃ │
│ ┃ Confidence: 96.8%                                       ┃ │
│ ┃ Decision: BLOCK                                         ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
└─────────────────────────────────────────────────────────────┘
```

### Testing Dashboard (public/dashboards/kong-dashboard.html)

```
┌─────────────────────────────────────────────────────────────┐
│ Header                                                      │
│ Kong Guard AI - Testing Dashboard                          │
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ STATUS BAR                                              ┃ │
│ ┣━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━┫ │
│ ┃ 🟢 Kong Online │ 🟢 AI Service │ 🟢 Dashboard Ready  ┃ │
│ ┗━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━┛ │
├───────────────────────────────┬─────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓│┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓│
│ ┃ ATTACK SIMULATOR         ┃│┃ RESULTS DISPLAY          ┃│
│ ┣━━━━━━━━━━━━━━━━━━━━━━━━━━┫│┣━━━━━━━━━━━━━━━━━━━━━━━━━━┫│
│ ┃                          ┃│┃ Request:                 ┃│
│ ┃ [Normal Traffic]         ┃│┃ GET /api/users?id=1'     ┃│
│ ┃                          ┃│┃                          ┃│
│ ┃ [SQL Injection]          ┃│┃ Status: BLOCKED          ┃│
│ ┃                          ┃│┃ Threat: SQL Injection    ┃│
│ ┃ [XSS Attack]             ┃│┃ Confidence: 98.3%        ┃│
│ ┃                          ┃│┃ Response: 15ms           ┃│
│ ┃ [DDoS Burst]             ┃│┃                          ┃│
│ ┃                          ┃│┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛│
│ ┃ [Path Traversal]         ┃│                            │
│ ┃                          ┃│┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓│
│ ┃ [Custom Test]            ┃│┃ TEST STATISTICS          ┃│
│ ┃                          ┃│┣━━━━━━━━━━━━━━━━━━━━━━━━━━┫│
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛│┃ Tests Run: 24            ┃│
│                              │┃ Blocked: 18              ┃│
│                              │┃ Allowed: 6               ┃│
│                              │┃ Detection: 98.5%         ┃│
│                              │┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛│
├─────────────────────────────────────────────────────────────┤
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ ACTIONS                                                 ┃ │
│ ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│ ┃ [Clear Results] [Export Report] [View Logs] [Settings]┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
└─────────────────────────────────────────────────────────────┘
```

### shadcn/ui Dashboard (Multi-page)

```
┌─────────────────────────────────────────────────────────────┐
│ ┏━━━━━━━┓ KONG GUARD AI                [User] [🔔]  [🌓]  │
│ ┃       ┃                                                   │
│ ┃       ┃ ┌───────────────────────────────────────────────┐│
│ ┃  🏠   ┃ │ DASHBOARD OVERVIEW                            ││
│ ┃       ┃ ├───────────────────────────────────────────────┤│
│ ┃  📊   ┃ │ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐          ││
│ ┃       ┃ │ │ Card │ │ Card │ │ Card │ │ Card │          ││
│ ┃  ⚠️   ┃ │ │  1   │ │  2   │ │  3   │ │  4   │          ││
│ ┃       ┃ │ └──────┘ └──────┘ └──────┘ └──────┘          ││
│ ┃  🔒   ┃ │                                               ││
│ ┃       ┃ │ ┌──────────────────┐ ┌──────────────────┐    ││
│ ┃  ⚙️   ┃ │ │ Chart Component  │ │ Recent Activity  │    ││
│ ┃       ┃ │ │                  │ │                  │    ││
│ ┃  📚   ┃ │ └──────────────────┘ └──────────────────┘    ││
│ ┃       ┃ │                                               ││
│ ┃  👤   ┃ │ ┌─────────────────────────────────────────┐  ││
│ ┃       ┃ │ │ Data Table: Recent Threats              │  ││
│ ┗━━━━━━━┛ │ └─────────────────────────────────────────┘  ││
│           └───────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘

Sidebar Icons:
🏠 Dashboard
📊 Analytics
⚠️ Threats
🔒 Security
⚙️ Settings
📚 Documentation
👤 Profile
```

---

## 🔗 Dashboard Relationships

```
┌──────────────────────────────────────┐
│ Primary Production Dashboard         │
│ visualization/index.html             │
│ - Live WebSocket data                │
│ - Real-time updates                  │
│ - Production use                     │
└──────────────────────────────────────┘
            │
            ├─ Used by: hackathon_demo_recorder.py
            ├─ URL: http://localhost:8080
            └─ WebSocket: ws://localhost:8000/ws

┌──────────────────────────────────────┐
│ Testing & Development                │
│ public/dashboards/kong-dashboard.html│
│ - Interactive testing                │
│ - Attack simulation                  │
│ - Development/QA use                 │
└──────────────────────────────────────┘
            │
            ├─ Standalone testing tool
            ├─ No WebSocket dependency
            └─ Direct HTTP to Kong Gateway

┌──────────────────────────────────────┐
│ Modern Enterprise UI                 │
│ shadcn-dashboard/                    │
│ - Multi-page app                     │
│ - Modern UI components               │
│ - Enterprise features                │
└──────────────────────────────────────┘
            │
            ├─ Next.js routing
            ├─ shadcn/ui components
            └─ Future production candidate

┌──────────────────────────────────────┐
│ Demo/Presentation                    │
│ visualization/fixed-dashboard.html   │
│ - Static/mock data                   │
│ - No dependencies                    │
│ - Demo/offline use                   │
└──────────────────────────────────────┘
            │
            ├─ Standalone demo
            ├─ No backend required
            └─ Presentation fallback
```

---

## 🎬 Recording System Dashboard Usage

The hackathon demo recorder uses the **primary dashboard**:

```python
# hackathon_demo_recorder.py

DEFAULT_URL = "http://localhost:8080"  # visualization/index.html

# Recording flow:
1. Launch Playwright browser
2. Navigate to dashboard URL
3. Wait for dashboard to load
4. Inject visual effects (demo_visual_effects.js)
5. Execute scene actions from narrator_timing.json
6. Capture screenshots
7. Record video
```

---

## 📊 Dashboard Feature Matrix

| Feature | Main Dashboard | Testing Dashboard | shadcn Dashboard | Fixed Dashboard |
|---------|---------------|-------------------|------------------|-----------------|
| **Real-time Updates** | ✅ WebSocket | ✅ HTTP | ✅ WebSocket | ❌ Static |
| **Threat Visualization** | ✅ Animated | ✅ Results | ✅ Charts | ✅ Static |
| **Attack Simulator** | ❌ | ✅ | ❌ | ❌ |
| **Multi-page Navigation** | ❌ | ❌ | ✅ | ❌ |
| **Charts/Graphs** | ✅ Chart.js | ✅ Custom | ✅ Recharts | ✅ Static |
| **AI Thinking Display** | ✅ | ✅ | ✅ | ❌ |
| **Event Feed** | ✅ Live | ✅ Results | ✅ Live | ❌ |
| **Geographic Map** | ✅ | ❌ | ✅ | ❌ |
| **Mobile Responsive** | ✅ | ✅ | ✅ | ✅ |
| **Dark Mode** | ✅ Default | ❌ | ✅ Toggle | ✅ Default |
| **Export/Reports** | ❌ | ✅ | ✅ | ❌ |
| **Used in Recording** | ✅ Primary | ❌ | ❌ | ✅ Fallback |

---

## 🚀 Dashboard Access URLs

### Local Development

```bash
# Main Dashboard (Primary)
http://localhost:8080
→ Serves: visualization/index.html

# Testing Dashboard
http://localhost:8080/public/dashboards/kong-dashboard.html

# shadcn Dashboard (if running)
http://localhost:3000

# Fixed Dashboard (Direct file)
file:///path/to/visualization/fixed-dashboard.html
```

### Production/Deployment

```bash
# Nginx serves dashboards
http://your-domain.com/
→ visualization/index.html

http://your-domain.com/testing
→ public/dashboards/kong-dashboard.html
```

---

## 📋 Dashboard Summary

### Total Dashboards: 19 files

**Primary Active**: 3
- `visualization/index.html` (Main - React)
- `public/dashboards/kong-dashboard.html` (Testing)
- `shadcn-dashboard/` (Modern UI)

**Purpose-Specific**: 6
- Enterprise demo versions
- Attack visualization
- AI insights
- Branded versions

**Legacy/Archived**: 10
- Older implementations
- Development prototypes
- Historical versions

---

## 🎯 Recommended Dashboard Usage

**For Hackathon Recording**:
```
visualization/index.html (Main Dashboard)
- Live real-time updates
- Visual animations
- Professional appearance
- WebSocket connectivity
```

**For Testing/Development**:
```
public/dashboards/kong-dashboard.html
- Interactive attack testing
- No backend dependencies
- Quick prototyping
```

**For Presentations**:
```
visualization/fixed-dashboard.html
- Offline/standalone
- No services required
- Consistent behavior
```

**For Future Production**:
```
shadcn-dashboard/
- Modern UI/UX
- Enterprise features
- Scalable architecture
```

---

**Created**: 2024-09-30  
**Dashboard Count**: 19 HTML files  
**Primary Dashboard**: `visualization/index.html` (407 lines)  
**Status**: Complete wireframe and navigation flow ✅
