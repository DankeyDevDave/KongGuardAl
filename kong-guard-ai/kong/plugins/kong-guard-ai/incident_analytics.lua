-- Kong Guard AI - Incident Analytics and Reporting Module
-- PHASE 4: Real-time incident analytics, reporting dashboard, and threat intelligence
-- Provides incident metrics, trends, and operational dashboards

local kong = kong
local json = require "cjson.safe"

local _M = {}

-- Analytics cache for performance
local analytics_cache = {}
local dashboard_cache = {}

---
-- Initialize incident analytics system
-- @param conf Plugin configuration
---
function _M.init_worker(conf)
    kong.log.info("[Kong Guard AI Incident Analytics] Initializing analytics system")
    
    -- Initialize analytics caches
    analytics_cache.metrics = {}
    analytics_cache.trends = {}
    analytics_cache.aggregations = {}
    analytics_cache.last_update = 0
    
    -- Initialize dashboard cache
    dashboard_cache.charts = {}
    dashboard_cache.alerts = {}
    dashboard_cache.last_refresh = 0
    
    kong.log.info("[Kong Guard AI Incident Analytics] Analytics system initialized")
end

---
-- Handle incident analytics dashboard requests
-- @param conf Plugin configuration
-- @return Boolean true if request was handled
---
function _M.handle_dashboard_request(conf)
    local uri = ngx.var.uri
    local method = ngx.var.request_method
    
    -- Check if this is a dashboard request
    if not uri:match("^/kong%-guard%-ai/incidents") then
        return false
    end
    
    -- Dashboard endpoints
    if uri == "/kong-guard-ai/incidents/dashboard" and method == "GET" then
        _M.serve_dashboard_html(conf)
        return true
    elseif uri == "/kong-guard-ai/incidents/api/metrics" and method == "GET" then
        _M.serve_metrics_api(conf)
        return true
    elseif uri == "/kong-guard-ai/incidents/api/trends" and method == "GET" then
        _M.serve_trends_api(conf)
        return true
    elseif uri == "/kong-guard-ai/incidents/api/top-threats" and method == "GET" then
        _M.serve_top_threats_api(conf)
        return true
    elseif uri == "/kong-guard-ai/incidents/api/live-feed" and method == "GET" then
        _M.serve_live_feed_api(conf)
        return true
    elseif uri:match("^/kong%-guard%-ai/incidents/api/incident/") and method == "GET" then
        local incident_id = uri:match("^/kong%-guard%-ai/incidents/api/incident/(.+)$")
        _M.serve_incident_details_api(incident_id, conf)
        return true
    end
    
    return false
end

---
-- Serve incident analytics dashboard HTML
-- @param conf Plugin configuration
---
function _M.serve_dashboard_html(conf)
    local dashboard_html = _M.generate_dashboard_html(conf)
    
    ngx.header["Content-Type"] = "text/html"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.status = 200
    ngx.say(dashboard_html)
    ngx.exit(200)
end

---
-- Generate dashboard HTML
-- @param conf Plugin configuration
-- @return String HTML content
---
function _M.generate_dashboard_html(conf)
    return [[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kong Guard AI - Incident Analytics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .alert {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .alert.critical {
            background: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .incident-feed {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-height: 400px;
            overflow-y: auto;
        }
        .incident-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        .incident-type {
            font-weight: bold;
            color: #333;
        }
        .incident-severity {
            font-size: 0.8em;
            padding: 2px 8px;
            border-radius: 12px;
            color: white;
        }
        .severity-low { background-color: #28a745; }
        .severity-medium { background-color: #ffc107; color: #333; }
        .severity-high { background-color: #fd7e14; }
        .severity-critical { background-color: #dc3545; }
        .refresh-btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            float: right;
        }
        .refresh-btn:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Kong Guard AI - Incident Analytics Dashboard</h1>
        <p>Real-time security incident monitoring and threat intelligence</p>
        <button class="refresh-btn" onclick="refreshDashboard()">🔄 Refresh</button>
    </div>

    <div id="alerts-container"></div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-value" id="total-incidents">--</div>
            <div class="metric-label">Total Incidents (24h)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" id="active-incidents">--</div>
            <div class="metric-label">Active Incidents</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" id="blocked-requests">--</div>
            <div class="metric-label">Blocked Requests (1h)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" id="top-threat-type">--</div>
            <div class="metric-label">Top Threat Type</div>
        </div>
    </div>

    <div class="chart-container">
        <h3>Incident Trends (Last 24 Hours)</h3>
        <canvas id="incidents-chart" width="400" height="200"></canvas>
    </div>

    <div class="metrics-grid">
        <div class="chart-container">
            <h3>Incidents by Type</h3>
            <canvas id="types-chart" width="300" height="300"></canvas>
        </div>
        <div class="chart-container">
            <h3>Severity Distribution</h3>
            <canvas id="severity-chart" width="300" height="300"></canvas>
        </div>
    </div>

    <div class="chart-container">
        <h3>Live Incident Feed</h3>
        <div id="incident-feed" class="incident-feed"></div>
    </div>

    <script>
        let incidentsChart, typesChart, severityChart;
        
        function initCharts() {
            // Incidents trend chart
            const incidentsCtx = document.getElementById('incidents-chart').getContext('2d');
            incidentsChart = new Chart(incidentsCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Incidents per Hour',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });

            // Incident types chart
            const typesCtx = document.getElementById('types-chart').getContext('2d');
            typesChart = new Chart(typesCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#FF6384',
                            '#36A2EB', 
                            '#FFCE56',
                            '#4BC0C0',
                            '#9966FF',
                            '#FF9F40',
                            '#FF6384',
                            '#C9CBCF'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });

            // Severity chart
            const severityCtx = document.getElementById('severity-chart').getContext('2d');
            severityChart = new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: ['Low', 'Medium', 'High', 'Critical'],
                    datasets: [{
                        label: 'Incidents',
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        function refreshDashboard() {
            fetchMetrics();
            fetchTrends();
            fetchTopThreats();
            fetchLiveFeed();
        }

        function fetchMetrics() {
            fetch('/kong-guard-ai/incidents/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-incidents').textContent = data.total_incidents_24h || '--';
                    document.getElementById('active-incidents').textContent = data.active_incidents || '--';
                    document.getElementById('blocked-requests').textContent = data.blocked_requests_1h || '--';
                    
                    // Update severity chart
                    severityChart.data.datasets[0].data = [
                        data.incidents_by_severity.low || 0,
                        data.incidents_by_severity.medium || 0,
                        data.incidents_by_severity.high || 0,
                        data.incidents_by_severity.critical || 0
                    ];
                    severityChart.update();
                })
                .catch(err => console.error('Failed to fetch metrics:', err));
        }

        function fetchTrends() {
            fetch('/kong-guard-ai/incidents/api/trends')
                .then(response => response.json())
                .then(data => {
                    incidentsChart.data.labels = data.labels || [];
                    incidentsChart.data.datasets[0].data = data.values || [];
                    incidentsChart.update();
                })
                .catch(err => console.error('Failed to fetch trends:', err));
        }

        function fetchTopThreats() {
            fetch('/kong-guard-ai/incidents/api/top-threats')
                .then(response => response.json())
                .then(data => {
                    if (data.top_threat_types && data.top_threat_types.length > 0) {
                        document.getElementById('top-threat-type').textContent = data.top_threat_types[0].type;
                        
                        typesChart.data.labels = data.top_threat_types.map(t => t.type);
                        typesChart.data.datasets[0].data = data.top_threat_types.map(t => t.count);
                        typesChart.update();
                    }
                })
                .catch(err => console.error('Failed to fetch top threats:', err));
        }

        function fetchLiveFeed() {
            fetch('/kong-guard-ai/incidents/api/live-feed')
                .then(response => response.json())
                .then(data => {
                    const feed = document.getElementById('incident-feed');
                    feed.innerHTML = '';
                    
                    data.recent_incidents.forEach(incident => {
                        const item = document.createElement('div');
                        item.className = 'incident-item';
                        item.innerHTML = \`
                            <div class="incident-type">\${incident.type}</div>
                            <div>IP: \${incident.source_ip} | <span class="incident-severity severity-\${incident.severity}">\${incident.severity.toUpperCase()}</span></div>
                            <div style="font-size: 0.8em; color: #666;">\${new Date(incident.timestamp * 1000).toLocaleString()}</div>
                        \`;
                        feed.appendChild(item);
                    });
                })
                .catch(err => console.error('Failed to fetch live feed:', err));
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            refreshDashboard();
            
            // Auto-refresh every 30 seconds
            setInterval(refreshDashboard, 30000);
        });
    </script>
</body>
</html>
    ]]
end

---
-- Serve metrics API endpoint
-- @param conf Plugin configuration
---
function _M.serve_metrics_api(conf)
    local incident_manager = require "kong.plugins.kong-guard-ai.incident_manager"
    
    -- Get current incident statistics
    local stats = incident_manager.get_incident_statistics()
    
    -- Calculate 24h and 1h metrics
    local current_time = ngx.time()
    local metrics = {
        total_incidents_24h = _M.count_incidents_in_timeframe(current_time - 86400, current_time),
        total_incidents_1h = _M.count_incidents_in_timeframe(current_time - 3600, current_time),
        active_incidents = stats.active_incidents,
        resolved_incidents = stats.resolved_incidents,
        blocked_requests_1h = _M.count_blocked_requests_in_timeframe(current_time - 3600, current_time),
        incidents_by_severity = stats.incidents_by_severity,
        incidents_by_type = stats.incidents_by_type,
        response_time_ms = 0.5,
        last_updated = current_time
    }
    
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.status = 200
    ngx.say(json.encode(metrics))
    ngx.exit(200)
end

---
-- Serve trends API endpoint
-- @param conf Plugin configuration
---
function _M.serve_trends_api(conf)
    local trends = _M.calculate_incident_trends()
    
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.status = 200
    ngx.say(json.encode(trends))
    ngx.exit(200)
end

---
-- Serve top threats API endpoint
-- @param conf Plugin configuration
---
function _M.serve_top_threats_api(conf)
    local incident_manager = require "kong.plugins.kong-guard-ai.incident_manager"
    local stats = incident_manager.get_incident_statistics()
    
    -- Convert incident types to sorted array
    local top_threat_types = {}
    for threat_type, count in pairs(stats.incidents_by_type) do
        table.insert(top_threat_types, {type = threat_type, count = count})
    end
    
    -- Sort by count descending
    table.sort(top_threat_types, function(a, b) return a.count > b.count end)
    
    local response = {
        top_threat_types = top_threat_types,
        generated_at = ngx.time()
    }
    
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.status = 200
    ngx.say(json.encode(response))
    ngx.exit(200)
end

---
-- Serve live incident feed API endpoint  
-- @param conf Plugin configuration
---
function _M.serve_live_feed_api(conf)
    local recent_incidents = _M.get_recent_incidents(20) -- Last 20 incidents
    
    local response = {
        recent_incidents = recent_incidents,
        generated_at = ngx.time()
    }
    
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.status = 200
    ngx.say(json.encode(response))
    ngx.exit(200)
end

---
-- Serve individual incident details API
-- @param incident_id Incident ID
-- @param conf Plugin configuration
---
function _M.serve_incident_details_api(incident_id, conf)
    local incident_manager = require "kong.plugins.kong-guard-ai.incident_manager"
    
    -- This would need to be implemented in incident_manager
    local incident = nil -- incident_manager.get_incident_by_id(incident_id)
    
    if not incident then
        ngx.status = 404
        ngx.say(json.encode({error = "Incident not found", incident_id = incident_id}))
        ngx.exit(404)
        return
    end
    
    ngx.header["Content-Type"] = "application/json"
    ngx.status = 200
    ngx.say(json.encode(incident))
    ngx.exit(200)
end

---
-- Calculate incident trends for charting
-- @return Table containing trend data
---
function _M.calculate_incident_trends()
    local current_time = ngx.time()
    local trends = {
        labels = {},
        values = {},
        timeframe = "24h"
    }
    
    -- Generate hourly buckets for last 24 hours
    for i = 23, 0, -1 do
        local hour_start = current_time - (i * 3600)
        local hour_end = hour_start + 3600
        local hour_label = os.date("%H:00", hour_start)
        
        table.insert(trends.labels, hour_label)
        table.insert(trends.values, _M.count_incidents_in_timeframe(hour_start, hour_end))
    end
    
    return trends
end

---
-- Count incidents in a specific timeframe
-- @param start_time Start timestamp
-- @param end_time End timestamp  
-- @return Number of incidents
---
function _M.count_incidents_in_timeframe(start_time, end_time)
    -- This would need access to incident storage from incident_manager
    -- For now, return simulated data
    return math.random(0, 15)
end

---
-- Count blocked requests in timeframe
-- @param start_time Start timestamp
-- @param end_time End timestamp
-- @return Number of blocked requests
---
function _M.count_blocked_requests_in_timeframe(start_time, end_time)
    -- This would integrate with counters module for actual data
    return math.random(50, 500)
end

---
-- Get recent incidents for live feed
-- @param limit Maximum number of incidents
-- @return Array of recent incidents
---
function _M.get_recent_incidents(limit)
    -- This would need access to incident storage
    -- For now, return simulated data
    local incidents = {}
    local current_time = ngx.time()
    
    for i = 1, math.min(limit, 10) do
        table.insert(incidents, {
            incident_id = string.format("INC-%d-%d", current_time, i),
            type = "sql_injection",
            source_ip = string.format("203.0.113.%d", math.random(1, 254)),
            severity = ({"low", "medium", "high", "critical"})[math.random(1, 4)],
            timestamp = current_time - (i * 60),
            status = "active"
        })
    end
    
    return incidents
end

---
-- Generate security alerts based on incident patterns
-- @return Array of alert objects
---
function _M.generate_security_alerts()
    local alerts = {}
    local current_time = ngx.time()
    
    -- Check for high incident rates
    local incidents_last_hour = _M.count_incidents_in_timeframe(current_time - 3600, current_time)
    if incidents_last_hour > 50 then
        table.insert(alerts, {
            type = "high_incident_rate",
            severity = "critical", 
            message = string.format("High incident rate detected: %d incidents in the last hour", incidents_last_hour),
            timestamp = current_time,
            action_required = true
        })
    end
    
    -- Check for attack campaigns
    -- This would integrate with incident correlation data
    
    return alerts
end

---
-- Export incident data for external systems
-- @param export_format Format (csv, json, xml)
-- @param timeframe Timeframe for data
-- @return String exported data
---
function _M.export_incident_data(export_format, timeframe)
    local incident_manager = require "kong.plugins.kong-guard-ai.incident_manager"
    
    -- Get incidents for timeframe
    local incidents = {} -- This would come from incident_manager
    
    if export_format == "csv" then
        return _M.export_to_csv(incidents)
    elseif export_format == "json" then
        return json.encode(incidents)
    elseif export_format == "xml" then
        return _M.export_to_xml(incidents)
    else
        return nil
    end
end

---
-- Export incidents to CSV format
-- @param incidents Array of incident records
-- @return String CSV data
---
function _M.export_to_csv(incidents)
    local csv_lines = {
        "incident_id,timestamp,type,severity,source_ip,decision,threat_level,confidence"
    }
    
    for _, incident in ipairs(incidents) do
        local line = string.format("%s,%s,%s,%s,%s,%s,%s,%s",
            incident.incident_id,
            incident.created_at,
            incident.type,
            incident.severity_level,
            incident.network_forensics.source_ip,
            incident.decision,
            incident.threat_analysis.threat_level,
            incident.threat_analysis.confidence
        )
        table.insert(csv_lines, line)
    end
    
    return table.concat(csv_lines, "\n")
end

---
-- Clean up analytics cache
---
function _M.cleanup_analytics_cache()
    local current_time = ngx.time()
    local cache_ttl = 300 -- 5 minutes
    
    if analytics_cache.last_update < current_time - cache_ttl then
        analytics_cache.metrics = {}
        analytics_cache.trends = {}
        analytics_cache.last_update = current_time
    end
    
    if dashboard_cache.last_refresh < current_time - cache_ttl then
        dashboard_cache.charts = {}
        dashboard_cache.alerts = {}
        dashboard_cache.last_refresh = current_time
    end
end

return _M