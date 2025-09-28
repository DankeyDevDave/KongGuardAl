-- Kong Guard AI - Prometheus Metrics Integration
-- Provides comprehensive Prometheus metrics for advanced rate limiting features

local ngx = ngx
local math = math
local string = string
local table = table

local PrometheusMetrics = {}
PrometheusMetrics.__index = PrometheusMetrics

-- Metric constants
local METRIC_PREFIX = "kong_guard_ai_"

-- Initialize Prometheus metrics collector
function PrometheusMetrics:new(config)
    local self = setmetatable({}, PrometheusMetrics)

    self.config = config or {}
    self.metrics_cache = ngx.shared.kong_cache

    -- Metric definitions for advanced rate limiting
    self.metrics = {
        -- Adaptive rate limiting metrics
        adaptive_rate_limit_applications = {
            name = METRIC_PREFIX .. "adaptive_rate_limit_applications_total",
            help = "Total number of adaptive rate limit applications",
            type = "counter",
            labels = {"client_ip", "action"}
        },
        adaptive_rate_limit_violations = {
            name = METRIC_PREFIX .. "adaptive_rate_limit_violations_total",
            help = "Total number of adaptive rate limit violations",
            type = "counter",
            labels = {"client_ip", "threat_level"}
        },
        adaptive_rate_current_limits = {
            name = METRIC_PREFIX .. "adaptive_rate_current_limits",
            help = "Current adaptive rate limits by IP",
            type = "gauge",
            labels = {"client_ip"}
        },
        adaptive_rate_adjustments = {
            name = METRIC_PREFIX .. "adaptive_rate_adjustments_total",
            help = "Total number of rate limit adjustments",
            type = "counter",
            labels = {"client_ip", "direction"}
        },

        -- DDoS mitigation metrics
        ddos_attacks_detected = {
            name = METRIC_PREFIX .. "ddos_attacks_detected_total",
            help = "Total number of DDoS attacks detected",
            type = "counter",
            labels = {"attack_type", "severity"}
        },
        ddos_challenges_issued = {
            name = METRIC_PREFIX .. "ddos_challenges_issued_total",
            help = "Total number of DDoS challenges issued",
            type = "counter",
            labels = {"difficulty_level"}
        },
        ddos_challenges_solved = {
            name = METRIC_PREFIX .. "ddos_challenges_solved_total",
            help = "Total number of DDoS challenges successfully solved",
            type = "counter",
            labels = {"difficulty_level", "client_ip"}
        },
        ddos_mitigation_actions = {
            name = METRIC_PREFIX .. "ddos_mitigation_actions_total",
            help = "Total number of DDoS mitigation actions taken",
            type = "counter",
            labels = {"action_type", "client_ip"}
        },
        ddos_attack_duration = {
            name = METRIC_PREFIX .. "ddos_attack_duration_seconds",
            help = "Duration of detected DDoS attacks in seconds",
            type = "histogram",
            buckets = {1, 5, 10, 30, 60, 300, 600, 1800, 3600}
        },

        -- Geographic rate limiting metrics
        geo_rate_limit_applications = {
            name = METRIC_PREFIX .. "geo_rate_limit_applications_total",
            help = "Total number of geographic rate limit applications",
            type = "counter",
            labels = {"country_code", "action"}
        },
        geo_rate_limit_violations = {
            name = METRIC_PREFIX .. "geo_rate_limit_violations_total",
            help = "Total number of geographic rate limit violations",
            type = "counter",
            labels = {"country_code", "client_ip"}
        },
        geo_anomaly_detections = {
            name = METRIC_PREFIX .. "geo_anomaly_detections_total",
            help = "Total number of geographic anomalies detected",
            type = "counter",
            labels = {"anomaly_type", "country_code"}
        },
        geo_impossible_travel = {
            name = METRIC_PREFIX .. "geo_impossible_travel_total",
            help = "Total number of impossible travel detections",
            type = "counter",
            labels = {"client_ip", "country_from", "country_to"}
        },

        -- Security Controls Metrics
        access_authentications = {
            name = METRIC_PREFIX .. "access_authentications_total",
            help = "Total number of authentication attempts",
            type = "counter",
            labels = {"result", "method"}
        },
        access_authorizations = {
            name = METRIC_PREFIX .. "access_authorizations_total",
            help = "Total number of authorization checks",
            type = "counter",
            labels = {"result", "resource", "action"}
        },
        access_sessions = {
            name = METRIC_PREFIX .. "access_sessions_active",
            help = "Number of active user sessions",
            type = "gauge",
            labels = {"user_id"}
        },
        encryption_operations = {
            name = METRIC_PREFIX .. "encryption_operations_total",
            help = "Total number of encryption/decryption operations",
            type = "counter",
            labels = {"operation", "algorithm", "result"}
        },
        encryption_key_rotations = {
            name = METRIC_PREFIX .. "encryption_key_rotations_total",
            help = "Total number of encryption key rotations",
            type = "counter",
            labels = {"key_type"}
        },
        security_alerts = {
            name = METRIC_PREFIX .. "security_alerts_total",
            help = "Total number of security alerts generated",
            type = "counter",
            labels = {"severity", "alert_type", "status"}
        },
        security_events = {
            name = METRIC_PREFIX .. "security_events_total",
            help = "Total number of security events recorded",
            type = "counter",
            labels = {"event_type", "severity"}
        },
        security_anomalies = {
            name = METRIC_PREFIX .. "security_anomalies_detected_total",
            help = "Total number of security anomalies detected",
            type = "counter",
            labels = {"anomaly_type", "confidence"}
        },
        compliance_violations = {
            name = METRIC_PREFIX .. "compliance_violations_total",
            help = "Total number of compliance violations detected",
            type = "counter",
            labels = {"violation_type", "severity"}
        },
        audit_events = {
            name = METRIC_PREFIX .. "audit_events_total",
            help = "Total number of audit events logged",
            type = "counter",
            labels = {"event_type", "user_id"}
        },
            name = METRIC_PREFIX .. "geo_impossible_travel_total",
            help = "Total number of impossible travel detections",
            type = "counter",
            labels = {"from_country", "to_country", "client_ip"}
        },
        geo_vpn_proxy_detections = {
            name = METRIC_PREFIX .. "geo_vpn_proxy_detections_total",
            help = "Total number of VPN/proxy detections",
            type = "counter",
            labels = {"service_type", "country_code"}
        },

        -- Circuit breaker metrics
        circuit_breaker_state_changes = {
            name = METRIC_PREFIX .. "circuit_breaker_state_changes_total",
            help = "Total number of circuit breaker state changes",
            type = "counter",
            labels = {"service_id", "from_state", "to_state"}
        },
        circuit_breaker_requests_blocked = {
            name = METRIC_PREFIX .. "circuit_breaker_requests_blocked_total",
            help = "Total number of requests blocked by circuit breaker",
            type = "counter",
            labels = {"service_id", "reason"}
        },
        circuit_breaker_recovery_time = {
            name = METRIC_PREFIX .. "circuit_breaker_recovery_time_seconds",
            help = "Time taken for circuit breaker to recover",
            type = "histogram",
            buckets = {1, 5, 10, 30, 60, 120, 300, 600}
        },
        circuit_breaker_failure_rate = {
            name = METRIC_PREFIX .. "circuit_breaker_failure_rate",
            help = "Current failure rate for circuit breaker",
            type = "gauge",
            labels = {"service_id"}
        },
        circuit_breaker_response_time = {
            name = METRIC_PREFIX .. "circuit_breaker_response_time_seconds",
            help = "Response time tracked by circuit breaker",
            type = "histogram",
            buckets = {0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0}
        },

        -- General rate limiting metrics
        rate_limit_requests_total = {
            name = METRIC_PREFIX .. "rate_limit_requests_total",
            help = "Total number of rate limit checks performed",
            type = "counter",
            labels = {"limiter_type", "result"}
        },
        rate_limit_current_usage = {
            name = METRIC_PREFIX .. "rate_limit_current_usage",
            help = "Current rate limit usage",
            type = "gauge",
            labels = {"client_ip", "limiter_type"}
        },
        rate_limit_quota_remaining = {
            name = METRIC_PREFIX .. "rate_limit_quota_remaining",
            help = "Remaining quota for rate limited clients",
            type = "gauge",
            labels = {"client_ip", "limiter_type"}
        }
    }

    return self
end

-- Increment counter metric
function PrometheusMetrics:increment_counter(metric_name, labels, value)
    if not self.metrics[metric_name] then
        ngx.log(ngx.WARN, "Unknown metric: ", metric_name)
        return
    end

    local cache_key = self:build_cache_key(metric_name, labels)
    local current_value = self.metrics_cache:get(cache_key) or 0
    local new_value = current_value + (value or 1)

    self.metrics_cache:set(cache_key, new_value, 3600) -- 1 hour TTL
end

-- Set gauge metric
function PrometheusMetrics:set_gauge(metric_name, labels, value)
    if not self.metrics[metric_name] then
        ngx.log(ngx.WARN, "Unknown metric: ", metric_name)
        return
    end

    local cache_key = self:build_cache_key(metric_name, labels)
    self.metrics_cache:set(cache_key, value, 3600) -- 1 hour TTL
end

-- Observe histogram metric
function PrometheusMetrics:observe_histogram(metric_name, labels, value)
    if not self.metrics[metric_name] then
        ngx.log(ngx.WARN, "Unknown metric: ", metric_name)
        return
    end

    local metric_def = self.metrics[metric_name]
    if not metric_def.buckets then
        ngx.log(ngx.WARN, "Histogram metric missing buckets: ", metric_name)
        return
    end

    -- Update histogram buckets
    for _, bucket in ipairs(metric_def.buckets) do
        if value <= bucket then
            local bucket_key = self:build_cache_key(metric_name .. "_bucket", labels, {le = tostring(bucket)})
            local current = self.metrics_cache:get(bucket_key) or 0
            self.metrics_cache:set(bucket_key, current + 1, 3600)
        end
    end

    -- Update sum and count
    local sum_key = self:build_cache_key(metric_name .. "_sum", labels)
    local count_key = self:build_cache_key(metric_name .. "_count", labels)

    local current_sum = self.metrics_cache:get(sum_key) or 0
    local current_count = self.metrics_cache:get(count_key) or 0

    self.metrics_cache:set(sum_key, current_sum + value, 3600)
    self.metrics_cache:set(count_key, current_count + 1, 3600)
end

-- Security Controls Metrics Methods

-- Record authentication event
function PrometheusMetrics:record_authentication(result, method, labels)
    self:increment_counter("access_authentications", {
        result = result,
        method = method or "unknown"
    }, labels)
end

-- Record authorization event
function PrometheusMetrics:record_authorization(result, resource, action, labels)
    self:increment_counter("access_authorizations", {
        result = result,
        resource = resource or "unknown",
        action = action or "unknown"
    }, labels)
end

-- Update active sessions gauge
function PrometheusMetrics:update_active_sessions(user_id, count, labels)
    self:set_gauge("access_sessions", count, {
        user_id = user_id or "unknown"
    }, labels)
end

-- Record encryption operation
function PrometheusMetrics:record_encryption_operation(operation, algorithm, result, labels)
    self:increment_counter("encryption_operations", {
        operation = operation,
        algorithm = algorithm or "unknown",
        result = result
    }, labels)
end

-- Record key rotation
function PrometheusMetrics:record_key_rotation(key_type, labels)
    self:increment_counter("encryption_key_rotations", {
        key_type = key_type or "unknown"
    }, labels)
end

-- Record security alert
function PrometheusMetrics:record_security_alert(severity, alert_type, status, labels)
    self:increment_counter("security_alerts", {
        severity = severity or "unknown",
        alert_type = alert_type or "unknown",
        status = status or "unknown"
    }, labels)
end

-- Record security event
function PrometheusMetrics:record_security_event(event_type, severity, labels)
    self:increment_counter("security_events", {
        event_type = event_type or "unknown",
        severity = severity or "unknown"
    }, labels)
end

-- Record security anomaly
function PrometheusMetrics:record_security_anomaly(anomaly_type, confidence, labels)
    self:increment_counter("security_anomalies", {
        anomaly_type = anomaly_type or "unknown",
        confidence = tostring(confidence or 0)
    }, labels)
end

-- Record compliance violation
function PrometheusMetrics:record_compliance_violation(violation_type, severity, labels)
    self:increment_counter("compliance_violations", {
        violation_type = violation_type or "unknown",
        severity = severity or "unknown"
    }, labels)
end

-- Record audit event
function PrometheusMetrics:record_audit_event(event_type, user_id, labels)
    self:increment_counter("audit_events", {
        event_type = event_type or "unknown",
        user_id = user_id or "system"
    }, labels)
end

-- Build cache key for metric with labels
function PrometheusMetrics:build_cache_key(metric_name, labels, extra_labels)
    local key_parts = {"metric", metric_name}

    -- Add regular labels
    if labels then
        for k, v in pairs(labels) do
            table.insert(key_parts, k .. "=" .. tostring(v))
        end
    end

    -- Add extra labels (for histogram buckets)
    if extra_labels then
        for k, v in pairs(extra_labels) do
            table.insert(key_parts, k .. "=" .. tostring(v))
        end
    end

    return table.concat(key_parts, ":")
end

-- Generate Prometheus metrics output
function PrometheusMetrics:generate_prometheus_output()
    local output_lines = {}

    for metric_name, metric_def in pairs(self.metrics) do
        -- Add metric help and type
        table.insert(output_lines, string.format("# HELP %s %s", metric_def.name, metric_def.help))
        table.insert(output_lines, string.format("# TYPE %s %s", metric_def.name, metric_def.type))

        if metric_def.type == "histogram" then
            self:add_histogram_metrics(output_lines, metric_name, metric_def)
        else
            self:add_simple_metrics(output_lines, metric_name, metric_def)
        end

        table.insert(output_lines, "")
    end

    return table.concat(output_lines, "\n")
end

-- Add simple counter/gauge metrics to output
function PrometheusMetrics:add_simple_metrics(output_lines, metric_name, metric_def)
    -- Get all keys for this metric from cache
    local pattern = "metric:" .. metric_name .. ":"

    -- Simplified approach - in production, you'd iterate through all cache keys
    -- For now, we'll output default values or known label combinations

    -- Output base metric if no specific labels found
    local base_key = "metric:" .. metric_name
    local base_value = self.metrics_cache:get(base_key) or 0
    table.insert(output_lines, string.format("%s %s", metric_def.name, tostring(base_value)))
end

-- Add histogram metrics to output
function PrometheusMetrics:add_histogram_metrics(output_lines, metric_name, metric_def)
    -- Output histogram buckets
    for _, bucket in ipairs(metric_def.buckets) do
        local bucket_key = "metric:" .. metric_name .. "_bucket:le=" .. tostring(bucket)
        local bucket_value = self.metrics_cache:get(bucket_key) or 0
        table.insert(output_lines, string.format('%s_bucket{le="%s"} %s',
                    metric_def.name, tostring(bucket), tostring(bucket_value)))
    end

    -- Output +Inf bucket
    local inf_key = "metric:" .. metric_name .. "_bucket:le=+Inf"
    local inf_value = self.metrics_cache:get(inf_key) or 0
    table.insert(output_lines, string.format('%s_bucket{le="+Inf"} %s', metric_def.name, tostring(inf_value)))

    -- Output sum and count
    local sum_key = "metric:" .. metric_name .. "_sum"
    local count_key = "metric:" .. metric_name .. "_count"

    local sum_value = self.metrics_cache:get(sum_key) or 0
    local count_value = self.metrics_cache:get(count_key) or 0

    table.insert(output_lines, string.format("%s_sum %s", metric_def.name, tostring(sum_value)))
    table.insert(output_lines, string.format("%s_count %s", metric_def.name, tostring(count_value)))
end

-- Adaptive Rate Limiting Metrics
function PrometheusMetrics:record_adaptive_rate_limit(client_ip, action, threat_level, current_limit)
    self:increment_counter("adaptive_rate_limit_applications", {client_ip = client_ip, action = action})

    if action == "violated" then
        self:increment_counter("adaptive_rate_limit_violations", {client_ip = client_ip, threat_level = threat_level})
    end

    if current_limit then
        self:set_gauge("adaptive_rate_current_limits", {client_ip = client_ip}, current_limit)
    end
end

function PrometheusMetrics:record_adaptive_rate_adjustment(client_ip, direction)
    self:increment_counter("adaptive_rate_adjustments", {client_ip = client_ip, direction = direction})
end

-- DDoS Mitigation Metrics
function PrometheusMetrics:record_ddos_attack(attack_type, severity, duration)
    self:increment_counter("ddos_attacks_detected", {attack_type = attack_type, severity = severity})

    if duration then
        self:observe_histogram("ddos_attack_duration", {attack_type = attack_type}, duration)
    end
end

function PrometheusMetrics:record_ddos_challenge(difficulty_level, client_ip, solved)
    self:increment_counter("ddos_challenges_issued", {difficulty_level = difficulty_level})

    if solved then
        self:increment_counter("ddos_challenges_solved", {difficulty_level = difficulty_level, client_ip = client_ip})
    end
end

function PrometheusMetrics:record_ddos_mitigation(action_type, client_ip)
    self:increment_counter("ddos_mitigation_actions", {action_type = action_type, client_ip = client_ip})
end

-- Geographic Rate Limiting Metrics
function PrometheusMetrics:record_geo_rate_limit(country_code, client_ip, action)
    self:increment_counter("geo_rate_limit_applications", {country_code = country_code, action = action})

    if action == "violated" then
        self:increment_counter("geo_rate_limit_violations", {country_code = country_code, client_ip = client_ip})
    end
end

function PrometheusMetrics:record_geo_anomaly(anomaly_type, country_code, from_country, to_country, client_ip)
    self:increment_counter("geo_anomaly_detections", {anomaly_type = anomaly_type, country_code = country_code})

    if anomaly_type == "impossible_travel" and from_country and to_country then
        self:increment_counter("geo_impossible_travel", {
            from_country = from_country,
            to_country = to_country,
            client_ip = client_ip
        })
    elseif anomaly_type == "vpn_proxy" then
        self:increment_counter("geo_vpn_proxy_detections", {
            service_type = "vpn_proxy",
            country_code = country_code
        })
    end
end

-- Circuit Breaker Metrics
function PrometheusMetrics:record_circuit_breaker_state_change(service_id, from_state, to_state, recovery_time)
    self:increment_counter("circuit_breaker_state_changes", {
        service_id = service_id,
        from_state = from_state,
        to_state = to_state
    })

    if recovery_time and to_state == "closed" then
        self:observe_histogram("circuit_breaker_recovery_time", {service_id = service_id}, recovery_time)
    end
end

function PrometheusMetrics:record_circuit_breaker_block(service_id, reason)
    self:increment_counter("circuit_breaker_requests_blocked", {service_id = service_id, reason = reason})
end

function PrometheusMetrics:record_circuit_breaker_metrics(service_id, failure_rate, response_time)
    if failure_rate then
        self:set_gauge("circuit_breaker_failure_rate", {service_id = service_id}, failure_rate)
    end

    if response_time then
        self:observe_histogram("circuit_breaker_response_time", {service_id = service_id}, response_time)
    end
end

-- General Rate Limiting Metrics
function PrometheusMetrics:record_rate_limit_check(limiter_type, result, client_ip, current_usage, quota_remaining)
    self:increment_counter("rate_limit_requests_total", {limiter_type = limiter_type, result = result})

    if current_usage then
        self:set_gauge("rate_limit_current_usage", {client_ip = client_ip, limiter_type = limiter_type}, current_usage)
    end

    if quota_remaining then
        self:set_gauge("rate_limit_quota_remaining", {client_ip = client_ip, limiter_type = limiter_type}, quota_remaining)
    end
end

-- Clear old metrics (maintenance function)
function PrometheusMetrics:cleanup_old_metrics()
    -- In a production implementation, this would iterate through cache keys
    -- and remove metrics older than a certain threshold
    -- For now, we rely on TTL expiration
end

-- Get metric summary for debugging
function PrometheusMetrics:get_metrics_summary()
    local summary = {
        total_metrics = 0,
        metric_types = {},
        cache_keys_count = 0
    }

    for metric_name, metric_def in pairs(self.metrics) do
        summary.total_metrics = summary.total_metrics + 1
        summary.metric_types[metric_def.type] = (summary.metric_types[metric_def.type] or 0) + 1
    end

    return summary
end

return PrometheusMetrics
