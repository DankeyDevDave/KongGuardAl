--- Threat Hunting Engine for Kong Guard AI
-- Provides advanced threat hunting capabilities with pattern-based searches and correlation

local cjson = require "cjson.safe"
local ngx = ngx
local kong = kong

local _M = {}

-- Module constants
local MAX_QUERY_RESULTS = 1000
local QUERY_TIMEOUT = 30000 -- 30 seconds
local CACHE_TTL = 300 -- 5 minutes
local MAX_CORRELATION_WINDOW = 3600 -- 1 hour

--- Create a new threat hunter instance
-- @param config The plugin configuration
-- @return Threat hunter instance
function _M.new(config)
    if not config then
        return nil, "Configuration is required"
    end

    local self = {
        config = config,
        query_cache = {},
        hunting_results = {},
        correlation_data = {},
        pattern_library = {},
        metrics = {
            queries_executed = 0,
            matches_found = 0,
            correlations_detected = 0,
            cache_hits = 0,
            cache_misses = 0
        }
    }

    -- Initialize pattern library
    self:initialize_pattern_library()

    return setmetatable(self, { __index = _M })
end

--- Initialize the threat hunter
-- @return success, error
function _M:init()
    if not self.config.threat_hunting then
        return false, "Threat hunting configuration is missing"
    end

    if not self.config.threat_hunting.enable_hunting then
        kong.log.debug("Threat hunting is disabled")
        return true
    end

    -- Validate hunting queries
    local queries = self.config.threat_hunting.hunting_queries or {}
    for i, query in ipairs(queries) do
        if not query or #query == 0 then
            return false, "Hunting query " .. i .. " is empty"
        end
    end

    kong.log.info("Threat hunter initialized with ", #queries, " hunting queries")
    return true
end

--- Initialize the pattern library with common threat patterns
function _M:initialize_pattern_library()
    self.pattern_library = {
        -- SQL Injection patterns
        sql_injection = {
            patterns = {
                "union%s+select",
                "drop%s+table",
                "insert%s+into",
                "select%s+from",
                "exec%s+sp_",
                "xp_cmdshell"
            },
            severity = "high",
            category = "injection"
        },

        -- XSS patterns
        xss = {
            patterns = {
                "<script",
                "javascript:",
                "onerror=",
                "onload=",
                "eval%(",
                "document%.cookie"
            },
            severity = "high",
            category = "injection"
        },

        -- Directory traversal patterns
        directory_traversal = {
            patterns = {
                "%.%.%/",
                "%.%.\\",
                "%.%./",
                "%.%.\\",
                "/etc/passwd",
                "/etc/shadow",
                "c:\\windows\\system32"
            },
            severity = "high",
            category = "traversal"
        },

        -- Command injection patterns
        command_injection = {
            patterns = {
                "%|%s*cat",
                "%|%s*ls",
                "%|%s*rm",
                "%|%s*wget",
                "%|%s*curl",
                "&&%s*rm",
                "&&%s*wget"
            },
            severity = "critical",
            category = "injection"
        },

        -- Suspicious user agents
        suspicious_ua = {
            patterns = {
                "sqlmap",
                "nmap",
                "nikto",
                "dirbuster",
                "gobuster",
                "masscan",
                "zgrab"
            },
            severity = "medium",
            category = "reconnaissance"
        },

        -- Anomalous request patterns
        anomalous_requests = {
            patterns = {
                "%.php%?.*=",
                "%.asp%?.*=",
                "%.jsp%?.*=",
                "/admin",
                "/wp-admin",
                "/wp-login",
                "/phpmyadmin"
            },
            severity = "low",
            category = "suspicious"
        }
    }
end

--- Execute threat hunting queries
-- @param time_window Time window in seconds (optional)
-- @return results, error
function _M:execute_hunting_queries(time_window)
    if not self.config.threat_hunting.enable_hunting then
        return {}, "Threat hunting is disabled"
    end

    time_window = time_window or 3600 -- 1 hour default
    local results = {}
    local queries = self.config.threat_hunting.hunting_queries or {}

    kong.log.info("Executing ", #queries, " threat hunting queries")

    for _, query in ipairs(queries) do
        local query_results, err = self:execute_query(query, time_window)
        if err then
            kong.log.err("Query execution failed: ", query, " - ", err)
        else
            for _, result in ipairs(query_results) do
                table.insert(results, result)
            end
        end
    end

    -- Apply correlation analysis
    local correlated_results = self:analyze_correlations(results, time_window)

    self.metrics.queries_executed = self.metrics.queries_executed + #queries
    self.metrics.matches_found = self.metrics.matches_found + #results

    return correlated_results
end

--- Execute a single hunting query
-- @param query The query string
-- @param time_window Time window in seconds
-- @return results, error
function _M:execute_query(query, time_window)
    if not query or #query == 0 then
        return {}, "Query is empty"
    end

    -- Check cache first
    local cache_key = query .. "_" .. time_window
    if self.query_cache[cache_key] and
       (ngx.now() - self.query_cache[cache_key].timestamp) < CACHE_TTL then
        self.metrics.cache_hits = self.metrics.cache_hits + 1
        return self.query_cache[cache_key].results
    end

    self.metrics.cache_misses = self.metrics.cache_misses + 1

    local results = {}
    local start_time = ngx.now() - time_window

    -- Parse query type
    if query:find("^pattern:") then
        results = self:execute_pattern_query(query, start_time)
    elseif query:find("^statistical:") then
        results = self:execute_statistical_query(query, start_time)
    elseif query:find("^correlation:") then
        results = self:execute_correlation_query(query, start_time)
    else
        -- Default to pattern matching
        results = self:execute_pattern_query("pattern:" .. query, start_time)
    end

    -- Cache results
    self.query_cache[cache_key] = {
        results = results,
        timestamp = ngx.now()
    }

    return results
end

--- Execute pattern-based query
-- @param query The pattern query
-- @param start_time Start time for the query
-- @return results
function _M:execute_pattern_query(query, start_time)
    local pattern = query:gsub("^pattern:", "")
    local results = {}

    -- Search through recent request data
    -- In a real implementation, this would query a data store
    -- For now, we'll simulate pattern matching against stored data

    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time then
            if self:matches_pattern(data, pattern) then
                table.insert(results, {
                    type = "pattern_match",
                    pattern = pattern,
                    data = data,
                    timestamp = data.timestamp,
                    severity = self:calculate_pattern_severity(pattern),
                    category = self:get_pattern_category(pattern)
                })
            end
        end

        if #results >= MAX_QUERY_RESULTS then
            break
        end
    end

    return results
end

--- Execute statistical analysis query
-- @param query The statistical query
-- @param start_time Start time for the query
-- @return results
function _M:execute_statistical_query(query, start_time)
    local stat_type = query:gsub("^statistical:", "")
    local results = {}

    -- Analyze statistical anomalies
    if stat_type == "anomalous_traffic" then
        results = self:analyze_traffic_anomalies(start_time)
    elseif stat_type == "unusual_patterns" then
        results = self:analyze_unusual_patterns(start_time)
    elseif stat_type == "frequency_analysis" then
        results = self:analyze_frequency_patterns(start_time)
    end

    return results
end

--- Execute correlation query
-- @param query The correlation query
-- @param start_time Start time for the query
-- @return results
function _M:execute_correlation_query(query, start_time)
    local correlation_type = query:gsub("^correlation:", "")
    local results = {}

    -- Analyze correlations between events
    if correlation_type == "ip_useragent" then
        results = self:correlate_ip_useragent(start_time)
    elseif correlation_type == "time_based" then
        results = self:correlate_time_based(start_time)
    elseif correlation_type == "behavioral" then
        results = self:correlate_behavioral_patterns(start_time)
    end

    return results
end

--- Check if data matches a pattern
-- @param data The request/response data
-- @param pattern The pattern to match
-- @return boolean
function _M:matches_pattern(data, pattern)
    if not data or not pattern then
        return false
    end

    -- Check various data fields for pattern matches
    local fields_to_check = {
        data.request_path or "",
        data.user_agent or "",
        data.query_string or "",
        data.request_body or "",
        data.headers and cjson.encode(data.headers) or ""
    }

    for _, field in ipairs(fields_to_check) do
        if field:find(pattern) then
            return true
        end
    end

    return false
end

--- Analyze traffic anomalies
-- @param start_time Start time for analysis
-- @return results
function _M:analyze_traffic_anomalies(start_time)
    local results = {}
    local ip_counts = {}
    local path_counts = {}

    -- Count requests by IP and path
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time then
            ip_counts[data.client_ip] = (ip_counts[data.client_ip] or 0) + 1
            path_counts[data.request_path] = (path_counts[data.request_path] or 0) + 1
        end
    end

    -- Detect anomalous patterns
    for ip, count in pairs(ip_counts) do
        if count > 100 then -- Threshold for suspicious activity
            table.insert(results, {
                type = "traffic_anomaly",
                anomaly_type = "high_frequency_ip",
                ip = ip,
                request_count = count,
                severity = "medium",
                timestamp = ngx.now()
            })
        end
    end

    for path, count in pairs(path_counts) do
        if count > 50 and path:find("%.php$") then
            table.insert(results, {
                type = "traffic_anomaly",
                anomaly_type = "frequent_php_access",
                path = path,
                request_count = count,
                severity = "low",
                timestamp = ngx.now()
            })
        end
    end

    return results
end

--- Analyze unusual patterns
-- @param start_time Start time for analysis
-- @return results
function _M:analyze_unusual_patterns(start_time)
    local results = {}
    local user_agent_patterns = {}

    -- Analyze user agent patterns
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time and data.user_agent then
            local ua_key = data.user_agent:gsub("%d+", "X") -- Normalize versions
            user_agent_patterns[ua_key] = user_agent_patterns[ua_key] or {}
            table.insert(user_agent_patterns[ua_key], data)
        end
    end

    -- Detect unusual user agents
    for ua_pattern, requests in pairs(user_agent_patterns) do
        if #requests < 3 then -- Rare user agent
            table.insert(results, {
                type = "unusual_pattern",
                pattern_type = "rare_user_agent",
                user_agent_pattern = ua_pattern,
                occurrences = #requests,
                severity = "low",
                timestamp = ngx.now()
            })
        end
    end

    return results
end

--- Analyze frequency patterns
-- @param start_time Start time for analysis
-- @return results
function _M:analyze_frequency_patterns(start_time)
    local results = {}
    local time_windows = {}
    local window_size = 300 -- 5 minutes

    -- Group requests by time windows
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time then
            local window = math.floor(data.timestamp / window_size) * window_size
            time_windows[window] = (time_windows[window] or 0) + 1
        end
    end

    -- Detect frequency spikes
    local avg_requests = 0
    local window_count = 0
    for _, count in pairs(time_windows) do
        avg_requests = avg_requests + count
        window_count = window_count + 1
    end
    avg_requests = window_count > 0 and avg_requests / window_count or 0

    for window, count in pairs(time_windows) do
        if count > avg_requests * 2 then -- 2x average
            table.insert(results, {
                type = "frequency_pattern",
                pattern_type = "traffic_spike",
                window_start = window,
                request_count = count,
                average_requests = avg_requests,
                severity = "medium",
                timestamp = ngx.now()
            })
        end
    end

    return results
end

--- Correlate IP with user agent patterns
-- @param start_time Start time for analysis
-- @return results
function _M:correlate_ip_useragent(start_time)
    local results = {}
    local ip_ua_map = {}

    -- Build IP to user agent mapping
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time and data.client_ip and data.user_agent then
            ip_ua_map[data.client_ip] = ip_ua_map[data.client_ip] or {}
            ip_ua_map[data.client_ip][data.user_agent] = (ip_ua_map[data.client_ip][data.user_agent] or 0) + 1
        end
    end

    -- Detect suspicious correlations
    for ip, ua_counts in pairs(ip_ua_map) do
        local ua_count = 0
        for _ in pairs(ua_counts) do
            ua_count = ua_count + 1
        end

        if ua_count > 5 then -- IP using many different user agents
            table.insert(results, {
                type = "correlation",
                correlation_type = "ip_useragent_variety",
                ip = ip,
                unique_user_agents = ua_count,
                severity = "medium",
                timestamp = ngx.now()
            })
        end
    end

    return results
end

--- Analyze time-based correlations
-- @param start_time Start time for analysis
-- @return results
function _M:analyze_time_based_correlations(start_time)
    local results = {}
    local event_sequences = {}

    -- Group events by IP and time windows
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time then
            local key = data.client_ip .. "_" .. math.floor(data.timestamp / 600) -- 10-minute windows
            event_sequences[key] = event_sequences[key] or {}
            table.insert(event_sequences[key], data)
        end
    end

    -- Detect sequential suspicious activities
    for _, events in pairs(event_sequences) do
        if #events >= 3 then
            local has_sql = false
            local has_xss = false
            local has_traversal = false

            for _, event in ipairs(events) do
                if event.request_path and event.request_path:find("union%s+select") then
                    has_sql = true
                end
                if event.request_path and event.request_path:find("<script") then
                    has_xss = true
                end
                if event.request_path and event.request_path:find("%.%.%/") then
                    has_traversal = true
                end
            end

            if has_sql or has_xss or has_traversal then
                table.insert(results, {
                    type = "correlation",
                    correlation_type = "sequential_attacks",
                    ip = events[1].client_ip,
                    event_count = #events,
                    attack_types = {
                        sql_injection = has_sql,
                        xss = has_xss,
                        directory_traversal = has_traversal
                    },
                    severity = "high",
                    timestamp = ngx.now()
                })
            end
        end
    end

    return results
end

--- Analyze behavioral patterns
-- @param start_time Start time for analysis
-- @return results
function _M:analyze_behavioral_patterns(start_time)
    local results = {}
    local ip_behaviors = {}

    -- Analyze behavior patterns per IP
    for _, data in ipairs(self.correlation_data) do
        if data.timestamp >= start_time and data.client_ip then
            ip_behaviors[data.client_ip] = ip_behaviors[data.client_ip] or {
                request_count = 0,
                error_count = 0,
                unique_paths = {},
                methods = {},
                response_codes = {}
            }

            local behavior = ip_behaviors[data.client_ip]
            behavior.request_count = behavior.request_count + 1

            if data.response_code and data.response_code >= 400 then
                behavior.error_count = behavior.error_count + 1
            end

            if data.request_path then
                behavior.unique_paths[data.request_path] = true
            end

            if data.request_method then
                behavior.methods[data.request_method] = (behavior.methods[data.request_method] or 0) + 1
            end

            if data.response_code then
                behavior.response_codes[data.response_code] = (behavior.response_codes[data.response_code] or 0) + 1
            end
        end
    end

    -- Detect suspicious behavioral patterns
    for ip, behavior in pairs(ip_behaviors) do
        local unique_path_count = 0
        for _ in pairs(behavior.unique_paths) do
            unique_path_count = unique_path_count + 1
        end

        local error_rate = behavior.request_count > 0 and behavior.error_count / behavior.request_count or 0

        -- High error rate with many unique paths (probing/scanning)
        if error_rate > 0.5 and unique_path_count > 10 then
            table.insert(results, {
                type = "behavioral_pattern",
                pattern_type = "probing_scan",
                ip = ip,
                request_count = behavior.request_count,
                error_count = behavior.error_count,
                error_rate = error_rate,
                unique_paths = unique_path_count,
                severity = "high",
                timestamp = ngx.now()
            })
        end

        -- Unusual method distribution
        local get_count = behavior.methods.GET or 0
        local post_count = behavior.methods.POST or 0
        if post_count > get_count * 3 then -- Mostly POST requests
            table.insert(results, {
                type = "behavioral_pattern",
                pattern_type = "unusual_method_distribution",
                ip = ip,
                get_requests = get_count,
                post_requests = post_count,
                severity = "medium",
                timestamp = ngx.now()
            })
        end
    end

    return results
end

--- Analyze correlations across all hunting results
-- @param results Raw hunting results
-- @param time_window Time window for correlation
-- @return correlated_results
function _M:analyze_correlations(results, time_window)
    if #results == 0 then
        return results
    end

    local correlated_results = {}
    local correlation_groups = {}

    -- Group results by IP and time windows
    for _, result in ipairs(results) do
        if result.data and result.data.client_ip then
            local window = math.floor(result.timestamp / 300) * 300 -- 5-minute windows
            local key = result.data.client_ip .. "_" .. window

            correlation_groups[key] = correlation_groups[key] or {}
            table.insert(correlation_groups[key], result)
        end
    end

    -- Analyze correlations within groups
    for _, group in pairs(correlation_groups) do
        if #group >= 2 then
            -- Multiple suspicious activities from same IP in short time
            local severity_sum = 0
            local categories = {}

            for _, result in ipairs(group) do
                if result.severity == "critical" then
                    severity_sum = severity_sum + 3
                elseif result.severity == "high" then
                    severity_sum = severity_sum + 2
                elseif result.severity == "medium" then
                    severity_sum = severity_sum + 1
                end

                categories[result.category or "unknown"] = true
            end

            local category_count = 0
            for _ in pairs(categories) do
                category_count = category_count + 1
            end

            if severity_sum >= 3 or category_count >= 2 then
                table.insert(correlated_results, {
                    type = "correlation_alert",
                    correlation_type = "multi_vector_attack",
                    ip = group[1].data.client_ip,
                    event_count = #group,
                    severity_sum = severity_sum,
                    category_count = category_count,
                    time_window = 300,
                    severity = severity_sum >= 5 and "critical" or "high",
                    timestamp = ngx.now(),
                    correlated_events = group
                })

                self.metrics.correlations_detected = self.metrics.correlations_detected + 1
            end
        end
    end

    -- Add original results
    for _, result in ipairs(results) do
        table.insert(correlated_results, result)
    end

    return correlated_results
end

--- Calculate severity for a pattern match
-- @param pattern The matched pattern
-- @return severity string
function _M:calculate_pattern_severity(pattern)
    for _, pattern_info in pairs(self.pattern_library) do
        for _, p in ipairs(pattern_info.patterns) do
            if pattern:find(p) then
                return pattern_info.severity
            end
        end
    end
    return "low"
end

--- Get category for a pattern match
-- @param pattern The matched pattern
-- @return category string
function _M:get_pattern_category(pattern)
    for _, pattern_info in pairs(self.pattern_library) do
        for _, p in ipairs(pattern_info.patterns) do
            if pattern:find(p) then
                return pattern_info.category
            end
        end
    end
    return "unknown"
end

--- Add data to correlation analysis
-- @param data Request/response data to analyze
function _M:add_correlation_data(data)
    if not data or not data.timestamp then
        return
    end

    table.insert(self.correlation_data, {
        timestamp = data.timestamp,
        client_ip = data.client_ip,
        request_path = data.request_path,
        request_method = data.request_method,
        user_agent = data.user_agent,
        query_string = data.query_string,
        request_body = data.request_body,
        response_code = data.response_code,
        headers = data.headers,
        threat_score = data.threat_score
    })

    -- Maintain data retention limit
    local retention_seconds = self.config.threat_hunting.data_retention_days * 86400
    local cutoff_time = ngx.now() - retention_seconds

    while #self.correlation_data > 0 and self.correlation_data[1].timestamp < cutoff_time do
        table.remove(self.correlation_data, 1)
    end
end

--- Get threat hunter health and metrics
-- @return status table
function _M:get_health_status()
    local correlation_data_count = #self.correlation_data
    local cache_entries = 0
    for _ in pairs(self.query_cache) do
        cache_entries = cache_entries + 1
    end

    return {
        enabled = self.config.threat_hunting and self.config.threat_hunting.enable_hunting or false,
        correlation_data_count = correlation_data_count,
        cache_entries = cache_entries,
        pattern_library_size = #self.pattern_library,
        metrics = self.metrics,
        data_retention_days = self.config.threat_hunting and self.config.threat_hunting.data_retention_days or 30
    }
end

--- Clean up old cached data
function _M:cleanup_cache()
    local now = ngx.now()
    local cleanup_count = 0

    for key, entry in pairs(self.query_cache) do
        if (now - entry.timestamp) > CACHE_TTL then
            self.query_cache[key] = nil
            cleanup_count = cleanup_count + 1
        end
    end

    if cleanup_count > 0 then
        kong.log.info("Cleaned up ", cleanup_count, " expired cache entries")
    end
end

return _M
