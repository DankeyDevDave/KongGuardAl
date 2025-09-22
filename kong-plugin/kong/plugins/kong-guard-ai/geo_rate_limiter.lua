-- Kong Guard AI - Geographic Rate Limiter
-- Location-based rate limiting and geographic anomaly detection

local ngx = ngx
local math = math
local string = string
local table = table
local bit = require "bit"

local GeoRateLimiter = {}
GeoRateLimiter.__index = GeoRateLimiter

-- Module constants
local GEO_CACHE_TTL = 3600      -- 1 hour cache for IP-to-country mappings
local ANOMALY_WINDOW = 300      -- 5 minutes for anomaly detection
local DEFAULT_COUNTRY = "XX"    -- Unknown country code

-- Common VPN/Proxy indicators
local VPN_INDICATORS = {
    "vpn", "proxy", "hosting", "cloud", "datacenter", "server",
    "amazon", "google", "microsoft", "digitalocean", "linode"
}

-- Initialize geographic rate limiter
function GeoRateLimiter:new(config)
    local self = setmetatable({}, GeoRateLimiter)

    self.config = config or {}
    self.geo_rate_limits = self.config.geo_rate_limits or {}
    self.default_rate = self.config.default_rate_per_minute or 100
    self.enable_anomaly_detection = self.config.enable_geo_anomaly_detection ~= false
    self.anomaly_threshold = self.config.geo_anomaly_threshold or 0.8

    -- Shared dictionaries
    self.cache = ngx.shared.kong_cache
    self.metrics_cache = ngx.shared.kong_cache

    -- Build country rate limit lookup table
    self.country_limits = {}
    for _, limit_config in ipairs(self.geo_rate_limits) do
        self.country_limits[limit_config.country_code] = limit_config.rate_per_minute
    end

    return self
end

-- Get country code from IP address
function GeoRateLimiter:get_country_from_ip(ip_address)
    if not ip_address then
        return DEFAULT_COUNTRY
    end

    -- Check cache first
    local cache_key = "geo_country:" .. ip_address
    local cached_country = self.cache:get(cache_key)
    if cached_country then
        return cached_country
    end

    -- Determine IP version and get country
    local country = self:resolve_ip_to_country(ip_address)

    -- Cache the result
    self.cache:set(cache_key, country, GEO_CACHE_TTL)

    return country
end

-- Resolve IP to country using various methods
function GeoRateLimiter:resolve_ip_to_country(ip_address)
    -- Try HTTP-based geolocation services (fallback methods)
    local country = self:try_geolocation_services(ip_address)
    if country and country ~= DEFAULT_COUNTRY then
        return country
    end

    -- Try local GeoIP database if available
    country = self:try_local_geoip(ip_address)
    if country and country ~= DEFAULT_COUNTRY then
        return country
    end

    -- Try Kong's built-in geolocation if available
    country = self:try_kong_geolocation(ip_address)
    if country and country ~= DEFAULT_COUNTRY then
        return country
    end

    -- Fallback to basic IP range analysis
    return self:analyze_ip_range(ip_address)
end

-- Try external geolocation services (simplified for demo)
function GeoRateLimiter:try_geolocation_services(ip_address)
    -- This would integrate with services like MaxMind, IPinfo, etc.
    -- For demo purposes, using a simplified implementation

    -- Check for private IP ranges
    if self:is_private_ip(ip_address) then
        return "US" -- Assume private IPs are domestic
    end

    -- Check for common cloud provider ranges
    local cloud_country = self:check_cloud_provider_ranges(ip_address)
    if cloud_country then
        return cloud_country
    end

    return DEFAULT_COUNTRY
end

-- Try local GeoIP database
function GeoRateLimiter:try_local_geoip(ip_address)
    -- This would use MaxMind GeoLite2 or similar database
    -- Implementation would depend on available database format
    return nil
end

-- Try Kong's built-in geolocation
function GeoRateLimiter:try_kong_geolocation(ip_address)
    -- Check if Kong has geolocation capabilities
    if ngx.var.geoip_country_code then
        return ngx.var.geoip_country_code
    end

    -- Check for CloudFlare geo headers
    local cf_country = ngx.var.http_cf_ipcountry
    if cf_country and cf_country ~= "" and cf_country ~= "XX" then
        return cf_country
    end

    -- Check for other proxy geo headers
    local geo_headers = {
        "x-country-code",
        "x-geoip-country",
        "x-forwarded-country",
        "cf-ipcountry"
    }

    for _, header in ipairs(geo_headers) do
        local country = ngx.var["http_" .. string.gsub(header, "-", "_")]
        if country and country ~= "" and country ~= "XX" then
            return string.upper(country)
        end
    end

    return nil
end

-- Analyze IP range for basic geolocation
function GeoRateLimiter:analyze_ip_range(ip_address)
    -- Very basic IP range analysis (for demo purposes)
    -- Real implementation would use proper IP geolocation databases

    if self:is_private_ip(ip_address) then
        return "US" -- Assume private networks are domestic
    end

    -- Check for IPv6
    if string.find(ip_address, ":") then
        return self:analyze_ipv6_range(ip_address)
    end

    -- IPv4 analysis
    return self:analyze_ipv4_range(ip_address)
end

-- Check if IP is in private range
function GeoRateLimiter:is_private_ip(ip_address)
    if string.find(ip_address, ":") then
        -- IPv6 private ranges
        return string.match(ip_address, "^fc[0-9a-f][0-9a-f]:") or  -- fc00::/7
               string.match(ip_address, "^fd[0-9a-f][0-9a-f]:") or  -- fd00::/8
               string.match(ip_address, "^fe80:")                   -- fe80::/10
    else
        -- IPv4 private ranges
        local octets = {}
        for octet in string.gmatch(ip_address, "(%d+)") do
            table.insert(octets, tonumber(octet))
        end

        if #octets == 4 then
            local first, second = octets[1], octets[2]

            -- 10.0.0.0/8
            if first == 10 then
                return true
            end

            -- 172.16.0.0/12
            if first == 172 and second >= 16 and second <= 31 then
                return true
            end

            -- 192.168.0.0/16
            if first == 192 and second == 168 then
                return true
            end

            -- 127.0.0.0/8 (loopback)
            if first == 127 then
                return true
            end
        end
    end

    return false
end

-- Analyze IPv4 range for country hints
function GeoRateLimiter:analyze_ipv4_range(ip_address)
    -- This is a simplified implementation
    -- Real implementation would use proper geolocation databases

    local octets = {}
    for octet in string.gmatch(ip_address, "(%d+)") do
        table.insert(octets, tonumber(octet))
    end

    if #octets == 4 then
        local first = octets[1]

        -- Very rough geographic hints based on first octet
        if first >= 1 and first <= 126 then
            return "US" -- North America
        elseif first >= 128 and first <= 191 then
            return "EU" -- Europe (using EU as placeholder)
        elseif first >= 192 and first <= 223 then
            return "AP" -- Asia Pacific (using AP as placeholder)
        end
    end

    return DEFAULT_COUNTRY
end

-- Analyze IPv6 range for country hints
function GeoRateLimiter:analyze_ipv6_range(ip_address)
    -- Simplified IPv6 analysis
    local prefix = string.sub(ip_address, 1, 4)

    -- Very basic regional allocation hints
    if prefix >= "2001" and prefix <= "2003" then
        return "US"
    elseif prefix >= "2a00" and prefix <= "2a0f" then
        return "EU"
    end

    return DEFAULT_COUNTRY
end

-- Check cloud provider IP ranges
function GeoRateLimiter:check_cloud_provider_ranges(ip_address)
    -- This would check against known cloud provider IP ranges
    -- For demo purposes, simplified implementation

    -- AWS, Google Cloud, Azure ranges would be checked here
    -- Return country where the cloud region is likely located

    return nil
end

-- Get rate limit for specific country
function GeoRateLimiter:get_country_rate_limit(country_code)
    return self.country_limits[country_code] or self.default_rate
end

-- Check if client from country exceeds rate limit
function GeoRateLimiter:check_country_rate_limit(client_ip, country_code, rate_limit)
    local current_time = ngx.now()
    local window_start = math.floor(current_time / 60) * 60 -- 1-minute window

    -- Track per-IP rate within country context
    local rate_key = "geo_rate:" .. country_code .. ":" .. client_ip .. ":" .. window_start
    local count = self.cache:incr(rate_key, 1, 0, 60)

    -- Update country-level metrics
    self:update_country_metrics(country_code, count or 1, rate_limit)

    return (count or 1) > rate_limit
end

-- Detect geographic anomalies
function GeoRateLimiter:detect_geographic_anomaly(client_ip, current_country)
    if not self.enable_anomaly_detection then
        return {
            is_anomaly = false,
            confidence = 0,
            reason = "detection_disabled"
        }
    end

    -- Get client's geographic history
    local geo_history = self:get_client_geo_history(client_ip)

    -- Analyze for anomalies
    local anomaly_results = {
        is_anomaly = false,
        confidence = 0,
        reason = nil,
        details = {}
    }

    -- Check for rapid geographic changes
    local rapid_change = self:detect_rapid_geo_change(geo_history, current_country)
    if rapid_change.detected then
        anomaly_results.is_anomaly = true
        anomaly_results.confidence = math.max(anomaly_results.confidence, rapid_change.confidence)
        anomaly_results.reason = "rapid_geographic_change"
        anomaly_results.details.rapid_change = rapid_change
    end

    -- Check for impossible travel
    local impossible_travel = self:detect_impossible_travel(geo_history, current_country)
    if impossible_travel.detected then
        anomaly_results.is_anomaly = true
        anomaly_results.confidence = math.max(anomaly_results.confidence, impossible_travel.confidence)
        anomaly_results.reason = "impossible_travel"
        anomaly_results.details.impossible_travel = impossible_travel
    end

    -- Check for VPN/proxy indicators
    local vpn_indicators = self:detect_vpn_proxy_usage(client_ip, current_country, geo_history)
    if vpn_indicators.detected then
        anomaly_results.is_anomaly = true
        anomaly_results.confidence = math.max(anomaly_results.confidence, vpn_indicators.confidence)
        anomaly_results.reason = "vpn_proxy_detected"
        anomaly_results.details.vpn_proxy = vpn_indicators
    end

    -- Update the client's geo history
    self:update_client_geo_history(client_ip, current_country)

    return anomaly_results
end

-- Get client's geographic history
function GeoRateLimiter:get_client_geo_history(client_ip)
    local history_key = "geo_history:" .. client_ip
    local history_json = self.cache:get(history_key)

    if history_json then
        local success, history = pcall(require("cjson").decode, history_json)
        if success and history then
            return history
        end
    end

    return { locations = {}, first_seen = ngx.now() }
end

-- Update client's geographic history
function GeoRateLimiter:update_client_geo_history(client_ip, country_code)
    local history = self:get_client_geo_history(client_ip)
    local current_time = ngx.now()

    -- Add new location entry
    table.insert(history.locations, {
        country = country_code,
        timestamp = current_time,
        ip = client_ip
    })

    -- Keep only recent entries (last 24 hours)
    local cutoff_time = current_time - 86400 -- 24 hours
    local filtered_locations = {}
    for _, location in ipairs(history.locations) do
        if location.timestamp > cutoff_time then
            table.insert(filtered_locations, location)
        end
    end
    history.locations = filtered_locations

    -- Update first_seen if needed
    if not history.first_seen then
        history.first_seen = current_time
    end

    -- Cache updated history
    local history_key = "geo_history:" .. client_ip
    local cjson = require("cjson")
    self.cache:set(history_key, cjson.encode(history), 86400) -- 24 hours
end

-- Detect rapid geographic changes
function GeoRateLimiter:detect_rapid_geo_change(geo_history, current_country)
    if #geo_history.locations < 2 then
        return { detected = false, confidence = 0 }
    end

    local recent_countries = {}
    local cutoff_time = ngx.now() - 3600 -- Last hour

    for _, location in ipairs(geo_history.locations) do
        if location.timestamp > cutoff_time then
            recent_countries[location.country] = true
        end
    end

    local unique_countries = 0
    for _ in pairs(recent_countries) do
        unique_countries = unique_countries + 1
    end

    -- More than 3 countries in 1 hour is suspicious
    if unique_countries > 3 then
        return {
            detected = true,
            confidence = math.min(unique_countries / 5, 1.0),
            unique_countries = unique_countries,
            time_window = 3600
        }
    end

    return { detected = false, confidence = 0 }
end

-- Detect impossible travel patterns
function GeoRateLimiter:detect_impossible_travel(geo_history, current_country)
    if #geo_history.locations < 1 then
        return { detected = false, confidence = 0 }
    end

    local last_location = geo_history.locations[#geo_history.locations]
    local time_diff = ngx.now() - last_location.timestamp

    -- If less than 30 minutes between locations, check distance
    if time_diff < 1800 then -- 30 minutes
        local distance = self:estimate_country_distance(last_location.country, current_country)

        -- If countries are far apart, calculate if travel is possible
        if distance > 1000 then -- More than 1000km
            local max_speed = 900 -- km/h (commercial aircraft speed)
            local required_time = distance / max_speed * 3600 -- Convert to seconds

            if time_diff < required_time then
                return {
                    detected = true,
                    confidence = 1.0 - (time_diff / required_time),
                    distance_km = distance,
                    time_diff_seconds = time_diff,
                    required_time_seconds = required_time,
                    from_country = last_location.country,
                    to_country = current_country
                }
            end
        end
    end

    return { detected = false, confidence = 0 }
end

-- Estimate distance between countries (simplified)
function GeoRateLimiter:estimate_country_distance(country1, country2)
    if country1 == country2 then
        return 0
    end

    -- Simplified distance estimation
    -- Real implementation would use proper geographic data
    local continent_distances = {
        ["US"] = { ["EU"] = 7000, ["AP"] = 12000, ["CN"] = 11000 },
        ["EU"] = { ["US"] = 7000, ["AP"] = 8000, ["CN"] = 7000 },
        ["AP"] = { ["US"] = 12000, ["EU"] = 8000, ["CN"] = 3000 },
        ["CN"] = { ["US"] = 11000, ["EU"] = 7000, ["AP"] = 3000 }
    }

    if continent_distances[country1] and continent_distances[country1][country2] then
        return continent_distances[country1][country2]
    end

    -- Default large distance for unknown combinations
    return 5000
end

-- Detect VPN/proxy usage indicators
function GeoRateLimiter:detect_vpn_proxy_usage(client_ip, current_country, geo_history)
    local indicators = {
        detected = false,
        confidence = 0,
        indicators = {}
    }

    -- Check reverse DNS for VPN/proxy indicators
    local reverse_dns = self:get_reverse_dns(client_ip)
    if reverse_dns then
        for _, indicator in ipairs(VPN_INDICATORS) do
            if string.find(string.lower(reverse_dns), indicator, 1, true) then
                indicators.detected = true
                indicators.confidence = math.max(indicators.confidence, 0.8)
                table.insert(indicators.indicators, "dns:" .. indicator)
            end
        end
    end

    -- Check for hosting/datacenter IP ranges
    if self:is_hosting_ip(client_ip) then
        indicators.detected = true
        indicators.confidence = math.max(indicators.confidence, 0.7)
        table.insert(indicators.indicators, "hosting_ip")
    end

    -- Check for frequent country changes
    if #geo_history.locations > 5 then
        local unique_countries = {}
        for _, location in ipairs(geo_history.locations) do
            unique_countries[location.country] = true
        end

        local country_count = 0
        for _ in pairs(unique_countries) do
            country_count = country_count + 1
        end

        if country_count > 3 then
            indicators.detected = true
            indicators.confidence = math.max(indicators.confidence, 0.6)
            table.insert(indicators.indicators, "frequent_country_changes")
        end
    end

    return indicators
end

-- Get reverse DNS for IP (simplified)
function GeoRateLimiter:get_reverse_dns(ip_address)
    -- This would perform actual reverse DNS lookup
    -- For demo purposes, returning nil
    return nil
end

-- Check if IP is from hosting/datacenter
function GeoRateLimiter:is_hosting_ip(ip_address)
    -- This would check against known hosting provider IP ranges
    -- For demo purposes, simplified check
    return false
end

-- Update country-level metrics
function GeoRateLimiter:update_country_metrics(country_code, current_rate, rate_limit)
    -- Track requests per country
    local country_requests_key = "country_requests:" .. country_code
    self.metrics_cache:incr(country_requests_key, 1, 0, 3600)

    -- Track rate limit violations per country
    if current_rate > rate_limit then
        local country_violations_key = "country_violations:" .. country_code
        self.metrics_cache:incr(country_violations_key, 1, 0, 3600)
    end
end

-- Get geographic statistics
function GeoRateLimiter:get_statistics()
    local stats = {
        total_countries_seen = 0,
        top_countries = {},
        anomalies_detected = 0,
        vpn_proxy_detected = 0
    }

    -- This would require key iteration in real implementation
    -- For demo purposes, returning basic structure

    return stats
end

-- Get country distribution
function GeoRateLimiter:get_country_distribution()
    local distribution = {}

    -- This would iterate through country request keys
    -- For demo purposes, returning empty

    return distribution
end

-- Apply geographic restrictions
function GeoRateLimiter:apply_geographic_restrictions(client_ip, country_code, config)
    local restrictions = {
        blocked = false,
        rate_limited = false,
        reason = nil
    }

    -- Check country blocklist
    if config.blocked_countries then
        for _, blocked_country in ipairs(config.blocked_countries) do
            if country_code == blocked_country then
                restrictions.blocked = true
                restrictions.reason = "country_blocked"
                return restrictions
            end
        end
    end

    -- Check country allowlist
    if config.allowed_countries then
        local allowed = false
        for _, allowed_country in ipairs(config.allowed_countries) do
            if country_code == allowed_country then
                allowed = true
                break
            end
        end

        if not allowed then
            restrictions.blocked = true
            restrictions.reason = "country_not_allowed"
            return restrictions
        end
    end

    -- Apply country-specific rate limits
    local rate_limit = self:get_country_rate_limit(country_code)
    if self:check_country_rate_limit(client_ip, country_code, rate_limit) then
        restrictions.rate_limited = true
        restrictions.reason = "country_rate_limit_exceeded"
        restrictions.rate_limit = rate_limit
    end

    return restrictions
end

return GeoRateLimiter