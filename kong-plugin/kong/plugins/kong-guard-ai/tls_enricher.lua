-- TLS Fingerprinting Enricher Module
-- Extracts and enriches TLS fingerprints (JA3/JA4/JA3S/JA4S) from request headers

local TLSEnricher = {}
TLSEnricher.__index = TLSEnricher

-- Initialize the TLS enricher
function TLSEnricher:new(config)
    local self = setmetatable({}, TLSEnricher)
    self.config = config or {}
    self.cache_ttl = config.tls_cache_ttl_seconds or 600
    return self
end

-- Read TLS fingerprint headers from request
function TLSEnricher:read_headers(request, config)
    local headers = request.get_headers() or {}
    local header_map = config.tls_header_map or {}

    local tls_data = {
        ja3 = nil,
        ja3s = nil,
        ja4 = nil,
        ja4s = nil,
        tls_version = nil,
        tls_cipher = nil,
        sni = nil
    }

    -- Extract each fingerprint type using configured header names
    for fp_type, header_name in pairs(header_map) do
        if tls_data[fp_type] ~= nil then  -- Only process known fingerprint types
            local header_value = headers[header_name] or headers[header_name:lower()]
            if header_value and header_value ~= "" then
                tls_data[fp_type] = self:normalize(header_value)
            end
        end
    end

    return tls_data
end

-- Normalize fingerprint values
function TLSEnricher:normalize(value)
    if not value or type(value) ~= "string" then
        return nil
    end

    -- Strip whitespace and convert to lowercase
    local normalized = value:gsub("%s+", ""):lower()

    -- Basic validation for hex-like patterns (JA3/JA4 are typically MD5 hashes)
    -- JA3: 32 character MD5 hash
    -- JA4: variable length but typically alphanumeric
    if #normalized == 0 then
        return nil
    end

    -- Length validation (reasonable bounds)
    if #normalized > 256 then
        kong.log.warn("TLS fingerprint too long, truncating: ", #normalized)
        normalized = normalized:sub(1, 256)
    end

    -- Character set validation (allow alphanumeric and some common separators)
    if not normalized:match("^[a-f0-9_%-%.]+$") then
        kong.log.debug("TLS fingerprint contains unexpected characters: ", normalized)
        -- Still return it, but log for monitoring
    end

    return normalized
end

-- Enrich TLS data with validation and metadata
function TLSEnricher:enrich(tls_data)
    if not tls_data then
        return {
            ja3 = nil,
            ja3s = nil,
            ja4 = nil,
            ja4s = nil,
            tls_version = nil,
            tls_cipher = nil,
            sni = nil,
            valid = false,
            fingerprint_count = 0
        }
    end

    local fingerprint_count = 0
    local has_client_fp = false
    local has_server_fp = false

    -- Count valid fingerprints and categorize
    if tls_data.ja3 then
        fingerprint_count = fingerprint_count + 1
        has_client_fp = true
    end
    if tls_data.ja4 then
        fingerprint_count = fingerprint_count + 1
        has_client_fp = true
    end
    if tls_data.ja3s then
        fingerprint_count = fingerprint_count + 1
        has_server_fp = true
    end
    if tls_data.ja4s then
        fingerprint_count = fingerprint_count + 1
        has_server_fp = true
    end

    return {
        ja3 = tls_data.ja3,
        ja3s = tls_data.ja3s,
        ja4 = tls_data.ja4,
        ja4s = tls_data.ja4s,
        tls_version = tls_data.tls_version,
        tls_cipher = tls_data.tls_cipher,
        sni = tls_data.sni,
        valid = fingerprint_count > 0,
        fingerprint_count = fingerprint_count,
        has_client_fingerprint = has_client_fp,
        has_server_fingerprint = has_server_fp
    }
end

-- Cache operations using Kong's shared memory
function TLSEnricher:cache_get(key)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return nil
    end

    local value, flags = kong_cache:get(key)
    return value
end

function TLSEnricher:cache_set(key, value, ttl)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return false
    end

    local success, err, forcible = kong_cache:set(key, value, ttl or self.cache_ttl)
    if not success then
        kong.log.warn("Failed to cache TLS data: ", err)
        return false
    end

    if forcible then
        kong.log.debug("TLS cache entry was forcibly stored (cache full)")
    end

    return true
end

-- Get fingerprint statistics from cache
function TLSEnricher:get_fingerprint_stats(fingerprint)
    if not fingerprint then
        return {
            request_count = 0,
            unique_ips = 0,
            first_seen = nil,
            last_seen = nil
        }
    end

    local fp_key = "tls_fp_stats:" .. fingerprint
    local stats = self:cache_get(fp_key)

    if stats then
        -- Parse cached stats (stored as JSON-like string)
        local ok, parsed = pcall(require("cjson").decode, stats)
        if ok then
            return parsed
        end
    end

    -- Return default stats if not found or parse error
    return {
        request_count = 0,
        unique_ips = 0,
        first_seen = nil,
        last_seen = nil
    }
end

-- Update fingerprint statistics
function TLSEnricher:update_fingerprint_stats(fingerprint, client_ip)
    if not fingerprint then
        return
    end

    local current_time = os.time()
    local fp_key = "tls_fp_stats:" .. fingerprint
    local stats = self:get_fingerprint_stats(fingerprint)

    -- Update counters
    stats.request_count = (stats.request_count or 0) + 1
    stats.last_seen = current_time

    if not stats.first_seen then
        stats.first_seen = current_time
    end

    -- Track unique IPs (simplified approach using separate cache entries)
    if client_ip then
        local ip_key = "tls_fp_ip:" .. fingerprint .. ":" .. client_ip
        local ip_seen = self:cache_get(ip_key)

        if not ip_seen then
            self:cache_set(ip_key, "1", 3600) -- 1 hour TTL for IP tracking
            stats.unique_ips = (stats.unique_ips or 0) + 1
        end
    end

    -- Store updated stats
    local ok, json_stats = pcall(require("cjson").encode, stats)
    if ok then
        self:cache_set(fp_key, json_stats, self.cache_ttl)
    end
end

-- Get fingerprint velocity (requests per minute)
function TLSEnricher:get_fingerprint_velocity(fingerprint)
    if not fingerprint then
        return 0
    end

    local current_minute = math.floor(os.time() / 60)
    local velocity_key = "tls_fp_velocity:" .. fingerprint .. ":" .. current_minute

    local count = self:cache_get(velocity_key)
    return tonumber(count) or 0
end

-- Increment fingerprint velocity counter
function TLSEnricher:increment_fingerprint_velocity(fingerprint)
    if not fingerprint then
        return 0
    end

    local current_minute = math.floor(os.time() / 60)
    local velocity_key = "tls_fp_velocity:" .. fingerprint .. ":" .. current_minute
    local kong_cache = ngx.shared.kong_cache

    if kong_cache then
        local new_count, err = kong_cache:incr(velocity_key, 1, 0, 60) -- 60 second TTL
        if not new_count then
            kong.log.warn("Failed to increment velocity counter: ", err)
            return 0
        end
        return new_count
    end

    return 0
end

-- Check if fingerprint matches pattern (supports wildcards)
function TLSEnricher:matches_pattern(fingerprint, pattern)
    if not fingerprint or not pattern then
        return false
    end

    -- Convert simple wildcard pattern to Lua pattern
    local lua_pattern = pattern:gsub("%*", ".*")
    lua_pattern = "^" .. lua_pattern .. "$"

    return fingerprint:match(lua_pattern) ~= nil
end

-- Check if any fingerprint matches any pattern in a list
function TLSEnricher:matches_any_pattern(tls_data, pattern_list)
    if not tls_data or not pattern_list or #pattern_list == 0 then
        return false, nil
    end

    local fingerprints = {tls_data.ja3, tls_data.ja3s, tls_data.ja4, tls_data.ja4s}

    for _, pattern in ipairs(pattern_list) do
        for _, fp in ipairs(fingerprints) do
            if fp and self:matches_pattern(fp, pattern) then
                return true, {fingerprint = fp, pattern = pattern}
            end
        end
    end

    return false, nil
end

-- Basic User-Agent to JA3 plausibility check
function TLSEnricher:check_ua_ja3_plausibility(user_agent, ja3)
    if not user_agent or not ja3 then
        return true -- No mismatch if data missing
    end

    local ua_lower = user_agent:lower()

    -- Basic heuristics for major browsers
    -- These are simplified patterns - in production, you'd want more comprehensive mappings
    local known_mappings = {
        -- Chrome patterns
        chrome = {
            indicators = {"chrome", "chromium"},
            suspicious_ja3s = {} -- Would contain known non-Chrome JA3 patterns
        },
        firefox = {
            indicators = {"firefox", "gecko"},
            suspicious_ja3s = {} -- Would contain known non-Firefox JA3 patterns
        },
        safari = {
            indicators = {"safari", "webkit"},
            suspicious_ja3s = {} -- Would contain known non-Safari JA3 patterns
        }
    }

    -- Simple implementation: if we detect a specific browser in UA,
    -- we could flag mismatches with known incompatible JA3s
    -- For now, return true (no mismatch detected) as this requires extensive fingerprint DB

    return true
end

return TLSEnricher
