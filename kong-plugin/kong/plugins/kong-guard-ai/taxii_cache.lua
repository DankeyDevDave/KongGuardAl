local cjson = require "cjson.safe"
local ipmatcher = require "resty.ipmatcher"

local TaxiiCache = {}
TaxiiCache.__index = TaxiiCache

-- Cache namespace and key patterns
local CACHE_NAMESPACE = "taxii"
local VERSION_KEY = CACHE_NAMESPACE .. ":version"
local METADATA_KEY = CACHE_NAMESPACE .. ":metadata"

-- Cache key patterns
local function make_indicator_key(version, ioc_type, value)
    return string.format("%s:%s:%s:%s", CACHE_NAMESPACE, version, ioc_type, value)
end

local function make_collection_state_key(server_url, collection_id)
    return string.format("%s:state:%s:%s", CACHE_NAMESPACE,
        ngx.md5(server_url), collection_id)
end

-- Create new TAXII cache instance
function TaxiiCache.new(config)
    local self = setmetatable({}, TaxiiCache)
    self.config = config or {}
    self.ttl = config.taxii_cache_ttl_seconds or 3600
    self.cache_dict = ngx.shared.kong_cache
    self.current_version = nil

    if not self.cache_dict then
        kong.log.error("[TaxiiCache] kong_cache shared dict not available")
        return nil
    end

    return self
end

-- Log helper function
local function log_message(level, message, context)
    local log_func = kong.log[level] or kong.log.info
    if context then
        log_func("[TaxiiCache] " .. message .. " - " .. cjson.encode(context))
    else
        log_func("[TaxiiCache] " .. message)
    end
end

-- Get current cache version
function TaxiiCache:get_current_version()
    if self.current_version then
        return self.current_version
    end

    local version, err = self.cache_dict:get(VERSION_KEY)
    if err then
        log_message("error", "Failed to get cache version", {error = err})
        return nil
    end

    -- Initialize with version 1 if not set
    if not version then
        version = "1"
        local success, set_err = self.cache_dict:set(VERSION_KEY, version)
        if not success then
            log_message("error", "Failed to initialize cache version", {error = set_err})
            return nil
        end
    end

    self.current_version = version
    return version
end

-- Generate next version for atomic swap
function TaxiiCache:generate_next_version()
    local current = self:get_current_version()
    if not current then
        return nil
    end

    local current_num = tonumber(current)
    if not current_num then
        current_num = 1
    end

    return tostring(current_num + 1)
end

-- Set cache metadata
function TaxiiCache:set_metadata(data)
    local serialized = cjson.encode(data)
    local success, err = self.cache_dict:set(METADATA_KEY, serialized, self.ttl)
    if not success then
        log_message("error", "Failed to set cache metadata", {error = err})
        return false
    end
    return true
end

-- Get cache metadata
function TaxiiCache:get_metadata()
    local serialized, err = self.cache_dict:get(METADATA_KEY)
    if err then
        log_message("error", "Failed to get cache metadata", {error = err})
        return nil
    end

    if not serialized then
        return {}
    end

    local data, decode_err = cjson.decode(serialized)
    if not data then
        log_message("error", "Failed to decode cache metadata", {error = decode_err})
        return {}
    end

    return data
end

-- Store indicator in cache with version
function TaxiiCache:store_indicator(version, ioc_type, value, metadata)
    local key = make_indicator_key(version, ioc_type, value)
    local data = {
        value = value,
        type = ioc_type,
        metadata = metadata,
        timestamp = ngx.time()
    }

    local serialized = cjson.encode(data)
    local success, err = self.cache_dict:set(key, serialized, self.ttl)

    if not success then
        log_message("error", "Failed to store indicator", {
            key = key,
            error = err
        })
        return false
    end

    return true
end

-- Bulk load indicators for a specific version
function TaxiiCache:bulk_load_indicators(version, indicator_sets)
    local total_loaded = 0
    local errors = 0

    log_message("info", "Starting bulk load", {
        version = version,
        sets_count = self:count_sets(indicator_sets)
    })

    -- Load IP addresses
    for ip, metadata in pairs(indicator_sets.ip_set or {}) do
        if self:store_indicator(version, "ip", ip, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load CIDR ranges
    for cidr, metadata in pairs(indicator_sets.cidr_set or {}) do
        if self:store_indicator(version, "cidr", cidr, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load domains
    for domain, metadata in pairs(indicator_sets.domain_set or {}) do
        if self:store_indicator(version, "domain", domain, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load URLs
    for url, metadata in pairs(indicator_sets.url_set or {}) do
        if self:store_indicator(version, "url", url, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load JA3 fingerprints
    for ja3, metadata in pairs(indicator_sets.ja3_set or {}) do
        if self:store_indicator(version, "ja3", ja3, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load JA4 fingerprints
    for ja4, metadata in pairs(indicator_sets.ja4_set or {}) do
        if self:store_indicator(version, "ja4", ja4, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load regex patterns
    for regex, metadata in pairs(indicator_sets.regex_set or {}) do
        if self:store_indicator(version, "regex", regex, metadata) then
            total_loaded = total_loaded + 1
        else
            errors = errors + 1
        end
    end

    -- Load hash sets (if present in future)
    if indicator_sets.hash_set then
        for hash_type, hashes in pairs(indicator_sets.hash_set) do
            for hash, metadata in pairs(hashes) do
                if self:store_indicator(version, "hash_" .. hash_type, hash, metadata) then
                    total_loaded = total_loaded + 1
                else
                    errors = errors + 1
                end
            end
        end
    end

    log_message("info", "Bulk load completed", {
        version = version,
        loaded = total_loaded,
        errors = errors
    })

    return {
        loaded = total_loaded,
        errors = errors
    }
end

-- Count indicators in sets
function TaxiiCache:count_sets(indicator_sets)
    local count = 0

    for _, set in pairs(indicator_sets) do
        if type(set) == "table" then
            for _, _ in pairs(set) do
                count = count + 1
            end
        end
    end

    return count
end

-- Perform atomic version swap
function TaxiiCache:atomic_swap_version(new_version)
    local current_version = self:get_current_version()
    if not current_version then
        return false, "No current version available"
    end

    log_message("info", "Performing atomic version swap", {
        from = current_version,
        to = new_version
    })

    local success, err = self.cache_dict:set(VERSION_KEY, new_version)
    if not success then
        log_message("error", "Failed to swap cache version", {
            error = err,
            from = current_version,
            to = new_version
        })
        return false, err
    end

    -- Update local cache
    self.current_version = new_version

    -- Schedule cleanup of old version
    local cleanup_delay = 30  -- seconds
    local ok, timer_err = ngx.timer.at(cleanup_delay, function()
        self:cleanup_version(current_version)
    end)

    if not ok then
        log_message("warn", "Failed to schedule version cleanup", {
            error = timer_err,
            old_version = current_version
        })
    end

    log_message("info", "Version swap completed", {
        new_version = new_version,
        cleanup_scheduled = ok
    })

    return true, nil
end

-- Cleanup old version data
function TaxiiCache:cleanup_version(version)
    if not version then return end

    log_message("info", "Starting cleanup of old version", {version = version})

    local keys_cleaned = 0
    local pattern = CACHE_NAMESPACE .. ":" .. version .. ":"

    -- Get all keys (this is expensive but needed for cleanup)
    -- In production, consider implementing a key tracking mechanism
    local keys = self.cache_dict:get_keys(1000)  -- Limit to prevent memory issues

    for _, key in ipairs(keys or {}) do
        if key:find(pattern, 1, true) == 1 then  -- Key starts with pattern
            self.cache_dict:delete(key)
            keys_cleaned = keys_cleaned + 1
        end
    end

    log_message("info", "Version cleanup completed", {
        version = version,
        keys_cleaned = keys_cleaned
    })
end

-- Lookup IP address in cache
function TaxiiCache:lookup_ip(ip)
    local version = self:get_current_version()
    if not version then
        return nil
    end

    -- Direct IP lookup
    local key = make_indicator_key(version, "ip", ip)
    local result = self:get_indicator(key)
    if result then
        return result
    end

    -- CIDR lookup - check if IP falls within any cached CIDR ranges
    return self:lookup_ip_in_cidrs(ip, version)
end

-- Lookup IP in CIDR ranges
function TaxiiCache:lookup_ip_in_cidrs(ip, version)
    -- This is a simplified implementation
    -- In production, consider using a more efficient CIDR matching approach
    local cidr_keys = self.cache_dict:get_keys(100)  -- Limit search
    local cidr_pattern = CACHE_NAMESPACE .. ":" .. version .. ":cidr:"

    for _, key in ipairs(cidr_keys or {}) do
        if key:find(cidr_pattern, 1, true) == 1 then
            local cidr = key:sub(#cidr_pattern + 1)
            if self:ip_in_cidr(ip, cidr) then
                return self:get_indicator(key)
            end
        end
    end

    return nil
end

-- Check if IP is in CIDR range (simplified)
function TaxiiCache:ip_in_cidr(ip, cidr)
    -- Use resty.ipmatcher for proper CIDR matching
    local ok, matcher = pcall(ipmatcher.new, {cidr})
    if ok and matcher then
        return matcher:match(ip)
    end
    return false
end

-- Lookup domain in cache
function TaxiiCache:lookup_domain(domain)
    local version = self:get_current_version()
    if not version then
        return nil
    end

    local key = make_indicator_key(version, "domain", domain)
    return self:get_indicator(key)
end

-- Lookup URL in cache
function TaxiiCache:lookup_url(url)
    local version = self:get_current_version()
    if not version then
        return nil
    end

    local key = make_indicator_key(version, "url", url)
    return self:get_indicator(key)
end

-- Lookup JA3 fingerprint
function TaxiiCache:lookup_ja3(ja3)
    local version = self:get_current_version()
    if not version then
        return nil
    end

    local key = make_indicator_key(version, "ja3", ja3)
    return self:get_indicator(key)
end

-- Lookup JA4 fingerprint
function TaxiiCache:lookup_ja4(ja4)
    local version = self:get_current_version()
    if not version then
        return nil
    end

    local key = make_indicator_key(version, "ja4", ja4)
    return self:get_indicator(key)
end

-- Check against regex patterns
function TaxiiCache:lookup_regex_matches(text)
    local version = self:get_current_version()
    if not version then
        return {}
    end

    local matches = {}
    local regex_keys = self.cache_dict:get_keys(50)  -- Limit for performance
    local regex_pattern = CACHE_NAMESPACE .. ":" .. version .. ":regex:"

    for _, key in ipairs(regex_keys or {}) do
        if key:find(regex_pattern, 1, true) == 1 then
            local regex = key:sub(#regex_pattern + 1)
            if text:match(regex) then
                local indicator = self:get_indicator(key)
                if indicator then
                    table.insert(matches, indicator)
                end
            end
        end
    end

    return matches
end

-- Get indicator from cache
function TaxiiCache:get_indicator(key)
    local serialized, err = self.cache_dict:get(key)
    if err then
        log_message("debug", "Cache get error", {key = key, error = err})
        return nil
    end

    if not serialized then
        return nil
    end

    local data, decode_err = cjson.decode(serialized)
    if not data then
        log_message("warn", "Failed to decode cached indicator", {
            key = key,
            error = decode_err
        })
        return nil
    end

    return data
end

-- Store collection state (cursor, timestamps)
function TaxiiCache:store_collection_state(server_url, collection_id, state)
    local key = make_collection_state_key(server_url, collection_id)
    local serialized = cjson.encode(state)

    local success, err = self.cache_dict:set(key, serialized, 86400)  -- 24 hour TTL for state
    if not success then
        log_message("error", "Failed to store collection state", {
            server_url = server_url,
            collection_id = collection_id,
            error = err
        })
        return false
    end

    return true
end

-- Get collection state
function TaxiiCache:get_collection_state(server_url, collection_id)
    local key = make_collection_state_key(server_url, collection_id)
    local serialized, err = self.cache_dict:get(key)

    if err then
        log_message("error", "Failed to get collection state", {
            server_url = server_url,
            collection_id = collection_id,
            error = err
        })
        return nil
    end

    if not serialized then
        return {
            last_poll = nil,
            cursor = nil,
            last_success = nil
        }
    end

    local state, decode_err = cjson.decode(serialized)
    if not state then
        log_message("warn", "Failed to decode collection state", {
            error = decode_err
        })
        return {
            last_poll = nil,
            cursor = nil,
            last_success = nil
        }
    end

    return state
end

-- Get cache statistics
function TaxiiCache:get_stats()
    local version = self:get_current_version()
    local metadata = self:get_metadata()

    -- Count keys by type (simplified)
    local keys = self.cache_dict:get_keys(1000)
    local stats = {
        version = version,
        total_keys = #(keys or {}),
        by_type = {},
        metadata = metadata,
        cache_capacity = self.cache_dict:capacity(),
        cache_free_space = self.cache_dict:free_space()
    }

    if version then
        local version_pattern = CACHE_NAMESPACE .. ":" .. version .. ":"
        for _, key in ipairs(keys or {}) do
            if key:find(version_pattern, 1, true) == 1 then
                local parts = {}
                for part in key:gmatch("[^:]+") do
                    table.insert(parts, part)
                end

                if #parts >= 3 then
                    local ioc_type = parts[3]
                    stats.by_type[ioc_type] = (stats.by_type[ioc_type] or 0) + 1
                end
            end
        end
    end

    return stats
end

-- Clear all TAXII cache data
function TaxiiCache:clear_all()
    log_message("info", "Clearing all TAXII cache data")

    local keys = self.cache_dict:get_keys(1000)
    local cleared = 0

    for _, key in ipairs(keys or {}) do
        if key:find(CACHE_NAMESPACE .. ":", 1, true) == 1 then
            self.cache_dict:delete(key)
            cleared = cleared + 1
        end
    end

    -- Reset version
    self.current_version = nil

    log_message("info", "Cache clear completed", {keys_cleared = cleared})

    return cleared
end

return TaxiiCache