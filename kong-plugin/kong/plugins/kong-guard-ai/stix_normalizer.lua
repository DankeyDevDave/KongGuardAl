local cjson = require "cjson.safe"
local ipmatcher = require "resty.ipmatcher"

local StixNormalizer = {}
StixNormalizer.__index = StixNormalizer

-- Common STIX patterns for IoC extraction
local STIX_PATTERNS = {
    ipv4 = "^%[ipv%-addr:value%s*=%s*['\"]([%d%.]+)['\"]%]",
    ipv6 = "^%[ipv%-addr:value%s*=%s*['\"]([%x:]+)['\"]%]",
    domain = "^%[domain%-name:value%s*=%s*['\"]([^'\"]+)['\"]%]",
    url = "^%[url:value%s*=%s*['\"]([^'\"]+)['\"]%]",
    file_hash_md5 = "^%[file:hashes%.MD5%s*=%s*['\"]([%x]+)['\"]%]",
    file_hash_sha1 = "^%[file:hashes%.SHA%-1%s*=%s*['\"]([%x]+)['\"]%]",
    file_hash_sha256 = "^%[file:hashes%.SHA%-256%s*=%s*['\"]([%x]+)['\"]%]"
}

-- JA3/JA4 detection patterns
local TLS_PATTERNS = {
    ja3 = "ja3[%s%-_]*[=:]?[%s]*['\"]?([%x,]+)['\"]?",
    ja3s = "ja3s[%s%-_]*[=:]?[%s]*['\"]?([%x,]+)['\"]?",
    ja4 = "ja4[%s%-_]*[=:]?[%s]*['\"]?([%w_%-,]+)['\"]?",
    ja4s = "ja4s[%s%-_]*[=:]?[%s]*['\"]?([%w_%-,]+)['\"]?"
}

-- Create new STIX normalizer instance
function StixNormalizer.new(config)
    local self = setmetatable({}, StixNormalizer)
    self.config = config or {}
    self.enable_dedup = config.taxii_enable_dedup ~= false

    return self
end

-- Log helper function
local function log_message(level, message, context)
    local log_func = kong.log[level] or kong.log.info
    if context then
        log_func("[StixNormalizer] " .. message .. " - " .. cjson.encode(context))
    else
        log_func("[StixNormalizer] " .. message)
    end
end

-- Normalize and validate IPv4 address
function StixNormalizer:_normalize_ipv4(ip)
    if not ip then return nil end

    -- Basic IPv4 validation
    local parts = {}
    for part in ip:gmatch("(%d+)") do
        local num = tonumber(part)
        if not num or num < 0 or num > 255 then
            return nil
        end
        table.insert(parts, num)
    end

    if #parts ~= 4 then
        return nil
    end

    return table.concat(parts, ".")
end

-- Normalize and validate IPv6 address
function StixNormalizer:_normalize_ipv6(ip)
    if not ip then return nil end

    -- Basic IPv6 validation (simplified)
    -- Remove leading/trailing whitespace
    ip = ip:match("^%s*(.-)%s*$")

    -- Check for valid IPv6 characters
    if not ip:match("^[%x:]+$") then
        return nil
    end

    -- Expand :: notation (simplified)
    if ip:find("::") then
        local parts = {}
        for part in ip:gmatch("[^:]+") do
            table.insert(parts, part)
        end

        -- This is a simplified expansion - production should use a proper IPv6 library
        return ip:lower()
    end

    return ip:lower()
end

-- Normalize domain name (IDNA handling would be ideal but basic normalization for now)
function StixNormalizer:_normalize_domain(domain)
    if not domain then return nil end

    -- Remove leading/trailing whitespace and convert to lowercase
    domain = domain:match("^%s*(.-)%s*$"):lower()

    -- Remove leading dot if present
    domain = domain:gsub("^%.", "")

    -- Basic domain validation
    if not domain:match("^[%w%.%-]+$") then
        return nil
    end

    -- Check for valid domain structure
    if domain:match("%.%.") or domain:match("^%-") or domain:match("%-$") then
        return nil
    end

    return domain
end

-- Normalize URL
function StixNormalizer:_normalize_url(url)
    if not url then return nil end

    -- Remove leading/trailing whitespace
    url = url:match("^%s*(.-)%s*$")

    -- Basic URL validation
    if not url:match("^https?://") then
        return nil
    end

    -- Convert to lowercase (except query parameters)
    local scheme, rest = url:match("^(https?://)(.+)$")
    if scheme and rest then
        local host_path, query = rest:match("^([^%?]+)(.*)$")
        if host_path then
            return scheme:lower() .. host_path:lower() .. (query or "")
        end
    end

    return url:lower()
end

-- Validate and normalize file hash
function StixNormalizer:_normalize_hash(hash, hash_type)
    if not hash then return nil end

    hash = hash:match("^%s*(.-)%s*$"):lower()

    local expected_lengths = {
        md5 = 32,
        sha1 = 40,
        sha256 = 64
    }

    local expected_length = expected_lengths[hash_type:lower()]
    if not expected_length then
        return nil
    end

    -- Check length and hex characters
    if #hash ~= expected_length or not hash:match("^[%x]+$") then
        return nil
    end

    return hash
end

-- Extract IP addresses from CIDR notation
function StixNormalizer:_parse_cidr(cidr_string)
    if not cidr_string then return nil end

    local ip, mask = cidr_string:match("^([^/]+)/(%d+)$")
    if not ip or not mask then
        return nil
    end

    mask = tonumber(mask)
    if not mask then
        return nil
    end

    -- Validate IP and mask range
    local normalized_ip = self:_normalize_ipv4(ip) or self:_normalize_ipv6(ip)
    if not normalized_ip then
        return nil
    end

    -- IPv4 mask validation
    if normalized_ip:find("%.") and (mask < 0 or mask > 32) then
        return nil
    end

    -- IPv6 mask validation
    if normalized_ip:find(":") and (mask < 0 or mask > 128) then
        return nil
    end

    return {
        ip = normalized_ip,
        mask = mask,
        cidr = normalized_ip .. "/" .. mask
    }
end

-- Safe regex compilation with validation
function StixNormalizer:_validate_regex(pattern)
    if not pattern then return nil end

    -- Remove STIX pattern wrapper if present
    pattern = pattern:gsub("^%[.*:value%s*=%s*['\"]", ""):gsub("['\"]%s*%]$", "")

    -- Basic safety checks - reject potentially dangerous patterns
    local dangerous_patterns = {
        "%(", "%)", "%[", "%]", "%^", "%$", "%.", "%*", "%+", "%?",
        "\\", "|"
    }

    -- Count metacharacters to detect complex regex
    local meta_count = 0
    for _, meta in ipairs(dangerous_patterns) do
        local _, count = pattern:gsub(meta, "")
        meta_count = meta_count + count
    end

    -- Reject overly complex patterns
    if meta_count > 10 then
        log_message("warn", "Rejecting complex regex pattern", {
            pattern = pattern,
            metachar_count = meta_count
        })
        return nil
    end

    -- Try to compile the pattern
    local success, result = pcall(function()
        return string.match("test", pattern)
    end)

    if not success then
        log_message("warn", "Invalid regex pattern", {
            pattern = pattern,
            error = result
        })
        return nil
    end

    return pattern
end

-- Extract TLS fingerprints from STIX pattern or description
function StixNormalizer:_extract_tls_fingerprints(text)
    if not text then return {} end

    local fingerprints = {}
    text = text:lower()

    for fp_type, pattern in pairs(TLS_PATTERNS) do
        local match = text:match(pattern)
        if match then
            fingerprints[fp_type] = match
        end
    end

    return fingerprints
end

-- Parse a single STIX indicator object
function StixNormalizer:parse_indicator(stix_object)
    if not stix_object or stix_object.type ~= "indicator" then
        return nil
    end

    local pattern = stix_object.pattern
    if not pattern then
        log_message("debug", "Indicator missing pattern", {
            id = stix_object.id
        })
        return nil
    end

    local result = {
        id = stix_object.id,
        labels = stix_object.labels or {},
        pattern = pattern,
        valid_from = stix_object.valid_from,
        valid_until = stix_object.valid_until,
        confidence = stix_object.confidence,
        indicators = {
            ips = {},
            cidrs = {},
            domains = {},
            urls = {},
            hashes = {},
            regexes = {},
            tls_fingerprints = {}
        }
    }

    -- Extract IPv4 addresses
    for ip in pattern:gmatch(STIX_PATTERNS.ipv4) do
        local normalized = self:_normalize_ipv4(ip)
        if normalized then
            table.insert(result.indicators.ips, normalized)
        end
    end

    -- Extract IPv6 addresses
    for ip in pattern:gmatch(STIX_PATTERNS.ipv6) do
        local normalized = self:_normalize_ipv6(ip)
        if normalized then
            table.insert(result.indicators.ips, normalized)
        end
    end

    -- Extract CIDR ranges (look for CIDR notation in pattern)
    for cidr in pattern:gmatch("([%d%.:]+/[%d]+)") do
        local parsed = self:_parse_cidr(cidr)
        if parsed then
            table.insert(result.indicators.cidrs, parsed.cidr)
        end
    end

    -- Extract domains
    for domain in pattern:gmatch(STIX_PATTERNS.domain) do
        local normalized = self:_normalize_domain(domain)
        if normalized then
            table.insert(result.indicators.domains, normalized)
        end
    end

    -- Extract URLs
    for url in pattern:gmatch(STIX_PATTERNS.url) do
        local normalized = self:_normalize_url(url)
        if normalized then
            table.insert(result.indicators.urls, normalized)
        end
    end

    -- Extract file hashes
    for hash in pattern:gmatch(STIX_PATTERNS.file_hash_md5) do
        local normalized = self:_normalize_hash(hash, "md5")
        if normalized then
            result.indicators.hashes.md5 = result.indicators.hashes.md5 or {}
            table.insert(result.indicators.hashes.md5, normalized)
        end
    end

    for hash in pattern:gmatch(STIX_PATTERNS.file_hash_sha1) do
        local normalized = self:_normalize_hash(hash, "sha1")
        if normalized then
            result.indicators.hashes.sha1 = result.indicators.hashes.sha1 or {}
            table.insert(result.indicators.hashes.sha1, normalized)
        end
    end

    for hash in pattern:gmatch(STIX_PATTERNS.file_hash_sha256) do
        local normalized = self:_normalize_hash(hash, "sha256")
        if normalized then
            result.indicators.hashes.sha256 = result.indicators.hashes.sha256 or {}
            table.insert(result.indicators.hashes.sha256, normalized)
        end
    end

    -- Extract TLS fingerprints
    local tls_fps = self:_extract_tls_fingerprints(pattern)
    for fp_type, fp_value in pairs(tls_fps) do
        result.indicators.tls_fingerprints[fp_type] = fp_value
    end

    -- Also check description for TLS fingerprints
    if stix_object.description then
        local desc_fps = self:_extract_tls_fingerprints(stix_object.description)
        for fp_type, fp_value in pairs(desc_fps) do
            result.indicators.tls_fingerprints[fp_type] = fp_value
        end
    end

    -- Handle regex patterns (simplified - only basic patterns for safety)
    if pattern:find("MATCHES") or pattern:find("regex") then
        local regex = self:_validate_regex(pattern)
        if regex then
            table.insert(result.indicators.regexes, regex)
        end
    end

    return result
end

-- Process a batch of STIX objects
function StixNormalizer:process_objects(stix_objects)
    if not stix_objects or type(stix_objects) ~= "table" then
        return nil, "Invalid input: expected table of STIX objects"
    end

    local results = {
        indicators = {},
        stats = {
            total_objects = #stix_objects,
            indicators_parsed = 0,
            ips_extracted = 0,
            domains_extracted = 0,
            urls_extracted = 0,
            hashes_extracted = 0,
            tls_fingerprints_extracted = 0,
            regexes_extracted = 0,
            errors = 0
        }
    }

    local seen_ids = {}

    for _, obj in ipairs(stix_objects) do
        if obj.type == "indicator" then
            local parsed = self:parse_indicator(obj)
            if parsed then
                -- Deduplication
                if self.enable_dedup and seen_ids[parsed.id] then
                    log_message("debug", "Skipping duplicate indicator", {
                        id = parsed.id
                    })
                else
                    table.insert(results.indicators, parsed)
                    seen_ids[parsed.id] = true
                    results.stats.indicators_parsed = results.stats.indicators_parsed + 1

                    -- Update extraction stats
                    results.stats.ips_extracted = results.stats.ips_extracted + #parsed.indicators.ips
                    results.stats.domains_extracted = results.stats.domains_extracted + #parsed.indicators.domains
                    results.stats.urls_extracted = results.stats.urls_extracted + #parsed.indicators.urls

                    -- Count TLS fingerprints
                    for _, _ in pairs(parsed.indicators.tls_fingerprints) do
                        results.stats.tls_fingerprints_extracted = results.stats.tls_fingerprints_extracted + 1
                    end

                    -- Count hashes
                    for hash_type, hashes in pairs(parsed.indicators.hashes) do
                        results.stats.hashes_extracted = results.stats.hashes_extracted + #hashes
                    end

                    results.stats.regexes_extracted = results.stats.regexes_extracted + #parsed.indicators.regexes
                end
            else
                results.stats.errors = results.stats.errors + 1
            end
        end
    end

    log_message("info", "STIX processing completed", results.stats)

    return results, nil
end

-- Create lookup sets from parsed indicators
function StixNormalizer:create_lookup_sets(parsed_indicators)
    local sets = {
        ip_set = {},
        cidr_set = {},
        domain_set = {},
        url_set = {},
        hash_set = {
            md5 = {},
            sha1 = {},
            sha256 = {}
        },
        regex_set = {},
        ja3_set = {},
        ja4_set = {}
    }

    for _, indicator in ipairs(parsed_indicators) do
        local ind = indicator.indicators

        -- Process IPs
        for _, ip in ipairs(ind.ips) do
            sets.ip_set[ip] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        -- Process CIDRs
        for _, cidr in ipairs(ind.cidrs) do
            sets.cidr_set[cidr] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        -- Process domains
        for _, domain in ipairs(ind.domains) do
            sets.domain_set[domain] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        -- Process URLs
        for _, url in ipairs(ind.urls) do
            sets.url_set[url] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        -- Process hashes
        for hash_type, hashes in pairs(ind.hashes) do
            for _, hash in ipairs(hashes) do
                sets.hash_set[hash_type][hash] = {
                    source_id = indicator.id,
                    labels = indicator.labels,
                    valid_from = indicator.valid_from,
                    valid_until = indicator.valid_until,
                    confidence = indicator.confidence
                }
            end
        end

        -- Process regexes
        for _, regex in ipairs(ind.regexes) do
            sets.regex_set[regex] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        -- Process TLS fingerprints
        if ind.tls_fingerprints.ja3 then
            sets.ja3_set[ind.tls_fingerprints.ja3] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end

        if ind.tls_fingerprints.ja4 then
            sets.ja4_set[ind.tls_fingerprints.ja4] = {
                source_id = indicator.id,
                labels = indicator.labels,
                valid_from = indicator.valid_from,
                valid_until = indicator.valid_until,
                confidence = indicator.confidence
            }
        end
    end

    return sets
end

-- Check if indicator is still valid based on time window
function StixNormalizer:is_indicator_valid(indicator, current_time)
    current_time = current_time or ngx.time()

    -- Check valid_from
    if indicator.valid_from then
        local valid_from_ts = ngx.parse_http_time(indicator.valid_from)
        if valid_from_ts and current_time < valid_from_ts then
            return false
        end
    end

    -- Check valid_until
    if indicator.valid_until then
        local valid_until_ts = ngx.parse_http_time(indicator.valid_until)
        if valid_until_ts and current_time > valid_until_ts then
            return false
        end
    end

    return true
end

return StixNormalizer
