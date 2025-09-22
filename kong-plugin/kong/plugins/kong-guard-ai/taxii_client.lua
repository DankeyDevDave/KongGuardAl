local http = require "resty.http"
local cjson = require "cjson.safe"

local TaxiiClient = {}
TaxiiClient.__index = TaxiiClient

-- TAXII 2.x Content Types
local TAXII_CONTENT_TYPES = {
    ["2.0"] = "application/vnd.oasis.taxii+json; version=2.0",
    ["2.1"] = "application/taxii+json; version=2.1"
}

-- Create new TAXII client instance
function TaxiiClient.new(config)
    local self = setmetatable({}, TaxiiClient)
    self.config = config or {}
    self.version = config.taxii_version or "2.1"
    self.timeout_ms = config.taxii_http_timeout_ms or 2000
    self.retry_config = config.taxii_retry_backoff_ms or {
        initial = 200,
        max = 5000,
        factor = 2
    }
    self.insecure = config.taxii_tls_insecure_skip_verify or false
    self.proxy_url = config.taxii_proxy_url

    return self
end

-- Log helper function
local function log_message(level, message, context)
    local log_func = kong.log[level] or kong.log.info
    if context then
        log_func("[TaxiiClient] " .. message .. " - " .. cjson.encode(context))
    else
        log_func("[TaxiiClient] " .. message)
    end
end

-- Create HTTP client with configuration
function TaxiiClient:_create_http_client()
    local httpc = http.new()
    httpc:set_timeout(self.timeout_ms)

    return httpc
end

-- Build request headers for TAXII API
function TaxiiClient:_build_headers(server_config)
    local headers = {
        ["Accept"] = TAXII_CONTENT_TYPES[self.version],
        ["Content-Type"] = TAXII_CONTENT_TYPES[self.version],
        ["User-Agent"] = "Kong-Guard-AI TAXII Client/1.0"
    }

    -- Add authentication headers
    if server_config.auth_type == "basic" and server_config.username and server_config.password then
        local auth_string = server_config.username .. ":" .. server_config.password
        headers["Authorization"] = "Basic " .. ngx.encode_base64(auth_string)
    elseif server_config.auth_type == "bearer" and server_config.token then
        headers["Authorization"] = "Bearer " .. server_config.token
    end

    return headers
end

-- Perform HTTP request with retries and error handling
function TaxiiClient:_http_request(method, url, headers, body)
    local httpc = self:_create_http_client()
    local retry_delay = self.retry_config.initial
    local max_retries = 3

    for attempt = 1, max_retries do
        local res, err = httpc:request_uri(url, {
            method = method,
            headers = headers,
            body = body,
            ssl_verify = not self.insecure,
            proxy = self.proxy_url
        })

        if res then
            if res.status >= 200 and res.status < 300 then
                log_message("debug", "HTTP request successful", {
                    method = method,
                    url = url,
                    status = res.status,
                    attempt = attempt
                })
                return res, nil
            elseif res.status >= 500 or res.status == 429 then
                -- Retry on server errors and rate limiting
                log_message("warn", "HTTP request failed, retrying", {
                    method = method,
                    url = url,
                    status = res.status,
                    attempt = attempt,
                    retry_delay_ms = retry_delay
                })

                if attempt < max_retries then
                    ngx.sleep(retry_delay / 1000)
                    retry_delay = math.min(retry_delay * self.retry_config.factor, self.retry_config.max)
                end
            else
                -- Don't retry on client errors
                log_message("error", "HTTP request failed with client error", {
                    method = method,
                    url = url,
                    status = res.status,
                    body = res.body
                })
                return nil, "HTTP " .. res.status .. ": " .. (res.body or "Unknown error")
            end
        else
            log_message("error", "HTTP request failed", {
                method = method,
                url = url,
                error = err,
                attempt = attempt
            })

            if attempt < max_retries then
                ngx.sleep(retry_delay / 1000)
                retry_delay = math.min(retry_delay * self.retry_config.factor, self.retry_config.max)
            end
        end
    end

    return nil, "Max retries exceeded"
end

-- Parse JSON response with error handling
function TaxiiClient:_parse_json_response(res)
    if not res or not res.body then
        return nil, "Empty response"
    end

    local data, err = cjson.decode(res.body)
    if not data then
        log_message("error", "Failed to parse JSON response", {
            error = err,
            body_length = #res.body
        })
        return nil, "Invalid JSON: " .. (err or "unknown error")
    end

    return data, nil
end

-- Discover TAXII server information
function TaxiiClient:discover_server(server_config)
    local base_url = server_config.url:gsub("/$", "")  -- Remove trailing slash
    local discovery_url = base_url .. "/taxii/"

    log_message("info", "Discovering TAXII server", {
        url = discovery_url,
        version = self.version
    })

    local headers = self:_build_headers(server_config)
    local res, err = self:_http_request("GET", discovery_url, headers)

    if not res then
        return nil, "Discovery failed: " .. err
    end

    local data, parse_err = self:_parse_json_response(res)
    if not data then
        return nil, "Discovery parse error: " .. parse_err
    end

    -- Validate discovery response structure
    if not data.api_roots then
        return nil, "Invalid discovery response: missing api_roots"
    end

    log_message("info", "TAXII server discovery successful", {
        title = data.title,
        description = data.description,
        api_roots_count = #data.api_roots
    })

    return data, nil
end

-- Get collections from an API root
function TaxiiClient:get_collections(server_config, api_root_url)
    local collections_url = api_root_url:gsub("/$", "") .. "/collections/"

    log_message("debug", "Fetching collections", {
        url = collections_url
    })

    local headers = self:_build_headers(server_config)
    local res, err = self:_http_request("GET", collections_url, headers)

    if not res then
        return nil, "Collections fetch failed: " .. err
    end

    local data, parse_err = self:_parse_json_response(res)
    if not data then
        return nil, "Collections parse error: " .. parse_err
    end

    if not data.collections then
        return nil, "Invalid collections response: missing collections array"
    end

    log_message("info", "Collections fetched successfully", {
        count = #data.collections
    })

    return data.collections, nil
end

-- Poll objects from a specific collection
function TaxiiClient:poll_collection(server_config, api_root_url, collection_id, options)
    options = options or {}
    local objects_url = api_root_url:gsub("/$", "") .. "/collections/" .. collection_id .. "/objects/"

    -- Build query parameters
    local params = {}
    if options.added_after then
        table.insert(params, "added_after=" .. ngx.escape_uri(options.added_after))
    end
    if options.limit then
        table.insert(params, "limit=" .. tostring(options.limit))
    end
    if options.next then
        table.insert(params, "next=" .. ngx.escape_uri(options.next))
    end

    if #params > 0 then
        objects_url = objects_url .. "?" .. table.concat(params, "&")
    end

    log_message("debug", "Polling collection objects", {
        collection_id = collection_id,
        url = objects_url,
        options = options
    })

    local headers = self:_build_headers(server_config)
    local res, err = self:_http_request("GET", objects_url, headers)

    if not res then
        return nil, "Objects poll failed: " .. err
    end

    local data, parse_err = self:_parse_json_response(res)
    if not data then
        return nil, "Objects parse error: " .. parse_err
    end

    if not data.objects then
        return nil, "Invalid objects response: missing objects array"
    end

    log_message("info", "Collection poll successful", {
        collection_id = collection_id,
        objects_count = #data.objects,
        has_more = data.more or false
    })

    return {
        objects = data.objects,
        more = data.more or false,
        next = data.next
    }, nil
end

-- Validate server configuration
function TaxiiClient:validate_server_config(server_config)
    if not server_config.url then
        return false, "Missing server URL"
    end

    if server_config.auth_type == "basic" then
        if not server_config.username or not server_config.password then
            return false, "Basic auth requires username and password"
        end
    elseif server_config.auth_type == "bearer" then
        if not server_config.token then
            return false, "Bearer auth requires token"
        end
    end

    return true, nil
end

-- Test connectivity to a TAXII server
function TaxiiClient:test_connection(server_config)
    local valid, err = self:validate_server_config(server_config)
    if not valid then
        return false, "Configuration error: " .. err
    end

    log_message("info", "Testing TAXII server connection", {
        url = server_config.url,
        auth_type = server_config.auth_type
    })

    -- Try discovery first
    local discovery, discovery_err = self:discover_server(server_config)
    if not discovery then
        return false, "Connection test failed: " .. discovery_err
    end

    -- Try to get collections from first API root
    if discovery.api_roots and #discovery.api_roots > 0 then
        local api_root = discovery.api_roots[1]
        local collections, collections_err = self:get_collections(server_config, api_root)
        if not collections then
            log_message("warn", "Collections test failed", {
                error = collections_err
            })
            -- Don't fail the connection test if collections fail
        else
            log_message("info", "Connection test successful", {
                collections_count = #collections
            })
        end
    end

    return true, nil
end

-- Get formatted error for logging
function TaxiiClient:_format_error(context, error)
    return {
        component = "TaxiiClient",
        context = context,
        error = error,
        timestamp = ngx.time()
    }
end

return TaxiiClient