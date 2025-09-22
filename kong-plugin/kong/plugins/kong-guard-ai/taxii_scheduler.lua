local TaxiiClient = require "kong.plugins.kong-guard-ai.taxii_client"
local StixNormalizer = require "kong.plugins.kong-guard-ai.stix_normalizer"
local TaxiiCache = require "kong.plugins.kong-guard-ai.taxii_cache"
local cjson = require "cjson.safe"

local TaxiiScheduler = {}
TaxiiScheduler.__index = TaxiiScheduler

-- Scheduler state and metrics keys
local SCHEDULER_STATE_KEY = "taxii:scheduler_state"
local METRICS_PREFIX = "taxii_metrics:"

-- Create new TAXII scheduler instance
function TaxiiScheduler.new(config)
    local self = setmetatable({}, TaxiiScheduler)
    self.config = config or {}
    self.poll_interval = config.taxii_poll_interval_seconds or 300
    self.max_objects = config.taxii_max_objects_per_poll or 500
    self.enabled = config.enable_taxii_ingestion or false
    self.client = TaxiiClient.new(config)
    self.normalizer = StixNormalizer.new(config)
    self.cache = TaxiiCache.new(config)
    self.running = false

    return self
end

-- Log helper function
local function log_message(level, message, context)
    local log_func = kong.log[level] or kong.log.info
    if context then
        log_func("[TaxiiScheduler] " .. message .. " - " .. cjson.encode(context))
    else
        log_func("[TaxiiScheduler] " .. message)
    end
end

-- Start the scheduler
function TaxiiScheduler:start()
    if not self.enabled then
        log_message("info", "TAXII ingestion disabled, scheduler not started")
        return true
    end

    if self.running then
        log_message("warn", "Scheduler already running")
        return true
    end

    if not self.client or not self.normalizer or not self.cache then
        log_message("error", "Failed to initialize TAXII components")
        return false
    end

    self.running = true
    log_message("info", "Starting TAXII scheduler", {
        poll_interval = self.poll_interval,
        servers_count = #(self.config.taxii_servers or {})
    })

    -- Schedule initial poll
    local ok, err = ngx.timer.at(0, function()
        self:poll_all_servers()
    end)

    if not ok then
        log_message("error", "Failed to schedule initial poll", {error = err})
        self.running = false
        return false
    end

    return true
end

-- Stop the scheduler
function TaxiiScheduler:stop()
    self.running = false
    log_message("info", "TAXII scheduler stopped")
end

-- Poll all configured TAXII servers
function TaxiiScheduler:poll_all_servers()
    if not self.running then
        return
    end

    local servers = self.config.taxii_servers or {}
    if #servers == 0 then
        log_message("warn", "No TAXII servers configured")
        return
    end

    log_message("info", "Starting polling cycle", {
        servers_count = #servers
    })

    local total_indicators = 0
    local total_errors = 0
    local poll_start_time = ngx.now()

    for _, server_config in ipairs(servers) do
        local indicators, errors = self:poll_server(server_config)
        total_indicators = total_indicators + indicators
        total_errors = total_errors + errors
    end

    local poll_duration = (ngx.now() - poll_start_time) * 1000 -- Convert to milliseconds

    -- Update metrics
    self:update_metrics("polls_total", 1)
    self:update_metrics("indicators_loaded", total_indicators)
    self:update_metrics("errors_total", total_errors)
    self:update_metrics("last_poll_duration_ms", poll_duration)
    self:update_metrics("last_success_ts", ngx.time())

    log_message("info", "Polling cycle completed", {
        servers_polled = #servers,
        total_indicators = total_indicators,
        total_errors = total_errors,
        duration_ms = poll_duration
    })

    -- Schedule next poll
    if self.running then
        local ok, err = ngx.timer.at(self.poll_interval, function()
            self:poll_all_servers()
        end)

        if not ok then
            log_message("error", "Failed to schedule next poll", {error = err})
        end
    end
end

-- Poll a single TAXII server
function TaxiiScheduler:poll_server(server_config)
    local server_url = server_config.url
    log_message("debug", "Polling server", {url = server_url})

    local total_indicators = 0
    local total_errors = 0

    -- Discover server and get API roots
    local discovery, discovery_err = self.client:discover_server(server_config)
    if not discovery then
        log_message("error", "Server discovery failed", {
            url = server_url,
            error = discovery_err
        })
        self:update_metrics("discovery_errors_total", 1)
        return 0, 1
    end

    -- Process each API root
    for _, api_root_url in ipairs(discovery.api_roots) do
        local collections, collections_err = self.client:get_collections(server_config, api_root_url)
        if not collections then
            log_message("error", "Failed to get collections", {
                server_url = server_url,
                api_root = api_root_url,
                error = collections_err
            })
            total_errors = total_errors + 1
            goto continue_api_root
        end

        -- Filter collections based on configuration
        local target_collections = server_config.collections or {}
        local collections_to_poll = {}

        if #target_collections > 0 then
            -- Poll only specified collections
            for _, collection in ipairs(collections) do
                for _, target_id in ipairs(target_collections) do
                    if collection.id == target_id then
                        table.insert(collections_to_poll, collection)
                        break
                    end
                end
            end
        else
            -- Poll all available collections
            collections_to_poll = collections
        end

        -- Poll each collection
        for _, collection in ipairs(collections_to_poll) do
            local indicators, errors = self:poll_collection(server_config, api_root_url, collection)
            total_indicators = total_indicators + indicators
            total_errors = total_errors + errors
        end

        ::continue_api_root::
    end

    return total_indicators, total_errors
end

-- Poll a single collection
function TaxiiScheduler:poll_collection(server_config, api_root_url, collection)
    local collection_id = collection.id
    log_message("debug", "Polling collection", {
        server_url = server_config.url,
        collection_id = collection_id
    })

    -- Get collection state (cursor, last poll time)
    local state = self.cache:get_collection_state(server_config.url, collection_id)
    local current_time = os.date("!%Y-%m-%dT%H:%M:%S.000Z")

    -- Prepare polling options
    local poll_options = {
        limit = self.max_objects
    }

    if state.cursor then
        poll_options.next = state.cursor
    elseif state.last_poll then
        poll_options.added_after = state.last_poll
    end

    local total_indicators = 0
    local has_more = true
    local errors = 0

    -- Poll with pagination
    while has_more and self.running do
        local result, err = self.client:poll_collection(
            server_config, api_root_url, collection_id, poll_options
        )

        if not result then
            log_message("error", "Collection polling failed", {
                server_url = server_config.url,
                collection_id = collection_id,
                error = err
            })
            errors = errors + 1
            break
        end

        local objects = result.objects or {}
        if #objects > 0 then
            local processed_indicators = self:process_stix_objects(objects, server_config.url, collection_id)
            total_indicators = total_indicators + processed_indicators
        end

        -- Update pagination
        has_more = result.more or false
        if result.next then
            poll_options.next = result.next
            poll_options.added_after = nil -- Clear added_after when using cursor
        else
            has_more = false
        end

        log_message("debug", "Collection poll batch completed", {
            collection_id = collection_id,
            batch_size = #objects,
            has_more = has_more,
            total_so_far = total_indicators
        })
    end

    -- Update collection state
    if errors == 0 then
        local new_state = {
            last_poll = current_time,
            cursor = poll_options.next,
            last_success = ngx.time(),
            last_indicator_count = total_indicators
        }
        self.cache:store_collection_state(server_config.url, collection_id, new_state)
    end

    log_message("info", "Collection polling completed", {
        collection_id = collection_id,
        indicators_processed = total_indicators,
        errors = errors
    })

    return total_indicators, errors
end

-- Process STIX objects and update cache
function TaxiiScheduler:process_stix_objects(stix_objects, server_url, collection_id)
    if not stix_objects or #stix_objects == 0 then
        return 0
    end

    log_message("debug", "Processing STIX objects", {
        server_url = server_url,
        collection_id = collection_id,
        objects_count = #stix_objects
    })

    -- Parse and normalize STIX objects
    local parsed_result, parse_err = self.normalizer:process_objects(stix_objects)
    if not parsed_result then
        log_message("error", "STIX processing failed", {
            error = parse_err,
            objects_count = #stix_objects
        })
        return 0
    end

    if #parsed_result.indicators == 0 then
        log_message("debug", "No indicators found in STIX objects", {
            objects_processed = parsed_result.stats.total_objects
        })
        return 0
    end

    -- Create lookup sets
    local indicator_sets = self.normalizer:create_lookup_sets(parsed_result.indicators)

    -- Generate new cache version and load indicators
    local new_version = self.cache:generate_next_version()
    if not new_version then
        log_message("error", "Failed to generate cache version")
        return 0
    end

    -- Bulk load indicators into cache
    local load_result = self.cache:bulk_load_indicators(new_version, indicator_sets)

    -- Update cache metadata
    local metadata = self.cache:get_metadata()
    metadata.last_update = ngx.time()
    metadata.sources = metadata.sources or {}
    metadata.sources[server_url] = {
        collection_id = collection_id,
        last_update = ngx.time(),
        indicators_count = load_result.loaded
    }
    metadata.total_indicators = (metadata.total_indicators or 0) + load_result.loaded

    self.cache:set_metadata(metadata)

    -- Perform atomic version swap
    local swap_success, swap_err = self.cache:atomic_swap_version(new_version)
    if not swap_success then
        log_message("error", "Failed to swap cache version", {
            error = swap_err,
            version = new_version
        })
        return 0
    end

    log_message("info", "STIX objects processed successfully", {
        server_url = server_url,
        collection_id = collection_id,
        objects_processed = parsed_result.stats.total_objects,
        indicators_loaded = load_result.loaded,
        cache_version = new_version,
        stats = parsed_result.stats
    })

    return load_result.loaded
end

-- Update scheduler metrics
function TaxiiScheduler:update_metrics(metric_name, value)
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return
    end

    local key = METRICS_PREFIX .. metric_name
    if metric_name:find("_total$") then
        -- Increment counter metrics
        kong_cache:incr(key, value, 0)
    else
        -- Set gauge metrics
        kong_cache:set(key, value)
    end
end

-- Get scheduler metrics
function TaxiiScheduler:get_metrics()
    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return {}
    end

    local metrics = {}
    local metric_keys = {
        "polls_total",
        "indicators_loaded",
        "errors_total",
        "discovery_errors_total",
        "last_poll_duration_ms",
        "last_success_ts"
    }

    for _, metric in ipairs(metric_keys) do
        local key = METRICS_PREFIX .. metric
        metrics[metric] = kong_cache:get(key) or 0
    end

    return metrics
end

-- Get scheduler status
function TaxiiScheduler:get_status()
    local metrics = self:get_metrics()
    local cache_stats = self.cache:get_stats()

    return {
        running = self.running,
        enabled = self.enabled,
        poll_interval_seconds = self.poll_interval,
        servers_configured = #(self.config.taxii_servers or {}),
        metrics = metrics,
        cache = cache_stats,
        last_poll_time = metrics.last_success_ts > 0 and
            os.date("!%Y-%m-%dT%H:%M:%SZ", metrics.last_success_ts) or "never"
    }
end

-- Force immediate poll of all servers
function TaxiiScheduler:force_poll()
    if not self.enabled then
        return false, "TAXII ingestion disabled"
    end

    log_message("info", "Force polling requested")

    -- Schedule immediate poll
    local ok, err = ngx.timer.at(0, function()
        self:poll_all_servers()
    end)

    if not ok then
        log_message("error", "Failed to schedule force poll", {error = err})
        return false, err
    end

    return true, nil
end

-- Test connectivity to all configured servers
function TaxiiScheduler:test_connectivity()
    local servers = self.config.taxii_servers or {}
    local results = {}

    for i, server_config in ipairs(servers) do
        local success, err = self.client:test_connection(server_config)
        results[i] = {
            url = server_config.url,
            success = success,
            error = err,
            timestamp = ngx.time()
        }

        log_message(success and "info" or "error", "Connectivity test", {
            url = server_config.url,
            success = success,
            error = err
        })
    end

    return results
end

-- Reset scheduler state and metrics
function TaxiiScheduler:reset()
    log_message("info", "Resetting scheduler state")

    local kong_cache = ngx.shared.kong_cache
    if kong_cache then
        -- Clear metrics
        local metric_keys = {
            "polls_total",
            "indicators_loaded",
            "errors_total",
            "discovery_errors_total",
            "last_poll_duration_ms",
            "last_success_ts"
        }

        for _, metric in ipairs(metric_keys) do
            kong_cache:delete(METRICS_PREFIX .. metric)
        end

        -- Clear scheduler state
        kong_cache:delete(SCHEDULER_STATE_KEY)
    end

    -- Clear cache
    if self.cache then
        self.cache:clear_all()
    end

    log_message("info", "Scheduler reset completed")
end

-- Handle backoff on repeated failures
function TaxiiScheduler:handle_failure_backoff(server_url, failure_count)
    local base_interval = self.poll_interval
    local backoff_factor = math.min(failure_count, 5) -- Cap at 5x backoff
    local backoff_interval = base_interval * backoff_factor

    log_message("warn", "Applying failure backoff", {
        server_url = server_url,
        failure_count = failure_count,
        original_interval = base_interval,
        backoff_interval = backoff_interval
    })

    return backoff_interval
end

-- Cleanup function for graceful shutdown
function TaxiiScheduler:cleanup()
    log_message("info", "Performing scheduler cleanup")
    self:stop()

    -- Additional cleanup if needed
    if self.cache then
        -- Could add cache cleanup operations here
    end

    log_message("info", "Scheduler cleanup completed")
end

return TaxiiScheduler
