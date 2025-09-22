--- Data Catalog Integration Module for Kong Guard AI
-- Integrates with data catalog systems for metadata management and data discovery

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local http = require("resty.http")
local uuid = require("resty.uuid")

-- Supported catalog systems
local CATALOG_SYSTEMS = {
    ALATION = "alation",
    COLLIBRA = "collibra",
    DATAHUB = "datahub",
    AMUNDSEN = "amundsen",
    GENERIC_REST = "generic_rest"
}

-- Data asset types
local ASSET_TYPES = {
    API_ENDPOINT = "api_endpoint",
    DATABASE_TABLE = "database_table",
    DATA_STREAM = "data_stream",
    FILE = "file",
    DASHBOARD = "dashboard",
    MODEL = "model"
}

-- Metadata fields
local METADATA_FIELDS = {
    -- Basic metadata
    name = "string",
    description = "string",
    owner = "string",
    created_at = "timestamp",
    updated_at = "timestamp",
    tags = "array",

    -- Data governance
    classification = "string",
    sensitivity_level = "string",
    retention_policy = "string",
    data_steward = "string",

    -- Technical metadata
    schema = "object",
    data_type = "string",
    size_bytes = "number",
    record_count = "number",

    -- Usage metadata
    access_count = "number",
    last_accessed = "timestamp",
    dependent_assets = "array",

    -- Quality metadata
    quality_score = "number",
    data_quality_issues = "array",

    -- Security metadata
    encryption_status = "string",
    access_policies = "array",
    compliance_status = "string"
}

--- Create a new data catalog integrator instance
function _M.new(config)
    local self = {
        config = config or {},
        catalog_system = config.catalog_system or CATALOG_SYSTEMS.GENERIC_REST,
        catalog_endpoint = config.catalog_endpoint,
        api_key = config.api_key,
        auth_token = config.auth_token,
        registered_assets = {},
        metadata_cache = {},
        sync_interval = config.sync_interval or 3600, -- 1 hour
        enable_auto_registration = config.enable_auto_registration or false,
        enable_metadata_sync = config.enable_metadata_sync or false
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the catalog integrator
function _M:init()
    -- Set up periodic metadata sync
    if self.enable_metadata_sync then
        local ok, err = ngx.timer.every(self.sync_interval, function()
            self:_sync_metadata()
        end)

        if not ok then
            kong.log.err("[kong-guard-ai] Failed to initialize metadata sync: ", err)
        end
    end

    kong.log.info("[kong-guard-ai] Data catalog integrator initialized for: ", self.catalog_system)
end

--- Register a data asset in the catalog
function _M:register_asset(asset_data, context)
    if not asset_data or not asset_data.name then
        return false, "Asset name is required"
    end

    local asset_id = asset_data.asset_id or uuid.generate()
    local asset_type = asset_data.asset_type or ASSET_TYPES.API_ENDPOINT

    -- Prepare asset metadata
    local metadata = self:_prepare_asset_metadata(asset_data, context)
    metadata.asset_id = asset_id
    metadata.asset_type = asset_type
    metadata.registered_at = ngx.now()
    metadata.registered_by = "kong-guard-ai"

    -- Register with catalog system
    local success, result = self:_register_with_catalog(metadata)

    if success then
        -- Store locally
        self.registered_assets[asset_id] = metadata

        kong.log.info("[kong-guard-ai] Asset registered in catalog: ", {
            asset_id = asset_id,
            name = metadata.name,
            type = asset_type
        })

        return true, {
            asset_id = asset_id,
            catalog_reference = result.catalog_reference,
            metadata = metadata
        }
    else
        kong.log.err("[kong-guard-ai] Failed to register asset in catalog: ", result)
        return false, result
    end
end

--- Update asset metadata
function _M:update_asset_metadata(asset_id, updates, context)
    if not self.registered_assets[asset_id] then
        return false, "Asset not found"
    end

    local metadata = self.registered_assets[asset_id]

    -- Apply updates
    for key, value in pairs(updates) do
        if METADATA_FIELDS[key] then
            metadata[key] = value
        end
    end

    metadata.updated_at = ngx.now()
    metadata.updated_by = context.user_id or "kong-guard-ai"

    -- Update in catalog system
    local success, result = self:_update_catalog_asset(asset_id, metadata)

    if success then
        kong.log.debug("[kong-guard-ai] Asset metadata updated: ", asset_id)
        return true, metadata
    else
        kong.log.err("[kong-guard-ai] Failed to update asset metadata: ", result)
        return false, result
    end
end

--- Search for assets in the catalog
function _M:search_assets(query, filters, options)
    options = options or {}

    -- Search locally first
    local local_results = self:_search_local_assets(query, filters)

    -- Search catalog system
    local catalog_results = self:_search_catalog_assets(query, filters, options)

    -- Combine and deduplicate results
    local combined_results = self:_combine_search_results(local_results, catalog_results)

    -- Apply pagination
    if options.limit then
        local paginated = {}
        for i = 1, math.min(options.limit, #combined_results) do
            table.insert(paginated, combined_results[i])
        end
        combined_results = paginated
    end

    return combined_results
end

--- Get asset details
function _M:get_asset_details(asset_id, include_lineage)
    -- Check local cache first
    if self.registered_assets[asset_id] then
        local asset = self.registered_assets[asset_id]

        if include_lineage then
            asset.lineage = self:_get_asset_lineage(asset_id)
        end

        return asset
    end

    -- Fetch from catalog system
    local success, result = self:_get_catalog_asset(asset_id)

    if success then
        -- Cache locally
        self.registered_assets[asset_id] = result

        if include_lineage then
            result.lineage = self:_get_asset_lineage(asset_id)
        end

        return result
    end

    return nil, "Asset not found"
end

--- Get data lineage for an asset
function _M:get_asset_lineage(asset_id)
    return self:_get_asset_lineage(asset_id)
end

--- Tag an asset
function _M:tag_asset(asset_id, tags, context)
    if not self.registered_assets[asset_id] then
        return false, "Asset not found"
    end

    local metadata = self.registered_assets[asset_id]

    -- Add tags
    metadata.tags = metadata.tags or {}
    for _, tag in ipairs(tags) do
        if not self:_array_contains(metadata.tags, tag) then
            table.insert(metadata.tags, tag)
        end
    end

    metadata.updated_at = ngx.now()
    metadata.tagged_by = context.user_id or "kong-guard-ai"

    -- Update in catalog
    local success, result = self:_update_catalog_asset(asset_id, metadata)

    if success then
        kong.log.debug("[kong-guard-ai] Asset tagged: ", asset_id, " tags: ", cjson.encode(tags))
        return true, metadata.tags
    else
        return false, result
    end
end

--- Remove asset from catalog
function _M:unregister_asset(asset_id, context)
    if not self.registered_assets[asset_id] then
        return false, "Asset not found"
    end

    -- Remove from catalog system
    local success, result = self:_unregister_from_catalog(asset_id)

    if success then
        -- Remove locally
        self.registered_assets[asset_id] = nil

        kong.log.info("[kong-guard-ai] Asset unregistered from catalog: ", asset_id)
        return true
    else
        kong.log.err("[kong-guard-ai] Failed to unregister asset: ", result)
        return false, result
    end
end

--- Auto-register API endpoints
function _M:auto_register_api_endpoints(context)
    if not self.enable_auto_registration then
        return
    end

    -- Extract API endpoint information from context
    local endpoint_data = {
        name = context.path or "unknown_endpoint",
        description = "Auto-registered API endpoint",
        asset_type = ASSET_TYPES.API_ENDPOINT,
        endpoint_path = context.path,
        http_method = context.method,
        parameters = context.query_params,
        response_schema = context.response_schema
    }

    -- Check if already registered
    local existing_asset = self:_find_asset_by_path(context.path, context.method)
    if existing_asset then
        -- Update existing asset
        return self:update_asset_metadata(existing_asset.asset_id, {
            last_accessed = ngx.now(),
            access_count = (existing_asset.access_count or 0) + 1
        }, context)
    else
        -- Register new asset
        return self:register_asset(endpoint_data, context)
    end
end

--- Helper functions for catalog system integration

function _M:_register_with_catalog(metadata)
    if self.catalog_system == CATALOG_SYSTEMS.ALATION then
        return self:_register_alation_asset(metadata)
    elseif self.catalog_system == CATALOG_SYSTEMS.COLLIBRA then
        return self:_register_collibra_asset(metadata)
    elseif self.catalog_system == CATALOG_SYSTEMS.DATAHUB then
        return self:_register_datahub_asset(metadata)
    elseif self.catalog_system == CATALOG_SYSTEMS.GENERIC_REST then
        return self:_register_generic_rest_asset(metadata)
    else
        return false, "Unsupported catalog system: " .. self.catalog_system
    end
end

function _M:_update_catalog_asset(asset_id, metadata)
    if self.catalog_system == CATALOG_SYSTEMS.GENERIC_REST then
        return self:_update_generic_rest_asset(asset_id, metadata)
    else
        -- For other systems, implement specific update methods
        return true, {updated = true}
    end
end

function _M:_search_catalog_assets(query, filters, options)
    if self.catalog_system == CATALOG_SYSTEMS.GENERIC_REST then
        return self:_search_generic_rest_assets(query, filters, options)
    else
        -- Return empty results for unsupported systems
        return {}
    end
end

function _M:_get_catalog_asset(asset_id)
    if self.catalog_system == CATALOG_SYSTEMS.GENERIC_REST then
        return self:_get_generic_rest_asset(asset_id)
    else
        return false, "Asset not found in catalog"
    end
end

function _M:_unregister_from_catalog(asset_id)
    if self.catalog_system == CATALOG_SYSTEMS.GENERIC_REST then
        return self:_unregister_generic_rest_asset(asset_id)
    else
        return true, {unregistered = true}
    end
end

--- Generic REST API implementations

function _M:_register_generic_rest_asset(metadata)
    if not self.catalog_endpoint then
        return false, "Catalog endpoint not configured"
    end

    local httpc = http.new()
    local url = self.catalog_endpoint .. "/assets"

    local headers = {
        ["Content-Type"] = "application/json"
    }

    if self.auth_token then
        headers["Authorization"] = "Bearer " .. self.auth_token
    elseif self.api_key then
        headers["X-API-Key"] = self.api_key
    end

    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = cjson.encode(metadata),
        headers = headers
    })

    if res and res.status == 201 then
        local response = cjson.decode(res.body)
        return true, {
            catalog_reference = response.asset_id or response.id,
            registered = true
        }
    else
        return false, err or "Registration failed"
    end
end

function _M:_update_generic_rest_asset(asset_id, metadata)
    if not self.catalog_endpoint then
        return false, "Catalog endpoint not configured"
    end

    local httpc = http.new()
    local url = self.catalog_endpoint .. "/assets/" .. asset_id

    local headers = {
        ["Content-Type"] = "application/json"
    }

    if self.auth_token then
        headers["Authorization"] = "Bearer " .. self.auth_token
    elseif self.api_key then
        headers["X-API-Key"] = self.api_key
    end

    local res, err = httpc:request_uri(url, {
        method = "PUT",
        body = cjson.encode(metadata),
        headers = headers
    })

    if res and res.status == 200 then
        return true, {updated = true}
    else
        return false, err or "Update failed"
    end
end

function _M:_search_generic_rest_assets(query, filters, options)
    if not self.catalog_endpoint then
        return {}
    end

    local httpc = http.new()
    local url = self.catalog_endpoint .. "/assets/search"

    local search_params = {
        q = query,
        filters = cjson.encode(filters or {}),
        limit = options.limit or 50,
        offset = options.offset or 0
    }

    local query_string = ""
    for key, value in pairs(search_params) do
        if query_string ~= "" then
            query_string = query_string .. "&"
        end
        query_string = query_string .. key .. "=" .. ngx.escape_uri(tostring(value))
    end

    url = url .. "?" .. query_string

    local headers = {}
    if self.auth_token then
        headers["Authorization"] = "Bearer " .. self.auth_token
    elseif self.api_key then
        headers["X-API-Key"] = self.api_key
    end

    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = headers
    })

    if res and res.status == 200 then
        local response = cjson.decode(res.body)
        return response.assets or response.results or {}
    else
        kong.log.err("[kong-guard-ai] Catalog search failed: ", err)
        return {}
    end
end

function _M:_get_generic_rest_asset(asset_id)
    if not self.catalog_endpoint then
        return false, "Catalog endpoint not configured"
    end

    local httpc = http.new()
    local url = self.catalog_endpoint .. "/assets/" .. asset_id

    local headers = {}
    if self.auth_token then
        headers["Authorization"] = "Bearer " .. self.auth_token
    elseif self.api_key then
        headers["X-API-Key"] = self.api_key
    end

    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = headers
    })

    if res and res.status == 200 then
        local asset = cjson.decode(res.body)
        return true, asset
    else
        return false, err or "Asset not found"
    end
end

function _M:_unregister_generic_rest_asset(asset_id)
    if not self.catalog_endpoint then
        return false, "Catalog endpoint not configured"
    end

    local httpc = http.new()
    local url = self.catalog_endpoint .. "/assets/" .. asset_id

    local headers = {}
    if self.auth_token then
        headers["Authorization"] = "Bearer " .. self.auth_token
    elseif self.api_key then
        headers["X-API-Key"] = self.api_key
    end

    local res, err = httpc:request_uri(url, {
        method = "DELETE",
        headers = headers
    })

    if res and res.status == 204 then
        return true, {unregistered = true}
    else
        return false, err or "Unregistration failed"
    end
end

--- Local asset management

function _M:_search_local_assets(query, filters)
    local results = {}

    for asset_id, metadata in pairs(self.registered_assets) do
        if self:_matches_search_criteria(metadata, query, filters) then
            table.insert(results, {
                asset_id = asset_id,
                name = metadata.name,
                description = metadata.description,
                asset_type = metadata.asset_type,
                tags = metadata.tags,
                source = "local"
            })
        end
    end

    return results
end

function _M:_matches_search_criteria(metadata, query, filters)
    -- Check query match
    if query then
        local search_text = string.lower(metadata.name or "" .. " " .. (metadata.description or ""))
        if not string.find(search_text, string.lower(query)) then
            return false
        end
    end

    -- Check filters
    if filters then
        for key, value in pairs(filters) do
            if metadata[key] ~= value then
                return false
            end
        end
    end

    return true
end

function _M:_combine_search_results(local_results, catalog_results)
    local combined = {}

    -- Add all local results
    for _, result in ipairs(local_results) do
        table.insert(combined, result)
    end

    -- Add catalog results, avoiding duplicates
    for _, catalog_result in ipairs(catalog_results) do
        local is_duplicate = false
        for _, existing in ipairs(combined) do
            if existing.asset_id == catalog_result.asset_id or
               (existing.name == catalog_result.name and existing.asset_type == catalog_result.asset_type) then
                is_duplicate = true
                break
            end
        end

        if not is_duplicate then
            catalog_result.source = "catalog"
            table.insert(combined, catalog_result)
        end
    end

    return combined
end

function _M:_find_asset_by_path(path, method)
    for asset_id, metadata in pairs(self.registered_assets) do
        if metadata.asset_type == ASSET_TYPES.API_ENDPOINT and
           metadata.endpoint_path == path and
           (not method or metadata.http_method == method) then
            return metadata
        end
    end

    return nil
end

function _M:_get_asset_lineage(asset_id)
    -- Mock lineage data - in production would query lineage system
    return {
        upstream = {},
        downstream = {},
        transformations = {},
        last_updated = ngx.now()
    }
end

function _M:_prepare_asset_metadata(asset_data, context)
    local metadata = {}

    -- Copy standard fields
    for field, field_type in pairs(METADATA_FIELDS) do
        if asset_data[field] then
            metadata[field] = asset_data[field]
        end
    end

    -- Add context information
    if context then
        metadata.created_by = context.user_id or "kong-guard-ai"
        metadata.source_system = context.source_system or "kong-guard-ai"
        metadata.environment = context.environment or "production"
    end

    -- Set defaults
    metadata.created_at = metadata.created_at or ngx.now()
    metadata.updated_at = metadata.updated_at or ngx.now()
    metadata.tags = metadata.tags or {}

    return metadata
end

function _M:_array_contains(array, value)
    for _, item in ipairs(array) do
        if item == value then
            return true
        end
    end
    return false
end

--- Sync metadata with catalog system
function _M:_sync_metadata()
    if not self.enable_metadata_sync then
        return
    end

    kong.log.debug("[kong-guard-ai] Starting metadata sync with catalog")

    local sync_count = 0

    -- Sync registered assets
    for asset_id, metadata in pairs(self.registered_assets) do
        local success, result = self:_update_catalog_asset(asset_id, metadata)
        if success then
            sync_count = sync_count + 1
        else
            kong.log.warn("[kong-guard-ai] Failed to sync asset: ", asset_id, " error: ", result)
        end
    end

    kong.log.info("[kong-guard-ai] Metadata sync completed: ", sync_count, " assets synced")
end

--- Get catalog statistics
function _M:get_catalog_statistics()
    return {
        catalog_system = self.catalog_system,
        registered_assets = self:_count_table_fields(self.registered_assets),
        enable_auto_registration = self.enable_auto_registration,
        enable_metadata_sync = self.enable_metadata_sync,
        last_sync = ngx.now() -- In production, track actual sync times
    }
end

--- Validate catalog configuration
function _M:validate_configuration()
    local issues = {}

    if not self.catalog_endpoint and self.catalog_system ~= CATALOG_SYSTEMS.GENERIC_REST then
        table.insert(issues, "Catalog endpoint required for " .. self.catalog_system)
    end

    if self.enable_metadata_sync and not (self.auth_token or self.api_key) then
        table.insert(issues, "Authentication required for metadata sync")
    end

    return #issues == 0, issues
end

return _M