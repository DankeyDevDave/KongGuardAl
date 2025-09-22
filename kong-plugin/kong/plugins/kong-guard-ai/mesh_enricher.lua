-- Kubernetes/Service Mesh Metadata Enricher Module
-- Extracts and enriches K8s/mesh metadata from trusted headers (Istio/Envoy)

local MeshEnricher = {}
MeshEnricher.__index = MeshEnricher

-- Initialize the mesh enricher
function MeshEnricher:new(config)
    local self = setmetatable({}, MeshEnricher)
    self.config = config or {}
    self.cache_ttl = config.mesh_cache_ttl_seconds or 300
    self.pair_window = config.mesh_pair_window_seconds or 3600
    self.risky_namespaces = config.mesh_risky_namespaces or {"admin", "kube-system", "istio-system"}
    return self
end

-- Read mesh metadata headers from request
function MeshEnricher:read_headers(request, config)
    local headers = request.get_headers() or {}
    local header_map = config.mesh_header_map or {}

    local mesh_data = {
        trace_id = nil,
        namespace = nil,
        workload = nil,
        service = nil,
        pod = nil,
        zone = nil,
        mesh_source = nil
    }

    -- Extract each metadata type using configured header names
    for metadata_type, header_name in pairs(header_map) do
        if mesh_data[metadata_type] ~= nil then  -- Only process known metadata types
            local header_value = headers[header_name] or headers[header_name:lower()]
            if header_value and header_value ~= "" then
                mesh_data[metadata_type] = self:normalize(header_value)
            end
        end
    end

    return mesh_data
end

-- Normalize mesh metadata values
function MeshEnricher:normalize(value)
    if not value or type(value) ~= "string" then
        return nil
    end

    -- Strip whitespace and convert to lowercase for namespace/service/workload
    local normalized = value:gsub("^%s*(.-)%s*$", "%1"):lower()

    -- Validate length (prevent header injection)
    if #normalized > 253 then  -- DNS-1123 subdomain max length
        return nil
    end

    -- Validate characters for DNS-1123 compliance (for namespace/service/workload)
    -- Allow alphanumeric, hyphens, and dots
    if not normalized:match("^[a-z0-9.-]*$") then
        return nil
    end

    -- Don't allow empty strings
    if normalized == "" then
        return nil
    end

    return normalized
end

-- Check if namespace is considered risky
function MeshEnricher:is_risky_namespace(namespace)
    if not namespace then
        return false
    end

    for _, risky_ns in ipairs(self.risky_namespaces) do
        if namespace == risky_ns then
            return true
        end
    end
    return false
end

-- Generate pair key for tracking caller/callee relationships
function MeshEnricher:generate_pair_key(source, destination)
    if not source or not destination then
        return nil
    end

    -- Create a stable key for the service communication pair
    local src_key = (source.namespace or "unknown") .. ":" .. (source.service or "unknown")
    local dst_key = (destination.namespace or "unknown") .. ":" .. (destination.service or "unknown")

    return "mesh_pair:" .. src_key .. "->" .. dst_key
end

-- Get historical count for a service communication pair
function MeshEnricher:get_pair_count(source, destination)
    local pair_key = self:generate_pair_key(source, destination)
    if not pair_key then
        return 0
    end

    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return 0
    end

    local count = kong_cache:get(pair_key) or 0
    return tonumber(count) or 0
end

-- Increment pair counter with TTL
function MeshEnricher:increment_pair_count(source, destination)
    local pair_key = self:generate_pair_key(source, destination)
    if not pair_key then
        return
    end

    local kong_cache = ngx.shared.kong_cache
    if not kong_cache then
        return
    end

    -- Increment counter with TTL equal to the pair window
    local new_count, err = kong_cache:incr(pair_key, 1, 0, self.pair_window)
    if err then
        kong.log.warn("Failed to increment mesh pair counter: " .. (err or "unknown error"))
    end

    return new_count
end

-- Determine if a service pair is unusual based on historical data
function MeshEnricher:is_unusual_pair(source, destination, threshold)
    threshold = threshold or 5  -- Consider pairs with < 5 historical occurrences as unusual

    local count = self:get_pair_count(source, destination)
    return count < threshold
end

-- Extract destination service info from current service context
-- This would typically come from Kong's service/route configuration
function MeshEnricher:get_destination_info()
    -- Try to extract destination info from Kong context
    local service = kong.router.get_service()
    local route = kong.router.get_route()

    local destination = {
        namespace = nil,  -- Could be extracted from service tags or annotations
        service = nil,
        workload = nil
    }

    if service then
        destination.service = service.name

        -- Try to extract namespace from service tags
        if service.tags then
            for _, tag in ipairs(service.tags) do
                local ns_match = tag:match("^namespace:(.+)$")
                if ns_match then
                    destination.namespace = self:normalize(ns_match)
                    break
                end
            end
        end
    end

    if route then
        -- Could extract additional metadata from route if available
        if route.tags then
            for _, tag in ipairs(route.tags) do
                local workload_match = tag:match("^workload:(.+)$")
                if workload_match then
                    destination.workload = self:normalize(workload_match)
                    break
                end
            end
        end
    end

    return destination
end

-- Analyze mesh metadata and generate enrichment data
function MeshEnricher:analyze(mesh_data, config)
    local analysis = {
        cross_namespace = false,
        risky_namespace = false,
        unusual_pair = false,
        missing_headers = false,
        pair_count = 0,
        source_info = {},
        destination_info = {}
    }

    -- Check for missing critical headers
    local critical_headers = {"namespace", "service"}
    local missing_count = 0
    for _, header in ipairs(critical_headers) do
        if not mesh_data[header] or mesh_data[header] == "" then
            missing_count = missing_count + 1
        end
    end
    analysis.missing_headers = missing_count > 0

    -- If we have source namespace/service, proceed with analysis
    if mesh_data.namespace and mesh_data.service then
        analysis.source_info = {
            namespace = mesh_data.namespace,
            service = mesh_data.service,
            workload = mesh_data.workload,
            pod = mesh_data.pod,
            zone = mesh_data.zone
        }

        -- Check if source namespace is risky
        analysis.risky_namespace = self:is_risky_namespace(mesh_data.namespace)

        -- Get destination information
        analysis.destination_info = self:get_destination_info()

        -- Check for cross-namespace communication
        if analysis.destination_info.namespace and
           analysis.destination_info.namespace ~= mesh_data.namespace then
            analysis.cross_namespace = true
        end

        -- Check if this is an unusual service communication pair
        analysis.pair_count = self:get_pair_count(analysis.source_info, analysis.destination_info)
        analysis.unusual_pair = self:is_unusual_pair(analysis.source_info, analysis.destination_info)

        -- Increment the pair counter for future analysis
        self:increment_pair_count(analysis.source_info, analysis.destination_info)
    end

    return analysis
end

-- Calculate mesh-based threat score
function MeshEnricher:calculate_score(analysis, config)
    local score = 0
    local weights = config.mesh_score_weights or {
        cross_namespace = 0.3,
        risky_namespace = 0.3,
        unusual_pair = 0.3,
        missing_headers = 0.1
    }

    if analysis.cross_namespace then
        score = score + (weights.cross_namespace or 0.3)
    end

    if analysis.risky_namespace then
        score = score + (weights.risky_namespace or 0.3)
    end

    if analysis.unusual_pair then
        score = score + (weights.unusual_pair or 0.3)
    end

    if analysis.missing_headers then
        score = score + (weights.missing_headers or 0.1)
    end

    return math.min(score, 1.0)  -- Cap at 1.0
end

-- Generate detailed threat information for logging/alerting
function MeshEnricher:generate_threat_details(analysis, score)
    local details = {
        score = score,
        factors = {},
        source = analysis.source_info,
        destination = analysis.destination_info,
        pair_count = analysis.pair_count
    }

    if analysis.cross_namespace then
        table.insert(details.factors, "cross_namespace_communication")
    end

    if analysis.risky_namespace then
        table.insert(details.factors, "risky_namespace_access")
    end

    if analysis.unusual_pair then
        table.insert(details.factors, "unusual_service_pair")
    end

    if analysis.missing_headers then
        table.insert(details.factors, "missing_mesh_headers")
    end

    return details
end

return MeshEnricher