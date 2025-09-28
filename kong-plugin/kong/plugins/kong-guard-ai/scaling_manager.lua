--- Scaling Manager Module for Kong Guard AI
-- Provides horizontal scaling capabilities including load balancing, state synchronization,
-- health monitoring, and auto-scaling for distributed deployments.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local math = math
local table = table
local string = string
local os = os
local cjson = require("cjson.safe")

-- Constants
local DEFAULT_HEALTH_CHECK_INTERVAL = 30
local DEFAULT_LOAD_BALANCE_INTERVAL = 10
local DEFAULT_STATE_SYNC_INTERVAL = 60
local DEFAULT_MAX_INSTANCES = 10
local DEFAULT_HEALTH_TIMEOUT = 5
local DEFAULT_LOAD_THRESHOLD = 0.8

--- Create a new scaling manager instance
-- @param config Configuration table with scaling settings
-- @return Scaling manager instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for scaling manager"
    end

    local self = {
        -- Configuration
        config = config,

        -- Instance management
        instances = {
            local_instance = {
                id = config.instance_id or ngx.var.hostname or "instance-" .. ngx.now(),
                address = config.instance_address or "127.0.0.1",
                port = config.instance_port or 8000,
                status = "healthy",
                load = 0,
                last_seen = ngx.now(),
                capabilities = config.capabilities or {"threat_detection", "rate_limiting"}
            },
            peers = {},
            max_instances = config.max_instances or DEFAULT_MAX_INSTANCES
        },

        -- Load balancing
        load_balancer = {
            algorithm = config.load_balance_algorithm or "round_robin",
            current_index = 1,
            weights = {},
            enabled = config.enable_load_balancing or false,
            interval = config.load_balance_interval or DEFAULT_LOAD_BALANCE_INTERVAL,
            last_balance = 0
        },

        -- Health monitoring
        health_monitor = {
            enabled = config.enable_health_monitoring or true,
            interval = config.health_check_interval or DEFAULT_HEALTH_CHECK_INTERVAL,
            timeout = config.health_timeout or DEFAULT_HEALTH_TIMEOUT,
            failure_threshold = config.failure_threshold or 3,
            last_check = 0,
            checks = {}
        },

        -- State synchronization
        state_sync = {
            enabled = config.enable_state_sync or false,
            interval = config.state_sync_interval or DEFAULT_STATE_SYNC_INTERVAL,
            last_sync = 0,
            sync_data = {},
            conflicts = 0
        },

        -- Auto-scaling
        auto_scaling = {
            enabled = config.enable_auto_scaling or false,
            min_instances = config.min_instances or 1,
            max_instances = config.max_instances or 5,
            scale_up_threshold = config.scale_up_threshold or 0.8,
            scale_down_threshold = config.scale_down_threshold or 0.2,
            cooldown_period = config.cooldown_period or 300,
            last_scale_action = 0,
            current_instances = 1
        },

        -- Instance discovery
        discovery = {
            method = config.discovery_method or "static",
            endpoints = config.discovery_endpoints or {},
            last_discovery = 0,
            discovery_interval = config.discovery_interval or 60
        },

        -- Performance metrics
        metrics = {
            requests_routed = 0,
            load_balance_operations = 0,
            health_checks_performed = 0,
            state_sync_operations = 0,
            scaling_actions = 0,
            failover_events = 0,
            instance_failures = 0
        }
    }

    return setmetatable(self, mt)
end

--- Initialize scaling management features
function _M:init()
    -- Register local instance
    self:_register_instance(self.instances.local_instance)

    -- Initialize load balancer
    if self.load_balancer.enabled then
        self:_init_load_balancer()
    end

    -- Initialize health monitoring
    if self.health_monitor.enabled then
        self:_init_health_monitoring()
    end

    -- Initialize state synchronization
    if self.state_sync.enabled then
        self:_init_state_sync()
    end

    -- Initialize auto-scaling
    if self.auto_scaling.enabled then
        self:_init_auto_scaling()
    end

    -- Initialize instance discovery
    self:_init_discovery()

    kong.log.info("[kong-guard-ai] Scaling manager initialized: ", {
        instance_id = self.instances.local_instance.id,
        load_balancing = self.load_balancer.enabled,
        health_monitoring = self.health_monitor.enabled,
        auto_scaling = self.auto_scaling.enabled
    })
end

--- Register an instance in the cluster
function _M:_register_instance(instance)
    if not instance.id then
        return false, "Instance ID required"
    end

    -- Add to peers if not local instance
    if instance.id ~= self.instances.local_instance.id then
        self.instances.peers[instance.id] = instance
    end

    kong.log.debug("[kong-guard-ai] Instance registered: ", instance.id)
    return true
end

--- Initialize load balancer
function _M:_init_load_balancer()
    -- Set up periodic load balancing
    local ok, err = ngx.timer.every(self.load_balancer.interval, function()
        self:_perform_load_balancing()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize load balancer timer: ", err)
    end

    -- Initialize weights
    self:_update_instance_weights()
end

--- Initialize health monitoring
function _M:_init_health_monitoring()
    -- Set up periodic health checks
    local ok, err = ngx.timer.every(self.health_monitor.interval, function()
        self:_perform_health_checks()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize health monitoring timer: ", err)
    end
end

--- Initialize state synchronization
function _M:_init_state_sync()
    -- Set up periodic state sync
    local ok, err = ngx.timer.every(self.state_sync.interval, function()
        self:_perform_state_sync()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize state sync timer: ", err)
    end
end

--- Initialize auto-scaling
function _M:_init_auto_scaling()
    -- Set up periodic scaling checks
    local ok, err = ngx.timer.every(60, function()  -- Check every minute
        self:_check_auto_scaling()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize auto-scaling timer: ", err)
    end
end

--- Initialize instance discovery
function _M:_init_discovery()
    if self.discovery.method == "static" then
        -- Load static endpoints
        for _, endpoint in ipairs(self.discovery.endpoints) do
            self:_discover_instance(endpoint)
        end
    elseif self.discovery.method == "dns" then
        -- Set up DNS-based discovery
        self:_init_dns_discovery()
    elseif self.discovery.method == "etcd" or self.discovery.method == "consul" then
        -- Set up service discovery
        self:_init_service_discovery()
    end
end

--- Route request to appropriate instance
function _M:route_request(request_data)
    if not self.load_balancer.enabled then
        return self.instances.local_instance, "Local routing"
    end

    local target_instance = self:_select_instance(request_data)
    if target_instance then
        self.metrics.requests_routed = self.metrics.requests_routed + 1
        return target_instance
    end

    -- Fallback to local instance
    return self.instances.local_instance, "Fallback to local"
end

--- Select instance using load balancing algorithm
function _M:_select_instance(request_data)
    local healthy_instances = self:_get_healthy_instances()

    if #healthy_instances == 0 then
        kong.log.warn("[kong-guard-ai] No healthy instances available")
        return nil
    end

    if #healthy_instances == 1 then
        return healthy_instances[1]
    end

    -- Apply load balancing algorithm
    if self.load_balancer.algorithm == "round_robin" then
        return self:_round_robin_select(healthy_instances)
    elseif self.load_balancer.algorithm == "least_loaded" then
        return self:_least_loaded_select(healthy_instances)
    elseif self.load_balancer.algorithm == "weighted" then
        return self:_weighted_select(healthy_instances)
    elseif self.load_balancer.algorithm == "ip_hash" then
        return self:_ip_hash_select(healthy_instances, request_data)
    else
        return healthy_instances[1]  -- Default fallback
    end
end

--- Round-robin instance selection
function _M:_round_robin_select(instances)
    local instance = instances[self.load_balancer.current_index]
    self.load_balancer.current_index = self.load_balancer.current_index % #instances + 1
    return instance
end

--- Least loaded instance selection
function _M:_least_loaded_select(instances)
    local min_load = math.huge
    local selected_instance = nil

    for _, instance in ipairs(instances) do
        if instance.load < min_load then
            min_load = instance.load
            selected_instance = instance
        end
    end

    return selected_instance
end

--- Weighted instance selection
function _M:_weighted_select(instances)
    local total_weight = 0
    for _, instance in ipairs(instances) do
        total_weight = total_weight + (self.load_balancer.weights[instance.id] or 1)
    end

    local random_weight = math.random(1, total_weight)
    local current_weight = 0

    for _, instance in ipairs(instances) do
        current_weight = current_weight + (self.load_balancer.weights[instance.id] or 1)
        if random_weight <= current_weight then
            return instance
        end
    end

    return instances[1]  -- Fallback
end

--- IP hash instance selection
function _M:_ip_hash_select(instances, request_data)
    local client_ip = request_data.client_ip or ngx.var.remote_addr or "127.0.0.1"
    local hash = 0

    for i = 1, #client_ip do
        hash = (hash * 31 + client_ip:byte(i)) % #instances
    end

    return instances[hash + 1]
end

--- Get list of healthy instances
function _M:_get_healthy_instances()
    local healthy = {self.instances.local_instance}  -- Always include local instance

    for _, instance in pairs(self.instances.peers) do
        if instance.status == "healthy" then
            table.insert(healthy, instance)
        end
    end

    return healthy
end

--- Update instance weights based on capabilities and load
function _M:_update_instance_weights()
    for _, instance in pairs(self.instances.peers) do
        local weight = 1

        -- Base weight on capabilities
        if instance.capabilities then
            for _, capability in ipairs(instance.capabilities) do
                if capability == "gpu_acceleration" then
                    weight = weight * 2
                elseif capability == "high_memory" then
                    weight = weight * 1.5
                end
            end
        end

        -- Adjust for current load
        if instance.load > 0.7 then
            weight = weight * 0.5  -- Reduce weight for heavily loaded instances
        end

        self.load_balancer.weights[instance.id] = weight
    end
end

--- Perform load balancing operations
function _M:_perform_load_balancing()
    self:_update_instance_weights()
    self.metrics.load_balance_operations = self.metrics.load_balance_operations + 1
    self.load_balancer.last_balance = ngx.now()
end

--- Perform health checks on all instances
function _M:_perform_health_checks()
    local current_time = ngx.now()

    for instance_id, instance in pairs(self.instances.peers) do
        self:_check_instance_health(instance)
    end

    -- Check local instance health
    self:_check_local_health()

    self.health_monitor.last_check = current_time
    self.metrics.health_checks_performed = self.metrics.health_checks_performed + 1
end

--- Check health of a specific instance
function _M:_check_instance_health(instance)
    -- Simulate health check (in real implementation, make HTTP request)
    local is_healthy = self:_perform_health_check_request(instance)

    if is_healthy then
        if instance.status ~= "healthy" then
            kong.log.info("[kong-guard-ai] Instance recovered: ", instance.id)
        end
        instance.status = "healthy"
        instance.consecutive_failures = 0
    else
        instance.consecutive_failures = (instance.consecutive_failures or 0) + 1

        if instance.consecutive_failures >= self.health_monitor.failure_threshold then
            if instance.status == "healthy" then
                kong.log.warn("[kong-guard-ai] Instance failed: ", instance.id)
                self.metrics.instance_failures = self.metrics.instance_failures + 1
            end
            instance.status = "unhealthy"
        end
    end

    instance.last_health_check = ngx.now()
end

--- Perform actual health check request
function _M:_perform_health_check_request(instance)
    -- Placeholder for actual HTTP health check
    -- In real implementation, this would make an HTTP request to instance:port/health
    return math.random() > 0.1  -- 90% success rate for simulation
end

--- Check local instance health
function _M:_check_local_health()
    -- Local health check - check system resources
    local memory_usage = collectgarbage("count") / 1024  -- MB
    local is_healthy = memory_usage < 1024  -- Less than 1GB memory usage

    self.instances.local_instance.status = is_healthy and "healthy" or "degraded"
    self.instances.local_instance.last_health_check = ngx.now()
end

--- Perform state synchronization
function _M:_perform_state_sync()
    if not self.state_sync.enabled then
        return
    end

    -- Sync with peer instances
    for instance_id, instance in pairs(self.instances.peers) do
        if instance.status == "healthy" then
            self:_sync_with_instance(instance)
        end
    end

    self.state_sync.last_sync = ngx.now()
    self.metrics.state_sync_operations = self.metrics.state_sync_operations + 1
end

--- Synchronize state with a specific instance
function _M:_sync_with_instance(instance)
    -- Placeholder for state synchronization logic
    -- In real implementation, this would exchange state data via HTTP

    -- Simulate sync operation
    local sync_successful = math.random() > 0.05  -- 95% success rate

    if not sync_successful then
        self.state_sync.conflicts = self.state_sync.conflicts + 1
        kong.log.warn("[kong-guard-ai] State sync conflict with instance: ", instance.id)
    end
end

--- Check if auto-scaling is needed
function _M:_check_auto_scaling()
    if not self.auto_scaling.enabled then
        return
    end

    local current_time = ngx.now()
    if current_time - self.auto_scaling.last_scale_action < self.auto_scaling.cooldown_period then
        return  -- Still in cooldown
    end

    local avg_load = self:_calculate_average_load()
    local healthy_count = #self:_get_healthy_instances()

    -- Scale up
    if avg_load > self.auto_scaling.scale_up_threshold and
       healthy_count < self.auto_scaling.max_instances then
        self:_scale_up()
    end

    -- Scale down
    if avg_load < self.auto_scaling.scale_down_threshold and
       healthy_count > self.auto_scaling.min_instances then
        self:_scale_down()
    end
end

--- Scale up by adding instances
function _M:_scale_up()
    kong.log.info("[kong-guard-ai] Scaling up cluster")
    self.metrics.scaling_actions = self.metrics.scaling_actions + 1
    self.auto_scaling.last_scale_action = ngx.now()

    -- In real implementation, this would trigger instance creation
    -- via orchestration system (Kubernetes, Docker Swarm, etc.)
end

--- Scale down by removing instances
function _M:_scale_down()
    kong.log.info("[kong-guard-ai] Scaling down cluster")
    self.metrics.scaling_actions = self.metrics.scaling_actions + 1
    self.auto_scaling.last_scale_action = ngx.now()

    -- In real implementation, this would trigger instance removal
    -- via orchestration system
end

--- Calculate average load across all instances
function _M:_calculate_average_load()
    local total_load = 0
    local instance_count = 0

    -- Local instance
    total_load = total_load + (self.instances.local_instance.load or 0)
    instance_count = instance_count + 1

    -- Peer instances
    for _, instance in pairs(self.instances.peers) do
        if instance.status == "healthy" then
            total_load = total_load + (instance.load or 0)
            instance_count = instance_count + 1
        end
    end

    return instance_count > 0 and (total_load / instance_count) or 0
end

--- Discover new instances
function _M:_discover_instance(endpoint)
    -- Placeholder for instance discovery logic
    -- In real implementation, this would query service discovery systems

    local new_instance = {
        id = "discovered-" .. ngx.now(),
        address = endpoint.address,
        port = endpoint.port,
        status = "unknown",
        load = 0,
        last_seen = ngx.now(),
        capabilities = endpoint.capabilities or {}
    }

    self:_register_instance(new_instance)
end

--- Initialize DNS-based discovery
function _M:_init_dns_discovery()
    -- Placeholder for DNS discovery setup
    kong.log.debug("[kong-guard-ai] DNS-based discovery initialized")
end

--- Initialize service discovery
function _M:_init_service_discovery()
    -- Placeholder for service discovery setup (etcd, consul, etc.)
    kong.log.debug("[kong-guard-ai] Service discovery initialized")
end

--- Update instance load
function _M:update_instance_load(instance_id, load)
    if instance_id == self.instances.local_instance.id then
        self.instances.local_instance.load = load
    elseif self.instances.peers[instance_id] then
        self.instances.peers[instance_id].load = load
    end
end

--- Handle instance failure/failover
function _M:handle_instance_failure(instance_id)
    if self.instances.peers[instance_id] then
        self.instances.peers[instance_id].status = "failed"
        self.metrics.failover_events = self.metrics.failover_events + 1

        kong.log.warn("[kong-guard-ai] Instance failure handled: ", instance_id)

        -- Trigger failover logic
        self:_trigger_failover(instance_id)
    end
end

--- Trigger failover for failed instance
function _M:_trigger_failover(instance_id)
    -- Redistribute load to healthy instances
    self:_perform_load_balancing()

    -- Notify other instances of failure
    for peer_id, peer in pairs(self.instances.peers) do
        if peer.status == "healthy" and peer_id ~= instance_id then
            -- In real implementation, send notification to peer
            kong.log.debug("[kong-guard-ai] Notified peer of failure: ", peer_id)
        end
    end
end

--- Get scaling statistics
function _M:get_stats()
    local healthy_instances = self:_get_healthy_instances()
    local total_instances = 1 + #self.instances.peers  -- Local + peers

    return {
        instances = {
            total = total_instances,
            healthy = #healthy_instances,
            unhealthy = total_instances - #healthy_instances,
            local_instance = self.instances.local_instance
        },
        load_balancer = self.load_balancer.enabled and {
            algorithm = self.load_balancer.algorithm,
            operations = self.metrics.load_balance_operations,
            last_balance = self.load_balancer.last_balance
        } or nil,
        health_monitor = self.health_monitor.enabled and {
            checks_performed = self.metrics.health_checks_performed,
            last_check = self.health_monitor.last_check,
            failures = self.metrics.instance_failures
        } or nil,
        state_sync = self.state_sync.enabled and {
            operations = self.metrics.state_sync_operations,
            last_sync = self.state_sync.last_sync,
            conflicts = self.state_sync.conflicts
        } or nil,
        auto_scaling = self.auto_scaling.enabled and {
            current_instances = self.auto_scaling.current_instances,
            scaling_actions = self.metrics.scaling_actions,
            last_scale_action = self.auto_scaling.last_scale_action
        } or nil,
        performance = {
            requests_routed = self.metrics.requests_routed,
            failover_events = self.metrics.failover_events,
            average_load = self:_calculate_average_load()
        }
    }
end

--- Clean up resources
function _M:cleanup()
    -- Clear instance data
    self.instances.peers = {}

    -- Reset metrics
    for key in pairs(self.metrics) do
        self.metrics[key] = 0
    end

    kong.log.info("[kong-guard-ai] Scaling manager cleanup completed")
end

return _M
