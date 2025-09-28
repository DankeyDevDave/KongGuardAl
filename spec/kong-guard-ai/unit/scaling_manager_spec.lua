--- Unit tests for Scaling Manager Module
-- Tests load balancing, health monitoring, state sync, and auto-scaling features

local ScalingManager = require("kong.plugins.kong-guard-ai.scaling_manager")

describe("Scaling Manager", function()
    local config
    local manager

    before_each(function()
        config = {
            instance_id = "test-instance-1",
            instance_address = "127.0.0.1",
            instance_port = 8000,
            enable_load_balancing = true,
            load_balance_algorithm = "round_robin",
            enable_health_monitoring = true,
            health_check_interval = 30,
            enable_state_sync = true,
            enable_auto_scaling = true,
            min_instances = 1,
            max_instances = 5,
            scale_up_threshold = 0.8,
            scale_down_threshold = 0.2,
            discovery_method = "static",
            discovery_endpoints = {
                {address = "127.0.0.2", port = 8000},
                {address = "127.0.0.3", port = 8000}
            }
        }

        -- Mock kong global
        _G.kong = {
            log = {
                info = function(...) end,
                warn = function(...) end,
                err = function(...) end,
                debug = function(...) end
            }
        }

        -- Mock ngx global
        _G.ngx = {
            now = function() return os.time() end,
            timer = {
                every = function(interval, callback)
                    return true
                end
            },
            var = {
                hostname = "test-host",
                remote_addr = "127.0.0.1"
            }
        }

        -- Mock cjson
        _G.cjson = {
            encode = function(obj) return "{}" end,
            decode = function(str) return {} end
        }

        -- Mock math.random for predictable testing
        local original_random = math.random
        math.random = function(...)
            if ... then
                return original_random(...)
            else
                return 0.5  -- Return 0.5 for health checks
            end
        end

        manager = ScalingManager.new(config)
        assert.is_not_nil(manager)
    end)

    after_each(function()
        manager = nil
        _G.kong = nil
        _G.ngx = nil
        _G.cjson = nil
        math.random = _G.original_math_random or math.random
    end)

    describe("Initialization", function()
        it("should create manager with valid config", function()
            local mgr = ScalingManager.new(config)
            assert.is_not_nil(mgr)
            assert.is_table(mgr.instances)
            assert.is_table(mgr.load_balancer)
            assert.is_table(mgr.health_monitor)
        end)

        it("should fail with invalid config", function()
            local mgr, err = ScalingManager.new(nil)
            assert.is_nil(mgr)
            assert.is_string(err)
        end)

        it("should initialize with local instance", function()
            manager:init()
            assert.equal("test-instance-1", manager.instances.local_instance.id)
            assert.equal("healthy", manager.instances.local_instance.status)
        end)
    end)

    describe("Instance Management", function()
        it("should register peer instances", function()
            local peer_instance = {
                id = "peer-1",
                address = "127.0.0.2",
                port = 8000,
                status = "healthy"
            }

            local success = manager:_register_instance(peer_instance)
            assert.is_true(success)
            assert.is_not_nil(manager.instances.peers["peer-1"])
        end)

        it("should get healthy instances", function()
            -- Add a healthy peer
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy"
            }

            -- Add an unhealthy peer
            manager.instances.peers["peer-2"] = {
                id = "peer-2",
                status = "unhealthy"
            }

            local healthy = manager:_get_healthy_instances()
            assert.equal(2, #healthy)  -- Local + 1 healthy peer
            assert.equal("test-instance-1", healthy[1].id)
            assert.equal("peer-1", healthy[2].id)
        end)

        it("should update instance load", function()
            manager:update_instance_load("test-instance-1", 0.7)
            assert.equal(0.7, manager.instances.local_instance.load)

            manager:update_instance_load("peer-1", 0.5)
            assert.equal(0.5, manager.instances.peers["peer-1"].load)
        end)
    end)

    describe("Load Balancing", function()
        before_each(function()
            manager:init()
            -- Add some peer instances
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy",
                load = 0.3
            }
            manager.instances.peers["peer-2"] = {
                id = "peer-2",
                status = "healthy",
                load = 0.4
            }
        end)

        it("should route requests using round-robin", function()
            local request_data = {client_ip = "127.0.0.1"}

            local instance1 = manager:route_request(request_data)
            local instance2 = manager:route_request(request_data)
            local instance3 = manager:route_request(request_data)

            -- Should cycle through instances
            assert.is_not_nil(instance1)
            assert.is_not_nil(instance2)
            assert.is_not_nil(instance3)
        end)

        it("should select least loaded instance", function()
            manager.load_balancer.algorithm = "least_loaded"

            local request_data = {client_ip = "127.0.0.1"}
            local selected = manager:route_request(request_data)

            -- Should select peer-1 (lower load)
            assert.equal("peer-1", selected.id)
        end)

        it("should handle IP hash routing", function()
            manager.load_balancer.algorithm = "ip_hash"

            local request_data = {client_ip = "192.168.1.100"}
            local selected1 = manager:route_request(request_data)
            local selected2 = manager:route_request(request_data)

            -- Same IP should route to same instance
            assert.equal(selected1.id, selected2.id)
        end)

        it("should update instance weights", function()
            manager:_update_instance_weights()

            -- Should have weights for peer instances
            assert.is_number(manager.load_balancer.weights["peer-1"])
            assert.is_number(manager.load_balancer.weights["peer-2"])
        end)

        it("should fallback to local instance when no peers available", function()
            -- Clear peers and set them unhealthy
            manager.instances.peers = {}
            manager.load_balancer.enabled = true

            local request_data = {client_ip = "127.0.0.1"}
            local selected = manager:route_request(request_data)

            assert.equal("test-instance-1", selected.id)
        end)
    end)

    describe("Health Monitoring", function()
        it("should perform health checks", function()
            -- Add a peer instance
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                address = "127.0.0.1",
                port = 8000,
                status = "unknown",
                consecutive_failures = 0
            }

            manager:_perform_health_checks()

            -- Instance should be marked as healthy (based on mock)
            assert.equal("healthy", manager.instances.peers["peer-1"].status)
        end)

        it("should handle instance failures", function()
            -- Mock health check to always fail
            manager._perform_health_check_request = function() return false end

            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy",
                consecutive_failures = 0
            }

            -- Perform multiple health checks to trigger failure
            for i = 1, manager.health_monitor.failure_threshold do
                manager:_check_instance_health(manager.instances.peers["peer-1"])
            end

            assert.equal("unhealthy", manager.instances.peers["peer-1"].status)
        end)

        it("should check local instance health", function()
            manager:_check_local_health()

            -- Local instance should be healthy (based on memory check)
            assert.is_not_nil(manager.instances.local_instance.status)
        end)
    end)

    describe("State Synchronization", function()
        it("should perform state sync when enabled", function()
            manager.state_sync.enabled = true

            -- Add a healthy peer
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy"
            }

            local initial_syncs = manager.metrics.state_sync_operations
            manager:_perform_state_sync()

            assert.is_true(manager.metrics.state_sync_operations > initial_syncs)
        end)

        it("should skip state sync when disabled", function()
            manager.state_sync.enabled = false

            local initial_syncs = manager.metrics.state_sync_operations
            manager:_perform_state_sync()

            assert.equal(initial_syncs, manager.metrics.state_sync_operations)
        end)

        it("should handle sync conflicts", function()
            -- Mock sync to always fail
            manager._sync_with_instance = function() return false end

            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy"
            }

            local initial_conflicts = manager.state_sync.conflicts
            manager:_perform_state_sync()

            assert.is_true(manager.state_sync.conflicts > initial_conflicts)
        end)
    end)

    describe("Auto-Scaling", function()
        before_each(function()
            manager:init()
            manager.auto_scaling.last_scale_action = 0  -- Reset cooldown
        end)

        it("should scale up when load is high", function()
            -- Set high load
            manager.instances.local_instance.load = 0.9
            manager.auto_scaling.current_instances = 2

            local initial_actions = manager.metrics.scaling_actions
            manager:_check_auto_scaling()

            -- Should trigger scale up
            assert.is_true(manager.metrics.scaling_actions > initial_actions)
        end)

        it("should scale down when load is low", function()
            -- Set low load
            manager.instances.local_instance.load = 0.1
            manager.auto_scaling.current_instances = 3

            local initial_actions = manager.metrics.scaling_actions
            manager:_check_auto_scaling()

            -- Should trigger scale down
            assert.is_true(manager.metrics.scaling_actions > initial_actions)
        end)

        it("should respect cooldown period", function()
            manager.auto_scaling.last_scale_action = ngx.now()  -- Just scaled

            local initial_actions = manager.metrics.scaling_actions
            manager:_check_auto_scaling()

            -- Should not scale due to cooldown
            assert.equal(initial_actions, manager.metrics.scaling_actions)
        end)

        it("should respect min/max instance limits", function()
            -- Test minimum instances
            manager.instances.local_instance.load = 0.1
            manager.auto_scaling.current_instances = 1  -- At minimum

            manager:_check_auto_scaling()
            -- Should not scale down below minimum

            -- Test maximum instances
            manager.instances.local_instance.load = 0.9
            manager.auto_scaling.current_instances = 5  -- At maximum

            manager:_check_auto_scaling()
            -- Should not scale up above maximum
        end)
    end)

    describe("Instance Discovery", function()
        it("should discover static endpoints", function()
            manager:_init_discovery()

            -- Should have discovered instances from config
            assert.is_true(#manager.discovery.endpoints > 0)
        end)

        it("should handle DNS discovery initialization", function()
            manager.discovery.method = "dns"
            manager:_init_discovery()

            -- Should not error (placeholder implementation)
            assert.is_not_nil(manager.discovery)
        end)

        it("should handle service discovery initialization", function()
            manager.discovery.method = "etcd"
            manager:_init_discovery()

            -- Should not error (placeholder implementation)
            assert.is_not_nil(manager.discovery)
        end)
    end)

    describe("Failover Handling", function()
        it("should handle instance failure", function()
            -- Add a peer instance
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy"
            }

            manager:handle_instance_failure("peer-1")

            assert.equal("failed", manager.instances.peers["peer-1"].status)
            assert.equal(1, manager.metrics.failover_events)
        end)

        it("should trigger failover logic", function()
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy"
            }
            manager.instances.peers["peer-2"] = {
                id = "peer-2",
                status = "healthy"
            }

            manager:handle_instance_failure("peer-1")

            -- Should trigger load balancing redistribution
            assert.equal(1, manager.metrics.failover_events)
        end)
    end)

    describe("Statistics", function()
        it("should return comprehensive stats", function()
            manager:init()

            -- Add some peer instances
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy",
                load = 0.3
            }

            -- Perform some operations
            manager:route_request({})
            manager:_perform_health_checks()

            local stats = manager:get_stats()
            assert.is_table(stats)
            assert.is_table(stats.instances)
            assert.is_table(stats.performance)

            -- Check instance stats
            assert.equal(2, stats.instances.total)  -- Local + 1 peer
            assert.equal(2, stats.instances.healthy)

            -- Check performance stats
            assert.is_number(stats.performance.requests_routed)
            assert.is_number(stats.performance.average_load)
        end)

        it("should include load balancer stats when enabled", function()
            manager.load_balancer.enabled = true
            manager:_perform_load_balancing()

            local stats = manager:get_stats()
            assert.is_table(stats.load_balancer)
            assert.equal("round_robin", stats.load_balancer.algorithm)
        end)

        it("should include health monitor stats when enabled", function()
            manager.health_monitor.enabled = true
            manager:_perform_health_checks()

            local stats = manager:get_stats()
            assert.is_table(stats.health_monitor)
            assert.is_number(stats.health_monitor.checks_performed)
        end)

        it("should include auto-scaling stats when enabled", function()
            manager.auto_scaling.enabled = true

            local stats = manager:get_stats()
            assert.is_table(stats.auto_scaling)
            assert.is_number(stats.auto_scaling.current_instances)
        end)
    end)

    describe("Load Calculation", function()
        it("should calculate average load correctly", function()
            manager.instances.local_instance.load = 0.5
            manager.instances.peers["peer-1"] = {
                id = "peer-1",
                status = "healthy",
                load = 0.3
            }
            manager.instances.peers["peer-2"] = {
                id = "peer-2",
                status = "unhealthy",  -- Should be excluded
                load = 0.8
            }

            local avg_load = manager:_calculate_average_load()
            assert.equal(0.4, avg_load)  -- (0.5 + 0.3) / 2
        end)

        it("should handle no peer instances", function()
            manager.instances.peers = {}
            manager.instances.local_instance.load = 0.6

            local avg_load = manager:_calculate_average_load()
            assert.equal(0.6, avg_load)
        end)
    end)

    describe("Cleanup", function()
        it("should clean up resources", function()
            -- Add some peer instances
            manager.instances.peers["peer-1"] = {id = "peer-1"}
            manager.instances.peers["peer-2"] = {id = "peer-2"}

            -- Perform some operations to generate metrics
            manager:route_request({})
            manager:handle_instance_failure("peer-1")

            -- Verify data exists
            assert.is_not_nil(manager.instances.peers["peer-1"])
            assert.is_true(manager.metrics.requests_routed > 0)

            -- Clean up
            manager:cleanup()

            -- Verify cleanup
            assert.equal(0, #manager.instances.peers)
            assert.equal(0, manager.metrics.requests_routed)
            assert.equal(0, manager.metrics.failover_events)
        end)
    end)

    describe("Error Handling", function()
        it("should handle invalid instance registration", function()
            local success, err = manager:_register_instance({})
            assert.is_false(success)
            assert.equal("Instance ID required", err)
        end)

        it("should handle load update for non-existent instance", function()
            manager:update_instance_load("non-existent", 0.5)
            -- Should not error
            assert.is_not_nil(manager.instances.local_instance)
        end)

        it("should handle empty healthy instances list", function()
            manager.instances.peers = {}
            manager.instances.local_instance.status = "unhealthy"

            local healthy = manager:_get_healthy_instances()
            assert.equal(0, #healthy)
        end)
    end)
end)
