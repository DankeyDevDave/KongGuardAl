-- Kong Guard AI - IP Blacklist Module Tests
-- Comprehensive test suite for IP blacklist enforcement functionality

local ip_blacklist = require "kong.plugins.kong-guard-ai.ip_blacklist"

describe("Kong Guard AI IP Blacklist", function()
    local mock_kong

    before_each(function()
        -- Reset module state
        package.loaded["kong.plugins.kong-guard-ai.ip_blacklist"] = nil
        ip_blacklist = require "kong.plugins.kong-guard-ai.ip_blacklist"

        -- Mock Kong functions
        mock_kong = {
            log = {
                info = function() end,
                warn = function() end,
                debug = function() end,
                error = function() end
            },
            client = {
                get_ip = function() return "203.0.113.100" end
            },
            request = {
                get_headers = function() return {} end,
                get_method = function() return "GET" end,
                get_path = function() return "/test" end,
                get_body = function() return {} end
            },
            response = {
                exit = function() end,
                set_header = function() end
            },
            ctx = {
                plugin = {}
            }
        }

        -- Mock global functions
        _G.kong = mock_kong
        _G.ngx = {
            time = function() return 1640995200 end,  -- Fixed timestamp
            now = function() return 1640995200.123 end,
            var = { request_id = "test-123" }
        }
    end)

    describe("IPv4 to Integer Conversion", function()
        it("should convert valid IPv4 addresses to integers", function()
            assert.equal(0, ip_blacklist.ipv4_to_int("0.0.0.0"))
            assert.equal(16777216, ip_blacklist.ipv4_to_int("1.0.0.0"))
            assert.equal(3232235876, ip_blacklist.ipv4_to_int("203.0.113.100"))
            assert.equal(4294967295, ip_blacklist.ipv4_to_int("255.255.255.255"))
        end)

        it("should return nil for invalid IPv4 addresses", function()
            assert.is_nil(ip_blacklist.ipv4_to_int("256.1.1.1"))
            assert.is_nil(ip_blacklist.ipv4_to_int("1.1.1"))
            assert.is_nil(ip_blacklist.ipv4_to_int("not.an.ip.address"))
            assert.is_nil(ip_blacklist.ipv4_to_int(""))
            assert.is_nil(ip_blacklist.ipv4_to_int(nil))
        end)
    end)

    describe("CIDR Parsing", function()
        it("should parse valid CIDR blocks", function()
            local result = ip_blacklist.parse_cidr("203.0.113.0/24")
            assert.is_not_nil(result)
            assert.equal(24, result.prefix_len)
            assert.equal(3232235776, result.network_int)  -- 203.0.113.0
            assert.is_false(result.is_ipv6)
        end)

        it("should parse single IPs as /32 CIDR", function()
            local result = ip_blacklist.parse_cidr("203.0.113.100")
            assert.is_not_nil(result)
            assert.equal(32, result.prefix_len)
            assert.equal(3232235876, result.network_int)  -- 203.0.113.100
            assert.is_false(result.is_ipv6)
        end)

        it("should return nil for invalid CIDR blocks", function()
            assert.is_nil(ip_blacklist.parse_cidr("203.0.113.0/33"))  -- Invalid prefix
            assert.is_nil(ip_blacklist.parse_cidr("256.1.1.0/24"))    -- Invalid IP
            assert.is_nil(ip_blacklist.parse_cidr("203.0.113.0/"))    -- Missing prefix
            assert.is_nil(ip_blacklist.parse_cidr(""))
            assert.is_nil(ip_blacklist.parse_cidr(nil))
        end)
    end)

    describe("IPv4 CIDR Matching", function()
        it("should match IPs in CIDR blocks correctly", function()
            local ip_int = ip_blacklist.ipv4_to_int("203.0.113.100")
            local network_int = ip_blacklist.ipv4_to_int("203.0.113.0")

            -- Should match /24 network
            assert.is_true(ip_blacklist.ipv4_in_cidr(ip_int, network_int, 24))

            -- Should not match /25 network (203.0.113.0-127)
            assert.is_false(ip_blacklist.ipv4_in_cidr(ip_int, network_int, 25))

            -- Should match /16 network
            assert.is_true(ip_blacklist.ipv4_in_cidr(ip_int, network_int, 16))

            -- Should match /0 (all IPs)
            assert.is_true(ip_blacklist.ipv4_in_cidr(ip_int, network_int, 0))

            -- Should not match different /24 network
            local other_network = ip_blacklist.ipv4_to_int("203.0.113.0")
            assert.is_false(ip_blacklist.ipv4_in_cidr(ip_int, other_network, 24))
        end)
    end)

    describe("Blacklist Management", function()
        before_each(function()
            local test_conf = {
                ip_blacklist = {},
                ip_whitelist = {}
            }
            ip_blacklist.init_worker(test_conf)
        end)

        it("should add single IPs to blacklist", function()
            local success = ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test_reason", 3600)
            assert.is_true(success)

            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.100")
            assert.is_not_nil(block_result)
            assert.is_true(block_result.blocked)
            assert.equal("test_reason", block_result.reason)
            assert.equal("exact_ip", block_result.match_type)
        end)

        it("should add CIDR blocks to blacklist", function()
            local success = ip_blacklist.add_ip_to_blacklist("203.0.113.0/24", "network_block", 3600)
            assert.is_true(success)

            -- Should block IPs in the CIDR range
            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.50")
            assert.is_not_nil(block_result)
            assert.is_true(block_result.blocked)
            assert.equal("network_block", block_result.reason)
            assert.equal("cidr_block", block_result.match_type)
            assert.equal("203.0.113.0/24", block_result.cidr)

            -- Should not block IPs outside the CIDR range
            local no_block = ip_blacklist.check_ip_blacklist("203.0.113.50")
            assert.is_nil(no_block)
        end)

        it("should handle whitelist overrides", function()
            -- Add IP to blacklist
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test_block", 3600)

            -- Add same IP to whitelist
            ip_blacklist.add_ip_to_whitelist("203.0.113.100")

            -- Should not block whitelisted IP
            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.100")
            assert.is_nil(block_result)
        end)

        it("should handle CIDR whitelist overrides", function()
            -- Add CIDR to blacklist
            ip_blacklist.add_ip_to_blacklist("203.0.113.0/16", "network_block", 3600)

            -- Add more specific CIDR to whitelist
            ip_blacklist.add_ip_to_whitelist("203.0.113.0/24")

            -- Should not block IPs in whitelisted subnet
            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.50")
            assert.is_nil(block_result)

            -- Should still block IPs outside whitelisted subnet
            local should_block = ip_blacklist.check_ip_blacklist("203.0.113.50")
            assert.is_not_nil(should_block)
            assert.is_true(should_block.blocked)
        end)

        it("should remove IPs from blacklist", function()
            -- Add and verify IP is blocked
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test", 3600)
            assert.is_not_nil(ip_blacklist.check_ip_blacklist("203.0.113.100"))

            -- Remove and verify IP is no longer blocked
            local removed = ip_blacklist.remove_from_blacklist("203.0.113.100")
            assert.is_true(removed)
            assert.is_nil(ip_blacklist.check_ip_blacklist("203.0.113.100"))
        end)

        it("should handle invalid IP formats gracefully", function()
            local success = ip_blacklist.add_ip_to_blacklist("invalid.ip.address", "test", 3600)
            assert.is_false(success)

            local success2 = ip_blacklist.add_ip_to_blacklist("", "test", 3600)
            assert.is_false(success2)

            local success3 = ip_blacklist.add_ip_to_blacklist(nil, "test", 3600)
            assert.is_false(success3)
        end)
    end)

    describe("Client IP Extraction", function()
        it("should extract client IP from Kong by default", function()
            local conf = {}
            local client_ip = ip_blacklist.get_real_client_ip(conf)
            assert.equal("203.0.113.100", client_ip)
        end)

        it("should extract IP from X-Forwarded-For header", function()
            mock_kong.request.get_headers = function()
                return { ["x-forwarded-for"] = "203.0.113.45, 203.0.113.100" }
            end

            local conf = { trust_proxy_headers = true }
            local client_ip = ip_blacklist.get_real_client_ip(conf)
            assert.equal("203.0.113.45", client_ip)
        end)

        it("should extract IP from X-Real-IP header", function()
            mock_kong.request.get_headers = function()
                return { ["x-real-ip"] = "203.0.113.45" }
            end

            local conf = { trust_proxy_headers = true }
            local client_ip = ip_blacklist.get_real_client_ip(conf)
            assert.equal("203.0.113.45", client_ip)
        end)

        it("should extract IP from CF-Connecting-IP header", function()
            mock_kong.request.get_headers = function()
                return { ["cf-connecting-ip"] = "203.0.113.45" }
            end

            local conf = { trust_proxy_headers = true }
            local client_ip = ip_blacklist.get_real_client_ip(conf)
            assert.equal("203.0.113.45", client_ip)
        end)

        it("should prioritize headers correctly", function()
            mock_kong.request.get_headers = function()
                return {
                    ["cf-connecting-ip"] = "203.0.113.45",
                    ["x-real-ip"] = "203.0.113.46",
                    ["x-forwarded-for"] = "203.0.113.47"
                }
            end

            local conf = { trust_proxy_headers = true }
            local client_ip = ip_blacklist.get_real_client_ip(conf)
            -- CF-Connecting-IP should have highest priority
            assert.equal("203.0.113.45", client_ip)
        end)
    end)

    describe("Statistics and Monitoring", function()
        before_each(function()
            local test_conf = { ip_blacklist = {}, ip_whitelist = {} }
            ip_blacklist.init_worker(test_conf)
        end)

        it("should track blacklist statistics", function()
            -- Add some IPs and test blocking
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test", 3600)
            ip_blacklist.add_ip_to_blacklist("198.51.100.0/8", "network", 3600)

            -- Test some IPs
            ip_blacklist.check_ip_blacklist("203.0.113.100")  -- Should hit
            ip_blacklist.check_ip_blacklist("198.51.100.50")      -- Should hit
            ip_blacklist.check_ip_blacklist("203.0.113.45")   -- Should miss

            local stats = ip_blacklist.get_blacklist_stats()
            assert.is_not_nil(stats)
            assert.equal(2, stats.cache_hits)
            assert.equal(1, stats.cache_misses)
            assert.is_number(stats.hit_rate)
            assert.is_table(stats.blacklist_size)
            assert.is_table(stats.whitelist_size)
        end)
    end)

    describe("TTL and Cleanup", function()
        before_each(function()
            local test_conf = { ip_blacklist = {}, ip_whitelist = {} }
            ip_blacklist.init_worker(test_conf)
        end)

        it("should respect TTL for blacklist entries", function()
            -- Mock time progression
            local current_time = 1640995200
            _G.ngx.time = function() return current_time end

            -- Add IP with short TTL
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test", 10)

            -- Should be blocked initially
            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.100")
            assert.is_not_nil(block_result)

            -- Advance time past TTL
            current_time = current_time + 20

            -- Should no longer be blocked
            local no_block = ip_blacklist.check_ip_blacklist("203.0.113.100")
            assert.is_nil(no_block)
        end)

        it("should clean up expired entries", function()
            local current_time = 1640995200
            _G.ngx.time = function() return current_time end

            -- Add entries with different TTLs
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "short", 10)
            ip_blacklist.add_ip_to_blacklist("203.0.113.101", "long", 3600)

            -- Advance time to expire first entry
            current_time = current_time + 20

            -- Trigger cleanup
            ip_blacklist.cleanup_expired_entries()

            local stats = ip_blacklist.get_blacklist_stats()
            -- Should have cleaned up the expired entry
            assert.equal(1, stats.blacklist_size.active_ips)
        end)
    end)

    describe("Performance", function()
        before_each(function()
            local test_conf = { ip_blacklist = {}, ip_whitelist = {} }
            ip_blacklist.init_worker(test_conf)
        end)

        it("should provide response time metrics", function()
            ip_blacklist.add_ip_to_blacklist("203.0.113.100", "test", 3600)

            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.100")
            assert.is_not_nil(block_result)
            assert.is_number(block_result.response_time_us)
            assert.is_true(block_result.response_time_us >= 0)
        end)

        it("should handle large blacklists efficiently", function()
            -- Add many IPs to test performance characteristics
            for i = 1, 100 do
                ip_blacklist.add_ip_to_blacklist("203.0.113." .. i, "bulk_test", 3600)
            end

            -- Add CIDR blocks
            for i = 1, 10 do
                ip_blacklist.add_ip_to_blacklist("10." .. i .. ".0.0/16", "bulk_cidr", 3600)
            end

            -- Test lookup performance
            local start_time = _G.ngx.now()
            local block_result = ip_blacklist.check_ip_blacklist("203.0.113.50")
            local end_time = _G.ngx.now()

            assert.is_not_nil(block_result)
            local lookup_time_ms = (end_time - start_time) * 1000
            -- Should be very fast (under 2ms requirement)
            assert.is_true(lookup_time_ms < 2)
        end)
    end)

    describe("Error Handling", function()
        it("should handle missing dependencies gracefully", function()
            -- Mock missing enforcement_gate
            package.loaded["kong.plugins.kong-guard-ai.enforcement_gate"] = nil

            local success, err = pcall(function()
                ip_blacklist.enforce_ip_blacklist({})
            end)

            -- Should handle missing dependencies without crashing
            assert.is_boolean(success)
        end)

        it("should handle malformed configuration", function()
            local malformed_conf = {
                ip_blacklist = { "invalid-ip", "", nil, 12345 },
                ip_whitelist = { "also-invalid" }
            }

            -- Should not crash during initialization
            local success = pcall(function()
                ip_blacklist.init_worker(malformed_conf)
            end)
            assert.is_true(success)
        end)
    end)

    describe("Integration with Enforcement Gate", function()
        before_each(function()
            -- Mock enforcement_gate
            local mock_enforcement_gate = {
                get_action_types = function()
                    return { BLOCK_IP = "block_ip" }
                end,
                enforce_action = function(action_type, data, conf, callback)
                    if conf.dry_run_mode then
                        return {
                            executed = false,
                            simulated = true,
                            action_type = action_type,
                            details = data
                        }
                    else
                        local result = callback(data, conf)
                        return {
                            executed = true,
                            simulated = false,
                            action_type = action_type,
                            details = result
                        }
                    end
                end
            }
            package.loaded["kong.plugins.kong-guard-ai.enforcement_gate"] = mock_enforcement_gate

            -- Mock instrumentation
            local mock_instrumentation = {
                get_correlation_id = function() return "test-correlation-123" end
            }
            package.loaded["kong.plugins.kong-guard-ai.instrumentation"] = mock_instrumentation
        end)

        it("should integrate with enforcement gate for blocking", function()
            local test_conf = {
                ip_blacklist = { "203.0.113.100" },
                dry_run_mode = false
            }
            ip_blacklist.init_worker(test_conf)

            mock_kong.client.get_ip = function() return "203.0.113.100" end

            local enforcement_result = ip_blacklist.enforce_ip_blacklist(test_conf)
            assert.is_not_nil(enforcement_result)
            assert.is_true(enforcement_result.executed)
            assert.equal("block_ip", enforcement_result.action_type)
        end)

        it("should respect dry-run mode", function()
            local test_conf = {
                ip_blacklist = { "203.0.113.100" },
                dry_run_mode = true
            }
            ip_blacklist.init_worker(test_conf)

            mock_kong.client.get_ip = function() return "203.0.113.100" end

            local enforcement_result = ip_blacklist.enforce_ip_blacklist(test_conf)
            assert.is_not_nil(enforcement_result)
            assert.is_false(enforcement_result.executed)
            assert.is_true(enforcement_result.simulated)
        end)
    end)
end)
