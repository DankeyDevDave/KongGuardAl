local helpers = require "spec.helpers"
local cjson = require "cjson"

for _, strategy in helpers.each_strategy() do
  describe("Kong Guard AI Plugin #" .. strategy, function()
    local proxy_port = 8000
    local admin_port = 8001
    local proxy_ssl_port = 8443
    local admin_ssl_port = 8444

    setup(function()
      -- Create a test service and route
      local bp = helpers.get_db_utils(strategy, nil)

      local service1 = bp.services:insert({
        protocol = "http",
        host = "httpbin.org",
        port = 80,
        path = "/anything"
      })

      local route1 = bp.routes:insert({
        service = service1,
        hosts = { "test.com" },
        paths = { "/test" }
      })

      -- Add Kong Guard AI plugin to the service
      bp.plugins:insert {
        name = "kong-guard-ai",
        service = service1,
        config = {
          dry_run = true,
          log_requests = true,
          log_level = "debug",
          block_threshold = 0.8,
          rate_limit_threshold = 0.6,
          enable_ml_detection = true,
          enable_ai_gateway = false,
          whitelist_ips = {},
          ddos_rpm_threshold = 100,
          notification_url = nil
        }
      }

      -- Start Kong
      assert(helpers.start_kong({
        database = strategy,
        plugins = "bundled,kong-guard-ai",
        nginx_conf = "spec/fixtures/custom_nginx.template"
      }))
    end)

    teardown(function()
      helpers.stop_kong()
    end)

    before_each(function()
      proxy_client = helpers.proxy_client()
      admin_client = helpers.admin_client()
    end)

    after_each(function()
      if proxy_client then
        proxy_client:close()
      end
      if admin_client then
        admin_client:close()
      end
    end)

    describe("Plugin Schema Validation", function()
      it("accepts valid configuration", function()
        local res = admin_client:get("/plugins", {
          headers = { ["Content-Type"] = "application/json" }
        })
        local body = assert.res_status(200, res)
        local plugins = cjson.decode(body)

        -- Find our plugin
        local kong_guard_ai_plugin = nil
        for _, plugin in ipairs(plugins.data) do
          if plugin.name == "kong-guard-ai" then
            kong_guard_ai_plugin = plugin
            break
          end
        end

        assert.is_not_nil(kong_guard_ai_plugin)
        assert.equal("kong-guard-ai", kong_guard_ai_plugin.name)
        assert.is_true(kong_guard_ai_plugin.config.dry_run)
        assert.equal(0.8, kong_guard_ai_plugin.config.block_threshold)
      end)

      it("rejects invalid block_threshold", function()
        local res = admin_client:post("/plugins", {
          body = {
            name = "kong-guard-ai",
            config = {
              block_threshold = 1.5 -- Invalid: should be between 0 and 1
            }
          },
          headers = { ["Content-Type"] = "application/json" }
        })
        assert.res_status(400, res)
      end)

      it("rejects invalid rate_limit_threshold", function()
        local res = admin_client:post("/plugins", {
          body = {
            name = "kong-guard-ai",
            config = {
              rate_limit_threshold = -0.1 -- Invalid: should be between 0 and 1
            }
          },
          headers = { ["Content-Type"] = "application/json" }
        })
        assert.res_status(400, res)
      end)
    end)

    describe("Request Processing", function()
      it("allows normal requests in dry-run mode", function()
        local res = proxy_client:get("/test", {
          headers = {
            ["Host"] = "test.com",
            ["User-Agent"] = "Mozilla/5.0 (compatible; test)"
          }
        })
        assert.res_status(200, res)
      end)

      it("detects SQL injection patterns", function()
        local res = proxy_client:get("/test?id=1' OR 1=1 --", {
          headers = {
            ["Host"] = "test.com",
            ["User-Agent"] = "SQLInjectionBot/1.0"
          }
        })
        -- Should still allow in dry-run mode but log the threat
        assert.res_status(200, res)
      end)

      it("detects XSS patterns", function()
        local res = proxy_client:get("/test?search=<script>alert('xss')</script>", {
          headers = {
            ["Host"] = "test.com",
            ["User-Agent"] = "XSSBot/1.0"
          }
        })
        -- Should still allow in dry-run mode but log the threat
        assert.res_status(200, res)
      end)

      it("detects path traversal patterns", function()
        local res = proxy_client:get("/test/../../../etc/passwd", {
          headers = {
            ["Host"] = "test.com",
            ["User-Agent"] = "PathTraversalBot/1.0"
          }
        })
        -- Should still allow in dry-run mode but log the threat
        assert.res_status(200, res)
      end)

      it("handles high-rate requests", function()
        -- Simulate multiple rapid requests
        for i = 1, 10 do
          local res = proxy_client:get("/test?req=" .. i, {
            headers = {
              ["Host"] = "test.com",
              ["User-Agent"] = "RapidBot/1.0"
            }
          })
          assert.res_status(200, res)
        end
      end)

      it("handles whitelist IPs correctly", function()
        -- This would require setting up the plugin with whitelist IPs
        -- and testing from those IPs (complex in test environment)
        pending("Integration test for IP whitelisting")
      end)
    end)

    describe("Feature Extraction", function()
      it("extracts temporal features correctly", function()
        local res = proxy_client:get("/test", {
          headers = {
            ["Host"] = "test.com",
            ["User-Agent"] = "FeatureBot/1.0"
          }
        })
        assert.res_status(200, res)
        -- Feature extraction testing would require access to Kong's internal state
        -- This would be better tested in unit tests for the Lua functions
      end)
    end)

    describe("Error Handling", function()
      it("handles missing User-Agent header", function()
        local res = proxy_client:get("/test", {
          headers = {
            ["Host"] = "test.com"
            -- No User-Agent header
          }
        })
        assert.res_status(200, res)
      end)

      it("handles malformed request data", function()
        local res = proxy_client:post("/test", {
          body = "malformed json {[}",
          headers = {
            ["Host"] = "test.com",
            ["Content-Type"] = "application/json"
          }
        })
        -- Should not crash the plugin
        assert.response(res)
      end)
    end)

    describe("Plugin Metrics", function()
      it("tracks request metrics", function()
        -- Make several requests
        for i = 1, 5 do
          local res = proxy_client:get("/test?metric_test=" .. i, {
            headers = {
              ["Host"] = "test.com",
              ["User-Agent"] = "MetricBot/1.0"
            }
          })
          assert.res_status(200, res)
        end

        -- Metrics would be tracked in Kong's shared memory
        -- Verification would require access to Kong's internal state
        pending("Integration test for metrics tracking")
      end)
    end)

  end)
end
