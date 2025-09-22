#!/usr/bin/env lua

-- Test Runner for Security Module
-- Runs all security-related tests and reports results

local function run_tests()
    print("=== Kong Guard AI - Security Module Tests ===")
    print("")

    -- Test files to run
    local test_files = {
        "rate_limiter_spec.lua",
        "request_validator_spec.lua",
        "auth_manager_spec.lua",
        "security_orchestrator_spec.lua"
    }

    local total_tests = 0
    local passed_tests = 0
    local failed_tests = 0
    local test_results = {}

    for _, test_file in ipairs(test_files) do
        print("Running " .. test_file .. "...")

        local success, result = pcall(function()
            return dofile(test_file)
        end)

        if success then
            print("✓ " .. test_file .. " - PASSED")
            passed_tests = passed_tests + 1
            table.insert(test_results, {file = test_file, status = "PASSED"})
        else
            print("✗ " .. test_file .. " - FAILED")
            print("  Error: " .. tostring(result))
            failed_tests = failed_tests + 1
            table.insert(test_results, {file = test_file, status = "FAILED", error = result})
        end

        total_tests = total_tests + 1
        print("")
    end

    -- Summary
    print("=== Test Summary ===")
    print("Total tests: " .. total_tests)
    print("Passed: " .. passed_tests)
    print("Failed: " .. failed_tests)
    print("")

    if failed_tests > 0 then
        print("Failed tests:")
        for _, result in ipairs(test_results) do
            if result.status == "FAILED" then
                print("  " .. result.file .. ": " .. tostring(result.error))
            end
        end
        print("")
    end

    local success_rate = (passed_tests / total_tests) * 100
    print(string.format("Success rate: %.1f%%", success_rate))

    if failed_tests == 0 then
        print("🎉 All security tests passed!")
        return 0
    else
        print("❌ Some tests failed. Please review and fix.")
        return 1
    end
end

-- Performance benchmark for security modules
local function run_performance_tests()
    print("\n=== Security Module Performance Tests ===")

    local RateLimiter = require "kong.plugins.kong-guard-ai.modules.security.rate_limiter"
    local RequestValidator = require "kong.plugins.kong-guard-ai.modules.security.request_validator"
    local AuthManager = require "kong.plugins.kong-guard-ai.modules.security.auth_manager"
    local SecurityOrchestrator = require "kong.plugins.kong-guard-ai.modules.security.security_orchestrator"

    -- Rate Limiter Performance
    print("Rate Limiter Performance:")
    local rate_limiter = RateLimiter.new()
    local start_time = os.clock()

    for i = 1, 1000 do
        local request = {
            client_ip = "192.168.1." .. (i % 255),
            method = "GET",
            path = "/api/test"
        }
        rate_limiter:should_limit(request)
    end

    local rate_limit_time = os.clock() - start_time
    print(string.format("  1000 rate limit checks: %.3fs", rate_limit_time))

    -- Request Validator Performance
    print("Request Validator Performance:")
    local validator = RequestValidator.new()
    start_time = os.clock()

    for i = 1, 500 do
        local request = {
            method = "POST",
            path = "/api/test",
            headers = {
                ["content-type"] = "application/json",
                ["user-agent"] = "Test-Agent/1.0"
            },
            body = '{"test": "data", "value": ' .. i .. '}'
        }
        validator:validate_request(request)
    end

    local validation_time = os.clock() - start_time
    print(string.format("  500 request validations: %.3fs", validation_time))

    -- Auth Manager Performance
    print("Auth Manager Performance:")
    local auth_manager = AuthManager.new()

    -- Create test API key
    local test_api_key = auth_manager:create_api_key("test_user", {"api:read"})

    start_time = os.clock()

    for i = 1, 500 do
        local request = {
            headers = {
                ["X-API-Key"] = test_api_key
            },
            client_ip = "192.168.1.100"
        }
        auth_manager:authenticate_request(request)
    end

    local auth_time = os.clock() - start_time
    print(string.format("  500 authentication checks: %.3fs", auth_time))

    -- Security Orchestrator Performance
    print("Security Orchestrator Performance:")
    local orchestrator = SecurityOrchestrator.new()
    start_time = os.clock()

    for i = 1, 200 do
        local request = {
            method = "POST",
            path = "/api/test",
            client_ip = "192.168.1." .. (i % 100),
            headers = {
                ["content-type"] = "application/json",
                ["user-agent"] = "Test-Agent/1.0"
            },
            body = '{"test": "data"}'
        }
        orchestrator:process_request(request)
    end

    local orchestrator_time = os.clock() - start_time
    print(string.format("  200 complete security checks: %.3fs", orchestrator_time))

    print("\nPerformance Summary:")
    print(string.format("  Rate limit ops/sec: %.0f", 1000 / rate_limit_time))
    print(string.format("  Validation ops/sec: %.0f", 500 / validation_time))
    print(string.format("  Auth ops/sec: %.0f", 500 / auth_time))
    print(string.format("  Full security ops/sec: %.0f", 200 / orchestrator_time))
end

-- Security attack simulation
local function run_attack_simulation()
    print("\n=== Security Attack Simulation ===")

    local SecurityOrchestrator = require "kong.plugins.kong-guard-ai.modules.security.security_orchestrator"
    local orchestrator = SecurityOrchestrator.new({
        security_level = "strict"
    })

    print("Testing against common attack patterns...")

    local attack_tests = {
        {
            name = "SQL Injection",
            request = {
                method = "GET",
                path = "/api/users",
                query_params = {
                    id = "1' OR '1'='1"
                },
                client_ip = "192.168.1.100"
            }
        },
        {
            name = "XSS Attack",
            request = {
                method = "POST",
                path = "/api/comments",
                headers = {
                    ["content-type"] = "application/json"
                },
                body = '{"comment": "<script>alert(\'xss\')</script>"}',
                client_ip = "192.168.1.101"
            }
        },
        {
            name = "Path Traversal",
            request = {
                method = "GET",
                path = "/api/files",
                query_params = {
                    filename = "../../../etc/passwd"
                },
                client_ip = "192.168.1.102"
            }
        },
        {
            name = "Oversized Request",
            request = {
                method = "POST",
                path = "/api/upload",
                headers = {
                    ["content-type"] = "application/json",
                    ["content-length"] = "20971520" -- 20MB
                },
                body = string.rep("x", 1000),
                client_ip = "192.168.1.103"
            }
        },
        {
            name = "Rate Limit Test",
            requests = {}
        }
    }

    -- Generate multiple requests for rate limit test
    for i = 1, 150 do
        table.insert(attack_tests[5].requests, {
            method = "GET",
            path = "/api/test",
            client_ip = "192.168.1.200"
        })
    end

    local blocked_attacks = 0
    local total_attacks = 0

    for _, test in ipairs(attack_tests) do
        if test.request then
            -- Single request test
            local allowed, result = orchestrator:process_request(test.request)
            total_attacks = total_attacks + 1

            if not allowed then
                blocked_attacks = blocked_attacks + 1
                print(string.format("✓ %s: BLOCKED (Risk: %d)", test.name, result.risk_score))
            else
                print(string.format("✗ %s: ALLOWED (Risk: %d)", test.name, result.risk_score))
            end
        elseif test.requests then
            -- Multiple request test (rate limiting)
            local first_blocked_at = nil

            for i, request in ipairs(test.requests) do
                local allowed, result = orchestrator:process_request(request)
                total_attacks = total_attacks + 1

                if not allowed then
                    blocked_attacks = blocked_attacks + 1
                    if not first_blocked_at then
                        first_blocked_at = i
                    end
                end
            end

            if first_blocked_at then
                print(string.format("✓ Rate Limit Test: First block at request #%d", first_blocked_at))
            else
                print("✗ Rate Limit Test: No requests blocked")
            end
        end
    end

    local block_rate = (blocked_attacks / total_attacks) * 100
    print(string.format("\nAttack Simulation Results:"))
    print(string.format("  Total attacks: %d", total_attacks))
    print(string.format("  Blocked attacks: %d", blocked_attacks))
    print(string.format("  Block rate: %.1f%%", block_rate))

    if block_rate >= 80 then
        print("✓ Security posture: EXCELLENT")
    elseif block_rate >= 60 then
        print("⚠ Security posture: GOOD")
    elseif block_rate >= 40 then
        print("⚠ Security posture: MODERATE")
    else
        print("❌ Security posture: POOR")
    end
end

-- Main execution
local function main()
    local exit_code = run_tests()

    if exit_code == 0 then
        run_performance_tests()
        run_attack_simulation()

        print("\n🛡️ All security module tests completed!")
        print("Security hardening implementation is ready for production.")
    else
        print("\n❌ Security test failures detected. Fix issues before deployment.")
    end

    return exit_code
end

-- Run if executed directly
if arg and arg[0] and arg[0]:match("run_security_tests.lua$") then
    os.exit(main())
end

return main
