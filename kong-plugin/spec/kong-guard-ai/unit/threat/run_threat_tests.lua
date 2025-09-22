#!/usr/bin/env lua

-- Comprehensive test runner for threat detection modules
-- Integrates with existing Kong plugin testing infrastructure

local busted = require 'busted'

-- Add the kong-plugin path to package.path for module loading
package.path = package.path .. ";kong-plugin/?.lua;kong-plugin/kong/plugins/kong-guard-ai/?.lua"

print("Kong Guard AI - Threat Detection Module Tests")
print("=" .. string.rep("=", 50))

-- Configure test environment
busted.setup({
    output = "spec",
    verbose = true,
    coverage = true
})

-- Test suites to run
local test_suites = {
    "spec.kong-guard-ai.unit.threat.sql_injection_detector_spec",
    -- Add more test suites here as they are created
    -- "spec.kong-guard-ai.unit.threat.xss_detector_spec",
    -- "spec.kong-guard-ai.unit.threat.path_traversal_detector_spec",
    -- "spec.kong-guard-ai.unit.threat.threat_orchestrator_spec"
}

-- Run all test suites
local total_tests = 0
local passed_tests = 0
local failed_tests = 0

for _, suite in ipairs(test_suites) do
    print(string.format("\nRunning test suite: %s", suite))
    print("-" .. string.rep("-", 50))
    
    local success, result = pcall(require, suite)
    if success then
        print(string.format("✓ Loaded test suite: %s", suite))
        total_tests = total_tests + 1
        passed_tests = passed_tests + 1
    else
        print(string.format("✗ Failed to load test suite: %s", suite))
        print(string.format("  Error: %s", result))
        total_tests = total_tests + 1
        failed_tests = failed_tests + 1
    end
end

-- Summary
print("\n" .. string.rep("=", 60))
print("TEST SUMMARY")
print(string.rep("=", 60))
print(string.format("Total test suites: %d", total_tests))
print(string.format("Passed: %d", passed_tests))
print(string.format("Failed: %d", failed_tests))

if failed_tests > 0 then
    print("\n⚠️  Some tests failed. Please check the output above.")
    os.exit(1)
else
    print("\n✅ All threat detection tests passed!")
    os.exit(0)
end