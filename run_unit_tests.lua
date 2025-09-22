#!/usr/bin/env lua

-- Test runner for Kong Guard AI unit tests
-- Usage: lua run_unit_tests.lua [test_pattern]

local lu = require('luaunit')

-- Add the kong-plugin path to package.path for module loading
package.path = package.path .. ";kong-plugin/?.lua;kong-plugin/kong/plugins/kong-guard-ai/?.lua"

-- Import test modules
local test_performance_utils = require('tests.unit.modules.utils.test_performance_utils')
local test_module_loader = require('tests.unit.modules.utils.test_module_loader')

print("Running Kong Guard AI Unit Tests")
print("================================")

-- Configure test runner
lu.LuaUnit.verbosity = 2

-- Run all tests
local runner = lu.LuaUnit.new()
runner:setOutputType("text")

-- Add test suites
runner:addSuite(test_performance_utils)
runner:addSuite(test_module_loader)

-- Run tests
local result = runner:runSuite()

-- Exit with proper code
os.exit(result)
