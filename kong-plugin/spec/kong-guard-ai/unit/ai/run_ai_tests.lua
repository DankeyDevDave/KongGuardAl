#!/usr/bin/env lua

-- AI Modules Test Runner
-- Runs all unit tests for the extracted AI modules

local function run_test_file(test_file)
    print("Running " .. test_file .. "...")
    local status = os.execute("cd " .. arg[0]:match("(.*)/") .. " && lua " .. test_file)
    if status == 0 then
        print("✓ " .. test_file .. " passed")
        return true
    else
        print("✗ " .. test_file .. " failed")
        return false
    end
end

local function main()
    print("=== Kong Guard AI - AI Modules Unit Tests ===\n")

    local test_files = {
        "ai_service_spec.lua",
        "threat_detector_spec.lua"
    }

    local passed = 0
    local total = #test_files

    for _, test_file in ipairs(test_files) do
        if run_test_file(test_file) then
            passed = passed + 1
        end
        print()
    end

    print("=== Test Results ===")
    print(string.format("Passed: %d/%d", passed, total))

    if passed == total then
        print("✓ All AI module tests passed!")
        os.exit(0)
    else
        print("✗ Some tests failed")
        os.exit(1)
    end
end

main()
