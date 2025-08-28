-- Kong Guard AI Load Testing Script for wrk
-- Advanced load testing with attack simulation and performance monitoring

-- Test configuration
local attack_patterns = {
    sql_injection = {
        "' OR '1'='1",
        "' UNION SELECT * FROM users--",
        "'; DROP TABLE users; --",
        "' AND SLEEP(5)--"
    },
    xss_attacks = {
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "javascript:alert('xss')"
    },
    path_traversal = {
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd"
    },
    admin_access = {
        "/admin/config.php",
        "/wp-admin/",
        "/administrator/",
        "/phpmyadmin/"
    }
}

local normal_patterns = {
    "/api/users",
    "/api/products",
    "/api/orders",
    "/docs/api",
    "/health",
    "/status"
}

-- Request counters
local request_count = 0
local attack_request_count = 0
local normal_request_count = 0

-- Attack probability (10% of requests will be attacks)
local attack_probability = 0.1

-- Random seed
math.randomseed(os.time())

-- Helper function to get random element from array
local function get_random_element(array)
    return array[math.random(#array)]
end

-- Helper function to get random attack pattern
local function get_random_attack()
    local attack_types = {"sql_injection", "xss_attacks", "path_traversal", "admin_access"}
    local attack_type = get_random_element(attack_types)
    local pattern = get_random_element(attack_patterns[attack_type])
    return attack_type, pattern
end

-- Setup function - called once when thread starts
function setup(thread)
    thread:set("id", thread.id)
    thread:set("request_count", 0)
    thread:set("attack_count", 0)
end

-- Request function - called for each request
function request()
    request_count = request_count + 1
    local path = "/"
    local method = "GET"
    local headers = {}
    local body = nil
    
    -- Determine if this should be an attack request
    if math.random() < attack_probability then
        -- Generate attack request
        attack_request_count = attack_request_count + 1
        local attack_type, pattern = get_random_attack()
        
        if attack_type == "sql_injection" then
            path = "/api/users?id=" .. pattern
            headers["X-Attack-Type"] = "sql_injection"
        elseif attack_type == "xss_attacks" then
            path = "/search?q=" .. pattern
            headers["X-Attack-Type"] = "xss"
        elseif attack_type == "path_traversal" then
            path = pattern
            headers["X-Attack-Type"] = "path_traversal"
        elseif attack_type == "admin_access" then
            path = pattern
            headers["X-Attack-Type"] = "admin_access"
        end
        
        -- Add malicious headers
        headers["User-Agent"] = "AttackBot/1.0"
        headers["X-Forwarded-For"] = "203.0.113." .. math.random(100, 200)
        
    else
        -- Generate normal request
        normal_request_count = normal_request_count + 1
        path = get_random_element(normal_patterns)
        
        -- Vary HTTP methods for normal requests
        local methods = {"GET", "GET", "GET", "POST", "PUT"}  -- GET is more common
        method = get_random_element(methods)
        
        if method == "POST" or method == "PUT" then
            headers["Content-Type"] = "application/json"
            body = '{"user_id": ' .. math.random(1, 1000) .. ', "action": "normal_operation"}'
        end
        
        -- Normal user agent
        local user_agents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
        headers["User-Agent"] = get_random_element(user_agents)
        headers["X-Forwarded-For"] = "203.0.113." .. math.random(1, 100)
    end
    
    -- Add common headers
    headers["Accept"] = "application/json"
    headers["X-Request-ID"] = "load-test-" .. request_count
    headers["X-Test-Thread"] = thread.id or "unknown"
    
    -- Build request
    local request_str = method .. " " .. path .. " HTTP/1.1\r\n"
    for name, value in pairs(headers) do
        request_str = request_str .. name .. ": " .. value .. "\r\n"
    end
    request_str = request_str .. "\r\n"
    
    if body then
        request_str = request_str .. body
    end
    
    return request_str
end

-- Response function - called for each response
function response(status, headers, body)
    -- Track response metrics
    local thread_id = thread.id or "unknown"
    
    -- Log blocked requests (Kong Guard AI blocking)
    if status == 403 or status == 429 or status == 418 then
        -- Request was blocked by Kong Guard AI
        print("Thread " .. thread_id .. ": Request blocked with status " .. status)
    elseif status >= 500 then
        -- Server error
        print("Thread " .. thread_id .. ": Server error " .. status)
    end
    
    -- Check for Kong Guard AI headers
    if headers["X-Kong-Guard-AI"] then
        print("Thread " .. thread_id .. ": Kong Guard AI action: " .. headers["X-Kong-Guard-AI"])
    end
end

-- Done function - called when load test completes
function done(summary, latency, requests)
    -- Print load test statistics
    print("\n--- Kong Guard AI Load Test Results ---")
    print("Duration: " .. summary.duration / 1000000 .. "s")
    print("Total Requests: " .. summary.requests)
    print("Total Bytes: " .. summary.bytes)
    print("Requests/sec: " .. (summary.requests / (summary.duration / 1000000)))
    print("Transfer/sec: " .. (summary.bytes / (summary.duration / 1000000)) .. " bytes")
    
    print("\nRequest Breakdown:")
    print("Normal Requests: " .. normal_request_count .. " (" .. (normal_request_count / request_count * 100) .. "%)")
    print("Attack Requests: " .. attack_request_count .. " (" .. (attack_request_count / request_count * 100) .. "%)")
    
    print("\nLatency Distribution:")
    print("50th percentile: " .. latency:percentile(50.0) / 1000 .. "ms")
    print("90th percentile: " .. latency:percentile(90.0) / 1000 .. "ms")
    print("99th percentile: " .. latency:percentile(99.0) / 1000 .. "ms")
    print("99.9th percentile: " .. latency:percentile(99.9) / 1000 .. "ms")
    print("Max latency: " .. latency.max / 1000 .. "ms")
    
    print("\nHTTP Status Codes:")
    for code, count in pairs(summary.status) do
        print("HTTP " .. code .. ": " .. count .. " (" .. (count / summary.requests * 100) .. "%)")
    end
    
    -- Calculate Kong Guard AI effectiveness
    local blocked_requests = (summary.status[403] or 0) + (summary.status[429] or 0) + (summary.status[418] or 0)
    local block_rate = blocked_requests / attack_request_count * 100
    
    print("\nKong Guard AI Performance:")
    print("Blocked Requests: " .. blocked_requests)
    print("Attack Block Rate: " .. block_rate .. "%")
    
    if block_rate > 80 then
        print("✅ Kong Guard AI is effectively blocking attacks (>80% block rate)")
    else
        print("⚠️ Kong Guard AI block rate is below threshold (<80%)")
    end
    
    -- Performance validation
    local avg_latency = latency.mean / 1000
    local p99_latency = latency:percentile(99.0) / 1000
    local throughput = summary.requests / (summary.duration / 1000000)
    
    print("\nPerformance Validation:")
    print("Average Latency: " .. avg_latency .. "ms (Requirement: <10ms)")
    print("99th Percentile Latency: " .. p99_latency .. "ms (Requirement: <50ms)")
    print("Throughput: " .. throughput .. " RPS (Requirement: >1000 RPS)")
    
    local performance_passed = avg_latency < 10 and p99_latency < 50 and throughput > 1000
    if performance_passed then
        print("✅ Performance requirements met")
    else
        print("❌ Performance requirements not met")
    end
end