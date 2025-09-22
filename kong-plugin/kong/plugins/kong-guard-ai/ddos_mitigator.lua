-- Kong Guard AI - DDoS Mitigator
-- Advanced DDoS detection and mitigation with challenge-response mechanisms

local ngx = ngx
local math = math
local string = string
local table = table
local cjson = require "cjson"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

local DDoSMitigator = {}
DDoSMitigator.__index = DDoSMitigator

-- Module constants
local GLOBAL_RPS_WINDOW = 10    -- 10 second window for global RPS
local PATTERN_HISTORY_SIZE = 10 -- Number of patterns to track
local CHALLENGE_PREFIX = "ddos_challenge"
local CHALLENGE_COOKIE_NAME = "kong_guard_ai_challenge"

-- Challenge difficulty levels
local DIFFICULTY_LEVELS = {
    [1] = 1000,      -- 1K iterations
    [2] = 5000,      -- 5K iterations
    [3] = 10000,     -- 10K iterations
    [4] = 25000,     -- 25K iterations
    [5] = 50000,     -- 50K iterations
    [6] = 100000,    -- 100K iterations
    [7] = 250000,    -- 250K iterations
    [8] = 500000,    -- 500K iterations
    [9] = 1000000,   -- 1M iterations
    [10] = 2000000   -- 2M iterations
}

-- Initialize DDoS mitigator
function DDoSMitigator:new(config)
    local self = setmetatable({}, DDoSMitigator)

    self.config = config or {}
    self.threshold_rps = self.config.ddos_threshold_rps or 100
    self.challenge_enabled = self.config.challenge_response_enabled ~= false
    self.challenge_timeout = self.config.challenge_timeout_seconds or 30
    self.challenge_difficulty = self.config.challenge_difficulty or 2
    self.mitigation_actions = self.config.mitigation_actions or {"challenge", "rate_limit"}

    -- Shared dictionaries
    self.cache = ngx.shared.kong_cache
    self.metrics_cache = ngx.shared.kong_cache

    return self
end

-- Detect DDoS attack based on traffic patterns
function DDoSMitigator:detect_ddos_attack(features)
    local attack_indicators = {
        global_rps_exceeded = false,
        per_ip_rps_exceeded = false,
        pattern_detected = false,
        volumetric_attack = false,
        protocol_anomaly = false
    }

    -- Check global RPS threshold
    local global_rps = self:get_global_rps()
    if global_rps > self.threshold_rps then
        attack_indicators.global_rps_exceeded = true
    end

    -- Check per-IP RPS
    local client_ip = features.client_ip
    local ip_rps = self:get_ip_rps(client_ip)
    if ip_rps > (self.threshold_rps * 0.1) then -- 10% of global threshold per IP
        attack_indicators.per_ip_rps_exceeded = true
    end

    -- Check for attack patterns
    local patterns = self:analyze_attack_patterns(features)
    if patterns.suspicious_pattern then
        attack_indicators.pattern_detected = true
    end

    -- Check for volumetric indicators
    if features.content_length and features.content_length > 1000000 then -- >1MB
        attack_indicators.volumetric_attack = true
    end

    -- Check for protocol anomalies
    if features.user_agent and (
        string.find(features.user_agent, "bot", 1, true) or
        string.find(features.user_agent, "crawler", 1, true) or
        features.user_agent == ""
    ) then
        attack_indicators.protocol_anomaly = true
    end

    -- Calculate attack severity
    local severity = self:calculate_attack_severity(attack_indicators)

    -- Update attack metrics
    self:update_attack_metrics(attack_indicators, severity)

    return {
        is_attack = severity > 0.6,
        severity = severity,
        indicators = attack_indicators,
        recommended_actions = self:get_recommended_actions(severity)
    }
end

-- Get current global requests per second
function DDoSMitigator:get_global_rps()
    local current_time = ngx.now()
    local window_start = math.floor(current_time / GLOBAL_RPS_WINDOW) * GLOBAL_RPS_WINDOW
    local rps_key = "global_rps:" .. window_start

    local count = self.cache:incr(rps_key, 1, 0, GLOBAL_RPS_WINDOW)
    if not count then
        return 0
    end

    -- Calculate RPS
    return count / GLOBAL_RPS_WINDOW
end

-- Get requests per second for specific IP
function DDoSMitigator:get_ip_rps(client_ip)
    local current_time = ngx.now()
    local window_start = math.floor(current_time / GLOBAL_RPS_WINDOW) * GLOBAL_RPS_WINDOW
    local ip_rps_key = "ip_rps:" .. client_ip .. ":" .. window_start

    local count = self.cache:incr(ip_rps_key, 1, 0, GLOBAL_RPS_WINDOW)
    if not count then
        return 0
    end

    return count / GLOBAL_RPS_WINDOW
end

-- Analyze attack patterns
function DDoSMitigator:analyze_attack_patterns(features)
    local patterns = {
        suspicious_pattern = false,
        pattern_type = nil,
        confidence = 0
    }

    -- Check for repeated identical requests
    local request_signature = self:generate_request_signature(features)
    local sig_count = self:track_request_signature(request_signature)
    if sig_count > 10 then -- Same request >10 times in window
        patterns.suspicious_pattern = true
        patterns.pattern_type = "repeated_requests"
        patterns.confidence = math.min(sig_count / 50, 1.0)
    end

    -- Check for request flooding patterns
    local flooding_score = self:detect_flooding_pattern(features.client_ip)
    if flooding_score > 0.7 then
        patterns.suspicious_pattern = true
        patterns.pattern_type = "request_flooding"
        patterns.confidence = flooding_score
    end

    -- Check for protocol abuse patterns
    local protocol_abuse = self:detect_protocol_abuse(features)
    if protocol_abuse.detected then
        patterns.suspicious_pattern = true
        patterns.pattern_type = "protocol_abuse"
        patterns.confidence = protocol_abuse.confidence
    end

    return patterns
end

-- Generate request signature for pattern detection
function DDoSMitigator:generate_request_signature(features)
    local signature_parts = {
        features.method or "GET",
        features.path or "/",
        features.user_agent or "",
        tostring(features.content_length or 0)
    }
    return table.concat(signature_parts, "|")
end

-- Track request signature frequency
function DDoSMitigator:track_request_signature(signature)
    local sig_key = "req_sig:" .. str.to_hex(resty_sha256:new():update(signature):final())
    return self.cache:incr(sig_key, 1, 0, 60) or 1 -- 1 minute window
end

-- Detect request flooding patterns
function DDoSMitigator:detect_flooding_pattern(client_ip)
    -- Track request intervals
    local current_time = ngx.now()
    local interval_key = "flood_intervals:" .. client_ip
    local last_time = self.cache:get(interval_key) or current_time

    self.cache:set(interval_key, current_time, 300)

    local interval = current_time - last_time
    if interval < 0.1 then -- Requests coming in faster than 100ms
        local flood_count_key = "flood_count:" .. client_ip
        local count = self.cache:incr(flood_count_key, 1, 0, 60) or 1
        return math.min(count / 20, 1.0) -- Normalize to 0-1 scale
    end

    return 0
end

-- Detect protocol abuse patterns
function DDoSMitigator:detect_protocol_abuse(features)
    local abuse = {
        detected = false,
        confidence = 0,
        abuse_type = nil
    }

    -- Check for missing or suspicious headers
    if not features.user_agent or features.user_agent == "" then
        abuse.detected = true
        abuse.abuse_type = "missing_user_agent"
        abuse.confidence = 0.6
    end

    -- Check for suspicious HTTP methods
    if features.method and not string.match(features.method, "^[A-Z]+$") then
        abuse.detected = true
        abuse.abuse_type = "invalid_method"
        abuse.confidence = 0.8
    end

    -- Check for oversized headers
    if features.header_count and features.header_count > 50 then
        abuse.detected = true
        abuse.abuse_type = "header_bombing"
        abuse.confidence = 0.7
    end

    return abuse
end

-- Calculate overall attack severity
function DDoSMitigator:calculate_attack_severity(indicators)
    local severity = 0

    -- Weight different indicators
    if indicators.global_rps_exceeded then
        severity = severity + 0.4
    end

    if indicators.per_ip_rps_exceeded then
        severity = severity + 0.3
    end

    if indicators.pattern_detected then
        severity = severity + 0.2
    end

    if indicators.volumetric_attack then
        severity = severity + 0.1
    end

    if indicators.protocol_anomaly then
        severity = severity + 0.1
    end

    return math.min(severity, 1.0)
end

-- Get recommended mitigation actions based on severity
function DDoSMitigator:get_recommended_actions(severity)
    local actions = {}

    if severity > 0.9 then
        table.insert(actions, "block")
        table.insert(actions, "challenge")
    elseif severity > 0.7 then
        table.insert(actions, "challenge")
        table.insert(actions, "rate_limit")
    elseif severity > 0.5 then
        table.insert(actions, "rate_limit")
        if self.challenge_enabled then
            table.insert(actions, "challenge")
        end
    else
        table.insert(actions, "monitor")
    end

    return actions
end

-- Generate cryptographic challenge for client
function DDoSMitigator:generate_challenge(client_ip, difficulty_level)
    difficulty_level = difficulty_level or self.challenge_difficulty
    local iterations = DIFFICULTY_LEVELS[difficulty_level] or DIFFICULTY_LEVELS[2]

    -- Generate random challenge data
    local challenge_data = {
        timestamp = ngx.now(),
        client_ip = client_ip,
        nonce = ngx.var.request_id or tostring(math.random(1000000, 9999999)),
        iterations = iterations,
        difficulty = difficulty_level
    }

    -- Create challenge hash
    local challenge_string = table.concat({
        challenge_data.timestamp,
        challenge_data.client_ip,
        challenge_data.nonce
    }, ":")

    local sha256 = resty_sha256:new()
    sha256:update(challenge_string)
    challenge_data.target_hash = str.to_hex(sha256:final())

    -- Store challenge in cache
    local challenge_key = CHALLENGE_PREFIX .. ":" .. client_ip
    self.cache:set(challenge_key, cjson.encode(challenge_data), self.challenge_timeout)

    return challenge_data
end

-- Validate challenge response from client
function DDoSMitigator:validate_challenge_response(client_ip, request_headers)
    -- Check for challenge cookie or header
    local response_data = self:extract_challenge_response(request_headers)
    if not response_data then
        return false, "No challenge response found"
    end

    -- Get stored challenge
    local challenge_key = CHALLENGE_PREFIX .. ":" .. client_ip
    local challenge_json = self.cache:get(challenge_key)
    if not challenge_json then
        return false, "Challenge expired or not found"
    end

    local challenge_data = cjson.decode(challenge_json)
    if not challenge_data then
        return false, "Invalid challenge data"
    end

    -- Validate response
    local is_valid = self:verify_proof_of_work(challenge_data, response_data)
    if is_valid then
        -- Mark client as validated
        local validated_key = "validated:" .. client_ip
        self.cache:set(validated_key, true, 300) -- Valid for 5 minutes

        -- Clean up challenge
        self.cache:delete(challenge_key)

        return true, "Challenge solved successfully"
    end

    return false, "Invalid challenge solution"
end

-- Extract challenge response from request headers
function DDoSMitigator:extract_challenge_response(request_headers)
    -- Try cookie first
    local cookies = request_headers["cookie"]
    if cookies then
        local challenge_value = string.match(cookies, CHALLENGE_COOKIE_NAME .. "=([^;]+)")
        if challenge_value then
            return { solution = challenge_value, source = "cookie" }
        end
    end

    -- Try custom header
    local header_value = request_headers["x-challenge-response"]
    if header_value then
        return { solution = header_value, source = "header" }
    end

    return nil
end

-- Verify proof-of-work solution
function DDoSMitigator:verify_proof_of_work(challenge_data, response_data)
    if not response_data.solution then
        return false
    end

    -- Reconstruct the challenge string with solution
    local test_string = table.concat({
        challenge_data.timestamp,
        challenge_data.client_ip,
        challenge_data.nonce,
        response_data.solution
    }, ":")

    -- Hash the test string
    local sha256 = resty_sha256:new()
    sha256:update(test_string)
    local result_hash = str.to_hex(sha256:final())

    -- Check if hash meets difficulty requirement
    local required_zeros = math.floor(challenge_data.difficulty / 2)
    local prefix = string.rep("0", required_zeros)

    return string.sub(result_hash, 1, required_zeros) == prefix
end

-- Check if client has been validated
function DDoSMitigator:is_client_validated(client_ip)
    local validated_key = "validated:" .. client_ip
    return self.cache:get(validated_key) ~= nil
end

-- Generate HTML challenge page
function DDoSMitigator:get_challenge_html(client_ip, difficulty_level)
    local challenge_data = self:generate_challenge(client_ip, difficulty_level)

    local html_template = [[
<!DOCTYPE html>
<html>
<head>
    <title>Security Verification</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .challenge-box { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
        .progress { width: 100%; height: 20px; background: #f0f0f0; border-radius: 10px; overflow: hidden; }
        .progress-bar { height: 100%; background: #4CAF50; width: 0%; transition: width 0.3s; }
        .status { margin: 10px 0; font-weight: bold; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:disabled { background: #ccc; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="challenge-box">
        <h2>🛡️ Security Verification Required</h2>
        <p>To protect against automated attacks, please complete this security challenge.</p>

        <div class="status" id="status">Click "Start Verification" to begin</div>
        <div class="progress">
            <div class="progress-bar" id="progressBar"></div>
        </div>

        <p>
            <button onclick="startChallenge()" id="startButton">Start Verification</button>
            <button onclick="submitSolution()" id="submitButton" disabled>Submit</button>
        </p>

        <div id="result"></div>
    </div>

    <script>
        const challengeData = ]] .. cjson.encode(challenge_data) .. [[;
        let solution = null;
        let isRunning = false;

        function startChallenge() {
            if (isRunning) return;

            isRunning = true;
            document.getElementById('startButton').disabled = true;
            document.getElementById('status').textContent = 'Computing security proof...';

            // Use Web Worker for non-blocking computation
            solveChallenge();
        }

        function solveChallenge() {
            const target = challengeData.target_hash;
            const iterations = challengeData.iterations;
            const baseString = challengeData.timestamp + ':' + challengeData.client_ip + ':' + challengeData.nonce + ':';

            let attempt = 0;
            const batchSize = 1000;

            function solveBatch() {
                const endAttempt = Math.min(attempt + batchSize, iterations);

                for (let i = attempt; i < endAttempt; i++) {
                    const testString = baseString + i;
                    const hash = sha256(testString);

                    // Check if hash meets difficulty requirement
                    const requiredZeros = Math.floor(challengeData.difficulty / 2);
                    const prefix = '0'.repeat(requiredZeros);

                    if (hash.substring(0, requiredZeros) === prefix) {
                        solution = i;
                        onSolutionFound();
                        return;
                    }
                }

                attempt = endAttempt;
                const progress = (attempt / iterations) * 100;
                document.getElementById('progressBar').style.width = progress + '%';
                document.getElementById('status').textContent = 'Computing... ' + Math.round(progress) + '%';

                if (attempt < iterations) {
                    setTimeout(solveBatch, 10); // Small delay to prevent browser blocking
                } else {
                    onSolutionNotFound();
                }
            }

            solveBatch();
        }

        function onSolutionFound() {
            document.getElementById('status').textContent = 'Solution found! Ready to submit.';
            document.getElementById('progressBar').style.width = '100%';
            document.getElementById('submitButton').disabled = false;
            isRunning = false;
        }

        function onSolutionNotFound() {
            document.getElementById('status').textContent = 'No solution found. Please refresh and try again.';
            document.getElementById('startButton').disabled = false;
            isRunning = false;
        }

        function submitSolution() {
            if (solution === null) {
                alert('Please complete the challenge first.');
                return;
            }

            // Set cookie with solution
            document.cookie = ']] .. CHALLENGE_COOKIE_NAME .. [[=' + solution + '; path=/; max-age=300';

            // Reload page to continue with validated session
            window.location.reload();
        }

        // Simple SHA-256 implementation for client-side use
        function sha256(message) {
            // This would be replaced with a proper SHA-256 implementation
            // For demo purposes, using a simplified hash
            let hash = 0;
            for (let i = 0; i < message.length; i++) {
                const char = message.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32-bit integer
            }
            return Math.abs(hash).toString(16).padStart(8, '0');
        }
    </script>
</body>
</html>
]]

    return html_template
end

-- Adjust challenge difficulty based on attack severity
function DDoSMitigator:adjust_challenge_difficulty(attack_severity)
    local new_difficulty = self.challenge_difficulty

    if attack_severity > 0.9 then
        new_difficulty = math.min(10, self.challenge_difficulty + 3)
    elseif attack_severity > 0.7 then
        new_difficulty = math.min(8, self.challenge_difficulty + 2)
    elseif attack_severity > 0.5 then
        new_difficulty = math.min(6, self.challenge_difficulty + 1)
    elseif attack_severity < 0.3 then
        new_difficulty = math.max(1, self.challenge_difficulty - 1)
    end

    return new_difficulty
end

-- Apply mitigation actions
function DDoSMitigator:apply_mitigation(client_ip, actions, severity)
    local results = {}

    for _, action in ipairs(actions) do
        if action == "block" then
            results[action] = self:apply_temporary_block(client_ip, severity)
        elseif action == "challenge" then
            results[action] = self:require_challenge(client_ip, severity)
        elseif action == "rate_limit" then
            results[action] = self:apply_emergency_rate_limit(client_ip, severity)
        elseif action == "delay" then
            results[action] = self:apply_request_delay(client_ip, severity)
        end
    end

    return results
end

-- Apply temporary IP block
function DDoSMitigator:apply_temporary_block(client_ip, severity)
    local block_duration = math.min(3600, 60 * severity * 10) -- Max 1 hour
    local block_key = "blocked:" .. client_ip

    self.cache:set(block_key, true, block_duration)

    return {
        applied = true,
        duration = block_duration,
        reason = "DDoS attack detected"
    }
end

-- Require challenge completion
function DDoSMitigator:require_challenge(client_ip, severity)
    local difficulty = self:adjust_challenge_difficulty(severity)
    local challenge_data = self:generate_challenge(client_ip, difficulty)

    return {
        applied = true,
        challenge_id = challenge_data.nonce,
        difficulty = difficulty,
        timeout = self.challenge_timeout
    }
end

-- Apply emergency rate limiting
function DDoSMitigator:apply_emergency_rate_limit(client_ip, severity)
    local rate_limit = math.max(1, 10 * (1 - severity)) -- 1-10 requests per minute
    local rate_key = "emergency_rate:" .. client_ip

    self.cache:set(rate_key, rate_limit, 300) -- 5 minutes

    return {
        applied = true,
        rate_limit = rate_limit,
        duration = 300
    }
end

-- Apply request delay
function DDoSMitigator:apply_request_delay(client_ip, severity)
    local delay_ms = math.min(5000, severity * 2000) -- Max 5 seconds

    ngx.sleep(delay_ms / 1000)

    return {
        applied = true,
        delay_ms = delay_ms
    }
end

-- Update attack metrics
function DDoSMitigator:update_attack_metrics(indicators, severity)
    -- Count total attacks
    self.metrics_cache:incr("ddos_attacks_total", 1, 0, 3600)

    -- Count by severity
    if severity > 0.8 then
        self.metrics_cache:incr("ddos_attacks_severe", 1, 0, 3600)
    elseif severity > 0.6 then
        self.metrics_cache:incr("ddos_attacks_moderate", 1, 0, 3600)
    else
        self.metrics_cache:incr("ddos_attacks_low", 1, 0, 3600)
    end

    -- Count by indicator type
    for indicator, detected in pairs(indicators) do
        if detected then
            self.metrics_cache:incr("ddos_indicator_" .. indicator, 1, 0, 3600)
        end
    end
end

-- Get DDoS statistics
function DDoSMitigator:get_statistics()
    return {
        total_attacks = self.metrics_cache:get("ddos_attacks_total") or 0,
        severe_attacks = self.metrics_cache:get("ddos_attacks_severe") or 0,
        moderate_attacks = self.metrics_cache:get("ddos_attacks_moderate") or 0,
        low_attacks = self.metrics_cache:get("ddos_attacks_low") or 0,
        current_global_rps = self:get_global_rps(),
        active_challenges = self:count_active_challenges(),
        blocked_ips = self:count_blocked_ips()
    }
end

-- Count active challenges
function DDoSMitigator:count_active_challenges()
    -- Simplified count - would need key iteration in real implementation
    return 0
end

-- Count currently blocked IPs
function DDoSMitigator:count_blocked_ips()
    -- Simplified count - would need key iteration in real implementation
    return 0
end

return DDoSMitigator