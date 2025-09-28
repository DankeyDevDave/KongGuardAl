#!/usr/bin/env lua

-- Mock TAXII Server for Integration Testing
-- This provides a simple HTTP server that mimics TAXII 2.1 API responses

local socket = require("socket")
local cjson = require("cjson")

local MockTaxiiServer = {}
MockTaxiiServer.__index = MockTaxiiServer

function MockTaxiiServer.new(port)
    local self = setmetatable({}, MockTaxiiServer)
    self.port = port or 8080
    self.running = false
    return self
end

-- Mock TAXII discovery response
function MockTaxiiServer:get_discovery_response()
    return {
        title = "Mock TAXII Server",
        description = "Mock server for testing Kong Guard AI TAXII integration",
        contact = "test@example.com",
        default = "http://localhost:" .. self.port .. "/api1/",
        api_roots = {
            "http://localhost:" .. self.port .. "/api1/"
        }
    }
end

-- Mock collections response
function MockTaxiiServer:get_collections_response()
    return {
        collections = {
            {
                id = "test-collection",
                title = "Test Threat Intelligence Collection",
                description = "Collection containing test threat indicators",
                can_read = true,
                can_write = false,
                media_types = {
                    "application/stix+json;version=2.1"
                }
            },
            {
                id = "malware-collection",
                title = "Malware Indicators",
                description = "Collection of malware-related indicators",
                can_read = true,
                can_write = false,
                media_types = {
                    "application/stix+json;version=2.1"
                }
            }
        }
    }
end

-- Mock objects response with STIX indicators
function MockTaxiiServer:get_objects_response(collection_id, limit, added_after)
    local objects = {}

    if collection_id == "test-collection" then
        objects = {
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--test-malicious-ip-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "[ipv4-addr:value = '1.2.3.4']",
                labels = {"malicious-activity"},
                confidence = 85,
                valid_from = "2023-01-01T00:00:00.000Z"
            },
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--test-malicious-domain-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "[domain-name:value = 'evil.example.com']",
                labels = {"malicious-activity"},
                confidence = 90,
                valid_from = "2023-01-01T00:00:00.000Z"
            },
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--test-malicious-url-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "[url:value = 'https://evil.example.com/malware']",
                labels = {"malware"},
                confidence = 95,
                valid_from = "2023-01-01T00:00:00.000Z"
            },
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--test-ja3-fingerprint-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "x-ja3-hash:value = 'a1b2c3d4e5f6g7h8i9j0'",
                description = "Malicious JA3 fingerprint from known botnet",
                labels = {"malicious-activity", "botnet"},
                confidence = 88,
                valid_from = "2023-01-01T00:00:00.000Z"
            },
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--test-allowlist-ip-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "[ipv4-addr:value = '8.8.8.8']",
                labels = {"benign", "trusted"},
                confidence = 100,
                valid_from = "2023-01-01T00:00:00.000Z"
            }
        }
    elseif collection_id == "malware-collection" then
        objects = {
            {
                type = "indicator",
                spec_version = "2.1",
                id = "indicator--malware-hash-1",
                created = "2023-01-01T00:00:00.000Z",
                modified = "2023-01-01T00:00:00.000Z",
                pattern = "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                labels = {"malicious-activity", "trojan"],
                confidence = 95,
                valid_from = "2023-01-01T00:00:00.000Z"
            }
        }
    end

    -- Apply limit if specified
    if limit and #objects > limit then
        objects = {table.unpack(objects, 1, limit)}
    end

    return {
        more = false,
        objects = objects
    }
end

-- Parse HTTP request
function MockTaxiiServer:parse_request(data)
    local lines = {}
    for line in data:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    if #lines == 0 then
        return nil
    end

    local request_line = lines[1]
    local method, path, version = request_line:match("^(%S+)%s+(%S+)%s+(%S+)$")

    local headers = {}
    for i = 2, #lines do
        local line = lines[i]
        if line == "" then
            break
        end
        local key, value = line:match("^([^:]+):%s*(.*)$")
        if key and value then
            headers[key:lower()] = value
        end
    end

    return {
        method = method,
        path = path,
        version = version,
        headers = headers
    }
end

-- Handle HTTP request
function MockTaxiiServer:handle_request(request)
    local path = request.path
    local method = request.method

    print(string.format("[Mock TAXII] %s %s", method, path))

    local response_data
    local status = "200 OK"
    local content_type = "application/taxii+json;version=2.1"

    if method == "GET" then
        if path == "/taxii/" then
            -- Discovery endpoint
            response_data = self:get_discovery_response()
        elseif path:match("^/api1/collections/?$") then
            -- Collections endpoint
            response_data = self:get_collections_response()
        elseif path:match("^/api1/collections/([^/]+)/objects/?") then
            -- Objects endpoint
            local collection_id = path:match("^/api1/collections/([^/]+)/objects/?")
            response_data = self:get_objects_response(collection_id)
        else
            -- Not found
            status = "404 Not Found"
            response_data = {error = "Endpoint not found"}
        end
    else
        -- Method not allowed
        status = "405 Method Not Allowed"
        response_data = {error = "Method not allowed"}
    end

    local json_response = cjson.encode(response_data)
    local response = string.format(
        "HTTP/1.1 %s\r\n" ..
        "Content-Type: %s\r\n" ..
        "Content-Length: %d\r\n" ..
        "Connection: close\r\n" ..
        "\r\n" ..
        "%s",
        status,
        content_type,
        #json_response,
        json_response
    )

    return response
end

-- Start the mock server
function MockTaxiiServer:start()
    local server = assert(socket.bind("*", self.port))
    server:settimeout(1)  -- 1 second timeout

    print(string.format("Mock TAXII server started on port %d", self.port))
    print("Available endpoints:")
    print("  GET /taxii/ - Discovery")
    print("  GET /api1/collections/ - Collections")
    print("  GET /api1/collections/{id}/objects/ - Objects")

    self.running = true

    while self.running do
        local client = server:accept()
        if client then
            client:settimeout(5)

            local data, err = client:receive("*l")
            if data then
                -- Read the full request
                local request_data = data .. "\r\n"
                while true do
                    local line, err = client:receive("*l")
                    if not line or line == "" then
                        break
                    end
                    request_data = request_data .. line .. "\r\n"
                end

                local request = self:parse_request(request_data)
                if request then
                    local response = self:handle_request(request)
                    client:send(response)
                end
            end

            client:close()
        end
    end

    server:close()
    print("Mock TAXII server stopped")
end

-- Stop the server
function MockTaxiiServer:stop()
    self.running = false
end

-- Command line interface
if arg and arg[0]:match("mock_taxii_server%.lua$") then
    local port = tonumber(arg[1]) or 8080
    local server = MockTaxiiServer.new(port)

    -- Handle Ctrl+C
    local function signal_handler()
        print("\nReceived interrupt signal, stopping server...")
        server:stop()
        os.exit(0)
    end

    -- Set up signal handling (Unix-like systems)
    if os.execute("which kill > /dev/null 2>&1") == 0 then
        os.execute("trap 'kill -TERM $$' INT")
    end

    server:start()
end

return MockTaxiiServer
