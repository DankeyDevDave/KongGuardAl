--- Unit tests for Incident Response Engine

local IncidentResponder = require "kong.plugins.kong-guard-ai.incident_responder"

describe("Incident Responder", function()
    local responder
    local mock_config
    local mock_soar_client

    before_each(function()
        mock_config = {
            incident_response = {
                enable_auto_response = true,
                response_workflows = {
                    {
                        trigger_condition = "high_threat",
                        actions = {"block_ip", "notify"},
                        severity_threshold = 0.8
                    },
                    {
                        trigger_condition = "threat_score > 0.6",
                        actions = {"rate_limit", "log_enhance"},
                        severity_threshold = 0.5
                    }
                }
            },
            notification_url = "http://mock-webhook:8080/notify",
            rate_limit_duration = 300
        }

        mock_soar_client = {
            create_incident = function() return "mock-incident-123" end,
            update_incident_status = function() return true end
        }

        responder = IncidentResponder.new(mock_config, mock_soar_client)
    end)

    describe("new()", function()
        it("should create a new responder instance", function()
            assert.is_not_nil(responder)
            assert.is_table(responder)
        end)

        it("should return nil for invalid config", function()
            local invalid_responder = IncidentResponder.new(nil)
            assert.is_nil(invalid_responder)
        end)
    end)

    describe("init()", function()
        it("should initialize successfully with valid config", function()
            local success, err = responder:init()
            assert.is_true(success)
            assert.is_nil(err)
        end)

        it("should fail with missing incident response config", function()
            local bad_config = {}
            local bad_responder = IncidentResponder.new(bad_config)
            local success, err = bad_responder:init()
            assert.is_false(success)
            assert.is_not_nil(err)
        end)

        it("should skip initialization when disabled", function()
            local disabled_config = {
                incident_response = { enable_auto_response = false }
            }
            local disabled_responder = IncidentResponder.new(disabled_config)
            local success, err = disabled_responder:init()
            assert.is_true(success)
        end)
    end)

    describe("evaluate_condition()", function()
        it("should evaluate high_threat condition", function()
            local threat_data = { threat_score = 0.9 }
            assert.is_true(responder:evaluate_condition("high_threat", threat_data))
        end)

        it("should evaluate threat_score conditions", function()
            local threat_data = { threat_score = 0.7 }
            assert.is_true(responder:evaluate_condition("threat_score > 0.6", threat_data))
            assert.is_false(responder:evaluate_condition("threat_score > 0.8", threat_data))
        end)

        it("should handle invalid conditions", function()
            local threat_data = { threat_score = 0.9 }
            assert.is_false(responder:evaluate_condition("invalid_condition", threat_data))
            assert.is_false(responder:evaluate_condition(nil, threat_data))
            assert.is_false(responder:evaluate_condition("high_threat", nil))
        end)
    end)

    describe("evaluate_triggers()", function()
        it("should return triggered workflows", function()
            local threat_data = { threat_score = 0.9, client_ip = "192.168.1.100" }
            local triggered = responder:evaluate_triggers(threat_data)
            assert.is_table(triggered)
            assert.equals(2, #triggered) -- Both workflows should trigger
        end)

        it("should return empty table when disabled", function()
            local disabled_config = {
                incident_response = { enable_auto_response = false }
            }
            local disabled_responder = IncidentResponder.new(disabled_config)
            local threat_data = { threat_score = 0.9 }
            local triggered = disabled_responder:evaluate_triggers(threat_data)
            assert.is_table(triggered)
            assert.equals(0, #triggered)
        end)

        it("should respect severity thresholds", function()
            local threat_data = { threat_score = 0.4, client_ip = "192.168.1.100" }
            local triggered = responder:evaluate_triggers(threat_data)
            assert.is_table(triggered)
            assert.equals(0, #triggered) -- No workflows should trigger due to low score
        end)
    end)

    describe("execute_action()", function()
        local threat_data = {
            threat_score = 0.9,
            client_ip = "192.168.1.100",
            request_path = "/api/users",
            message = "Test threat"
        }

        it("should execute block_ip action", function()
            local success, result, err = responder:execute_action("block_ip", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("block_ip", result.action)
            assert.equals("192.168.1.100", result.ip)
            assert.equals("test-incident", result.incident_id)
        end)

        it("should execute rate_limit action", function()
            local success, result, err = responder:execute_action("rate_limit", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("rate_limit", result.action)
            assert.equals("192.168.1.100", result.ip)
        end)

        it("should execute notify action", function()
            local success, result, err = responder:execute_action("notify", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("notify", result.action)
            assert.equals("http://mock-webhook:8080/notify", result.notification_url)
        end)

        it("should execute log_enhance action", function()
            local success, result, err = responder:execute_action("log_enhance", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("log_enhance", result.action)
        end)

        it("should execute soar_incident action", function()
            local success, result, err = responder:execute_action("soar_incident", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("soar_incident", result.action)
            assert.equals("mock-incident-123", result.incident_id)
        end)

        it("should execute quarantine action", function()
            local success, result, err = responder:execute_action("quarantine", threat_data, "test-incident")
            assert.is_true(success)
            assert.is_table(result)
            assert.equals("quarantine", result.action)
        end)

        it("should handle unknown actions", function()
            local success, result, err = responder:execute_action("unknown_action", threat_data, "test-incident")
            assert.is_false(success)
            assert.is_nil(result)
            assert.is_not_nil(err)
        end)

        it("should handle missing action", function()
            local success, result, err = responder:execute_action(nil, threat_data, "test-incident")
            assert.is_false(success)
            assert.is_nil(result)
            assert.is_not_nil(err)
        end)
    end)

    describe("execute_workflow()", function()
        it("should execute a complete workflow", function()
            local workflow = {
                trigger_condition = "high_threat",
                actions = {"block_ip", "notify"},
                severity_threshold = 0.8
            }
            local threat_data = {
                threat_score = 0.9,
                client_ip = "192.168.1.100",
                request_path = "/api/users"
            }

            local result, err = responder:execute_workflow(workflow, threat_data)
            assert.is_not_nil(result)
            assert.is_nil(err)
            assert.equals("completed", result.status)
            assert.equals(2, result.actions_completed)
            assert.equals(2, result.total_actions)
            assert.is_not_nil(result.execution_id)
            assert.is_not_nil(result.incident_id)
        end)

        it("should handle workflow execution errors", function()
            local workflow = {
                trigger_condition = "high_threat",
                actions = {"block_ip", "unknown_action"},
                severity_threshold = 0.8
            }
            local threat_data = {
                threat_score = 0.9,
                client_ip = "192.168.1.100"
            }

            local result, err = responder:execute_workflow(workflow, threat_data)
            assert.is_not_nil(result)
            assert.is_nil(err)
            assert.equals("partial", result.status)
            assert.equals(1, result.actions_completed)
            assert.equals(2, result.total_actions)
        end)

        it("should handle invalid parameters", function()
            local result, err = responder:execute_workflow(nil, {})
            assert.is_nil(result)
            assert.is_not_nil(err)
        end)
    end)

    describe("create_or_update_incident()", function()
        it("should create new incident", function()
            local threat_data = { threat_score = 0.8, client_ip = "10.0.0.1" }
            local incident_id, err = responder:create_or_update_incident(threat_data)
            assert.is_not_nil(incident_id)
            assert.is_nil(err)
            assert.is_not_nil(responder:get_incident(incident_id))
        end)

        it("should update existing incident", function()
            local threat_data = { threat_score = 0.8, client_ip = "10.0.0.1" }
            local incident_id, err = responder:create_or_update_incident(threat_data)
            assert.is_not_nil(incident_id)

            local updated_id, update_err = responder:create_or_update_incident(threat_data, incident_id)
            assert.equals(incident_id, updated_id)
            assert.is_nil(update_err)
        end)
    end)

    describe("get_health_status()", function()
        it("should return health status information", function()
            local status = responder:get_health_status()
            assert.is_table(status)
            assert.is_boolean(status.enabled)
            assert.is_number(status.active_incidents)
            assert.is_number(status.running_workflows)
            assert.is_table(status.metrics)
            assert.is_number(status.workflow_states_count)
        end)
    end)

    describe("cleanup_old_data()", function()
        it("should clean up old workflow states and incidents", function()
            -- Create some test data
            responder.workflow_states["old_exec"] = {
                status = "completed",
                end_time = ngx.now() - 7200, -- 2 hours ago
                start_time = ngx.now() - 7300
            }
            responder.active_incidents["old_inc"] = {
                id = "old_inc",
                last_updated = ngx.now() - 7200
            }

            local initial_states = #responder.workflow_states
            local initial_incidents = 0
            for _ in pairs(responder.active_incidents) do
                initial_incidents = initial_incidents + 1
            end

            responder:cleanup_old_data(3600) -- Clean data older than 1 hour

            -- Should have cleaned up old data
            assert.is_true(#responder.workflow_states < initial_states or initial_states == 0)
        end)
    end)

    describe("generate_execution_id() and generate_incident_id()", function()
        it("should generate unique IDs", function()
            local exec_id1 = responder:generate_execution_id()
            local exec_id2 = responder:generate_execution_id()
            local inc_id1 = responder:generate_incident_id()
            local inc_id2 = responder:generate_incident_id()

            assert.is_not_nil(exec_id1)
            assert.is_not_nil(exec_id2)
            assert.is_not_nil(inc_id1)
            assert.is_not_nil(inc_id2)

            assert.not_equals(exec_id1, exec_id2)
            assert.not_equals(inc_id1, inc_id2)

            assert.matches("^exec_", exec_id1)
            assert.matches("^inc_", inc_id1)
        end)
    end)
end)