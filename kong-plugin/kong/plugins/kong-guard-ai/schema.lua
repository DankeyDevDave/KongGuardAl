-- Kong Guard AI Plugin Schema
-- Refactored to use modular schema architecture for better maintainability
-- Original schema.lua was 2,041 lines - now modularized across multiple files

local typedefs = require "kong.db.schema.typedefs"
local schema_orchestrator = require "kong.plugins.kong-guard-ai.modules.schema.schema_orchestrator"

-- Get the complete schema from all modules
local config_fields = schema_orchestrator.get_complete_schema()

return {
    name = "kong-guard-ai",
    fields = {
        {
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = config_fields,
                custom_validator = function(config)
                    -- Use the orchestrator's comprehensive validation
                    local valid, error_msg = schema_orchestrator.validate_complete_config(config)
                    if not valid then
                        return false, error_msg
                    end
                    return true
                end
            }
        }
    }
}