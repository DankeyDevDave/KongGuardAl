-- AI Integration Configuration Schema
-- Extracted from schema.lua for better modularity and maintainability

local _M = {}

--- Get AI integration configuration schema fields
-- @return table configuration schema fields for AI integration
function _M.get_fields()
    return {
        -- AI Gateway Integration (optional)
        {
            enable_ai_gateway = {
                type = "boolean",
                default = false,
                description = "Enable Kong AI Gateway integration for advanced analysis"
            }
        },
        {
            ai_service_url = {
                type = "string",
                default = "http://ai-service:8000",
                description = "URL of the AI threat analysis service"
            }
        },
        {
            ai_model = {
                type = "string",
                default = "claude-3-haiku",
                one_of = {
                    "claude-3-haiku",
                    "claude-3-sonnet",
                    "claude-3-opus",
                    "gpt-4",
                    "gpt-4-turbo",
                    "gpt-3.5-turbo",
                    "gemini-pro",
                    "gemini-1.5-pro",
                    "llama2-7b",
                    "llama2-13b",
                    "llama2-70b"
                },
                description = "AI model to use for analysis"
            }
        },
        {
            ai_temperature = {
                type = "number",
                default = 0.1,
                between = {0, 1},
                description = "AI model temperature for consistent decisions"
            }
        },
        {
            ai_timeout = {
                type = "integer",
                default = 500,
                between = {100, 5000},
                description = "AI service timeout in milliseconds"
            }
        },
        {
            ai_max_tokens = {
                type = "integer",
                default = 1000,
                between = {100, 4000},
                description = "Maximum tokens for AI response"
            }
        },
        {
            ai_retry_attempts = {
                type = "integer",
                default = 3,
                between = {1, 5},
                description = "Number of retry attempts for AI service calls"
            }
        },
        {
            ai_fallback_mode = {
                type = "string",
                default = "rule_based",
                one_of = {"rule_based", "allow", "block"},
                description = "Fallback behavior when AI service is unavailable"
            }
        },
        -- AI Model Specific Configurations
        {
            claude_api_key = {
                type = "string",
                description = "Anthropic Claude API key"
            }
        },
        {
            openai_api_key = {
                type = "string", 
                description = "OpenAI API key"
            }
        },
        {
            google_api_key = {
                type = "string",
                description = "Google Gemini API key"
            }
        },
        {
            ai_confidence_threshold = {
                type = "number",
                default = 0.7,
                between = {0, 1},
                description = "Minimum confidence score to trust AI predictions"
            }
        },
        {
            enable_ai_learning = {
                type = "boolean",
                default = true,
                description = "Enable AI model learning from feedback"
            }
        },
        {
            ai_cache_ttl = {
                type = "integer",
                default = 300,
                between = {60, 3600},
                description = "AI response cache TTL in seconds"
            }
        }
    }
end

--- Get AI integration defaults
-- @return table default configuration values
function _M.get_defaults()
    return {
        enable_ai_gateway = false,
        ai_service_url = "http://ai-service:8000",
        ai_model = "claude-3-haiku",
        ai_temperature = 0.1,
        ai_timeout = 500,
        ai_max_tokens = 1000,
        ai_retry_attempts = 3,
        ai_fallback_mode = "rule_based",
        ai_confidence_threshold = 0.7,
        enable_ai_learning = true,
        ai_cache_ttl = 300
    }
end

--- Get supported AI models with their configurations
-- @return table AI model configurations
function _M.get_ai_models()
    return {
        ["claude-3-haiku"] = {
            provider = "anthropic",
            max_tokens = 4000,
            context_window = 200000,
            cost_per_1k_tokens = 0.00025
        },
        ["claude-3-sonnet"] = {
            provider = "anthropic", 
            max_tokens = 4000,
            context_window = 200000,
            cost_per_1k_tokens = 0.003
        },
        ["claude-3-opus"] = {
            provider = "anthropic",
            max_tokens = 4000, 
            context_window = 200000,
            cost_per_1k_tokens = 0.015
        },
        ["gpt-4"] = {
            provider = "openai",
            max_tokens = 4000,
            context_window = 8192,
            cost_per_1k_tokens = 0.03
        },
        ["gpt-4-turbo"] = {
            provider = "openai",
            max_tokens = 4000,
            context_window = 128000,
            cost_per_1k_tokens = 0.01
        },
        ["gpt-3.5-turbo"] = {
            provider = "openai",
            max_tokens = 4000,
            context_window = 16385,
            cost_per_1k_tokens = 0.0015
        },
        ["gemini-pro"] = {
            provider = "google",
            max_tokens = 2048,
            context_window = 32768,
            cost_per_1k_tokens = 0.0005
        },
        ["gemini-1.5-pro"] = {
            provider = "google",
            max_tokens = 8192,
            context_window = 1000000,
            cost_per_1k_tokens = 0.00125
        }
    }
end

--- Validate AI integration configuration
-- @param config table configuration to validate
-- @return boolean true if valid
-- @return string error message if invalid
function _M.validate_config(config)
    if not config then
        return false, "Configuration is required"
    end
    
    -- Validate AI service URL if AI gateway is enabled
    if config.enable_ai_gateway and not config.ai_service_url then
        return false, "ai_service_url is required when enable_ai_gateway is true"
    end
    
    -- Validate AI model
    local supported_models = _M.get_ai_models()
    if config.ai_model and not supported_models[config.ai_model] then
        return false, "Unsupported AI model: " .. config.ai_model
    end
    
    -- Validate API keys for specific providers
    if config.enable_ai_gateway and config.ai_model then
        local model_info = supported_models[config.ai_model]
        if model_info then
            if model_info.provider == "anthropic" and not config.claude_api_key then
                return false, "claude_api_key is required for Anthropic models"
            elseif model_info.provider == "openai" and not config.openai_api_key then
                return false, "openai_api_key is required for OpenAI models"
            elseif model_info.provider == "google" and not config.google_api_key then
                return false, "google_api_key is required for Google models"
            end
        end
    end
    
    -- Validate timeout
    if config.ai_timeout and (config.ai_timeout < 100 or config.ai_timeout > 5000) then
        return false, "ai_timeout must be between 100 and 5000 milliseconds"
    end
    
    return true
end

return _M