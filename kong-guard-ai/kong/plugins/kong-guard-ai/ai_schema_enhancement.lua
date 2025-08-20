-- Kong Guard AI - Enhanced AI Gateway Schema Configuration
-- Additional schema fields for comprehensive AI Gateway integration
-- This extends the base schema with multi-model support and advanced features

local ai_schema_enhancement = {
    -- Enhanced AI Gateway Integration - DISABLED BY DEFAULT FOR SAFETY
    {
        ai_gateway_enabled = {
            type = "boolean",
            default = false,  -- SAFE: Disabled to prevent external dependencies
            description = "Enable enhanced AI Gateway integration for advanced threat analysis. CAUTION: Requires external service configuration and API costs"
        }
    },
    
    -- Multi-Model AI Configuration
    {
        ai_gpt4_enabled = {
            type = "boolean",
            default = false,
            description = "Enable GPT-4 model for AI analysis"
        }
    },
    {
        ai_claude_enabled = {
            type = "boolean", 
            default = false,
            description = "Enable Claude model for AI analysis"
        }
    },
    {
        ai_gemini_enabled = {
            type = "boolean",
            default = false,
            description = "Enable Gemini model for AI analysis"
        }
    },
    
    -- Model API Configuration
    {
        openai_api_key = {
            type = "string",
            description = "OpenAI API key for GPT-4 access"
        }
    },
    {
        anthropic_api_key = {
            type = "string",
            description = "Anthropic API key for Claude access"
        }
    },
    {
        gemini_api_key = {
            type = "string",
            description = "Google Gemini API key"
        }
    },
    
    -- Model Endpoints (optional, uses defaults if not specified)
    {
        openai_endpoint = {
            type = "string",
            default = "https://api.openai.com/v1/chat/completions",
            description = "OpenAI API endpoint"
        }
    },
    {
        anthropic_endpoint = {
            type = "string", 
            default = "https://api.anthropic.com/v1/messages",
            description = "Anthropic API endpoint"
        }
    },
    {
        gemini_endpoint = {
            type = "string",
            default = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
            description = "Google Gemini API endpoint"
        }
    },
    
    -- AI Performance and Cost Configuration
    {
        ai_timeout_ms = {
            type = "number",
            default = 10000,  -- Increased for comprehensive analysis
            between = { 1000, 30000 },
            description = "AI model request timeout in milliseconds. RECOMMENDED: 10000ms for comprehensive analysis"
        }
    },
    {
        ai_cost_optimization_enabled = {
            type = "boolean",
            default = true,
            description = "Enable intelligent cost optimization with request sampling"
        }
    },
    {
        ai_max_daily_cost = {
            type = "number",
            default = 100.0,
            between = { 1.0, 10000.0 },
            description = "Maximum daily AI analysis cost in USD"
        }
    },
    {
        ai_ssl_verify = {
            type = "boolean",
            default = true,
            description = "Verify SSL certificates for AI API requests"
        }
    },
    
    -- AI Analysis Configuration
    {
        ai_analysis_threshold = {
            type = "number",
            default = 6.0,  -- SAFE: Higher threshold for expensive AI analysis
            between = { 1.0, 10.0 },
            description = "Threat level threshold for triggering AI analysis. RECOMMENDED: Use 6.0+ to control AI costs"
        }
    },
    {
        ai_comprehensive_analysis_threshold = {
            type = "number",
            default = 8.0,
            between = { 5.0, 10.0 },
            description = "Threat level threshold for comprehensive multi-model analysis"
        }
    },
    {
        ai_behavioral_analysis_enabled = {
            type = "boolean",
            default = true,
            description = "Enable AI-powered behavioral anomaly detection"
        }
    },
    {
        ai_payload_analysis_enabled = {
            type = "boolean",
            default = true,
            description = "Enable deep AI payload analysis for injection detection"
        }
    },
    {
        ai_contextual_analysis_enabled = {
            type = "boolean",
            default = false, -- More expensive, disabled by default
            description = "Enable contextual threat assessment with historical data"
        }
    },
    
    -- AI Learning and Feedback
    {
        ai_learning_enabled = {
            type = "boolean",
            default = true,
            description = "Enable AI model performance learning and adaptation"
        }
    },
    {
        ai_feedback_collection_enabled = {
            type = "boolean",
            default = true,
            description = "Enable feedback collection for continuous model improvement"
        }
    },
    {
        ai_analyst_feedback_endpoint = {
            type = "string",
            description = "Endpoint for security analyst feedback submission"
        }
    },
    
    -- AI Caching and Performance
    {
        ai_cache_enabled = {
            type = "boolean",
            default = true,
            description = "Enable AI response caching to reduce costs and latency"
        }
    },
    {
        ai_cache_ttl_seconds = {
            type = "number",
            default = 300, -- 5 minutes
            between = { 60, 3600 },
            description = "TTL for AI response cache in seconds"
        }
    },
    {
        ai_cache_size = {
            type = "number",
            default = 1000,
            between = { 100, 10000 },
            description = "Maximum number of AI responses to cache"
        }
    },
    
    -- AI Risk Sampling Configuration
    {
        ai_low_risk_sampling_rate = {
            type = "number",
            default = 0.1,
            between = { 0.01, 1.0 },
            description = "Sampling rate for low-risk requests (0.01-1.0)"
        }
    },
    {
        ai_medium_risk_sampling_rate = {
            type = "number",
            default = 0.5,
            between = { 0.1, 1.0 },
            description = "Sampling rate for medium-risk requests (0.1-1.0)"
        }
    },
    {
        ai_high_risk_sampling_rate = {
            type = "number",
            default = 1.0,
            between = { 0.5, 1.0 },
            description = "Sampling rate for high-risk requests (0.5-1.0)"
        }
    },
    
    -- AI Failover and Reliability
    {
        ai_model_failover_enabled = {
            type = "boolean",
            default = true,
            description = "Enable automatic failover to backup AI models"
        }
    },
    {
        ai_model_health_check_interval = {
            type = "number",
            default = 300, -- 5 minutes
            between = { 60, 3600 },
            description = "Interval for AI model health checks in seconds"
        }
    },
    {
        ai_max_retries = {
            type = "number",
            default = 2,
            between = { 0, 5 },
            description = "Maximum retry attempts for failed AI requests"
        }
    },
    
    -- AI Security and Privacy
    {
        ai_data_sanitization_enabled = {
            type = "boolean",
            default = true,
            description = "Enable sanitization of sensitive data before AI analysis"
        }
    },
    {
        ai_payload_size_limit = {
            type = "number",
            default = 2048, -- 2KB
            between = { 512, 10240 },
            description = "Maximum payload size to send to AI for analysis (bytes)"
        }
    },
    {
        ai_pii_redaction_enabled = {
            type = "boolean",
            default = true,
            description = "Enable PII redaction before sending data to AI models"
        }
    },
    
    -- AI Monitoring and Metrics
    {
        ai_metrics_collection_enabled = {
            type = "boolean",
            default = true,
            description = "Enable detailed AI performance metrics collection"
        }
    },
    {
        ai_cost_tracking_enabled = {
            type = "boolean",
            default = true,
            description = "Enable detailed AI cost tracking and reporting"
        }
    },
    {
        ai_latency_threshold_ms = {
            type = "number",
            default = 5000,
            between = { 1000, 30000 },
            description = "Latency threshold for AI performance alerts"
        }
    }
}

return ai_schema_enhancement