-- LuaRocks package specification for Kong Guard AI Plugin
-- Compatible with Kong Gateway 3.x+
package = "kong-plugin-kong-guard-ai"
version = "0.1.0-1"

source = {
    url = "git://github.com/yourorg/kong-guard-ai",
    tag = "0.1.0"
}

description = {
    summary = "Autonomous API Threat Response Agent for Kong Gateway",
    detailed = [[
        Advanced Kong plugin providing real-time, AI-driven API threat monitoring,
        incident classification, and automated remediation. Leverages Kong's
        plugin system, Admin API, and AI Gateway for comprehensive security.
    ]],
    homepage = "https://github.com/yourorg/kong-guard-ai",
    license = "Apache 2.0"
}

dependencies = {
    "lua >= 5.1",
    "kong >= 3.0.0"
}

build = {
    type = "builtin",
    modules = {
        ["kong.plugins.kong-guard-ai.handler"] = "kong/plugins/kong-guard-ai/handler.lua",
        ["kong.plugins.kong-guard-ai.schema"] = "kong/plugins/kong-guard-ai/schema.lua",
        ["kong.plugins.kong-guard-ai.detector"] = "kong/plugins/kong-guard-ai/detector.lua",
        ["kong.plugins.kong-guard-ai.responder"] = "kong/plugins/kong-guard-ai/responder.lua",
        ["kong.plugins.kong-guard-ai.notifier"] = "kong/plugins/kong-guard-ai/notifier.lua",
        ["kong.plugins.kong-guard-ai.ai_gateway"] = "kong/plugins/kong-guard-ai/ai_gateway.lua"
    }
}