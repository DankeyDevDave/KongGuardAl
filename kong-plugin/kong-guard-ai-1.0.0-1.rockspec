package = "kong-guard-ai"
version = "1.0.0-1"

source = {
    url = "git://github.com/DankeyDevDave/KongGuardAI",
    tag = "v1.0.0"
}

description = {
    summary = "Kong Guard AI - Autonomous API Threat Response Agent",
    detailed = [[
        An advanced Kong plugin that provides real-time, AI-driven API threat monitoring,
        incident classification, and automated remediation. Features ML-based anomaly detection,
        automatic blocking/rate limiting, and continuous learning from operator feedback.
    ]],
    homepage = "https://github.com/DankeyDevDave/KongGuardAI",
    license = "MIT"
}

dependencies = {
    "lua >= 5.1",
    "lua-resty-http >= 0.17.1"
}

build = {
    type = "builtin",
    modules = {
        ["kong.plugins.kong-guard-ai.handler"] = "kong/plugins/kong-guard-ai/handler.lua",
        ["kong.plugins.kong-guard-ai.schema"] = "kong/plugins/kong-guard-ai/schema.lua",
        ["kong.plugins.kong-guard-ai.api"] = "kong/plugins/kong-guard-ai/api.lua"
    }
}
