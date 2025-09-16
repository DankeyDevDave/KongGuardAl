-- Luacheck configuration for Kong Guard AI plugin
std = "ngx_lua+busted"
cache = true
codes = true

-- Global ignore patterns
exclude_files = {
    "spec/**/*.lua", -- Test files can be more lenient
}

-- Kong globals
globals = {
    "kong",
    "ngx",
    "cjson",
    "table",
    "string",
    "math",
    "os",
    "io",
    "tostring",
    "tonumber",
    "pairs",
    "ipairs",
    "next",
    "type",
    "getmetatable",
    "setmetatable",
    "rawget",
    "rawset",
    "require",
    "pcall",
    "xpcall",
    "error",
    "assert",
    "select",
    "unpack",
}

-- Read-only globals from Kong
read_globals = {
    "kong",
    "ngx",
    "resty",
    "cjson",
    -- Standard Lua globals
    "_G", "_VERSION", "arg", "debug", "getfenv", "getmetatable", "ipairs", "load", "loadfile",
    "loadstring", "module", "next", "pairs", "pcall", "print", "rawequal", "rawget", "rawlen",
    "rawset", "require", "select", "setfenv", "setmetatable", "tonumber", "tostring", "type",
    "unpack", "xpcall",
    -- Lua standard library
    "bit32", "coroutine", "io", "math", "os", "package", "string", "table", "utf8",
    -- Common OpenResty globals
    "ndk",
}

-- Ignore specific warnings
ignore = {
    "212", -- Unused argument
    "213", -- Unused loop variable
    "432", -- Shadowing upvalue
}

-- Per-file overrides
files = {
    ["kong-plugin/kong/plugins/kong-guard-ai/handler.lua"] = {
        ignore = {"631"} -- line too long - handler has long log messages
    },
    ["kong-plugin/kong/plugins/kong-guard-ai/schema.lua"] = {
        ignore = {"631"} -- line too long - schema definitions can be long
    },
    ["spec/*.lua"] = {
        std = "ngx_lua+busted",
        globals = {"describe", "it", "before_each", "after_each", "setup", "teardown", "pending", "finally", "spy", "stub", "mock", "assert"},
    }
}
