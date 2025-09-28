-- Module loading utilities with lazy initialization and caching
-- Extracted from handler.lua to improve modularity and testability

local _M = {}

-- Module-local cache for loaded modules and instances
local _modules = {}
local _instances = {}

--- Lazy module loader with caching
-- @param name module name to load
-- @return loaded module
function _M.load_module(name)
    if not _modules[name] then
        _modules[name] = require("kong.plugins.kong-guard-ai." .. name)
    end
    return _modules[name]
end

--- Lazy instance loader with caching
-- @param name module name for instance
-- @param config configuration for instance creation
-- @return module instance
function _M.get_instance(name, config)
    if not _instances[name] then
        local module = _M.load_module(name)
        if module and module.new then
            _instances[name] = module.new(config)
        else
            _instances[name] = module
        end
    end
    return _instances[name]
end

--- Clear module and instance caches
-- Useful for testing or memory management
function _M.clear_caches()
    _modules = {}
    _instances = {}
end

--- Get module cache statistics
-- @return table with cache information
function _M.get_cache_stats()
    local module_count = 0
    local instance_count = 0

    for _ in pairs(_modules) do
        module_count = module_count + 1
    end

    for _ in pairs(_instances) do
        instance_count = instance_count + 1
    end

    return {
        loaded_modules = module_count,
        cached_instances = instance_count
    }
end

--- Check if module is loaded
-- @param name module name to check
-- @return boolean indicating if module is loaded
function _M.is_module_loaded(name)
    return _modules[name] ~= nil
end

--- Check if instance exists
-- @param name instance name to check
-- @return boolean indicating if instance exists
function _M.has_instance(name)
    return _instances[name] ~= nil
end

return _M
