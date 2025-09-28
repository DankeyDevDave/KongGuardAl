-- Performance optimization utilities module
-- Extracted from handler.lua to improve modularity and testability

local _M = {}

-- Module-local cache variables
local _string_cache = {}
local _table_pool = {}

-- Log level constants
local LOG_LEVELS = {debug = 0, info = 1, warn = 2, error = 3, critical = 4}

--- Get cached string to reduce memory allocation
-- @param str string to cache
-- @return cached string instance
function _M.get_cached_string(str)
    if not _string_cache[str] then
        _string_cache[str] = str
    end
    return _string_cache[str]
end

--- Get a pooled table to reduce allocation overhead
-- @return empty table from pool or new table
function _M.get_pooled_table()
    local tbl = table.remove(_table_pool)
    if not tbl then
        tbl = {}
    end
    return tbl
end

--- Return table to pool for reuse
-- @param tbl table to return to pool
function _M.return_pooled_table(tbl)
    if tbl then
        for k in pairs(tbl) do
            tbl[k] = nil
        end
        table.insert(_table_pool, tbl)
    end
end

--- Check if message should be logged based on log level
-- @param config_level configured log level
-- @param msg_level message log level
-- @return boolean indicating if message should be logged
function _M.should_log(config_level, msg_level)
    return LOG_LEVELS[msg_level] >= LOG_LEVELS[config_level or "info"]
end

--- Log message with level checking
-- @param config plugin configuration
-- @param level log level
-- @param message log message
-- @param data optional data to include
function _M.log_message(config, level, message, data)
    if not _M.should_log(config.log_level, level) then
        return
    end

    local log_func = kong.log[level] or kong.log.info
    log_func(message, data)
end

--- Get performance statistics
-- @return table with cache statistics
function _M.get_performance_stats()
    return {
        string_cache_size = #_string_cache,
        table_pool_size = #_table_pool,
        cache_hit_ratio = nil -- TODO: implement hit ratio tracking
    }
end

--- Clear caches for testing or memory management
function _M.clear_caches()
    _string_cache = {}
    _table_pool = {}
end

return _M
