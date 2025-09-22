-- Configuration Migration Tool
-- Handles migration between different configuration versions and formats
-- Provides backward compatibility and smooth upgrades

local schema_orchestrator = require "kong.plugins.kong-guard-ai.modules.schema.schema_orchestrator"
local performance_utils = require "kong.plugins.kong-guard-ai.modules.utils.performance_utils"

local MigrationTool = {}
MigrationTool.__index = MigrationTool

-- Configuration version history
local CONFIG_VERSIONS = {
    "1.0.0", -- Initial version
    "1.1.0", -- Added AI integration
    "1.2.0", -- Added threat detection modules
    "1.3.0", -- Added performance optimization
    "2.0.0"  -- Current modular version
}

--- Initialize migration tool
-- @param config table current configuration
function MigrationTool.new(config)
    local self = setmetatable({}, MigrationTool)
    self.config = config or {}
    self.migration_log = {}

    return self
end

--- Detect configuration version
-- @param config table configuration to analyze
-- @return string detected version
function MigrationTool:detect_version(config)
    config = config or self.config

    -- Version 2.0.0 (current modular)
    if config.schema_version == "2.0.0" or
       (config.modules and config.modules.ai and config.modules.threat) then
        return "2.0.0"
    end

    -- Version 1.3.0 (performance optimization)
    if config.performance_optimization or
       config.cache_strategies or
       config.memory_management then
        return "1.3.0"
    end

    -- Version 1.2.0 (threat detection modules)
    if config.threat_detection_modules or
       config.sql_injection_detector or
       config.xss_detector then
        return "1.2.0"
    end

    -- Version 1.1.0 (AI integration)
    if config.ai_service or
       config.ai_models or
       config.threat_analysis then
        return "1.1.0"
    end

    -- Version 1.0.0 (initial)
    return "1.0.0"
end

--- Check if migration is needed
-- @param target_version string target version (default: latest)
-- @return boolean needs migration
-- @return string current version
-- @return string target version
function MigrationTool:needs_migration(target_version)
    target_version = target_version or CONFIG_VERSIONS[#CONFIG_VERSIONS]
    local current_version = self:detect_version()

    return current_version ~= target_version, current_version, target_version
end

--- Migrate configuration to target version
-- @param target_version string target version (default: latest)
-- @return table migrated configuration
-- @return table migration log
function MigrationTool:migrate(target_version)
    target_version = target_version or CONFIG_VERSIONS[#CONFIG_VERSIONS]
    local current_version = self:detect_version()

    self.migration_log = {}
    local config = self:_deep_copy(self.config)

    self:_log_migration("start", "Starting migration from " .. current_version .. " to " .. target_version)

    -- Apply migrations in sequence
    for i, version in ipairs(CONFIG_VERSIONS) do
        if self:_version_compare(current_version, version) < 0 and
           self:_version_compare(version, target_version) <= 0 then
            config = self:_migrate_to_version(config, version)
        end
    end

    -- Set final version
    config.schema_version = target_version

    self:_log_migration("complete", "Migration completed successfully")

    return config, self.migration_log
end

--- Migrate to specific version
-- @param config table configuration to migrate
-- @param version string target version
-- @return table migrated configuration
function MigrationTool:_migrate_to_version(config, version)
    local migration_method = "_migrate_to_" .. version:gsub("%.", "_")

    if self[migration_method] then
        self:_log_migration("version", "Migrating to version " .. version)
        config = self[migration_method](self, config)
        self:_log_migration("version_complete", "Migration to " .. version .. " completed")
    end

    return config
end

--- Migrate to version 1.1.0 (AI integration)
function MigrationTool:_migrate_to_1_1_0(config)
    -- Add AI service configuration
    if not config.ai_service then
        config.ai_service = {
            enabled = true,
            endpoint = "http://localhost:8080",
            timeout = 5000,
            models = {
                threat_detection = "threat-model-v1",
                anomaly_detection = "anomaly-model-v1"
            }
        }
        self:_log_migration("add", "Added ai_service configuration")
    end

    -- Migrate basic threat detection to AI-enhanced
    if config.basic_threat_detection then
        config.ai_threat_analysis = {
            enabled = config.basic_threat_detection.enabled,
            confidence_threshold = 0.7,
            real_time_analysis = true
        }
        config.basic_threat_detection = nil
        self:_log_migration("migrate", "Migrated basic_threat_detection to ai_threat_analysis")
    end

    return config
end

--- Migrate to version 1.2.0 (threat detection modules)
function MigrationTool:_migrate_to_1_2_0(config)
    -- Convert monolithic threat detection to modular
    if config.threat_detection and not config.threat_detection_modules then
        config.threat_detection_modules = {
            sql_injection = {
                enabled = config.threat_detection.sql_injection_enabled or true,
                patterns = config.threat_detection.sql_patterns or {},
                sensitivity = config.threat_detection.sql_sensitivity or "medium"
            },
            xss = {
                enabled = config.threat_detection.xss_enabled or true,
                patterns = config.threat_detection.xss_patterns or {},
                sanitization = config.threat_detection.xss_sanitization or true
            },
            path_traversal = {
                enabled = config.threat_detection.path_traversal_enabled or true,
                patterns = config.threat_detection.path_patterns or {},
                depth_limit = config.threat_detection.path_depth_limit or 5
            }
        }

        -- Remove old configuration
        config.threat_detection = nil
        self:_log_migration("modularize", "Converted monolithic threat detection to modular structure")
    end

    return config
end

--- Migrate to version 1.3.0 (performance optimization)
function MigrationTool:_migrate_to_1_3_0(config)
    -- Add performance optimization settings
    if not config.performance_optimization then
        config.performance_optimization = {
            cache_strategies = {
                threat_cache_ttl = 3600,
                model_cache_ttl = 7200,
                result_cache_ttl = 1800
            },
            memory_management = {
                max_memory_usage = "512MB",
                gc_threshold = 0.8,
                cleanup_interval = 300
            },
            connection_pooling = {
                enabled = true,
                max_connections = 100,
                timeout = 30
            }
        }
        self:_log_migration("add", "Added performance optimization configuration")
    end

    -- Migrate old cache settings
    if config.cache_ttl then
        config.performance_optimization.cache_strategies.threat_cache_ttl = config.cache_ttl
        config.cache_ttl = nil
        self:_log_migration("migrate", "Migrated cache_ttl to performance_optimization.cache_strategies")
    end

    return config
end

--- Migrate to version 2.0.0 (modular architecture)
function MigrationTool:_migrate_to_2_0_0(config)
    -- Restructure to modular architecture
    local modular_config = {
        schema_version = "2.0.0",
        modules = {
            ai = {},
            threat = {},
            performance = {},
            monitoring = {},
            compliance = {}
        }
    }

    -- Migrate AI configuration
    if config.ai_service or config.ai_threat_analysis then
        modular_config.modules.ai = {
            enabled = true,
            service = config.ai_service or {},
            threat_analysis = config.ai_threat_analysis or {},
            models = config.ai_models or {}
        }
        self:_log_migration("modularize", "Migrated AI configuration to modules.ai")
    end

    -- Migrate threat detection
    if config.threat_detection_modules then
        modular_config.modules.threat = config.threat_detection_modules
        self:_log_migration("modularize", "Migrated threat detection to modules.threat")
    end

    -- Migrate performance settings
    if config.performance_optimization then
        modular_config.modules.performance = config.performance_optimization
        self:_log_migration("modularize", "Migrated performance settings to modules.performance")
    end

    -- Migrate monitoring settings
    modular_config.modules.monitoring = {
        enabled = config.monitoring_enabled ~= false,
        logging_level = config.logging_level or "info",
        metrics = config.metrics or {},
        audit = config.audit_logging or false
    }
    self:_log_migration("modularize", "Created modular monitoring configuration")

    -- Migrate any remaining settings
    for key, value in pairs(config) do
        if not modular_config[key] and
           key ~= "ai_service" and
           key ~= "ai_threat_analysis" and
           key ~= "threat_detection_modules" and
           key ~= "performance_optimization" then
            modular_config[key] = value
        end
    end

    return modular_config
end

--- Create backup of current configuration
-- @param backup_name string optional backup name
-- @return string backup identifier
function MigrationTool:create_backup(backup_name)
    backup_name = backup_name or "auto_backup_" .. os.time()

    local backup = {
        name = backup_name,
        timestamp = os.time(),
        version = self:detect_version(),
        config = self:_deep_copy(self.config)
    }

    -- In a real implementation, this would save to persistent storage
    self.backup = backup

    self:_log_migration("backup", "Created backup: " .. backup_name)

    return backup_name
end

--- Restore from backup
-- @param backup_name string backup identifier
-- @return boolean success
function MigrationTool:restore_backup(backup_name)
    -- In a real implementation, this would load from persistent storage
    if self.backup and self.backup.name == backup_name then
        self.config = self:_deep_copy(self.backup.config)
        self:_log_migration("restore", "Restored from backup: " .. backup_name)
        return true
    end

    return false
end

--- Validate migrated configuration
-- @param config table configuration to validate
-- @return boolean valid
-- @return table validation errors
function MigrationTool:validate_migrated_config(config)
    local errors = {}

    -- Use schema orchestrator for validation
    local valid, schema_errors = schema_orchestrator.validate_configuration(config)

    if not valid then
        for _, error in ipairs(schema_errors) do
            table.insert(errors, "Schema validation: " .. error)
        end
    end

    -- Additional migration-specific validations
    if config.schema_version == "2.0.0" then
        if not config.modules then
            table.insert(errors, "Modular config missing modules section")
        end
    end

    return #errors == 0, errors
end

--- Log migration step
-- @param step_type string type of migration step
-- @param message string log message
function MigrationTool:_log_migration(step_type, message)
    table.insert(self.migration_log, {
        timestamp = os.time(),
        step_type = step_type,
        message = message
    })
end

--- Compare two version strings
-- @param v1 string first version
-- @param v2 string second version
-- @return number -1 if v1 < v2, 0 if equal, 1 if v1 > v2
function MigrationTool:_version_compare(v1, v2)
    local function split_version(version)
        local parts = {}
        for part in version:gmatch("(%d+)") do
            table.insert(parts, tonumber(part))
        end
        return parts
    end

    local parts1 = split_version(v1)
    local parts2 = split_version(v2)

    for i = 1, math.max(#parts1, #parts2) do
        local p1 = parts1[i] or 0
        local p2 = parts2[i] or 0

        if p1 < p2 then return -1 end
        if p1 > p2 then return 1 end
    end

    return 0
end

--- Deep copy a table
-- @param orig table original table
-- @return table copied table
function MigrationTool:_deep_copy(orig)
    local copy
    if type(orig) == 'table' then
        copy = {}
        for key, value in next, orig, nil do
            copy[self:_deep_copy(key)] = self:_deep_copy(value)
        end
        setmetatable(copy, self:_deep_copy(getmetatable(orig)))
    else
        copy = orig
    end
    return copy
end

return MigrationTool
