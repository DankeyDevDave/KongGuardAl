--- Data Retention Manager Module for Kong Guard AI
-- Provides automated data retention, cleanup policies, and compliance with data lifecycle management
-- Supports configurable retention periods, secure deletion, and retention reporting.

local _M = {}
local mt = { __index = _M }

-- Dependencies
local kong = kong
local ngx = ngx
local cjson = require("cjson.safe")
local string = string
local os = os
local math = math

-- Constants
local RETENTION_PERIODS = {
    THREAT_DATA = 30,      -- 30 days
    USER_DATA = 90,        -- 90 days
    LOG_DATA = 365,        -- 1 year
    AUDIT_DATA = 2555,     -- 7 years (regulatory requirement)
    SESSION_DATA = 7       -- 7 days
}

local CLEANUP_SCHEDULES = {
    HOURLY = 3600,
    DAILY = 86400,
    WEEKLY = 604800,
    MONTHLY = 2592000
}

local DATA_TYPES = {
    THREAT_DATA = "threat_data",
    USER_DATA = "user_data",
    LOG_DATA = "log_data",
    AUDIT_DATA = "audit_data",
    SESSION_DATA = "session_data",
    METRICS_DATA = "metrics_data"
}

--- Create a new retention manager instance
-- @param config Configuration table with retention settings
-- @return Retention manager instance
function _M.new(config)
    if not config then
        return nil, "Configuration required for retention manager"
    end

    local self = {
        -- Configuration
        config = config,

        -- Retention policies
        policies = {
            threat_data = {
                retention_days = config.threat_data_retention_days or RETENTION_PERIODS.THREAT_DATA,
                data_type = DATA_TYPES.THREAT_DATA,
                cleanup_priority = 1
            },
            user_data = {
                retention_days = config.user_data_retention_days or RETENTION_PERIODS.USER_DATA,
                data_type = DATA_TYPES.USER_DATA,
                cleanup_priority = 2
            },
            log_data = {
                retention_days = config.log_retention_days or RETENTION_PERIODS.LOG_DATA,
                data_type = DATA_TYPES.LOG_DATA,
                cleanup_priority = 3
            },
            audit_data = {
                retention_days = config.audit_retention_days or RETENTION_PERIODS.AUDIT_DATA,
                data_type = DATA_TYPES.AUDIT_DATA,
                cleanup_priority = 4
            },
            session_data = {
                retention_days = config.session_data_retention_days or RETENTION_PERIODS.SESSION_DATA,
                data_type = DATA_TYPES.SESSION_DATA,
                cleanup_priority = 5
            }
        },

        -- Cleanup configuration
        cleanup = {
            schedule = config.cleanup_schedule or "daily",
            last_cleanup = 0,
            next_cleanup = 0,
            batch_size = config.cleanup_batch_size or 1000,
            secure_deletion = config.secure_deletion or true,
            dry_run = config.cleanup_dry_run or false
        },

        -- Storage backends
        storage_backends = {
            database = config.storage_backend == "database",
            filesystem = config.storage_backend == "filesystem",
            s3 = config.storage_backend == "s3",
            redis = config.storage_backend == "redis"
        },

        -- Performance metrics
        metrics = {
            cleanup_operations = 0,
            records_deleted = 0,
            records_archived = 0,
            errors = 0,
            last_cleanup_duration = 0,
            total_cleanup_duration = 0
        },

        -- Data inventory
        inventory = {
            data_types = {},
            retention_status = {},
            last_inventory_update = 0
        }
    }

    return setmetatable(self, mt)
end

--- Initialize retention manager
function _M:init()
    -- Set up cleanup schedule
    local schedule_interval = CLEANUP_SCHEDULES[string.upper(self.cleanup.schedule)]
    if schedule_interval then
        local ok, err = ngx.timer.every(schedule_interval, function()
            self:_perform_scheduled_cleanup()
        end)

        if not ok then
            kong.log.err("[kong-guard-ai] Failed to initialize cleanup schedule: ", err)
        else
            self.cleanup.next_cleanup = ngx.now() + schedule_interval
        end
    end

    -- Initialize data inventory
    self:_init_data_inventory()

    kong.log.info("[kong-guard-ai] Retention manager initialized: ", {
        schedule = self.cleanup.schedule,
        secure_deletion = self.cleanup.secure_deletion,
        storage_backend = self.config.storage_backend
    })
end

--- Check if data should be retained based on policy
function _M:should_retain(data_type, data_timestamp, custom_retention_days)
    local policy = self.policies[data_type]
    if not policy then
        kong.log.warn("[kong-guard-ai] Unknown data type for retention check: ", data_type)
        return true  -- Retain by default for unknown types
    end

    local retention_days = custom_retention_days or policy.retention_days
    local retention_seconds = retention_days * 86400  -- Convert days to seconds
    local age_seconds = ngx.now() - data_timestamp

    return age_seconds <= retention_seconds
end

--- Schedule data for deletion
function _M:schedule_deletion(data_type, data_id, data_timestamp, context)
    if not self:should_retain(data_type, data_timestamp) then
        local deletion_record = {
            data_type = data_type,
            data_id = data_id,
            timestamp = data_timestamp,
            scheduled_at = ngx.now(),
            context = context,
            status = "scheduled"
        }

        -- Store deletion record (in real implementation, this would go to a database)
        self:_store_deletion_record(deletion_record)

        kong.log.debug("[kong-guard-ai] Data scheduled for deletion: ", {
            data_type = data_type,
            data_id = data_id,
            age_days = (ngx.now() - data_timestamp) / 86400
        })

        return true
    end

    return false
end

--- Perform immediate data deletion
function _M:delete_data(data_type, data_id, context)
    local success = false
    local error_msg = nil

    -- Perform deletion based on storage backend
    if self.storage_backends.database then
        success, error_msg = self:_delete_from_database(data_type, data_id)
    elseif self.storage_backends.filesystem then
        success, error_msg = self:_delete_from_filesystem(data_type, data_id)
    elseif self.storage_backends.s3 then
        success, error_msg = self:_delete_from_s3(data_type, data_id)
    elseif self.storage_backends.redis then
        success, error_msg = self:_delete_from_redis(data_type, data_id)
    else
        success, error_msg = false, "No storage backend configured"
    end

    if success then
        self.metrics.records_deleted = self.metrics.records_deleted + 1

        kong.log.info("[kong-guard-ai] Data deleted: ", {
            data_type = data_type,
            data_id = data_id,
            context = context,
            secure_deletion = self.cleanup.secure_deletion
        })

        -- Update inventory
        self:_update_inventory(data_type, -1)
    else
        self.metrics.errors = self.metrics.errors + 1

        kong.log.err("[kong-guard-ai] Data deletion failed: ", {
            data_type = data_type,
            data_id = data_id,
            error = error_msg
        })
    end

    return success, error_msg
end

--- Archive data before deletion (for compliance)
function _M:archive_data(data_type, data_id, data_content, context)
    if not self.config.enable_archiving then
        return true  -- Skip archiving if not enabled
    end

    local archive_record = {
        data_type = data_type,
        data_id = data_id,
        content = data_content,
        archived_at = ngx.now(),
        context = context,
        checksum = self:_calculate_checksum(data_content)
    }

    local success = self:_store_archive_record(archive_record)

    if success then
        self.metrics.records_archived = self.metrics.records_archived + 1

        kong.log.info("[kong-guard-ai] Data archived: ", {
            data_type = data_type,
            data_id = data_id,
            checksum = archive_record.checksum
        })
    end

    return success
end

--- Perform scheduled cleanup
function _M:_perform_scheduled_cleanup()
    local start_time = ngx.now()

    kong.log.info("[kong-guard-ai] Starting scheduled cleanup")

    -- Perform cleanup for each data type in priority order
    local cleanup_order = self:_get_cleanup_priority_order()

    for _, data_type in ipairs(cleanup_order) do
        self:_cleanup_data_type(data_type)
    end

    -- Update cleanup metrics
    local duration = ngx.now() - start_time
    self.metrics.last_cleanup_duration = duration
    self.metrics.total_cleanup_duration = self.metrics.total_cleanup_duration + duration
    self.metrics.cleanup_operations = self.metrics.cleanup_operations + 1

    self.cleanup.last_cleanup = ngx.now()

    kong.log.info("[kong-guard-ai] Scheduled cleanup completed: ", {
        duration_seconds = duration,
        operations = self.metrics.cleanup_operations,
        records_deleted = self.metrics.records_deleted
    })
end

--- Clean up specific data type
function _M:_cleanup_data_type(data_type)
    local policy = self.policies[data_type]
    if not policy then
        return
    end

    local retention_seconds = policy.retention_days * 86400
    local cutoff_timestamp = ngx.now() - retention_seconds

    kong.log.debug("[kong-guard-ai] Cleaning up ", data_type, ": ", {
        retention_days = policy.retention_days,
        cutoff_timestamp = cutoff_timestamp
    })

    -- Find and delete expired records
    local deleted_count = 0
    local batch_size = self.cleanup.batch_size

    -- In a real implementation, this would query the database for expired records
    -- For simulation, we'll use a placeholder
    local expired_records = self:_find_expired_records(data_type, cutoff_timestamp, batch_size)

    for _, record in ipairs(expired_records) do
        if not self.cleanup.dry_run then
            -- Archive if enabled
            if self.config.enable_archiving then
                self:archive_data(data_type, record.id, record.content, "scheduled_cleanup")
            end

            -- Delete the record
            local success = self:delete_data(data_type, record.id, "scheduled_cleanup")
            if success then
                deleted_count = deleted_count + 1
            end
        else
            -- Dry run - just count
            deleted_count = deleted_count + 1
            kong.log.debug("[kong-guard-ai] DRY RUN: Would delete ", data_type, " record: ", record.id)
        end
    end

    if deleted_count > 0 then
        kong.log.info("[kong-guard-ai] Cleaned up ", deleted_count, " ", data_type, " records")
    end
end

--- Get cleanup priority order
function _M:_get_cleanup_priority_order()
    local order = {}

    for data_type, policy in pairs(self.policies) do
        table.insert(order, {
            type = data_type,
            priority = policy.cleanup_priority
        })
    end

    -- Sort by priority (lower number = higher priority)
    table.sort(order, function(a, b) return a.priority < b.priority end)

    local result = {}
    for _, item in ipairs(order) do
        table.insert(result, item.type)
    end

    return result
end

--- Find expired records (placeholder for database query)
function _M:_find_expired_records(data_type, cutoff_timestamp, limit)
    -- In a real implementation, this would query the database
    -- For simulation, return empty array
    return {}
end

--- Delete from database (placeholder)
function _M:_delete_from_database(data_type, data_id)
    -- Placeholder for database deletion
    kong.log.debug("[kong-guard-ai] Database deletion not implemented for: ", data_type, ":", data_id)
    return true
end

--- Delete from filesystem (placeholder)
function _M:_delete_from_filesystem(data_type, data_id)
    -- Placeholder for filesystem deletion
    kong.log.debug("[kong-guard-ai] Filesystem deletion not implemented for: ", data_type, ":", data_id)
    return true
end

--- Delete from S3 (placeholder)
function _M:_delete_from_s3(data_type, data_id)
    -- Placeholder for S3 deletion
    kong.log.debug("[kong-guard-ai] S3 deletion not implemented for: ", data_type, ":", data_id)
    return true
end

--- Delete from Redis (placeholder)
function _M:_delete_from_redis(data_type, data_id)
    -- Placeholder for Redis deletion
    kong.log.debug("[kong-guard-ai] Redis deletion not implemented for: ", data_type, ":", data_id)
    return true
end

--- Store deletion record (placeholder)
function _M:_store_deletion_record(record)
    -- In a real implementation, this would store in a database
    kong.log.debug("[kong-guard-ai] Deletion record stored: ", record.data_id)
end

--- Store archive record (placeholder)
function _M:_store_archive_record(record)
    -- In a real implementation, this would store in archive storage
    kong.log.debug("[kong-guard-ai] Archive record stored: ", record.data_id)
    return true
end

--- Calculate checksum for data integrity
function _M:_calculate_checksum(data)
    -- Simple checksum calculation
    -- In production, use proper cryptographic hash
    local checksum = 0
    local data_str = type(data) == "table" and cjson.encode(data) or tostring(data)

    for i = 1, #data_str do
        checksum = (checksum * 31 + data_str:byte(i)) % 1000000
    end

    return string.format("%06d", checksum)
end

--- Initialize data inventory
function _M:_init_data_inventory()
    -- Initialize inventory tracking
    for data_type, _ in pairs(self.policies) do
        self.inventory.data_types[data_type] = {
            total_records = 0,
            active_records = 0,
            archived_records = 0,
            last_updated = ngx.now()
        }
    end

    self.inventory.last_inventory_update = ngx.now()
end

--- Update inventory counts
function _M:_update_inventory(data_type, delta)
    if self.inventory.data_types[data_type] then
        self.inventory.data_types[data_type].active_records =
            self.inventory.data_types[data_type].active_records + delta
        self.inventory.data_types[data_type].last_updated = ngx.now()
    end
end

--- Get retention policy for data type
function _M:get_retention_policy(data_type)
    return self.policies[data_type]
end

--- Update retention policy
function _M:update_retention_policy(data_type, new_retention_days)
    if self.policies[data_type] then
        local old_retention = self.policies[data_type].retention_days
        self.policies[data_type].retention_days = new_retention_days

        kong.log.info("[kong-guard-ai] Retention policy updated: ", {
            data_type = data_type,
            old_retention_days = old_retention,
            new_retention_days = new_retention_days
        })

        return true
    end

    return false, "Unknown data type: " .. data_type
end

--- Get retention compliance status
function _M:get_compliance_status()
    local status = {
        overall_compliant = true,
        data_types = {},
        violations = {},
        last_check = ngx.now()
    }

    for data_type, policy in pairs(self.policies) do
        local type_status = {
            retention_days = policy.retention_days,
            compliant = true,
            violations = 0,
            oldest_record_age = 0
        }

        -- In a real implementation, check actual data ages
        -- For simulation, assume compliance
        type_status.compliant = true

        status.data_types[data_type] = type_status

        if not type_status.compliant then
            status.overall_compliant = false
            table.insert(status.violations, {
                data_type = data_type,
                violation_type = "retention_period_exceeded",
                severity = "high"
            })
        end
    end

    return status
end

--- Generate retention report
function _M:generate_retention_report()
    local report = {
        generated_at = ngx.now(),
        report_period = {
            start = ngx.now() - (30 * 86400),  -- Last 30 days
            end = ngx.now()
        },
        summary = {
            total_cleanup_operations = self.metrics.cleanup_operations,
            total_records_deleted = self.metrics.records_deleted,
            total_records_archived = self.metrics.records_archived,
            total_errors = self.metrics.errors
        },
        data_types = {},
        compliance_status = self:get_compliance_status()
    }

    -- Add data type details
    for data_type, inventory in pairs(self.inventory.data_types) do
        report.data_types[data_type] = {
            retention_policy_days = self.policies[data_type].retention_days,
            total_records = inventory.total_records,
            active_records = inventory.active_records,
            archived_records = inventory.archived_records,
            last_updated = inventory.last_updated
        }
    end

    return report
end

--- Get retention statistics
function _M:get_stats()
    return {
        cleanup = {
            operations = self.metrics.cleanup_operations,
            last_duration = self.metrics.last_cleanup_duration,
            total_duration = self.metrics.total_cleanup_duration,
            schedule = self.cleanup.schedule,
            next_cleanup = self.cleanup.next_cleanup,
            last_cleanup = self.cleanup.last_cleanup
        },
        records = {
            deleted = self.metrics.records_deleted,
            archived = self.metrics.records_archived,
            errors = self.metrics.errors
        },
        policies = self.policies,
        inventory = self.inventory,
        configuration = {
            secure_deletion = self.cleanup.secure_deletion,
            dry_run = self.cleanup.dry_run,
            batch_size = self.cleanup.batch_size,
            storage_backend = self.config.storage_backend
        }
    }
end

--- Force immediate cleanup
function _M:force_cleanup(data_types)
    local target_types = data_types or self:_get_cleanup_priority_order()

    kong.log.info("[kong-guard-ai] Forcing immediate cleanup for: ", table.concat(target_types, ", "))

    for _, data_type in ipairs(target_types) do
        self:_cleanup_data_type(data_type)
    end

    return true
end

--- Validate retention configuration
function _M:validate_configuration()
    local issues = {}

    -- Check retention periods are reasonable
    for data_type, policy in pairs(self.policies) do
        if policy.retention_days < 1 then
            table.insert(issues, "Invalid retention period for " .. data_type .. ": must be >= 1 day")
        elseif policy.retention_days > 3650 then  -- 10 years
            table.insert(issues, "Potentially excessive retention period for " .. data_type .. ": " .. policy.retention_days .. " days")
        end
    end

    -- Check cleanup schedule is valid
    if not CLEANUP_SCHEDULES[string.upper(self.cleanup.schedule)] then
        table.insert(issues, "Invalid cleanup schedule: " .. self.cleanup.schedule)
    end

    -- Check batch size is reasonable
    if self.cleanup.batch_size < 1 or self.cleanup.batch_size > 10000 then
        table.insert(issues, "Invalid cleanup batch size: " .. self.cleanup.batch_size .. " (must be 1-10000)")
    end

    return #issues == 0, issues
end

--- Cleanup resources
function _M:cleanup()
    -- Cancel any pending timers
    -- (In a real implementation, store timer references to cancel them)

    kong.log.info("[kong-guard-ai] Retention manager cleanup completed")
end

return _M