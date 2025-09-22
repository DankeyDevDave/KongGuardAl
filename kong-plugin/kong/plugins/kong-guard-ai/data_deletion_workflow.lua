--- Data Deletion Workflow Manager for Kong Guard AI
-- Handles automated data deletion workflows for GDPR and CCPA compliance

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local privacy_manager = require("kong.plugins.kong-guard-ai.privacy_manager")
local audit_logger = require("kong.plugins.kong-guard-ai.audit_logger")

-- Workflow states
local WORKFLOW_STATES = {
    PENDING = "pending",
    IN_PROGRESS = "in_progress",
    COMPLETED = "completed",
    FAILED = "failed",
    CANCELLED = "cancelled"
}

-- Deletion stages
local DELETION_STAGES = {
    IDENTIFY_DATA = "identify_data",
    BACKUP_DATA = "backup_data",
    NOTIFY_STAKEHOLDERS = "notify_stakeholders",
    DELETE_FROM_SOURCES = "delete_from_sources",
    ANONYMIZE_REFERENCES = "anonymize_references",
    VERIFY_DELETION = "verify_deletion",
    LOG_COMPLETION = "log_completion"
}

--- Create a new data deletion workflow manager
function _M.new(config)
    local self = {
        config = config,
        workflows = {}, -- In-memory storage, in production use database
        workflow_counter = 0
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the workflow manager
function _M:init()
    -- Set up periodic cleanup of completed workflows
    local ok, err = ngx.timer.every(3600, function() -- Every hour
        self:_cleanup_old_workflows()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize workflow cleanup: ", err)
    end

    kong.log.info("[kong-guard-ai] Data deletion workflow manager initialized")
end

--- Start a data deletion workflow
function _M:start_deletion_workflow(user_id, request_type, context)
    self.workflow_counter = self.workflow_counter + 1
    local workflow_id = "del_" .. self.workflow_counter .. "_" .. ngx.time()

    local workflow = {
        workflow_id = workflow_id,
        user_id = user_id,
        request_type = request_type, -- "gdpr" or "ccpa"
        status = WORKFLOW_STATES.PENDING,
        created_at = ngx.time(),
        updated_at = ngx.time(),
        context = context or {},
        stages = {},
        current_stage = nil,
        progress = 0,
        errors = {},
        data_sources = {},
        backup_locations = {},
        notifications_sent = {}
    }

    -- Initialize stages
    for _, stage in ipairs(DELETION_STAGES) do
        workflow.stages[stage] = {
            status = WORKFLOW_STATES.PENDING,
            started_at = nil,
            completed_at = nil,
            attempts = 0,
            max_attempts = 3,
            error = nil
        }
    end

    self.workflows[workflow_id] = workflow

    -- Start the workflow asynchronously
    ngx.timer.at(0, function()
        self:_execute_workflow(workflow_id)
    end)

    kong.log.info("[kong-guard-ai] Started data deletion workflow: ", workflow_id, " for user: ", user_id)

    return workflow_id, workflow
end

--- Execute workflow stages
function _M:_execute_workflow(workflow_id)
    local workflow = self.workflows[workflow_id]
    if not workflow then
        kong.log.err("[kong-guard-ai] Workflow not found: ", workflow_id)
        return
    end

    workflow.status = WORKFLOW_STATES.IN_PROGRESS
    workflow.updated_at = ngx.time()

    kong.log.info("[kong-guard-ai] Executing workflow: ", workflow_id)

    -- Execute stages in order
    for _, stage_name in ipairs(DELETION_STAGES) do
        local success = self:_execute_stage(workflow, stage_name)
        if not success then
            workflow.status = WORKFLOW_STATES.FAILED
            workflow.updated_at = ngx.time()
            self:_handle_workflow_failure(workflow)
            return
        end

        workflow.progress = (#workflow.stages / #DELETION_STAGES) * 100
    end

    -- Workflow completed successfully
    workflow.status = WORKFLOW_STATES.COMPLETED
    workflow.updated_at = ngx.time()
    workflow.completed_at = ngx.time()

    self:_handle_workflow_completion(workflow)
    kong.log.info("[kong-guard-ai] Workflow completed: ", workflow_id)
end

--- Execute a specific workflow stage
function _M:_execute_stage(workflow, stage_name)
    local stage = workflow.stages[stage_name]
    if not stage then
        return false
    end

    stage.status = WORKFLOW_STATES.IN_PROGRESS
    stage.started_at = ngx.time()
    stage.attempts = stage.attempts + 1

    kong.log.debug("[kong-guard-ai] Executing stage: ", stage_name, " for workflow: ", workflow.workflow_id)

    local success, result = self:_run_stage_handler(workflow, stage_name)

    if success then
        stage.status = WORKFLOW_STATES.COMPLETED
        stage.completed_at = ngx.time()
        workflow.current_stage = stage_name
        return true
    else
        stage.error = result
        table.insert(workflow.errors, {
            stage = stage_name,
            error = result,
            timestamp = ngx.time(),
            attempt = stage.attempts
        })

        -- Check if we should retry
        if stage.attempts < stage.max_attempts then
            kong.log.warn("[kong-guard-ai] Stage failed, will retry: ", stage_name, " error: ", result)
            -- Schedule retry after delay
            ngx.timer.at(300, function() -- 5 minutes delay
                self:_execute_stage(workflow, stage_name)
            end)
            return true -- Don't fail the workflow yet
        else
            stage.status = WORKFLOW_STATES.FAILED
            return false
        end
    end
end

--- Run stage-specific handler
function _M:_run_stage_handler(workflow, stage_name)
    local handlers = {
        [DELETION_STAGES.IDENTIFY_DATA] = self._identify_user_data,
        [DELETION_STAGES.BACKUP_DATA] = self._backup_user_data,
        [DELETION_STAGES.NOTIFY_STAKEHOLDERS] = self._notify_stakeholders,
        [DELETION_STAGES.DELETE_FROM_SOURCES] = self._delete_from_sources,
        [DELETION_STAGES.ANONYMIZE_REFERENCES] = self._anonymize_references,
        [DELETION_STAGES.VERIFY_DELETION] = self._verify_deletion,
        [DELETION_STAGES.LOG_COMPLETION] = self._log_completion
    }

    local handler = handlers[stage_name]
    if not handler then
        return false, "No handler for stage: " .. stage_name
    end

    return handler(self, workflow)
end

--- Stage 1: Identify user data across all sources
function _M:_identify_user_data(workflow)
    kong.log.info("[kong-guard-ai] Identifying data for user: ", workflow.user_id)

    -- Get privacy manager to identify data sources
    local pm = privacy_manager.new(self.config.privacy_config)

    if workflow.request_type == "gdpr" then
        workflow.data_sources = pm:_find_user_data_sources(workflow.user_id)
    elseif workflow.request_type == "ccpa" then
        workflow.data_sources = pm:_find_ccpa_personal_info(workflow.user_id)
    else
        workflow.data_sources = {}
    end

    -- Add audit logs as a data source
    table.insert(workflow.data_sources, "audit_logs")
    table.insert(workflow.data_sources, "threat_detection_logs")

    kong.log.info("[kong-guard-ai] Identified ", #workflow.data_sources, " data sources for user: ", workflow.user_id)

    return true
end

--- Stage 2: Backup user data before deletion
function _M:_backup_user_data(workflow)
    kong.log.info("[kong-guard-ai] Backing up data for user: ", workflow.user_id)

    -- Create backup for each data source
    for _, source in ipairs(workflow.data_sources) do
        local backup_location = self:_create_backup(source, workflow.user_id, workflow.workflow_id)
        if backup_location then
            table.insert(workflow.backup_locations, {
                source = source,
                location = backup_location,
                created_at = ngx.time()
            })
        end
    end

    kong.log.info("[kong-guard-ai] Created ", #workflow.backup_locations, " backups for user: ", workflow.user_id)

    return true
end

--- Stage 3: Notify stakeholders about the deletion
function _M:_notify_stakeholders(workflow)
    kong.log.info("[kong-guard-ai] Notifying stakeholders for user: ", workflow.user_id)

    -- Notify relevant stakeholders (compliance team, legal, etc.)
    local stakeholders = self:_get_stakeholders_for_deletion(workflow)

    for _, stakeholder in ipairs(stakeholders) do
        local notification_sent = self:_send_deletion_notification(stakeholder, workflow)
        if notification_sent then
            table.insert(workflow.notifications_sent, {
                stakeholder = stakeholder,
                sent_at = ngx.time()
            })
        end
    end

    kong.log.info("[kong-guard-ai] Notified ", #workflow.notifications_sent, " stakeholders")

    return true
end

--- Stage 4: Delete data from all identified sources
function _M:_delete_from_sources(workflow)
    kong.log.info("[kong-guard-ai] Deleting data from sources for user: ", workflow.user_id)

    local pm = privacy_manager.new(self.config.privacy_config)
    local deletion_results = {}

    for _, source in ipairs(workflow.data_sources) do
        local success, result
        if workflow.request_type == "gdpr" then
            success, result = pm:_delete_data_from_source(source, workflow.user_id, workflow.context)
        elseif workflow.request_type == "ccpa" then
            success, result = pm:_delete_ccpa_data_from_source(source, workflow.user_id, workflow.context)
        end

        table.insert(deletion_results, {
            source = source,
            success = success,
            result = result,
            deleted_at = ngx.time()
        })
    end

    workflow.deletion_results = deletion_results

    -- Check if all deletions were successful
    local all_successful = true
    for _, result in ipairs(deletion_results) do
        if not result.success then
            all_successful = false
            break
        end
    end

    if not all_successful then
        return false, "Some data deletions failed"
    end

    kong.log.info("[kong-guard-ai] Completed data deletion for user: ", workflow.user_id)

    return true
end

--- Stage 5: Anonymize any remaining references
function _M:_anonymize_references(workflow)
    kong.log.info("[kong-guard-ai] Anonymizing references for user: ", workflow.user_id)

    local pm = privacy_manager.new(self.config.privacy_config)
    local anonymized = pm:_anonymize_user_references(workflow.user_id, workflow.context)

    workflow.references_anonymized = anonymized

    kong.log.info("[kong-guard-ai] Anonymized references for user: ", workflow.user_id)

    return true
end

--- Stage 6: Verify that deletion was successful
function _M:_verify_deletion(workflow)
    kong.log.info("[kong-guard-ai] Verifying deletion for user: ", workflow.user_id)

    local verification_results = {}

    for _, source in ipairs(workflow.data_sources) do
        local verified = self:_verify_source_deletion(source, workflow.user_id)
        table.insert(verification_results, {
            source = source,
            verified = verified,
            verified_at = ngx.time()
        })
    end

    workflow.verification_results = verification_results

    -- Check if all verifications passed
    local all_verified = true
    for _, result in ipairs(verification_results) do
        if not result.verified then
            all_verified = false
            break
        end
    end

    if not all_verified then
        return false, "Deletion verification failed for some sources"
    end

    kong.log.info("[kong-guard-ai] Deletion verified for user: ", workflow.user_id)

    return true
end

--- Stage 7: Log completion and final audit
function _M:_log_completion(workflow)
    kong.log.info("[kong-guard-ai] Logging completion for workflow: ", workflow.workflow_id)

    -- Log final audit entry
    local audit_result = audit_logger.log_event({
        event_type = "data_deletion_completed",
        workflow_id = workflow.workflow_id,
        user_id = workflow.user_id,
        request_type = workflow.request_type,
        data_sources_deleted = #workflow.data_sources,
        backups_created = #workflow.backup_locations,
        completion_time = ngx.time() - workflow.created_at
    }, self.config.audit_config)

    workflow.final_audit_logged = audit_result.success

    return true
end

--- Handle workflow failure
function _M:_handle_workflow_failure(workflow)
    kong.log.err("[kong-guard-ai] Workflow failed: ", workflow.workflow_id, " errors: ", cjson.encode(workflow.errors))

    -- Log failure
    audit_logger.log_event({
        event_type = "data_deletion_failed",
        workflow_id = workflow.workflow_id,
        user_id = workflow.user_id,
        request_type = workflow.request_type,
        errors = workflow.errors,
        failed_at = ngx.time()
    }, self.config.audit_config)

    -- Send failure notifications
    self:_send_failure_notifications(workflow)
end

--- Handle workflow completion
function _M:_handle_workflow_completion(workflow)
    kong.log.info("[kong-guard-ai] Workflow completed successfully: ", workflow.workflow_id)

    -- Send completion confirmation
    self:_send_completion_confirmation(workflow)
end

--- Helper functions

function _M:_create_backup(source, user_id, workflow_id)
    -- Mock backup creation - in production would create actual backups
    local backup_id = "backup_" .. source .. "_" .. user_id .. "_" .. ngx.time()
    kong.log.debug("[kong-guard-ai] Created backup: ", backup_id)
    return backup_id
end

function _M:_get_stakeholders_for_deletion(workflow)
    -- Return list of stakeholders to notify
    return {"compliance@company.com", "legal@company.com", "privacy@company.com"}
end

function _M:_send_deletion_notification(stakeholder, workflow)
    -- Mock notification sending
    kong.log.debug("[kong-guard-ai] Sent deletion notification to: ", stakeholder)
    return true
end

function _M:_verify_source_deletion(source, user_id)
    -- Mock verification - in production would check if data is actually deleted
    kong.log.debug("[kong-guard-ai] Verified deletion from source: ", source)
    return true
end

function _M:_send_failure_notifications(workflow)
    -- Mock failure notification
    kong.log.warn("[kong-guard-ai] Sent failure notifications for workflow: ", workflow.workflow_id)
end

function _M:_send_completion_confirmation(workflow)
    -- Mock completion confirmation
    kong.log.info("[kong-guard-ai] Sent completion confirmation for workflow: ", workflow.workflow_id)
end

--- Get workflow status
function _M:get_workflow_status(workflow_id)
    local workflow = self.workflows[workflow_id]
    if not workflow then
        return nil, "Workflow not found"
    end

    return {
        workflow_id = workflow.workflow_id,
        user_id = workflow.user_id,
        status = workflow.status,
        progress = workflow.progress,
        current_stage = workflow.current_stage,
        created_at = workflow.created_at,
        updated_at = workflow.updated_at,
        completed_at = workflow.completed_at,
        errors = workflow.errors
    }
end

--- List workflows for a user
function _M:get_user_workflows(user_id)
    local user_workflows = {}

    for workflow_id, workflow in pairs(self.workflows) do
        if workflow.user_id == user_id then
            table.insert(user_workflows, {
                workflow_id = workflow_id,
                status = workflow.status,
                request_type = workflow.request_type,
                created_at = workflow.created_at,
                completed_at = workflow.completed_at
            })
        end
    end

    return user_workflows
end

--- Cancel a workflow
function _M:cancel_workflow(workflow_id, reason)
    local workflow = self.workflows[workflow_id]
    if not workflow then
        return false, "Workflow not found"
    end

    if workflow.status == WORKFLOW_STATES.COMPLETED or workflow.status == WORKFLOW_STATES.FAILED then
        return false, "Cannot cancel completed or failed workflow"
    end

    workflow.status = WORKFLOW_STATES.CANCELLED
    workflow.cancelled_at = ngx.time()
    workflow.cancel_reason = reason
    workflow.updated_at = ngx.time()

    -- Log cancellation
    audit_logger.log_event({
        event_type = "data_deletion_cancelled",
        workflow_id = workflow_id,
        user_id = workflow.user_id,
        reason = reason
    }, self.config.audit_config)

    kong.log.info("[kong-guard-ai] Workflow cancelled: ", workflow_id, " reason: ", reason)

    return true
end

--- Cleanup old workflows
function _M:_cleanup_old_workflows()
    local current_time = ngx.now()
    local retention_days = 30 -- Keep workflows for 30 days
    local retention_seconds = retention_days * 24 * 60 * 60
    local cleaned = 0

    for workflow_id, workflow in pairs(self.workflows) do
        local age = current_time - workflow.created_at
        if age > retention_seconds and
           (workflow.status == WORKFLOW_STATES.COMPLETED or
            workflow.status == WORKFLOW_STATES.FAILED or
            workflow.status == WORKFLOW_STATES.CANCELLED) then
            self.workflows[workflow_id] = nil
            cleaned = cleaned + 1
        end
    end

    if cleaned > 0 then
        kong.log.info("[kong-guard-ai] Cleaned up ", cleaned, " old workflows")
    end
end

--- Get workflow statistics
function _M:get_statistics()
    local stats = {
        total_workflows = 0,
        pending_workflows = 0,
        in_progress_workflows = 0,
        completed_workflows = 0,
        failed_workflows = 0,
        cancelled_workflows = 0,
        average_completion_time = 0
    }

    local total_completion_time = 0
    local completed_count = 0

    for _, workflow in pairs(self.workflows) do
        stats.total_workflows = stats.total_workflows + 1

        if workflow.status == WORKFLOW_STATES.PENDING then
            stats.pending_workflows = stats.pending_workflows + 1
        elseif workflow.status == WORKFLOW_STATES.IN_PROGRESS then
            stats.in_progress_workflows = stats.in_progress_workflows + 1
        elseif workflow.status == WORKFLOW_STATES.COMPLETED then
            stats.completed_workflows = stats.completed_workflows + 1
            if workflow.completed_at and workflow.created_at then
                total_completion_time = total_completion_time + (workflow.completed_at - workflow.created_at)
                completed_count = completed_count + 1
            end
        elseif workflow.status == WORKFLOW_STATES.FAILED then
            stats.failed_workflows = stats.failed_workflows + 1
        elseif workflow.status == WORKFLOW_STATES.CANCELLED then
            stats.cancelled_workflows = stats.cancelled_workflows + 1
        end
    end

    if completed_count > 0 then
        stats.average_completion_time = total_completion_time / completed_count
    end

    return stats
end

return _M