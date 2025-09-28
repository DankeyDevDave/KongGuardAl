--- Access Control Module for Kong Guard AI
-- Manages permissions, roles, and access policies for secure data access

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local uuid = require("resty.uuid")

-- Access control levels
local ACCESS_LEVELS = {
    DENY = "deny",
    READ = "read",
    WRITE = "write",
    ADMIN = "admin"
}

-- User roles
local USER_ROLES = {
    PUBLIC = "public",
    USER = "user",
    ADMIN = "admin",
    AUDITOR = "auditor",
    COMPLIANCE_OFFICER = "compliance_officer"
}

-- Resource types
local RESOURCE_TYPES = {
    API_ENDPOINT = "api_endpoint",
    DATA_ASSET = "data_asset",
    USER_DATA = "user_data",
    SYSTEM_CONFIG = "system_config",
    AUDIT_LOGS = "audit_logs"
}

--- Create a new access control instance
function _M.new(config)
    local self = {
        config = config or {},
        access_policies = {},
        user_roles = {},
        resource_permissions = {},
        session_cache = {},
        audit_trail = {},
        enable_rbac = config.enable_rbac or true,
        enable_abac = config.enable_abac or false,
        session_timeout = config.session_timeout or 3600, -- 1 hour
        max_login_attempts = config.max_login_attempts or 5,
        lockout_duration = config.lockout_duration or 900 -- 15 minutes
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the access control system
function _M:init()
    -- Set up session cleanup
    local ok, err = ngx.timer.every(300, function() -- Every 5 minutes
        self:_cleanup_expired_sessions()
    end)

    if not ok then
        kong.log.err("[kong-guard-ai] Failed to initialize session cleanup: ", err)
    end

    -- Set up audit trail cleanup
    local ok2, err2 = ngx.timer.every(3600, function() -- Every hour
        self:_cleanup_audit_trail()
    end)

    if not ok2 then
        kong.log.err("[kong-guard-ai] Failed to initialize audit cleanup: ", err2)
    end

    kong.log.info("[kong-guard-ai] Access control system initialized")
end

--- Authenticate user
function _M:authenticate_user(credentials, context)
    if not credentials then
        return false, "Credentials required"
    end

    local user_id = credentials.user_id or credentials.username
    if not user_id then
        return false, "User ID required"
    end

    -- Check for account lockout
    if self:_is_account_locked(user_id) then
        self:_log_access_attempt(user_id, "denied", "account_locked", context)
        return false, "Account is temporarily locked due to too many failed attempts"
    end

    -- Validate credentials (mock implementation)
    local is_valid = self:_validate_credentials(credentials)
    if not is_valid then
        self:_record_failed_attempt(user_id)
        self:_log_access_attempt(user_id, "denied", "invalid_credentials", context)
        return false, "Invalid credentials"
    end

    -- Clear failed attempts on successful login
    self:_clear_failed_attempts(user_id)

    -- Create session
    local session = self:_create_session(user_id, context)

    -- Get user roles
    local roles = self:_get_user_roles(user_id)

    -- Log successful authentication
    self:_log_access_attempt(user_id, "granted", "authentication_successful", context)

    return true, {
        user_id = user_id,
        session_id = session.session_id,
        roles = roles,
        expires_at = session.expires_at
    }
end

--- Authorize access to resource
function _M:authorize_access(user_id, resource, action, context)
    if not user_id or not resource or not action then
        return false, "User ID, resource, and action are required"
    end

    -- Check if user is authenticated
    local session = self:_get_user_session(user_id)
    if not session then
        self:_log_access_attempt(user_id, "denied", "not_authenticated", context)
        return false, "User not authenticated"
    end

    -- Check session expiry
    if ngx.now() > session.expires_at then
        self:_invalidate_session(session.session_id)
        self:_log_access_attempt(user_id, "denied", "session_expired", context)
        return false, "Session expired"
    end

    -- Get user roles
    local user_roles = self:_get_user_roles(user_id)

    -- Check resource permissions
    local permission = self:_check_resource_permission(user_roles, resource, action, context)

    if permission.granted then
        self:_log_access_attempt(user_id, "granted", "authorization_successful", {
            resource = resource,
            action = action,
            context = context
        })
        return true, permission
    else
        self:_log_access_attempt(user_id, "denied", "insufficient_permissions", {
            resource = resource,
            action = action,
            required_roles = permission.required_roles,
            context = context
        })
        return false, permission.message or "Access denied"
    end
end

--- Check resource permission
function _M:_check_resource_permission(user_roles, resource, action, context)
    -- Check role-based access control (RBAC)
    if self.enable_rbac then
        for _, role in ipairs(user_roles) do
            local role_permissions = self:_get_role_permissions(role)
            for _, permission in ipairs(role_permissions) do
                if self:_matches_permission(permission, resource, action) then
                    return {
                        granted = true,
                        access_level = permission.access_level,
                        granted_by = "rbac",
                        role = role
                    }
                end
            end
        end
    end

    -- Check attribute-based access control (ABAC)
    if self.enable_abac then
        local abac_result = self:_evaluate_abac_policies(user_roles, resource, action, context)
        if abac_result.granted then
            return {
                granted = true,
                access_level = abac_result.access_level,
                granted_by = "abac",
                policy = abac_result.policy_id
            }
        end
    end

    -- Check resource-specific policies
    local resource_policy = self:_get_resource_policy(resource)
    if resource_policy then
        local policy_result = self:_evaluate_resource_policy(resource_policy, user_roles, action, context)
        if policy_result.granted then
            return {
                granted = true,
                access_level = policy_result.access_level,
                granted_by = "resource_policy",
                policy_id = resource_policy.id
            }
        end
    end

    return {
        granted = false,
        message = "No matching permissions found",
        required_roles = self:_get_required_roles_for_resource(resource, action)
    }
end

--- Create access policy
function _M:create_access_policy(policy_data, context)
    if not policy_data.name or not policy_data.resource or not policy_data.action then
        return false, "Policy name, resource, and action are required"
    end

    local policy_id = uuid.generate()
    local policy = {
        id = policy_id,
        name = policy_data.name,
        description = policy_data.description,
        resource = policy_data.resource,
        action = policy_data.action,
        conditions = policy_data.conditions or {},
        access_level = policy_data.access_level or ACCESS_LEVELS.READ,
        created_at = ngx.now(),
        created_by = context.user_id,
        enabled = policy_data.enabled ~= false
    }

    self.access_policies[policy_id] = policy

    kong.log.info("[kong-guard-ai] Access policy created: ", policy_id, " for resource: ", policy_data.resource)

    return true, policy
end

--- Assign role to user
function _M:assign_user_role(user_id, role, context)
    if not user_id or not role then
        return false, "User ID and role are required"
    end

    if not USER_ROLES[role:upper()] then
        return false, "Invalid role: " .. role
    end

    if not self.user_roles[user_id] then
        self.user_roles[user_id] = {}
    end

    -- Check if role is already assigned
    for _, existing_role in ipairs(self.user_roles[user_id]) do
        if existing_role.role == role then
            return false, "Role already assigned to user"
        end
    end

    -- Assign role
    table.insert(self.user_roles[user_id], {
        role = role,
        assigned_at = ngx.now(),
        assigned_by = context.user_id,
        expires_at = context.expires_at
    })

    kong.log.info("[kong-guard-ai] Role assigned: ", role, " to user: ", user_id)

    return true, {user_id = user_id, role = role, assigned_at = ngx.now()}
end

--- Revoke user role
function _M:revoke_user_role(user_id, role, context)
    if not user_id or not role then
        return false, "User ID and role are required"
    end

    if not self.user_roles[user_id] then
        return false, "User has no assigned roles"
    end

    -- Find and remove role
    for i, user_role in ipairs(self.user_roles[user_id]) do
        if user_role.role == role then
            table.remove(self.user_roles[user_id], i)

            kong.log.info("[kong-guard-ai] Role revoked: ", role, " from user: ", user_id)
            return true, {user_id = user_id, role = role, revoked_at = ngx.now()}
        end
    end

    return false, "Role not assigned to user"
end

--- Get user permissions
function _M:get_user_permissions(user_id)
    local user_roles = self:_get_user_roles(user_id)
    local permissions = {}

    for _, role in ipairs(user_roles) do
        local role_permissions = self:_get_role_permissions(role)
        for _, permission in ipairs(role_permissions) do
            table.insert(permissions, permission)
        end
    end

    return permissions
end

--- Validate session
function _M:validate_session(session_id)
    for user_id, sessions in pairs(self.session_cache) do
        for _, session in ipairs(sessions) do
            if session.session_id == session_id then
                if ngx.now() > session.expires_at then
                    self:_invalidate_session(session_id)
                    return false, "Session expired"
                end
                return true, {user_id = user_id, session = session}
            end
        end
    end

    return false, "Invalid session"
end

--- Invalidate session
function _M:invalidate_session(session_id, context)
    local success = self:_invalidate_session(session_id)

    if success then
        kong.log.info("[kong-guard-ai] Session invalidated: ", session_id)
        self:_log_access_attempt(nil, "session_invalidated", "manual_logout", context)
    end

    return success
end

--- Helper functions

function _M:_validate_credentials(credentials)
    -- Mock credential validation
    -- In production, this would validate against a user database
    return credentials.password == "mock_password" -- For testing only
end

function _M:_create_session(user_id, context)
    local session_id = uuid.generate()
    local session = {
        session_id = session_id,
        user_id = user_id,
        created_at = ngx.now(),
        expires_at = ngx.now() + self.session_timeout,
        ip_address = context.ip_address,
        user_agent = context.user_agent,
        last_activity = ngx.now()
    }

    if not self.session_cache[user_id] then
        self.session_cache[user_id] = {}
    end

    table.insert(self.session_cache[user_id], session)

    return session
end

function _M:_get_user_session(user_id)
    local user_sessions = self.session_cache[user_id]
    if not user_sessions then
        return nil
    end

    -- Return most recent session
    local latest_session = nil
    for _, session in ipairs(user_sessions) do
        if not latest_session or session.created_at > latest_session.created_at then
            latest_session = session
        end
    end

    return latest_session
end

function _M:_invalidate_session(session_id)
    for user_id, sessions in pairs(self.session_cache) do
        for i, session in ipairs(sessions) do
            if session.session_id == session_id then
                table.remove(sessions, i)
                return true
            end
        end
    end
    return false
end

function _M:_get_user_roles(user_id)
    local user_role_data = self.user_roles[user_id]
    if not user_role_data then
        return {USER_ROLES.PUBLIC} -- Default role
    end

    local roles = {}
    for _, role_data in ipairs(user_role_data) do
        if not role_data.expires_at or ngx.now() < role_data.expires_at then
            table.insert(roles, role_data.role)
        end
    end

    return roles
end

function _M:_get_role_permissions(role)
    -- Mock role permissions - in production, this would be configurable
    local role_permissions = {
        [USER_ROLES.ADMIN] = {
            {
                resource = "*",
                action = "*",
                access_level = ACCESS_LEVELS.ADMIN
            }
        },
        [USER_ROLES.USER] = {
            {
                resource = RESOURCE_TYPES.USER_DATA,
                action = "read",
                access_level = ACCESS_LEVELS.READ
            },
            {
                resource = RESOURCE_TYPES.API_ENDPOINT,
                action = "read",
                access_level = ACCESS_LEVELS.READ
            }
        },
        [USER_ROLES.AUDITOR] = {
            {
                resource = RESOURCE_TYPES.AUDIT_LOGS,
                action = "read",
                access_level = ACCESS_LEVELS.READ
            }
        },
        [USER_ROLES.COMPLIANCE_OFFICER] = {
            {
                resource = RESOURCE_TYPES.USER_DATA,
                action = "read",
                access_level = ACCESS_LEVELS.READ
            },
            {
                resource = RESOURCE_TYPES.AUDIT_LOGS,
                action = "read",
                access_level = ACCESS_LEVELS.READ
            }
        },
        [USER_ROLES.PUBLIC] = {
            {
                resource = RESOURCE_TYPES.API_ENDPOINT,
                action = "read",
                access_level = ACCESS_LEVELS.READ,
                conditions = {public_access = true}
            }
        }
    }

    return role_permissions[role] or {}
end

function _M:_matches_permission(permission, resource, action)
    -- Check resource pattern matching
    if permission.resource == "*" or permission.resource == resource then
        -- Check action matching
        if permission.action == "*" or permission.action == action then
            return true
        end
    end

    return false
end

function _M:_evaluate_abac_policies(user_roles, resource, action, context)
    -- Mock ABAC evaluation - in production would implement complex policy evaluation
    return {granted = false}
end

function _M:_get_resource_policy(resource)
    -- Mock resource policy lookup
    return nil
end

function _M:_evaluate_resource_policy(policy, user_roles, action, context)
    -- Mock policy evaluation
    return {granted = false}
end

function _M:_get_required_roles_for_resource(resource, action)
    -- Mock required roles lookup
    return {USER_ROLES.ADMIN}
end

function _M:_is_account_locked(user_id)
    -- Mock account lockout check
    return false
end

function _M:_record_failed_attempt(user_id)
    -- Mock failed attempt recording
end

function _M:_clear_failed_attempts(user_id)
    -- Mock failed attempt clearing
end

function _M:_log_access_attempt(user_id, result, reason, context)
    local audit_entry = {
        timestamp = ngx.now(),
        user_id = user_id,
        result = result,
        reason = reason,
        context = context,
        ip_address = context and context.ip_address,
        user_agent = context and context.user_agent
    }

    table.insert(self.audit_trail, audit_entry)

    -- Limit audit trail size
    if #self.audit_trail > 10000 then
        table.remove(self.audit_trail, 1)
    end
end

function _M:_cleanup_expired_sessions()
    local current_time = ngx.now()
    local cleaned = 0

    for user_id, sessions in pairs(self.session_cache) do
        local valid_sessions = {}
        for _, session in ipairs(sessions) do
            if current_time < session.expires_at then
                table.insert(valid_sessions, session)
            else
                cleaned = cleaned + 1
            end
        end

        if #valid_sessions == 0 then
            self.session_cache[user_id] = nil
        else
            self.session_cache[user_id] = valid_sessions
        end
    end

    if cleaned > 0 then
        kong.log.debug("[kong-guard-ai] Cleaned up ", cleaned, " expired sessions")
    end
end

function _M:_cleanup_audit_trail()
    local current_time = ngx.now()
    local retention_period = 7 * 24 * 60 * 60 -- 7 days
    local cleaned = 0

    while #self.audit_trail > 0 and current_time - self.audit_trail[1].timestamp > retention_period do
        table.remove(self.audit_trail, 1)
        cleaned = cleaned + 1
    end

    if cleaned > 0 then
        kong.log.debug("[kong-guard-ai] Cleaned up ", cleaned, " old audit entries")
    end
end

--- Get access control statistics
function _M:get_statistics()
    local stats = {
        total_users = self:_count_table_fields(self.user_roles),
        active_sessions = 0,
        total_policies = self:_count_table_fields(self.access_policies),
        audit_entries = #self.audit_trail,
        enable_rbac = self.enable_rbac,
        enable_abac = self.enable_abac
    }

    -- Count active sessions
    for _, sessions in pairs(self.session_cache) do
        stats.active_sessions = stats.active_sessions + #sessions
    end

    return stats
end

--- Validate access control configuration
function _M:validate_configuration()
    local issues = {}

    if self.enable_rbac and self.enable_abac then
        table.insert(issues, "Both RBAC and ABAC are enabled - this may cause conflicts")
    end

    if not self.enable_rbac and not self.enable_abac then
        table.insert(issues, "Neither RBAC nor ABAC is enabled - access control will be limited")
    end

    if self.session_timeout < 300 then
        table.insert(issues, "Session timeout is too short (minimum 5 minutes recommended)")
    end

    return #issues == 0, issues
end

function _M:_count_table_fields(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

return _M
