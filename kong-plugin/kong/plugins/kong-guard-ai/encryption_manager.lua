--- Encryption Manager Module for Kong Guard AI
-- Handles encryption and decryption of sensitive data

local _M = {}

-- Dependencies
local kong = kong
local cjson = require("cjson.safe")
local aes = require("resty.aes")
local random = require("resty.random")
local string = string

-- Encryption algorithms
local ENCRYPTION_ALGORITHMS = {
    AES_256_GCM = "aes-256-gcm",
    AES_256_CBC = "aes-256-cbc",
    CHACHA20_POLY1305 = "chacha20-poly1305"
}

-- Key management
local KEY_TYPES = {
    DATA_ENCRYPTION = "data_encryption",
    KEY_ENCRYPTION = "key_encryption",
    HMAC = "hmac"
}

--- Create a new encryption manager instance
function _M.new(config)
    local self = {
        config = config or {},
        encryption_algorithm = config.encryption_algorithm or ENCRYPTION_ALGORITHMS.AES_256_GCM,
        key_rotation_enabled = config.key_rotation_enabled or true,
        key_rotation_interval = config.key_rotation_interval or 30 * 24 * 60 * 60, -- 30 days
        encryption_keys = {},
        key_versions = {},
        encrypted_data_index = {},
        enable_fips_compliance = config.enable_fips_compliance or false,
        key_store_path = config.key_store_path or "/var/kong-guard-ai/keys"
    }

    return setmetatable(self, {__index = _M})
end

--- Initialize the encryption manager
function _M:init()
    -- Initialize encryption keys
    self:_initialize_keys()

    -- Set up key rotation
    if self.key_rotation_enabled then
        local ok, err = ngx.timer.every(self.key_rotation_interval, function()
            self:_rotate_keys()
        end)

        if not ok then
            kong.log.err("[kong-guard-ai] Failed to initialize key rotation: ", err)
        end
    end

    kong.log.info("[kong-guard-ai] Encryption manager initialized with algorithm: ", self.encryption_algorithm)
end

--- Encrypt data
function _M:encrypt_data(data, context)
    if not data then
        return nil, "Data is required for encryption"
    end

    local data_type = type(data)
    local data_to_encrypt

    -- Convert data to string for encryption
    if data_type == "table" then
        data_to_encrypt = cjson.encode(data)
    elseif data_type == "string" then
        data_to_encrypt = data
    else
        data_to_encrypt = tostring(data)
    end

    -- Get encryption key
    local key_id, encryption_key = self:_get_current_key(KEY_TYPES.DATA_ENCRYPTION)
    if not encryption_key then
        return nil, "No encryption key available"
    end

    -- Generate initialization vector
    local iv = random.bytes(16) -- 16 bytes for AES

    -- Create cipher
    local cipher, err = self:_create_cipher(encryption_key, iv)
    if not cipher then
        return nil, "Failed to create cipher: " .. (err or "unknown error")
    end

    -- Encrypt data
    local encrypted_data, err = cipher:encrypt(data_to_encrypt)
    if not encrypted_data then
        return nil, "Encryption failed: " .. (err or "unknown error")
    end

    -- Create encrypted data package
    local encrypted_package = {
        version = "1.0",
        algorithm = self.encryption_algorithm,
        key_id = key_id,
        iv = self:_base64_encode(iv),
        data = self:_base64_encode(encrypted_data),
        original_type = data_type,
        encrypted_at = ngx.now(),
        context = context or {}
    }

    -- Generate integrity hash
    encrypted_package.integrity_hash = self:_generate_integrity_hash(encrypted_package)

    -- Store encryption metadata
    local package_id = self:_generate_package_id()
    self.encrypted_data_index[package_id] = {
        package_id = package_id,
        key_id = key_id,
        encrypted_at = ngx.now(),
        data_type = data_type,
        context = context
    }

    kong.log.debug("[kong-guard-ai] Data encrypted with key: ", key_id, " package_id: ", package_id)

    return cjson.encode(encrypted_package), nil
end

--- Decrypt data
function _M:decrypt_data(encrypted_package_json, context)
    if not encrypted_package_json then
        return nil, "Encrypted data is required for decryption"
    end

    -- Parse encrypted package
    local encrypted_package = cjson.decode(encrypted_package_json)
    if not encrypted_package then
        return nil, "Invalid encrypted data format"
    end

    -- Verify integrity
    local calculated_hash = self:_generate_integrity_hash(encrypted_package)
    if calculated_hash ~= encrypted_package.integrity_hash then
        kong.log.warn("[kong-guard-ai] Data integrity check failed")
        return nil, "Data integrity check failed"
    end

    -- Get decryption key
    local decryption_key = self:_get_key_by_id(encrypted_package.key_id)
    if not decryption_key then
        return nil, "Decryption key not found or expired"
    end

    -- Decode IV and encrypted data
    local iv = self:_base64_decode(encrypted_package.iv)
    local encrypted_data = self:_base64_decode(encrypted_package.data)

    if not iv or not encrypted_data then
        return nil, "Invalid encrypted data format"
    end

    -- Create cipher for decryption
    local cipher, err = self:_create_cipher(decryption_key, iv)
    if not cipher then
        return nil, "Failed to create cipher: " .. (err or "unknown error")
    end

    -- Decrypt data
    local decrypted_data, err = cipher:decrypt(encrypted_data)
    if not decrypted_data then
        return nil, "Decryption failed: " .. (err or "unknown error")
    end

    -- Convert back to original type
    local result
    if encrypted_package.original_type == "table" then
        result = cjson.decode(decrypted_data)
    elseif encrypted_package.original_type == "number" then
        result = tonumber(decrypted_data)
    elseif encrypted_package.original_type == "boolean" then
        result = decrypted_data == "true"
    else
        result = decrypted_data
    end

    kong.log.debug("[kong-guard-ai] Data decrypted with key: ", encrypted_package.key_id)

    return result, nil
end

--- Encrypt sensitive fields in data
function _M:encrypt_sensitive_fields(data, sensitive_fields, context)
    if not data or not sensitive_fields then
        return data
    end

    local encrypted_data = self:_deep_copy(data)
    local encryption_results = {}

    for _, field_path in ipairs(sensitive_fields) do
        local field_value = self:_get_field_value(encrypted_data, field_path)
        if field_value then
            local encrypted_value, err = self:encrypt_data(field_value, {
                field_path = field_path,
                context = context
            })

            if encrypted_value then
                self:_set_field_value(encrypted_data, field_path, encrypted_value)
                table.insert(encryption_results, {
                    field = field_path,
                    success = true
                })
            else
                kong.log.warn("[kong-guard-ai] Failed to encrypt field: ", field_path, " error: ", err)
                table.insert(encryption_results, {
                    field = field_path,
                    success = false,
                    error = err
                })
            end
        end
    end

    return encrypted_data, encryption_results
end

--- Decrypt sensitive fields in data
function _M:decrypt_sensitive_fields(data, sensitive_fields, context)
    if not data or not sensitive_fields then
        return data
    end

    local decrypted_data = self:_deep_copy(data)
    local decryption_results = {}

    for _, field_path in ipairs(sensitive_fields) do
        local field_value = self:_get_field_value(decrypted_data, field_path)
        if field_value and type(field_value) == "string" then
            -- Try to decrypt (will fail gracefully if not encrypted)
            local decrypted_value, err = self:decrypt_data(field_value, {
                field_path = field_path,
                context = context
            })

            if decrypted_value then
                self:_set_field_value(decrypted_data, field_path, decrypted_value)
                table.insert(decryption_results, {
                    field = field_path,
                    success = true
                })
            else
                -- Field might not be encrypted, leave as-is
                table.insert(decryption_results, {
                    field = field_path,
                    success = true,
                    note = "field_not_encrypted"
                })
            end
        end
    end

    return decrypted_data, decryption_results
end

--- Generate data encryption key
function _M:generate_data_key(context)
    local key_id = self:_generate_key_id()
    local key_material = random.bytes(32) -- 256-bit key

    local key_data = {
        key_id = key_id,
        key_material = key_material,
        key_type = KEY_TYPES.DATA_ENCRYPTION,
        created_at = ngx.now(),
        expires_at = ngx.now() + self.key_rotation_interval,
        algorithm = self.encryption_algorithm,
        context = context or {}
    }

    self.encryption_keys[key_id] = key_data
    self.key_versions[KEY_TYPES.DATA_ENCRYPTION] = key_id

    kong.log.info("[kong-guard-ai] Generated new data encryption key: ", key_id)

    return key_id, key_data
end

--- Rotate encryption keys
function _M:rotate_keys()
    return self:_rotate_keys()
end

--- Get encryption statistics
function _M:get_encryption_statistics()
    return {
        algorithm = self.encryption_algorithm,
        total_keys = self:_count_table_fields(self.encryption_keys),
        current_key_version = self.key_versions[KEY_TYPES.DATA_ENCRYPTION],
        encrypted_packages = self:_count_table_fields(self.encrypted_data_index),
        key_rotation_enabled = self.key_rotation_enabled,
        key_rotation_interval_days = self.key_rotation_interval / (24 * 60 * 60)
    }
end

--- Helper functions

function _M:_initialize_keys()
    -- Generate initial encryption key if none exists
    if not self.key_versions[KEY_TYPES.DATA_ENCRYPTION] then
        self:generate_data_key({init = true})
    end
end

function _M:_get_current_key(key_type)
    local key_id = self.key_versions[key_type]
    if not key_id then
        return nil, nil
    end

    local key_data = self.encryption_keys[key_id]
    if not key_data then
        return nil, nil
    end

    -- Check if key is expired
    if ngx.now() > key_data.expires_at then
        kong.log.warn("[kong-guard-ai] Encryption key expired: ", key_id)
        return nil, nil
    end

    return key_id, key_data.key_material
end

function _M:_get_key_by_id(key_id)
    local key_data = self.encryption_keys[key_id]
    if not key_data then
        return nil
    end

    -- Check if key is expired
    if ngx.now() > key_data.expires_at then
        return nil
    end

    return key_data.key_material
end

function _M:_create_cipher(key, iv)
    if self.encryption_algorithm == ENCRYPTION_ALGORITHMS.AES_256_GCM then
        return aes:new(key, nil, aes.cipher(256, "gcm"), {iv = iv})
    elseif self.encryption_algorithm == ENCRYPTION_ALGORITHMS.AES_256_CBC then
        return aes:new(key, nil, aes.cipher(256, "cbc"), {iv = iv})
    else
        return nil, "Unsupported encryption algorithm: " .. self.encryption_algorithm
    end
end

function _M:_rotate_keys()
    kong.log.info("[kong-guard-ai] Starting key rotation")

    -- Generate new key
    local new_key_id, new_key_data = self:generate_data_key({rotation = true})

    -- Update current key version
    self.key_versions[KEY_TYPES.DATA_ENCRYPTION] = new_key_id

    -- Mark old keys as expired (keep for decryption of existing data)
    for key_id, key_data in pairs(self.encryption_keys) do
        if key_id ~= new_key_id and key_data.key_type == KEY_TYPES.DATA_ENCRYPTION then
            -- Keep old keys for 90 days to allow decryption of existing data
            key_data.expires_at = ngx.now() + (90 * 24 * 60 * 60)
        end
    end

    kong.log.info("[kong-guard-ai] Key rotation completed, new key: ", new_key_id)
end

function _M:_generate_key_id()
    return "key_" .. ngx.now() .. "_" .. random.token(8)
end

function _M:_generate_package_id()
    return "pkg_" .. ngx.now() .. "_" .. random.token(8)
end

function _M:_generate_integrity_hash(package)
    -- Create a copy without the integrity hash for calculation
    local package_copy = self:_deep_copy(package)
    package_copy.integrity_hash = nil

    -- Simple hash for integrity (in production, use proper HMAC)
    local data_string = cjson.encode(package_copy)
    return ngx.md5(data_string)
end

function _M:_base64_encode(data)
    return ngx.encode_base64(data)
end

function _M:_base64_decode(data)
    return ngx.decode_base64(data)
end

function _M:_deep_copy(obj)
    if type(obj) ~= "table" then
        return obj
    end

    local copy = {}
    for k, v in pairs(obj) do
        copy[k] = self:_deep_copy(v)
    end

    return copy
end

function _M:_get_field_value(data, field_path)
    local path_parts = self:_split_path(field_path)
    local current = data

    for _, part in ipairs(path_parts) do
        if type(current) == "table" then
            current = current[part]
        else
            return nil
        end
    end

    return current
end

function _M:_set_field_value(data, field_path, value)
    local path_parts = self:_split_path(field_path)
    local current = data

    for i = 1, #path_parts - 1 do
        local part = path_parts[i]
        if not current[part] or type(current[part]) ~= "table" then
            current[part] = {}
        end
        current = current[part]
    end

    current[path_parts[#path_parts]] = value
end

function _M:_split_path(path)
    local parts = {}
    for part in string.gmatch(path, "[^%.]+") do
        table.insert(parts, part)
    end
    return parts
end

function _M:_count_table_fields(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

--- Validate encryption configuration
function _M:validate_configuration()
    local issues = {}

    if not self.encryption_algorithm then
        table.insert(issues, "Encryption algorithm not specified")
    end

    if self.enable_fips_compliance and self.encryption_algorithm ~= ENCRYPTION_ALGORITHMS.AES_256_GCM then
        table.insert(issues, "FIPS compliance requires AES-256-GCM algorithm")
    end

    if self.key_rotation_interval < 7 * 24 * 60 * 60 then
        table.insert(issues, "Key rotation interval is too short (minimum 7 days recommended)")
    end

    return #issues == 0, issues
end

return _M
