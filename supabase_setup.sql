-- Kong Guard AI - Supabase PostgreSQL Schema Setup
-- Run this script on your Supabase instance at 198.51.100.201

-- Create database for Kong Guard AI (if needed)
-- CREATE DATABASE kongguardai;

-- Connect to the database
-- \c kongguardai;

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schema for Kong Guard AI
CREATE SCHEMA IF NOT EXISTS kongguard;

-- Set search path
SET search_path TO kongguard, public;

-- ============================================================================
-- Attack Run Metadata Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_runs (
    run_id BIGSERIAL PRIMARY KEY,
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    total_attacks INTEGER DEFAULT 0,
    intensity_level VARCHAR(20),
    strategy VARCHAR(50),
    duration INTEGER,
    config_json JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_attack_runs_start_time ON attack_runs (start_time DESC);
CREATE INDEX IF NOT EXISTS idx_attack_runs_intensity ON attack_runs (intensity_level);
CREATE INDEX IF NOT EXISTS idx_attack_runs_strategy ON attack_runs (strategy);

-- ============================================================================
-- Individual Attack Metrics Table (Main Data Table)
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_metrics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    tier VARCHAR(50) NOT NULL,
    attack_type VARCHAR(100),
    attack_category VARCHAR(100),
    payload TEXT,
    response_time_ms NUMERIC(10,3),
    threat_score NUMERIC(3,2) CHECK (threat_score >= 0 AND threat_score <= 1),
    confidence NUMERIC(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    action_taken VARCHAR(50),
    blocked BOOLEAN DEFAULT FALSE,
    status_code INTEGER,
    source_ip INET,
    user_agent TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Partition by date for better performance (optional)
-- CREATE TABLE attack_metrics_y2024m08 PARTITION OF attack_metrics 
-- FOR VALUES FROM ('2024-08-01') TO ('2024-09-01');

-- Add indexes for high-performance queries
CREATE INDEX IF NOT EXISTS idx_attack_metrics_run_id ON attack_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_timestamp ON attack_metrics (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_tier ON attack_metrics (tier);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_attack_type ON attack_metrics (attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_blocked ON attack_metrics (blocked);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_threat_score ON attack_metrics (threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_attack_metrics_composite ON attack_metrics (run_id, tier, attack_type);

-- ============================================================================
-- Tier Statistics Table (Aggregated Performance Metrics)
-- ============================================================================
CREATE TABLE IF NOT EXISTS tier_statistics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    tier VARCHAR(50) NOT NULL,
    total_requests INTEGER DEFAULT 0,
    attacks_blocked INTEGER DEFAULT 0,
    attacks_allowed INTEGER DEFAULT 0,
    detection_rate NUMERIC(5,2) DEFAULT 0.0,
    avg_response_time NUMERIC(10,3) DEFAULT 0.0,
    avg_threat_score NUMERIC(3,2) DEFAULT 0.0,
    avg_confidence NUMERIC(3,2) DEFAULT 0.0,
    max_response_time NUMERIC(10,3) DEFAULT 0.0,
    min_response_time NUMERIC(10,3) DEFAULT 0.0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_tier_statistics_run_id ON tier_statistics (run_id);
CREATE INDEX IF NOT EXISTS idx_tier_statistics_tier ON tier_statistics (tier);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tier_statistics_unique ON tier_statistics (run_id, tier);

-- ============================================================================
-- Performance Metrics Table (System Performance Data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS performance_metrics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(15,6),
    metric_unit VARCHAR(20),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_performance_metrics_run_id ON performance_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_name ON performance_metrics (metric_name);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics (timestamp DESC);

-- ============================================================================
-- Attack Patterns Cache Table (For Intelligent Caching)
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_patterns (
    id BIGSERIAL PRIMARY KEY,
    pattern_hash VARCHAR(64) UNIQUE NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- 'signature', 'behavioral', 'negative'
    payload_sample TEXT,
    threat_analysis JSONB NOT NULL,
    hit_count INTEGER DEFAULT 0,
    last_hit TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Add indexes for cache performance
CREATE INDEX IF NOT EXISTS idx_attack_patterns_hash ON attack_patterns (pattern_hash);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns (pattern_type);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_expires ON attack_patterns (expires_at);

-- ============================================================================
-- Real-time Analytics Views
-- ============================================================================

-- Current attack statistics view
CREATE OR REPLACE VIEW current_attack_stats AS
SELECT 
    ar.run_id,
    ar.start_time,
    ar.intensity_level,
    ar.strategy,
    COUNT(am.id) as total_attacks,
    COUNT(CASE WHEN am.blocked = true THEN 1 END) as blocked_attacks,
    AVG(am.response_time_ms) as avg_response_time,
    AVG(am.threat_score) as avg_threat_score,
    AVG(am.confidence) as avg_confidence
FROM attack_runs ar
LEFT JOIN attack_metrics am ON ar.run_id = am.run_id
WHERE ar.end_time IS NULL OR ar.end_time > NOW() - INTERVAL '1 hour'
GROUP BY ar.run_id, ar.start_time, ar.intensity_level, ar.strategy;

-- Tier performance comparison view
CREATE OR REPLACE VIEW tier_performance_comparison AS
SELECT 
    am.tier,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN am.blocked = true THEN 1 END) as blocked_requests,
    ROUND((COUNT(CASE WHEN am.blocked = true THEN 1 END)::NUMERIC / COUNT(*) * 100), 2) as block_rate_percent,
    ROUND(AVG(am.response_time_ms), 2) as avg_response_time_ms,
    ROUND(AVG(am.threat_score), 3) as avg_threat_score,
    MAX(am.timestamp) as last_attack
FROM attack_metrics am
WHERE am.timestamp > NOW() - INTERVAL '1 hour'
GROUP BY am.tier
ORDER BY block_rate_percent DESC;

-- Attack type breakdown view
CREATE OR REPLACE VIEW attack_type_breakdown AS
SELECT 
    am.attack_type,
    am.tier,
    COUNT(*) as attack_count,
    COUNT(CASE WHEN am.blocked = true THEN 1 END) as blocked_count,
    ROUND(AVG(am.threat_score), 3) as avg_threat_score,
    ROUND(AVG(am.response_time_ms), 2) as avg_response_time
FROM attack_metrics am
WHERE am.timestamp > NOW() - INTERVAL '24 hours'
GROUP BY am.attack_type, am.tier
ORDER BY attack_count DESC;

-- ============================================================================
-- Functions for Automated Statistics
-- ============================================================================

-- Function to calculate tier statistics for a run
CREATE OR REPLACE FUNCTION calculate_tier_stats(p_run_id BIGINT)
RETURNS VOID AS $$
BEGIN
    -- Delete existing stats for this run
    DELETE FROM tier_statistics WHERE run_id = p_run_id;
    
    -- Calculate and insert new stats
    INSERT INTO tier_statistics (
        run_id, tier, total_requests, attacks_blocked, attacks_allowed,
        detection_rate, avg_response_time, avg_threat_score, avg_confidence,
        max_response_time, min_response_time
    )
    SELECT 
        p_run_id,
        tier,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN blocked = true THEN 1 END) as attacks_blocked,
        COUNT(CASE WHEN blocked = false THEN 1 END) as attacks_allowed,
        ROUND((COUNT(CASE WHEN blocked = true THEN 1 END)::NUMERIC / COUNT(*) * 100), 2) as detection_rate,
        ROUND(AVG(response_time_ms), 3) as avg_response_time,
        ROUND(AVG(threat_score), 3) as avg_threat_score,
        ROUND(AVG(confidence), 3) as avg_confidence,
        MAX(response_time_ms) as max_response_time,
        MIN(response_time_ms) as min_response_time
    FROM attack_metrics 
    WHERE run_id = p_run_id
    GROUP BY tier;
END;
$$ LANGUAGE plpgsql;

-- Function to clean old data
CREATE OR REPLACE FUNCTION cleanup_old_data(days_to_keep INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete old attack runs and cascade to related data
    WITH deleted_runs AS (
        DELETE FROM attack_runs 
        WHERE start_time < NOW() - (days_to_keep || ' days')::INTERVAL
        RETURNING run_id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted_runs;
    
    -- Clean expired cache patterns
    DELETE FROM attack_patterns 
    WHERE expires_at IS NOT NULL AND expires_at < NOW();
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Triggers for Real-time Updates
-- ============================================================================

-- Update statistics when attack metrics are inserted
CREATE OR REPLACE FUNCTION trigger_update_tier_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Recalculate tier statistics for the affected run
    PERFORM calculate_tier_stats(NEW.run_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger (if not exists)
DROP TRIGGER IF EXISTS tr_update_tier_stats ON attack_metrics;
CREATE TRIGGER tr_update_tier_stats
    AFTER INSERT OR UPDATE OR DELETE ON attack_metrics
    FOR EACH STATEMENT
    EXECUTE FUNCTION trigger_update_tier_stats();

-- Update timestamps
CREATE OR REPLACE FUNCTION trigger_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables with updated_at
DROP TRIGGER IF EXISTS tr_attack_runs_updated_at ON attack_runs;
CREATE TRIGGER tr_attack_runs_updated_at
    BEFORE UPDATE ON attack_runs
    FOR EACH ROW
    EXECUTE FUNCTION trigger_updated_at();

DROP TRIGGER IF EXISTS tr_tier_statistics_updated_at ON tier_statistics;
CREATE TRIGGER tr_tier_statistics_updated_at
    BEFORE UPDATE ON tier_statistics
    FOR EACH ROW
    EXECUTE FUNCTION trigger_updated_at();

-- ============================================================================
-- Row Level Security (RLS) Setup
-- ============================================================================

-- Enable RLS on sensitive tables (optional - for multi-tenant scenarios)
-- ALTER TABLE attack_runs ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE attack_metrics ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE tier_statistics ENABLE ROW LEVEL SECURITY;

-- Example policy (customize based on your auth requirements)
-- CREATE POLICY "Users can view their own attack runs" ON attack_runs
--     FOR SELECT USING (auth.uid()::text = created_by OR auth.role() = 'admin');

-- ============================================================================
-- Initial Data and Testing
-- ============================================================================

-- Insert a test attack run for verification
INSERT INTO attack_runs (intensity_level, strategy, duration, config_json) VALUES
('medium', 'sustained', 60, '{"test": true, "version": "1.0"}');

-- Verify tables were created
SELECT schemaname, tablename, tableowner 
FROM pg_tables 
WHERE schemaname = 'kongguard'
ORDER BY tablename;

-- Show table sizes
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'kongguard'
ORDER BY tablename, attname;

COMMIT;