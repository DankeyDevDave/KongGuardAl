-- Kong Guard AI Attack Database Migration to Supabase
-- Run this in your self-hosted Supabase SQL editor

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Attack run metadata table
CREATE TABLE attack_runs (
    run_id BIGSERIAL PRIMARY KEY,
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    total_attacks INTEGER DEFAULT 0,
    intensity_level TEXT NOT NULL CHECK (intensity_level IN ('low', 'medium', 'high', 'extreme')),
    strategy TEXT NOT NULL CHECK (strategy IN ('wave', 'sustained', 'stealth', 'blended', 'escalation')),
    duration INTEGER NOT NULL CHECK (duration BETWEEN 5 AND 300),
    config_json JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Individual attack metrics table (main data store)
CREATE TABLE attack_metrics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    tier TEXT NOT NULL CHECK (tier IN ('unprotected', 'cloud', 'local')),
    attack_type TEXT NOT NULL,
    attack_category TEXT NOT NULL,
    payload TEXT,
    response_time_ms NUMERIC(10,3),
    threat_score NUMERIC(3,2) CHECK (threat_score BETWEEN 0 AND 1),
    confidence NUMERIC(3,2) CHECK (confidence BETWEEN 0 AND 1),
    action_taken TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    status_code INTEGER,
    source_ip INET,
    user_agent TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Aggregated tier statistics
CREATE TABLE tier_statistics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    tier TEXT NOT NULL CHECK (tier IN ('unprotected', 'cloud', 'local')),
    total_requests INTEGER DEFAULT 0,
    attacks_blocked INTEGER DEFAULT 0,
    attacks_allowed INTEGER DEFAULT 0,
    avg_response_time NUMERIC(10,3),
    detection_rate NUMERIC(5,2),
    min_threat_score NUMERIC(3,2),
    max_threat_score NUMERIC(3,2),
    avg_threat_score NUMERIC(3,2),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Performance metrics table
CREATE TABLE performance_metrics (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES attack_runs(run_id) ON DELETE CASCADE,
    metric_type TEXT NOT NULL,
    metric_value NUMERIC(15,6),
    metric_unit TEXT,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for high-performance queries
CREATE INDEX idx_attack_metrics_run_id ON attack_metrics(run_id);
CREATE INDEX idx_attack_metrics_tier ON attack_metrics(tier);
CREATE INDEX idx_attack_metrics_timestamp ON attack_metrics(timestamp);
CREATE INDEX idx_attack_metrics_attack_type ON attack_metrics(attack_type);
CREATE INDEX idx_attack_metrics_blocked ON attack_metrics(blocked);
CREATE INDEX idx_tier_statistics_run_id ON tier_statistics(run_id);
CREATE INDEX idx_tier_statistics_tier ON tier_statistics(tier);
CREATE INDEX idx_attack_runs_start_time ON attack_runs(start_time);

-- Real-time subscriptions setup
ALTER TABLE attack_runs REPLICA IDENTITY FULL;
ALTER TABLE attack_metrics REPLICA IDENTITY FULL;
ALTER TABLE tier_statistics REPLICA IDENTITY FULL;

-- Row Level Security (RLS) policies
ALTER TABLE attack_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE tier_statistics ENABLE ROW LEVEL SECURITY;
ALTER TABLE performance_metrics ENABLE ROW LEVEL SECURITY;

-- Allow all operations for authenticated users (adjust as needed)
CREATE POLICY "Enable all operations for authenticated users" ON attack_runs
    FOR ALL USING (auth.role() = 'authenticated');

CREATE POLICY "Enable all operations for authenticated users" ON attack_metrics
    FOR ALL USING (auth.role() = 'authenticated');

CREATE POLICY "Enable all operations for authenticated users" ON tier_statistics
    FOR ALL USING (auth.role() = 'authenticated');

CREATE POLICY "Enable all operations for authenticated users" ON performance_metrics
    FOR ALL USING (auth.role() = 'authenticated');

-- Views for common queries
CREATE OR REPLACE VIEW attack_summary AS
SELECT
    ar.run_id,
    ar.start_time,
    ar.end_time,
    ar.total_attacks,
    ar.intensity_level,
    ar.strategy,
    ar.duration,
    COUNT(am.id) as recorded_attacks,
    AVG(am.response_time_ms) as avg_response_time,
    COUNT(CASE WHEN am.blocked = true THEN 1 END) as total_blocked,
    COUNT(CASE WHEN am.blocked = false THEN 1 END) as total_allowed
FROM attack_runs ar
LEFT JOIN attack_metrics am ON ar.run_id = am.run_id
GROUP BY ar.run_id, ar.start_time, ar.end_time, ar.total_attacks, ar.intensity_level, ar.strategy, ar.duration
ORDER BY ar.start_time DESC;

-- Function to calculate real-time statistics
CREATE OR REPLACE FUNCTION calculate_tier_stats(target_run_id BIGINT)
RETURNS TABLE (
    tier TEXT,
    total_requests BIGINT,
    attacks_blocked BIGINT,
    attacks_allowed BIGINT,
    avg_response_time NUMERIC,
    detection_rate NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        am.tier,
        COUNT(*)::BIGINT as total_requests,
        COUNT(CASE WHEN am.blocked = true THEN 1 END)::BIGINT as attacks_blocked,
        COUNT(CASE WHEN am.blocked = false THEN 1 END)::BIGINT as attacks_allowed,
        ROUND(AVG(am.response_time_ms)::NUMERIC, 3) as avg_response_time,
        ROUND((COUNT(CASE WHEN am.blocked = true THEN 1 END) * 100.0 / COUNT(*))::NUMERIC, 2) as detection_rate
    FROM attack_metrics am
    WHERE am.run_id = target_run_id
    GROUP BY am.tier;
END;
$$ LANGUAGE plpgsql;

-- Insert sample configuration for testing
INSERT INTO attack_runs (intensity_level, strategy, duration, config_json) VALUES
('medium', 'wave', 30, '{"test": true, "environment": "development"}');

-- Grant permissions for API access
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;

COMMENT ON TABLE attack_runs IS 'Metadata for each attack simulation run';
COMMENT ON TABLE attack_metrics IS 'Individual attack records with response metrics';
COMMENT ON TABLE tier_statistics IS 'Aggregated performance statistics per protection tier';
COMMENT ON TABLE performance_metrics IS 'System performance metrics during attacks';
