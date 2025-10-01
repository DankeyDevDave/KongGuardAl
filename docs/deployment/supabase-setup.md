# Kong Guard AI - Self-Hosted Supabase Integration

This guide walks through setting up Kong Guard AI with your self-hosted Supabase instance for enterprise-grade attack simulation and analytics.

## Prerequisites

- Self-hosted Supabase instance running
- Python 3.8+ with pip
- Node.js (for dashboard real-time features)
- PostgreSQL access (for advanced queries)

## Installation Steps

### 1. Install Required Dependencies

```bash
# Python dependencies
pip install supabase psycopg2-binary python-dotenv

# Optional: For advanced features
pip install asyncpg sqlalchemy redis
```

### 2. Set Up Your Self-Hosted Supabase

#### Option A: Local Supabase Development
```bash
# Install Supabase CLI
npm install -g @supabase/cli

# Initialize local Supabase
supabase init
supabase start

# Note the API URL and keys displayed
```

#### Option B: Production Self-Hosted Supabase
- Ensure your Supabase instance is accessible
- Obtain your API URL and service role key
- Configure firewall rules for database access

### 3. Database Migration

#### Run the Migration Script
```bash
# Copy the migration SQL to your Supabase dashboard
cp supabase_migration.sql /path/to/your/supabase/sql/

# Or run directly via psql
psql -h YOUR_SUPABASE_HOST -U postgres -d postgres -f supabase_migration.sql
```

#### Via Supabase Dashboard
1. Open your Supabase dashboard
2. Go to SQL Editor
3. Copy and paste the contents of `supabase_migration.sql`
4. Execute the migration

### 4. Environment Configuration

#### Create Environment File
```bash
# Copy the example configuration
cp env_example .env

# Edit with your Supabase details
nano .env
```

#### Required Environment Variables
```bash
# Self-hosted Supabase Configuration
SUPABASE_URL=https://your-supabase-instance.com
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Database Configuration
DATABASE_TYPE=supabase
ENABLE_REAL_TIME_UPDATES=true

# Security Settings
ENABLE_INPUT_SANITIZATION=true
API_RATE_LIMIT=1000
```

### 5. Update Attack Flood Simulator

#### Replace SQLite with Database Adapter
```python
# In attack_flood_simulator.py, replace the database initialization:

from database_adapter import get_database_adapter, AttackMetric, AttackConfig

# Initialize database adapter (auto-detects Supabase vs SQLite)
self.db = get_database_adapter()

# Use the adapter for all database operations
run_id = self.db.create_attack_run(config)
self.db.save_attack_metrics_batch(metrics)
```

### 6. Dashboard Real-time Integration

#### Add Real-time Script to Dashboards
```html
<!-- Add to enterprise_demo_dashboard.html and attack_reports.html -->
<script src="realtime_dashboard.js"></script>
<script>
// Configure for your Supabase instance
window.SUPABASE_URL = 'https://your-supabase-instance.com';
window.SUPABASE_KEY = 'your_anon_key_here';
</script>
```

## Configuration Options

### Database Performance Tuning

#### PostgreSQL Configuration (postgresql.conf)
```sql
-- Optimize for high-throughput inserts
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB

-- Enable performance extensions
shared_preload_libraries = 'pg_stat_statements'
track_activity_query_size = 2048
```

#### Connection Pooling Setup
```python
# In database_adapter.py, add connection pooling:
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_timeout=30
)
```

### Real-time Subscriptions

#### Enable Real-time for Tables
```sql
-- Run in your Supabase SQL editor
ALTER TABLE attack_metrics REPLICA IDENTITY FULL;
ALTER TABLE attack_runs REPLICA IDENTITY FULL;
ALTER TABLE tier_statistics REPLICA IDENTITY FULL;
```

#### Dashboard Configuration
```javascript
// Configure real-time updates
const realtimeConfig = {
    dbType: 'supabase',
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseKey: process.env.SUPABASE_ANON_KEY,
    updateInterval: 500, // 500ms for high-frequency updates
    maxDataPoints: 1000 // Keep more data points for analysis
};
```

## Advanced Features

### High-Availability Setup

#### Master-Slave Replication
```yaml
# docker-compose.yml for HA Supabase
version: '3.8'
services:
  supabase-master:
    image: supabase/postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replicator
    volumes:
      - postgres_master_data:/var/lib/postgresql/data

  supabase-slave:
    image: supabase/postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_MASTER_HOST: supabase-master
    depends_on:
      - supabase-master
```

### Custom Analytics Queries

#### Performance Views
```sql
-- Create performance monitoring views
CREATE VIEW attack_performance_summary AS
SELECT 
    DATE_TRUNC('hour', ar.start_time) as hour,
    ar.intensity_level,
    ar.strategy,
    COUNT(ar.run_id) as total_runs,
    AVG(ar.total_attacks) as avg_attacks_per_run,
    AVG(ts.avg_response_time) as overall_avg_response_time
FROM attack_runs ar
LEFT JOIN tier_statistics ts ON ar.run_id = ts.run_id
WHERE ar.start_time >= NOW() - INTERVAL '24 hours'
GROUP BY hour, ar.intensity_level, ar.strategy
ORDER BY hour DESC;

-- Create attack pattern analysis
CREATE VIEW attack_pattern_analysis AS
SELECT 
    attack_type,
    attack_category,
    tier,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count,
    AVG(response_time_ms) as avg_response_time,
    AVG(threat_score) as avg_threat_score
FROM attack_metrics 
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY attack_type, attack_category, tier
ORDER BY total_attempts DESC;
```

### API Endpoints for Analytics

#### Custom REST API Routes
```python
# Add to ai-service/app.py
@app.get("/api/analytics/performance-summary")
async def get_performance_summary():
    db = get_database_adapter()
    if isinstance(db, SupabaseAdapter):
        result = db.client.table('attack_performance_summary').select('*').execute()
        return result.data
    else:
        # Fallback for SQLite
        return await get_sqlite_performance_summary()

@app.get("/api/analytics/attack-patterns")
async def get_attack_patterns():
    db = get_database_adapter()
    if isinstance(db, SupabaseAdapter):
        result = db.client.table('attack_pattern_analysis').select('*').execute()
        return result.data
    else:
        return await get_sqlite_attack_patterns()
```

## Security Considerations

### Row Level Security (RLS)

#### Tenant Isolation
```sql
-- Enable multi-tenant RLS
CREATE POLICY "Users can only see their own data" ON attack_runs
    FOR ALL USING (
        auth.jwt() ->> 'tenant_id' = tenant_id OR
        auth.jwt() ->> 'role' = 'admin'
    );

CREATE POLICY "Users can only see their own metrics" ON attack_metrics
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM attack_runs ar 
            WHERE ar.run_id = attack_metrics.run_id 
            AND (auth.jwt() ->> 'tenant_id' = ar.tenant_id OR auth.jwt() ->> 'role' = 'admin')
        )
    );
```

### API Key Management
```python
# Secure API key rotation
import os
from cryptography.fernet import Fernet

class SecureConfig:
    def __init__(self):
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        self.cipher = Fernet(self.encryption_key)
    
    def get_supabase_key(self):
        encrypted_key = os.getenv('ENCRYPTED_SUPABASE_KEY')
        return self.cipher.decrypt(encrypted_key.encode()).decode()
```

## Testing & Validation

### Test Database Connection
```bash
# Run the database adapter test
python database_adapter.py
```

### Load Testing
```python
# Create load test for Supabase performance
import asyncio
from database_adapter import get_database_adapter, AttackMetric

async def load_test_supabase():
    db = get_database_adapter()
    
    # Create test run
    config = AttackConfig("high", "sustained", 60, ["unprotected"])
    run_id = db.create_attack_run(config)
    
    # Generate test metrics
    metrics = []
    for i in range(10000): # 10K attack metrics
        metric = AttackMetric(
            run_id=run_id,
            tier="unprotected",
            attack_type="sql_injection",
            attack_category="Database Attack",
            payload=f"test_payload_{i}",
            response_time_ms=50.0 + (i % 100),
            threat_score=0.8,
            blocked=False
        )
        metrics.append(metric)
    
    # Batch insert
    import time
    start_time = time.time()
    db.save_attack_metrics_batch(metrics)
    end_time = time.time()
    
    print(f" Inserted {len(metrics)} metrics in {end_time - start_time:.2f}s")
    print(f" Rate: {len(metrics) / (end_time - start_time):.0f} records/second")

# Run load test
asyncio.run(load_test_supabase())
```

## Production Deployment

### Docker Configuration
```dockerfile
# Dockerfile.supabase
FROM python:3.11-slim

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY . /app
WORKDIR /app

# Set environment for Supabase
ENV DATABASE_TYPE=supabase
ENV ENABLE_REAL_TIME_UPDATES=true

# Run application
CMD ["python", "ai-service/app.py"]
```

### Environment-Specific Configs
```yaml
# production.yml
database:
  type: supabase
  url: ${SUPABASE_URL}
  key: ${SUPABASE_SERVICE_ROLE_KEY}
  pool_size: 50
  max_connections: 200

security:
  enable_rls: true
  api_rate_limit: 5000
  enable_audit_logging: true

monitoring:
  enable_metrics: true
  prometheus_endpoint: /metrics
  health_check_interval: 30
```

## Support & Troubleshooting

### Common Issues

#### Connection Failures
```bash
# Test Supabase connectivity
curl -H "apikey: YOUR_ANON_KEY" \
     -H "Authorization: Bearer YOUR_ANON_KEY" \
     https://your-supabase-url.com/rest/v1/attack_runs

# Check PostgreSQL connectivity
psql -h your-supabase-host -U postgres -c "SELECT version();"
```

#### Performance Issues
```sql
-- Check table sizes and index usage
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE tablename IN ('attack_runs', 'attack_metrics', 'tier_statistics');

-- Analyze query performance
EXPLAIN ANALYZE 
SELECT * FROM attack_metrics 
WHERE run_id = 123 AND tier = 'unprotected'
ORDER BY timestamp DESC 
LIMIT 100;
```

### Monitoring Queries
```sql
-- Monitor real-time activity
SELECT 
    pid,
    usename,
    application_name,
    client_addr,
    query_start,
    state,
    query
FROM pg_stat_activity 
WHERE application_name LIKE '%kong-guard%';

-- Check replication lag
SELECT 
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    write_lag,
    flush_lag,
    replay_lag
FROM pg_stat_replication;
```

---

## Verification Checklist

- [ ] Supabase instance accessible
- [ ] Migration script executed successfully  
- [ ] Environment variables configured
- [ ] Database adapter connects properly
- [ ] Real-time subscriptions working
- [ ] Attack flood simulator runs with Supabase
- [ ] Dashboards display real-time data
- [ ] Performance metrics within acceptable ranges
- [ ] Security policies properly configured
- [ ] Backup and monitoring systems active

** Your Kong Guard AI system is now powered by self-hosted Supabase!**

For advanced configurations and enterprise features, refer to the Kong Guard AI documentation or contact support.