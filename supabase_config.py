#!/usr/bin/env python3
"""
Kong Guard AI - Supabase Configuration and Connection Manager
Handles connection to Supabase PostgreSQL instance at 192.168.0.201
"""

import os
import asyncio
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import asyncpg
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class SupabaseConfig:
    host: str = "localhost"
    database: str = "postgres"
    user: str = "supabase_admin"
    password: str = "Jlwain@321"
    port: int = 25432
    schema: str = "kongguard"

class SupabaseManager:
    """Manage connections to Supabase PostgreSQL database"""
    
    def __init__(self, config: SupabaseConfig = None):
        self.config = config or SupabaseConfig()
        self.connection_pool = None
        self._sync_connection = None
        
    async def initialize_async_pool(self, min_connections=2, max_connections=10):
        """Initialize async connection pool for high-performance operations"""
        try:
            self.connection_pool = await asyncpg.create_pool(
                host=self.config.host,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
                port=self.config.port,
                min_size=min_connections,
                max_size=max_connections,
                command_timeout=30,
                ssl=False
            )
            logger.info("✅ Async connection pool initialized successfully")
            
            # Test connection and set search path
            async with self.connection_pool.acquire() as conn:
                await conn.execute(f"SET search_path TO {self.config.schema}, public")
                version = await conn.fetchval("SELECT version()")
                logger.info(f"Connected to: {version[:50]}...")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize async pool: {e}")
            raise
    
    def get_sync_connection(self):
        """Get synchronous connection for simple operations"""
        try:
            if not self._sync_connection or self._sync_connection.closed:
                self._sync_connection = psycopg2.connect(
                    host=self.config.host,
                    database=self.config.database,
                    user=self.config.user,
                    password=self.config.password,
                    port=self.config.port,
                    cursor_factory=RealDictCursor
                )
                
                # Set search path
                with self._sync_connection.cursor() as cursor:
                    cursor.execute(f"SET search_path TO {self.config.schema}, public")
                    self._sync_connection.commit()
                    
                logger.info("✅ Sync connection established")
                
            return self._sync_connection
            
        except Exception as e:
            logger.error(f"❌ Failed to get sync connection: {e}")
            raise
    
    async def close(self):
        """Close all connections"""
        if self.connection_pool:
            await self.connection_pool.close()
            
        if self._sync_connection and not self._sync_connection.closed:
            self._sync_connection.close()
            
        logger.info("🔒 All connections closed")
    
    # ========================================================================
    # Attack Run Management
    # ========================================================================
    
    async def create_attack_run(
        self, 
        intensity: str,
        strategy: str,
        duration: int,
        config: Dict[str, Any]
    ) -> int:
        """Create a new attack run and return run_id"""
        async with self.connection_pool.acquire() as conn:
            run_id = await conn.fetchval("""
                INSERT INTO attack_runs (intensity_level, strategy, duration, config_json)
                VALUES ($1, $2, $3, $4)
                RETURNING run_id
            """, intensity, strategy, duration, json.dumps(config))
            
            logger.info(f"Created attack run {run_id}")
            return run_id
    
    async def complete_attack_run(self, run_id: int, total_attacks: int):
        """Mark attack run as complete"""
        async with self.connection_pool.acquire() as conn:
            await conn.execute("""
                UPDATE attack_runs 
                SET end_time = NOW(), total_attacks = $2, updated_at = NOW()
                WHERE run_id = $1
            """, run_id, total_attacks)
            
            logger.info(f"Completed attack run {run_id} with {total_attacks} attacks")
    
    async def get_attack_run(self, run_id: int) -> Optional[Dict]:
        """Get attack run details"""
        async with self.connection_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM attack_runs WHERE run_id = $1
            """, run_id)
            
            return dict(row) if row else None
    
    # ========================================================================
    # Attack Metrics Management
    # ========================================================================
    
    async def insert_attack_metrics_batch(self, metrics: List[Dict[str, Any]]):
        """Insert multiple attack metrics efficiently"""
        if not metrics:
            return
            
        async with self.connection_pool.acquire() as conn:
            await conn.executemany("""
                INSERT INTO attack_metrics (
                    run_id, timestamp, tier, attack_type, attack_category, 
                    payload, response_time_ms, threat_score, confidence,
                    action_taken, blocked, status_code, source_ip, user_agent, error_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            """, [
                (
                    m.get('run_id'), 
                    m.get('timestamp', datetime.now()),
                    m.get('tier'),
                    m.get('attack_type'),
                    m.get('attack_category'),
                    m.get('payload'),
                    m.get('response_time_ms'),
                    m.get('threat_score'),
                    m.get('confidence'),
                    m.get('action_taken'),
                    m.get('blocked', False),
                    m.get('status_code'),
                    m.get('source_ip'),
                    m.get('user_agent'),
                    m.get('error_message')
                ) for m in metrics
            ])
            
        logger.info(f"Inserted {len(metrics)} attack metrics")
    
    async def get_attack_metrics(
        self, 
        run_id: Optional[int] = None,
        tier: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Get attack metrics with optional filtering"""
        query = "SELECT * FROM attack_metrics WHERE 1=1"
        params = []
        param_count = 0
        
        if run_id:
            param_count += 1
            query += f" AND run_id = ${param_count}"
            params.append(run_id)
            
        if tier:
            param_count += 1
            query += f" AND tier = ${param_count}"
            params.append(tier)
        
        query += f" ORDER BY timestamp DESC LIMIT ${param_count + 1}"
        params.append(limit)
        
        async with self.connection_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    # ========================================================================
    # Statistics and Analytics
    # ========================================================================
    
    async def get_tier_statistics(self, run_id: int) -> List[Dict]:
        """Get tier performance statistics for a run"""
        async with self.connection_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM tier_statistics WHERE run_id = $1 ORDER BY tier
            """, run_id)
            return [dict(row) for row in rows]
    
    async def calculate_tier_statistics(self, run_id: int):
        """Recalculate tier statistics for a run"""
        async with self.connection_pool.acquire() as conn:
            await conn.execute("SELECT calculate_tier_stats($1)", run_id)
            logger.info(f"Calculated tier statistics for run {run_id}")
    
    async def get_attack_type_breakdown(self, hours_back: int = 24) -> List[Dict]:
        """Get attack type breakdown for the last N hours"""
        async with self.connection_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM attack_type_breakdown 
                WHERE last_attack > NOW() - INTERVAL '{} hours'
                ORDER BY attack_count DESC
            """.format(hours_back))
            return [dict(row) for row in rows]
    
    async def get_tier_performance_comparison(self, hours_back: int = 1) -> List[Dict]:
        """Get current tier performance comparison"""
        async with self.connection_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT 
                    tier,
                    COUNT(*) as total_requests,
                    COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_requests,
                    ROUND((COUNT(CASE WHEN blocked = true THEN 1 END)::NUMERIC / COUNT(*) * 100), 2) as block_rate_percent,
                    ROUND(AVG(response_time_ms), 2) as avg_response_time_ms,
                    ROUND(AVG(threat_score), 3) as avg_threat_score,
                    MAX(timestamp) as last_attack
                FROM attack_metrics 
                WHERE timestamp > NOW() - INTERVAL '{} hours'
                GROUP BY tier
                ORDER BY block_rate_percent DESC
            """.format(hours_back))
            return [dict(row) for row in rows]
    
    # ========================================================================
    # Real-time Operations
    # ========================================================================
    
    async def get_live_attack_stats(self) -> Dict[str, Any]:
        """Get real-time attack statistics"""
        async with self.connection_pool.acquire() as conn:
            # Get current active runs
            active_runs = await conn.fetch("""
                SELECT run_id, start_time, intensity_level, strategy
                FROM attack_runs 
                WHERE end_time IS NULL OR end_time > NOW() - INTERVAL '5 minutes'
                ORDER BY start_time DESC
            """)
            
            # Get recent attack counts by tier
            tier_counts = await conn.fetch("""
                SELECT 
                    tier,
                    COUNT(*) as attack_count,
                    COUNT(CASE WHEN blocked THEN 1 END) as blocked_count,
                    AVG(response_time_ms) as avg_response_time
                FROM attack_metrics 
                WHERE timestamp > NOW() - INTERVAL '1 minute'
                GROUP BY tier
            """)
            
            return {
                "active_runs": [dict(row) for row in active_runs],
                "tier_metrics": [dict(row) for row in tier_counts],
                "last_updated": datetime.now().isoformat()
            }
    
    # ========================================================================
    # Cache Pattern Management
    # ========================================================================
    
    async def get_cached_pattern(self, pattern_hash: str) -> Optional[Dict]:
        """Get cached attack pattern"""
        async with self.connection_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT threat_analysis, hit_count FROM attack_patterns 
                WHERE pattern_hash = $1 
                AND (expires_at IS NULL OR expires_at > NOW())
            """, pattern_hash)
            
            if row:
                # Update hit count
                await conn.execute("""
                    UPDATE attack_patterns 
                    SET hit_count = hit_count + 1, last_hit = NOW()
                    WHERE pattern_hash = $1
                """, pattern_hash)
                
                return {
                    "threat_analysis": row["threat_analysis"],
                    "hit_count": row["hit_count"] + 1
                }
            return None
    
    async def cache_attack_pattern(
        self, 
        pattern_hash: str,
        pattern_type: str,
        threat_analysis: Dict[str, Any],
        expires_hours: Optional[int] = None
    ):
        """Cache an attack pattern"""
        expires_at = None
        if expires_hours:
            expires_at = f"NOW() + INTERVAL '{expires_hours} hours'"
        
        async with self.connection_pool.acquire() as conn:
            await conn.execute(f"""
                INSERT INTO attack_patterns (pattern_hash, pattern_type, threat_analysis, expires_at)
                VALUES ($1, $2, $3, {expires_at or 'NULL'})
                ON CONFLICT (pattern_hash) DO UPDATE SET
                    threat_analysis = EXCLUDED.threat_analysis,
                    hit_count = attack_patterns.hit_count + 1,
                    last_hit = NOW()
            """, pattern_hash, pattern_type, json.dumps(threat_analysis))
    
    # ========================================================================
    # Maintenance Operations
    # ========================================================================
    
    async def cleanup_old_data(self, days_to_keep: int = 30) -> int:
        """Clean up old attack data"""
        async with self.connection_pool.acquire() as conn:
            deleted_count = await conn.fetchval(
                "SELECT cleanup_old_data($1)", days_to_keep
            )
            logger.info(f"Cleaned up {deleted_count} old attack runs")
            return deleted_count
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        async with self.connection_pool.acquire() as conn:
            # Table sizes
            table_stats = await conn.fetch("""
                SELECT 
                    schemaname,
                    tablename,
                    n_tup_ins as inserts,
                    n_tup_upd as updates,
                    n_tup_del as deletes,
                    n_live_tup as live_tuples,
                    n_dead_tup as dead_tuples
                FROM pg_stat_user_tables 
                WHERE schemaname = $1
                ORDER BY n_live_tup DESC
            """, self.config.schema)
            
            # Connection stats
            connection_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(CASE WHEN state = 'active' THEN 1 END) as active_connections,
                    COUNT(CASE WHEN state = 'idle' THEN 1 END) as idle_connections
                FROM pg_stat_activity
                WHERE datname = $1
            """, self.config.database)
            
            return {
                "table_statistics": [dict(row) for row in table_stats],
                "connection_statistics": dict(connection_stats),
                "schema": self.config.schema,
                "timestamp": datetime.now().isoformat()
            }

# Global instance
supabase_manager = SupabaseManager()

# Example usage
async def test_supabase_connection():
    """Test Supabase connection and operations"""
    try:
        await supabase_manager.initialize_async_pool()
        
        # Test creating attack run
        run_id = await supabase_manager.create_attack_run(
            intensity="medium",
            strategy="test",
            duration=60,
            config={"test": True}
        )
        print(f"✅ Created test attack run: {run_id}")
        
        # Test getting stats
        stats = await supabase_manager.get_database_stats()
        print(f"✅ Database stats retrieved: {len(stats['table_statistics'])} tables")
        
        # Test live stats
        live_stats = await supabase_manager.get_live_attack_stats()
        print(f"✅ Live stats retrieved: {len(live_stats['active_runs'])} active runs")
        
        await supabase_manager.close()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_supabase_connection())