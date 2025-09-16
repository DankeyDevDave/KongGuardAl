#!/usr/bin/env python3
"""
Kong Guard AI - Database Adapter
Supports both SQLite (local) and Supabase (self-hosted) databases
"""

import json
import logging
import os
import sqlite3
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime

# Optional imports for Supabase
try:
    from supabase import Client
    from supabase import create_client

    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("⚠️  Supabase client not installed. Run: pip install supabase")

logger = logging.getLogger(__name__)


@dataclass
class AttackConfig:
    """Attack simulation configuration"""

    intensity: str
    strategy: str
    duration: int
    targets: list[str]
    record_metrics: bool = True


@dataclass
class AttackMetric:
    """Individual attack metric record"""

    run_id: int
    tier: str
    attack_type: str
    attack_category: str
    payload: str
    response_time_ms: float
    threat_score: float = 0.0
    confidence: float = 0.0
    action_taken: str = ""
    blocked: bool = False
    status_code: int = 0
    source_ip: str = "127.0.0.1"
    user_agent: str = ""
    error_message: str = ""


class DatabaseAdapter(ABC):
    """Abstract base class for database operations"""

    @abstractmethod
    def setup_database(self) -> None:
        """Initialize database schema"""
        pass

    @abstractmethod
    def create_attack_run(self, config: AttackConfig) -> int:
        """Create new attack run and return run_id"""
        pass

    @abstractmethod
    def save_attack_metric(self, metric: AttackMetric) -> None:
        """Save individual attack metric"""
        pass

    @abstractmethod
    def save_attack_metrics_batch(self, metrics: list[AttackMetric]) -> None:
        """Save multiple attack metrics efficiently"""
        pass

    @abstractmethod
    def complete_attack_run(self, run_id: int, total_attacks: int) -> None:
        """Mark attack run as completed with final statistics"""
        pass

    @abstractmethod
    def get_attack_runs(self, limit: int = 50) -> list[dict]:
        """Get recent attack runs"""
        pass

    @abstractmethod
    def get_run_statistics(self, run_id: int) -> dict:
        """Get comprehensive statistics for a specific run"""
        pass


class SQLiteAdapter(DatabaseAdapter):
    """SQLite database adapter (local development)"""

    def __init__(self, db_path: str = "attack_metrics.db"):
        self.db_path = db_path
        self.setup_database()

    def setup_database(self) -> None:
        """Initialize SQLite database with comprehensive schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Attack run metadata
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                total_attacks INTEGER DEFAULT 0,
                intensity_level TEXT,
                strategy TEXT,
                duration INTEGER,
                config_json TEXT
            )
        """
        )

        # Individual attack metrics
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tier TEXT,
                attack_type TEXT,
                attack_category TEXT,
                payload TEXT,
                response_time_ms REAL,
                threat_score REAL,
                confidence REAL,
                action_taken TEXT,
                blocked BOOLEAN,
                status_code INTEGER,
                source_ip TEXT,
                user_agent TEXT,
                error_message TEXT,
                FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
            )
        """
        )

        # Tier statistics
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tier_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                tier TEXT,
                total_requests INTEGER,
                attacks_blocked INTEGER,
                attacks_allowed INTEGER,
                avg_response_time REAL,
                detection_rate REAL,
                min_threat_score REAL,
                max_threat_score REAL,
                avg_threat_score REAL,
                FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
            )
        """
        )

        # Performance metrics
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                metric_type TEXT,
                metric_value REAL,
                metric_unit TEXT,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
            )
        """
        )

        conn.commit()
        conn.close()
        logger.info("SQLite database schema initialized")

    def create_attack_run(self, config: AttackConfig) -> int:
        """Create new attack run and return run_id"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO attack_runs (intensity_level, strategy, duration, config_json)
            VALUES (?, ?, ?, ?)
        """,
            (
                config.intensity,
                config.strategy,
                config.duration,
                json.dumps({"targets": config.targets, "record_metrics": config.record_metrics}),
            ),
        )

        run_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"Created attack run {run_id} with config: {config}")
        return run_id

    def save_attack_metric(self, metric: AttackMetric) -> None:
        """Save individual attack metric"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO attack_metrics (
                run_id, tier, attack_type, attack_category, payload,
                response_time_ms, threat_score, confidence, action_taken,
                blocked, status_code, source_ip, user_agent, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                metric.run_id,
                metric.tier,
                metric.attack_type,
                metric.attack_category,
                metric.payload,
                metric.response_time_ms,
                metric.threat_score,
                metric.confidence,
                metric.action_taken,
                metric.blocked,
                metric.status_code,
                metric.source_ip,
                metric.user_agent,
                metric.error_message,
            ),
        )

        conn.commit()
        conn.close()

    def save_attack_metrics_batch(self, metrics: list[AttackMetric]) -> None:
        """Save multiple attack metrics efficiently"""
        if not metrics:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        data = [
            (
                m.run_id,
                m.tier,
                m.attack_type,
                m.attack_category,
                m.payload,
                m.response_time_ms,
                m.threat_score,
                m.confidence,
                m.action_taken,
                m.blocked,
                m.status_code,
                m.source_ip,
                m.user_agent,
                m.error_message,
            )
            for m in metrics
        ]

        cursor.executemany(
            """
            INSERT INTO attack_metrics (
                run_id, tier, attack_type, attack_category, payload,
                response_time_ms, threat_score, confidence, action_taken,
                blocked, status_code, source_ip, user_agent, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            data,
        )

        conn.commit()
        conn.close()

        logger.info(f"Saved {len(metrics)} attack metrics to SQLite")

    def complete_attack_run(self, run_id: int, total_attacks: int) -> None:
        """Mark attack run as completed with final statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE attack_runs
            SET end_time = CURRENT_TIMESTAMP, total_attacks = ?
            WHERE run_id = ?
        """,
            (total_attacks, run_id),
        )

        # Calculate and save tier statistics
        cursor.execute(
            """
            SELECT tier,
                   COUNT(*) as total_requests,
                   COUNT(CASE WHEN blocked = 1 THEN 1 END) as attacks_blocked,
                   COUNT(CASE WHEN blocked = 0 THEN 1 END) as attacks_allowed,
                   AVG(response_time_ms) as avg_response_time,
                   MIN(threat_score) as min_threat_score,
                   MAX(threat_score) as max_threat_score,
                   AVG(threat_score) as avg_threat_score
            FROM attack_metrics
            WHERE run_id = ?
            GROUP BY tier
        """,
            (run_id,),
        )

        tier_stats = cursor.fetchall()

        for stats in tier_stats:
            tier, total, blocked, allowed, avg_time, min_score, max_score, avg_score = stats
            detection_rate = (blocked / total * 100) if total > 0 else 0

            cursor.execute(
                """
                INSERT INTO tier_statistics (
                    run_id, tier, total_requests, attacks_blocked, attacks_allowed,
                    avg_response_time, detection_rate, min_threat_score,
                    max_threat_score, avg_threat_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (run_id, tier, total, blocked, allowed, avg_time, detection_rate, min_score, max_score, avg_score),
            )

        conn.commit()
        conn.close()

        logger.info(f"Completed attack run {run_id} with {total_attacks} total attacks")

    def get_attack_runs(self, limit: int = 50) -> list[dict]:
        """Get recent attack runs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT run_id, start_time, end_time, total_attacks,
                   intensity_level, strategy, duration, config_json
            FROM attack_runs
            ORDER BY start_time DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

        runs = []
        for row in rows:
            runs.append(
                {
                    "run_id": row[0],
                    "start_time": row[1],
                    "end_time": row[2],
                    "total_attacks": row[3],
                    "intensity_level": row[4],
                    "strategy": row[5],
                    "duration": row[6],
                    "config": json.loads(row[7]) if row[7] else {},
                }
            )

        return runs

    def get_run_statistics(self, run_id: int) -> dict:
        """Get comprehensive statistics for a specific run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get run metadata
        cursor.execute(
            """
            SELECT start_time, end_time, total_attacks, intensity_level, strategy, duration
            FROM attack_runs WHERE run_id = ?
        """,
            (run_id,),
        )

        run_data = cursor.fetchone()
        if not run_data:
            conn.close()
            return {}

        # Get tier statistics
        cursor.execute(
            """
            SELECT tier, total_requests, attacks_blocked, attacks_allowed,
                   avg_response_time, detection_rate
            FROM tier_statistics WHERE run_id = ?
        """,
            (run_id,),
        )

        tier_stats = {}
        for row in cursor.fetchall():
            tier, total, blocked, allowed, avg_time, detection_rate = row
            tier_stats[tier] = {
                "total_requests": total,
                "attacks_blocked": blocked,
                "attacks_allowed": allowed,
                "avg_response_time": avg_time,
                "detection_rate": detection_rate,
            }

        conn.close()

        return {
            "run_id": run_id,
            "start_time": run_data[0],
            "end_time": run_data[1],
            "total_attacks": run_data[2],
            "intensity_level": run_data[3],
            "strategy": run_data[4],
            "duration": run_data[5],
            "tier_statistics": tier_stats,
        }


class SupabaseAdapter(DatabaseAdapter):
    """Supabase database adapter (self-hosted production)"""

    def __init__(self, supabase_url: str, supabase_key: str):
        if not SUPABASE_AVAILABLE:
            raise ImportError("Supabase client not available. Install with: pip install supabase")

        self.client: Client = create_client(supabase_url, supabase_key)
        logger.info(f"Connected to self-hosted Supabase at {supabase_url}")

    def setup_database(self) -> None:
        """Database schema should be set up via supabase_migration.sql"""
        logger.info("Supabase database schema managed via migration scripts")

    def create_attack_run(self, config: AttackConfig) -> int:
        """Create new attack run and return run_id"""
        data = {
            "intensity_level": config.intensity,
            "strategy": config.strategy,
            "duration": config.duration,
            "config_json": {"targets": config.targets, "record_metrics": config.record_metrics},
        }

        result = self.client.table("attack_runs").insert(data).execute()
        run_id = result.data[0]["run_id"]

        logger.info(f"Created Supabase attack run {run_id} with config: {config}")
        return run_id

    def save_attack_metric(self, metric: AttackMetric) -> None:
        """Save individual attack metric"""
        data = {
            "run_id": metric.run_id,
            "tier": metric.tier,
            "attack_type": metric.attack_type,
            "attack_category": metric.attack_category,
            "payload": metric.payload,
            "response_time_ms": metric.response_time_ms,
            "threat_score": metric.threat_score,
            "confidence": metric.confidence,
            "action_taken": metric.action_taken,
            "blocked": metric.blocked,
            "status_code": metric.status_code,
            "source_ip": metric.source_ip,
            "user_agent": metric.user_agent,
            "error_message": metric.error_message,
        }

        self.client.table("attack_metrics").insert(data).execute()

    def save_attack_metrics_batch(self, metrics: list[AttackMetric]) -> None:
        """Save multiple attack metrics efficiently"""
        if not metrics:
            return

        data = []
        for m in metrics:
            data.append(
                {
                    "run_id": m.run_id,
                    "tier": m.tier,
                    "attack_type": m.attack_type,
                    "attack_category": m.attack_category,
                    "payload": m.payload,
                    "response_time_ms": m.response_time_ms,
                    "threat_score": m.threat_score,
                    "confidence": m.confidence,
                    "action_taken": m.action_taken,
                    "blocked": m.blocked,
                    "status_code": m.status_code,
                    "source_ip": m.source_ip,
                    "user_agent": m.user_agent,
                    "error_message": m.error_message,
                }
            )

        # Supabase supports batch inserts up to 1000 records
        batch_size = 1000
        for i in range(0, len(data), batch_size):
            batch = data[i : i + batch_size]
            self.client.table("attack_metrics").insert(batch).execute()

        logger.info(f"Saved {len(metrics)} attack metrics to Supabase")

    def complete_attack_run(self, run_id: int, total_attacks: int) -> None:
        """Mark attack run as completed with final statistics"""
        # Update attack run
        self.client.table("attack_runs").update(
            {"end_time": datetime.now().isoformat(), "total_attacks": total_attacks}
        ).eq("run_id", run_id).execute()

        # Use the PostgreSQL function to calculate tier stats
        result = self.client.rpc("calculate_tier_stats", {"target_run_id": run_id}).execute()

        # Insert tier statistics
        for stats in result.data:
            self.client.table("tier_statistics").insert(
                {
                    "run_id": run_id,
                    "tier": stats["tier"],
                    "total_requests": stats["total_requests"],
                    "attacks_blocked": stats["attacks_blocked"],
                    "attacks_allowed": stats["attacks_allowed"],
                    "avg_response_time": stats["avg_response_time"],
                    "detection_rate": stats["detection_rate"],
                }
            ).execute()

        logger.info(f"Completed Supabase attack run {run_id} with {total_attacks} total attacks")

    def get_attack_runs(self, limit: int = 50) -> list[dict]:
        """Get recent attack runs"""
        result = self.client.table("attack_runs").select("*").order("start_time", desc=True).limit(limit).execute()
        return result.data

    def get_run_statistics(self, run_id: int) -> dict:
        """Get comprehensive statistics for a specific run"""
        # Get run data
        run_result = self.client.table("attack_runs").select("*").eq("run_id", run_id).execute()
        if not run_result.data:
            return {}

        run_data = run_result.data[0]

        # Get tier statistics
        stats_result = self.client.table("tier_statistics").select("*").eq("run_id", run_id).execute()

        tier_stats = {}
        for stats in stats_result.data:
            tier_stats[stats["tier"]] = {
                "total_requests": stats["total_requests"],
                "attacks_blocked": stats["attacks_blocked"],
                "attacks_allowed": stats["attacks_allowed"],
                "avg_response_time": stats["avg_response_time"],
                "detection_rate": stats["detection_rate"],
            }

        return {
            "run_id": run_data["run_id"],
            "start_time": run_data["start_time"],
            "end_time": run_data["end_time"],
            "total_attacks": run_data["total_attacks"],
            "intensity_level": run_data["intensity_level"],
            "strategy": run_data["strategy"],
            "duration": run_data["duration"],
            "tier_statistics": tier_stats,
        }


def get_database_adapter() -> DatabaseAdapter:
    """Factory function to get appropriate database adapter based on environment"""

    # Check for Supabase configuration
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if supabase_url and supabase_key and SUPABASE_AVAILABLE:
        logger.info("Using Supabase database adapter")
        return SupabaseAdapter(supabase_url, supabase_key)
    else:
        logger.info("Using SQLite database adapter (local development)")
        return SQLiteAdapter()


# Example usage
if __name__ == "__main__":
    # Test the adapter
    db = get_database_adapter()

    # Create test attack run
    config = AttackConfig(intensity="medium", strategy="wave", duration=30, targets=["unprotected"])

    run_id = db.create_attack_run(config)
    print(f"Created test run: {run_id}")

    # Get recent runs
    runs = db.get_attack_runs(limit=5)
    print(f"Recent runs: {len(runs)}")
