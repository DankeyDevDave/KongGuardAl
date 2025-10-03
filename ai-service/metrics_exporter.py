"""
SQLite Attack Metrics Exporter for Prometheus
Exports historical attack data from attack_metrics.db to Prometheus format
"""

import logging
import sqlite3
from datetime import datetime
from datetime import timedelta
from pathlib import Path

from prometheus_client import Gauge

logger = logging.getLogger(__name__)


class AttackMetricsExporter:
    """Export attack metrics from SQLite database to Prometheus"""

    def __init__(self, db_path: str = "../attack_metrics.db"):
        # Try multiple locations for the database
        possible_paths = [
            Path("/app/attack_metrics.db"),  # Docker mount
            Path(__file__).parent / "attack_metrics.db",  # Same directory
            Path(__file__).parent.parent / "attack_metrics.db",  # Parent directory
        ]

        self.db_path = None
        for path in possible_paths:
            if path.exists():
                self.db_path = path
                self.db_available = True
                logger.info(f"Attack metrics database found: {self.db_path}")
                break

        if not self.db_path:
            logger.warning(f"Attack metrics database not found in any location: {possible_paths}")
            self.db_available = False

        # Define Prometheus metrics
        self.db_total_attacks = Gauge(
            "kong_guard_db_total_attacks",
            "Total attacks recorded in database",
        )

        self.db_attacks_by_category = Gauge(
            "kong_guard_db_attacks_by_category",
            "Attacks by category from database",
            ["attack_category"],
        )

        self.db_blocked_count = Gauge(
            "kong_guard_db_blocked_total",
            "Total blocked attacks in database",
        )

        self.db_allowed_count = Gauge(
            "kong_guard_db_allowed_total",
            "Total allowed attacks in database",
        )

        self.db_avg_threat_score = Gauge(
            "kong_guard_db_avg_threat_score",
            "Average threat score from database",
        )

        self.db_avg_response_time = Gauge(
            "kong_guard_db_avg_response_time_ms",
            "Average response time in milliseconds",
        )

        self.db_recent_attacks_1h = Gauge(
            "kong_guard_db_recent_attacks_1h",
            "Attacks in the last hour",
        )

        self.db_recent_attacks_24h = Gauge(
            "kong_guard_db_recent_attacks_24h",
            "Attacks in the last 24 hours",
        )

        self.db_unique_source_ips = Gauge(
            "kong_guard_db_unique_source_ips",
            "Number of unique source IPs",
        )

        self.db_attack_runs = Gauge(
            "kong_guard_db_attack_runs_total",
            "Total attack simulation runs",
        )

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def export_metrics(self) -> dict[str, any]:
        """Export all metrics from database"""
        if not self.db_available:
            return {"error": "Database not available"}

        try:
            conn = self._get_connection()
            cur = conn.cursor()

            # Total attacks
            cur.execute("SELECT COUNT(*) as total FROM attack_metrics")
            total = cur.fetchone()["total"]
            self.db_total_attacks.set(total)

            # Attacks by category
            cur.execute(
                """
                SELECT attack_category, COUNT(*) as count
                FROM attack_metrics
                WHERE attack_category IS NOT NULL
                GROUP BY attack_category
            """
            )
            for row in cur.fetchall():
                category = row["attack_category"] or "unknown"
                self.db_attacks_by_category.labels(attack_category=category).set(row["count"])

            # Blocked vs allowed
            cur.execute("SELECT blocked, COUNT(*) as count FROM attack_metrics GROUP BY blocked")
            for row in cur.fetchall():
                if row["blocked"]:
                    self.db_blocked_count.set(row["count"])
                else:
                    self.db_allowed_count.set(row["count"])

            # Average threat score
            cur.execute("SELECT AVG(threat_score) as avg_score FROM attack_metrics WHERE threat_score IS NOT NULL")
            avg_score = cur.fetchone()["avg_score"] or 0.0
            self.db_avg_threat_score.set(avg_score)

            # Average response time
            cur.execute(
                "SELECT AVG(response_time_ms) as avg_time FROM attack_metrics WHERE response_time_ms IS NOT NULL"
            )
            avg_time = cur.fetchone()["avg_time"] or 0.0
            self.db_avg_response_time.set(avg_time)

            # Recent attacks (last 1 hour)
            one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cur.execute("SELECT COUNT(*) as count FROM attack_metrics WHERE timestamp >= ?", (one_hour_ago,))
            self.db_recent_attacks_1h.set(cur.fetchone()["count"])

            # Recent attacks (last 24 hours)
            day_ago = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            cur.execute("SELECT COUNT(*) as count FROM attack_metrics WHERE timestamp >= ?", (day_ago,))
            self.db_recent_attacks_24h.set(cur.fetchone()["count"])

            # Unique source IPs
            cur.execute("SELECT COUNT(DISTINCT source_ip) as count FROM attack_metrics WHERE source_ip IS NOT NULL")
            self.db_unique_source_ips.set(cur.fetchone()["count"])

            # Attack runs
            cur.execute("SELECT COUNT(*) as count FROM attack_runs")
            self.db_attack_runs.set(cur.fetchone()["count"])

            conn.close()

            logger.info(f"Exported metrics from database: {total} total attacks")
            return {
                "total_attacks": total,
                "avg_threat_score": avg_score,
                "recent_1h": self.db_recent_attacks_1h._value.get(),
                "status": "success",
            }

        except Exception as e:
            logger.error(f"Error exporting metrics from database: {e}")
            return {"error": str(e), "status": "failed"}

    def get_attack_rate_stats(self) -> dict[str, float]:
        """Calculate attack rate statistics for the last hour"""
        if not self.db_available:
            return {}

        try:
            conn = self._get_connection()
            cur = conn.cursor()

            # Get attack counts in 5-minute buckets for the last hour
            cur.execute(
                """
                SELECT
                    strftime('%Y-%m-%d %H:%M', timestamp, 'start of hour',
                             printf('%d minutes', (cast(strftime('%M', timestamp) as int) / 5) * 5)) as bucket,
                    COUNT(*) as count
                FROM attack_metrics
                WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY bucket
                ORDER BY bucket
            """
            )

            buckets = cur.fetchall()
            conn.close()

            if not buckets:
                return {"attack_rate_per_min": 0.0, "peak_rate": 0.0}

            total_attacks = sum(row["count"] for row in buckets)
            avg_rate = total_attacks / 60.0  # attacks per minute over last hour
            peak_rate = max(row["count"] for row in buckets) / 5.0  # peak attacks per minute in a 5-min bucket

            return {"attack_rate_per_min": avg_rate, "peak_rate_per_min": peak_rate}

        except Exception as e:
            logger.error(f"Error calculating attack rate stats: {e}")
            return {}
