#!/usr/bin/env python3
"""
Quick test script to verify all major attack categories work with Kong Guard AI
"""

import asyncio
from typing import Any

import httpx


class AttackTester:
    def __init__(self):
        self.ai_service_url = "http://localhost:18002"
        self.attack_tests = {
            "SQL Injection": {"body": "SELECT * FROM users WHERE id=1 OR 1=1", "expected_threat": "SQL Injection"},
            "XSS Attack": {"body": "<script>alert('XSS')</script>", "expected_threat": "XSS"},
            "Command Injection": {"body": "; rm -rf / #", "expected_threat": "Command Injection"},
            "Path Traversal": {"path": "/api/file?path=../../../etc/passwd", "expected_threat": "Path Traversal"},
            "LDAP Injection": {"body": "admin')(&(password=*))", "expected_threat": "LDAP Injection"},
        }

    async def test_attack(self, name: str, attack_data: dict[str, Any]) -> dict[str, Any]:
        """Test a specific attack pattern"""
        request_data = {
            "features": {
                "method": "POST",
                "path": attack_data.get("path", "/api/test"),
                "client_ip": "203.0.113.100",
                "user_agent": "Mozilla/5.0 (AttackTest)",
                "requests_per_minute": 1,
                "content_length": len(attack_data.get("body", "")),
                "query_param_count": 1 if "?" in attack_data.get("path", "") else 0,
                "header_count": 3,
                "hour_of_day": 14,
                "query": attack_data.get("query", ""),
                "body": attack_data.get("body", ""),
                "headers": {"Content-Type": "application/json"},
            },
            "context": {"previous_requests": 0},
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(f"{self.ai_service_url}/analyze", json=request_data, timeout=10.0)

                if response.status_code == 200:
                    result = response.json()
                    return {
                        "name": name,
                        "success": True,
                        "threat_score": result.get("threat_score", 0),
                        "threat_type": result.get("threat_type", "Unknown"),
                        "confidence": result.get("confidence", 0),
                        "expected": attack_data["expected_threat"],
                        "detected": result.get("threat_type", ""),
                        "processing_time": result.get("processing_time", 0),
                    }
                else:
                    return {"name": name, "success": False, "error": f"HTTP {response.status_code}"}

            except Exception as e:
                return {"name": name, "success": False, "error": str(e)}

    async def run_all_tests(self):
        """Run all attack tests"""
        print("🔥 Kong Guard AI - Attack Category Testing")
        print("=" * 60)
        print(f"🎯 Target Service: {self.ai_service_url}")
        print()

        results = []
        total_tests = len(self.attack_tests)
        successful_detections = 0

        for i, (attack_name, attack_data) in enumerate(self.attack_tests.items(), 1):
            print(f"🧪 Test {i}/{total_tests}: {attack_name}")

            result = await self.test_attack(attack_name, attack_data)
            results.append(result)

            if result["success"]:
                threat_score = result["threat_score"]
                detected = result["detected"]
                expected = result["expected"]
                processing_time = result["processing_time"] * 1000  # Convert to ms

                if threat_score > 0.5:  # Threshold for successful detection
                    successful_detections += 1
                    print(f"   ✅ DETECTED: {detected} (Score: {threat_score:.2f}, Time: {processing_time:.1f}ms)")
                else:
                    print(f"   ⚠️  LOW SCORE: {detected} (Score: {threat_score:.2f})")
            else:
                print(f"   ❌ FAILED: {result.get('error', 'Unknown error')}")

            # Small delay between tests
            await asyncio.sleep(0.5)

        print()
        print("=" * 60)
        print("📊 RESULTS SUMMARY")
        print("=" * 60)
        print(f"🎯 Total Tests: {total_tests}")
        print(f"✅ Successful Detections: {successful_detections}")
        print(f"📈 Detection Rate: {(successful_detections/total_tests)*100:.1f}%")

        if successful_detections >= total_tests * 0.8:  # 80% success rate
            print()
            print("🎉 EXCELLENT! Kong Guard AI successfully detected most attack patterns.")
            print("🛡️  Ready for enterprise demonstration!")
        else:
            print()
            print("⚠️  Some attacks had low detection scores. Review AI model configuration.")

        return results


async def main():
    tester = AttackTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
