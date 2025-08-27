#!/usr/bin/env python3
"""
Test dashboard data structure and verify all fields display correctly
"""
import asyncio
import httpx
import json

async def test_dashboard_data():
    """Send specific test cases to verify dashboard displays data correctly"""
    
    print("🧪 Testing Dashboard Data Display...")
    print("=" * 50)
    
    test_cases = [
        {
            "name": "High-Confidence SQL Injection",
            "payload": {
                "features": {
                    "method": "POST",
                    "path": "/api/login",
                    "client_ip": "203.0.113.42",
                    "user_agent": "sqlmap/1.6.12",
                    "requests_per_minute": 25,
                    "content_length": 150,
                    "query_param_count": 0,
                    "header_count": 8,
                    "hour_of_day": 15,
                    "query": "",
                    "body": "{\"username\": \"admin'--\", \"password\": \"1' OR '1'='1\"}"
                },
                "context": {
                    "previous_requests": 15,
                    "failed_attempts": 8,
                    "anomaly_score": 0.9
                }
            }
        },
        {
            "name": "Medium-Risk XSS Attempt",
            "payload": {
                "features": {
                    "method": "POST",
                    "path": "/api/comments",
                    "client_ip": "198.51.100.123",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "requests_per_minute": 12,
                    "content_length": 200,
                    "query_param_count": 1,
                    "header_count": 12,
                    "hour_of_day": 14,
                    "query": "post_id=42",
                    "body": "{\"comment\": \"Great post! <script>alert('XSS');</script>\"}"
                },
                "context": {
                    "previous_requests": 5,
                    "failed_attempts": 1,
                    "anomaly_score": 0.6
                }
            }
        },
        {
            "name": "Low-Risk Normal Request",
            "payload": {
                "features": {
                    "method": "GET",
                    "path": "/api/products",
                    "client_ip": "192.0.2.100",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "requests_per_minute": 3,
                    "content_length": 0,
                    "query_param_count": 3,
                    "header_count": 15,
                    "hour_of_day": 14,
                    "query": "category=electronics&page=1&sort=price",
                    "body": ""
                },
                "context": {
                    "previous_requests": 25,
                    "failed_attempts": 0,
                    "anomaly_score": 0.1
                }
            }
        }
    ]
    
    print("📊 Sending test requests to verify dashboard data...")
    print("-" * 30)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n🎯 Test {i}: {test_case['name']}")
            
            try:
                response = await client.post(
                    "http://localhost:18002/analyze",
                    json=test_case["payload"]
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    print(f"✅ Request successful")
                    print(f"   Threat Type: {result.get('threat_type', 'N/A')}")
                    print(f"   Threat Score: {result.get('threat_score', 0):.2f}")
                    print(f"   Confidence: {result.get('confidence', 0):.1%}")
                    print(f"   Processing Time: {result.get('processing_time', 0)*1000:.0f}ms")
                    print(f"   Action: {result.get('recommended_action', 'N/A')}")
                    print(f"   Reasoning: {result.get('reasoning', 'N/A')[:100]}...")
                    
                    # Verify expected data structure
                    required_fields = ['threat_score', 'threat_type', 'confidence', 'reasoning', 'recommended_action']
                    missing_fields = [field for field in required_fields if field not in result or result[field] is None]
                    
                    if missing_fields:
                        print(f"⚠️  Missing fields: {missing_fields}")
                    else:
                        print("✅ All required fields present")
                        
                else:
                    print(f"❌ Request failed: {response.status_code}")
                    print(f"   Response: {response.text}")
                
                # Wait between requests
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"❌ Test failed: {e}")
    
    print("\n" + "=" * 50)
    print("🖥️  Check the dashboard at: http://localhost:8080/simple-ai-dashboard.html")
    print("📊 You should now see:")
    print("   • Correct confidence percentages (not NaN%)")
    print("   • Proper threat reasoning text")
    print("   • Valid request details (not N/A)")
    print("   • Accurate processing times")
    print("   • Recent analysis history with real data")

if __name__ == "__main__":
    asyncio.run(test_dashboard_data())