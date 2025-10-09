#!/usr/bin/env python3
"""
Test script to verify normal traffic is correctly classified and not counted as blocked
"""

import asyncio
import aiohttp
import json


async def test_normal_traffic():
    """Test that normal traffic is not incorrectly classified as blocked"""
    
    url = "http://localhost:18002/analyze"
    
    # Normal traffic test cases
    normal_requests = [
        {
            "name": "Normal GET request",
            "features": {
                "method": "GET",
                "path": "/api/users",
                "client_ip": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "requests_per_minute": 5,
                "content_length": 0,
                "query_param_count": 1,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "id=123",
                "body": "",
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            },
            "context": {
                "previous_requests": 10,
                "failed_attempts": 0,
                "anomaly_score": 0.0,
                "ip_reputation": "good"
            }
        },
        {
            "name": "Normal POST request",
            "features": {
                "method": "POST",
                "path": "/api/products/search",
                "client_ip": "192.168.1.101",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "requests_per_minute": 3,
                "content_length": 50,
                "query_param_count": 0,
                "header_count": 6,
                "hour_of_day": 10,
                "query": "",
                "body": '{"search": "laptop", "category": "electronics"}',
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer valid_token_here"
                }
            },
            "context": {
                "previous_requests": 5,
                "failed_attempts": 0,
                "anomaly_score": 0.1,
                "ip_reputation": "good"
            }
        },
        {
            "name": "Normal health check",
            "features": {
                "method": "GET",
                "path": "/health",
                "client_ip": "192.168.1.102",
                "user_agent": "HealthMonitor/1.0",
                "requests_per_minute": 1,
                "content_length": 0,
                "query_param_count": 0,
                "header_count": 3,
                "hour_of_day": 15,
                "query": "",
                "body": "",
                "headers": {}
            },
            "context": {
                "previous_requests": 100,
                "failed_attempts": 0,
                "anomaly_score": 0.0,
                "ip_reputation": "excellent"
            }
        }
    ]
    
    print("=" * 80)
    print("Testing Normal Traffic Classification")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    
    async with aiohttp.ClientSession() as session:
        for req in normal_requests:
            print(f"Testing: {req['name']}")
            print(f"  Method: {req['features']['method']}")
            print(f"  Path: {req['features']['path']}")
            
            try:
                async with session.post(url, json=req, timeout=10) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        threat_score = result.get("threat_score", 0.0)
                        recommended_action = result.get("recommended_action", "unknown")
                        threat_type = result.get("threat_type", "unknown")
                        
                        print(f"  Threat Score: {threat_score:.2f}")
                        print(f"  Threat Type: {threat_type}")
                        print(f"  Action: {recommended_action}")
                        
                        # Check if classified correctly
                        is_blocked = recommended_action in ["block", "rate_limit"]
                        
                        if is_blocked:
                            print(f"  ❌ FAILED: Normal traffic incorrectly marked for blocking!")
                            failed += 1
                        else:
                            print(f"  ✅ PASSED: Correctly allowed")
                            passed += 1
                    else:
                        print(f"  ❌ FAILED: HTTP {response.status}")
                        failed += 1
                        
            except Exception as e:
                print(f"  ❌ FAILED: {e}")
                failed += 1
            
            print()
    
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return passed, failed


async def test_attack_traffic():
    """Test that actual attacks are still correctly blocked"""
    
    url = "http://localhost:18002/analyze"
    
    # Attack test cases
    attack_requests = [
        {
            "name": "SQL Injection Attack",
            "features": {
                "method": "GET",
                "path": "/api/users",
                "client_ip": "203.0.113.100",
                "user_agent": "sqlmap/1.6.12",
                "requests_per_minute": 50,
                "content_length": 100,
                "query_param_count": 3,
                "header_count": 5,
                "hour_of_day": 2,
                "query": "id=1' UNION SELECT user,password FROM users--",
                "body": "",
                "headers": {}
            },
            "context": {
                "previous_requests": 100,
                "failed_attempts": 50,
                "anomaly_score": 0.9,
                "ip_reputation": "bad"
            }
        }
    ]
    
    print("=" * 80)
    print("Testing Attack Traffic Detection")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    
    async with aiohttp.ClientSession() as session:
        for req in attack_requests:
            print(f"Testing: {req['name']}")
            print(f"  Payload: {req['features'].get('query', req['features'].get('body', ''))[:50]}...")
            
            try:
                async with session.post(url, json=req, timeout=10) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        threat_score = result.get("threat_score", 0.0)
                        recommended_action = result.get("recommended_action", "unknown")
                        threat_type = result.get("threat_type", "unknown")
                        
                        print(f"  Threat Score: {threat_score:.2f}")
                        print(f"  Threat Type: {threat_type}")
                        print(f"  Action: {recommended_action}")
                        
                        # Check if correctly blocked
                        is_blocked = recommended_action in ["block", "rate_limit"]
                        
                        if not is_blocked:
                            print(f"  ❌ FAILED: Attack not blocked!")
                            failed += 1
                        else:
                            print(f"  ✅ PASSED: Attack correctly blocked")
                            passed += 1
                    else:
                        print(f"  ❌ FAILED: HTTP {response.status}")
                        failed += 1
                        
            except Exception as e:
                print(f"  ❌ FAILED: {e}")
                failed += 1
            
            print()
    
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return passed, failed


async def main():
    print("\n" + "=" * 80)
    print("Kong Guard AI - Normal Traffic Classification Test")
    print("=" * 80)
    print()
    
    # Test normal traffic
    normal_passed, normal_failed = await test_normal_traffic()
    
    # Test attack traffic
    attack_passed, attack_failed = await test_attack_traffic()
    
    # Summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"Normal Traffic Tests: {normal_passed} passed, {normal_failed} failed")
    print(f"Attack Detection Tests: {attack_passed} passed, {attack_failed} failed")
    print()
    
    total_passed = normal_passed + attack_passed
    total_failed = normal_failed + attack_failed
    
    if total_failed == 0:
        print("✅ ALL TESTS PASSED!")
        print("Normal traffic is correctly classified and not counted as blocked.")
        return 0
    else:
        print(f"❌ {total_failed} TESTS FAILED")
        print("Please review the classification logic.")
        return 1


if __name__ == "__main__":
    exit(asyncio.run(main()))
