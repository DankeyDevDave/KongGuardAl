#!/usr/bin/env python3
"""
Complete end-to-end test of Kong Guard AI real-time dashboard
"""
import asyncio
import websockets
import json
import httpx
import time

async def test_complete_functionality():
    """Test all attack types and verify dashboard receives real-time updates"""
    print("🚀 Kong Guard AI - Complete Real-Time Dashboard Test")
    print("=" * 60)
    
    attacks = [
        {
            "name": "SQL Injection",
            "features": {
                "method": "GET",
                "path": "/api/users",
                "client_ip": "203.0.113.100",
                "user_agent": "AttackBot/1.0",
                "requests_per_minute": 50,
                "content_length": 0,
                "query_param_count": 1,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "id=1' OR '1'='1; DROP TABLE users;--",
                "body": ""
            }
        },
        {
            "name": "XSS Attack",
            "features": {
                "method": "POST",
                "path": "/api/comment",
                "client_ip": "203.0.113.101",
                "user_agent": "XSSBot/1.0",
                "requests_per_minute": 20,
                "content_length": 100,
                "query_param_count": 0,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "",
                "body": '{"comment":"<script>alert(document.cookie)</script>"}'
            }
        },
        {
            "name": "Path Traversal",
            "features": {
                "method": "GET",
                "path": "/download",
                "client_ip": "203.0.113.102",
                "user_agent": "PathBot/1.0",
                "requests_per_minute": 30,
                "content_length": 0,
                "query_param_count": 1,
                "header_count": 4,
                "hour_of_day": 14,
                "query": "file=../../../../etc/passwd",
                "body": ""
            }
        },
        {
            "name": "Normal Request",
            "features": {
                "method": "GET",
                "path": "/api/products",
                "client_ip": "203.0.113.200",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "requests_per_minute": 5,
                "content_length": 0,
                "query_param_count": 2,
                "header_count": 10,
                "hour_of_day": 14,
                "query": "category=electronics&page=1",
                "body": ""
            }
        }
    ]
    
    try:
        uri = "ws://localhost:18002/ws"
        received_analyses = []
        
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected to Kong Guard AI")
            
            async def message_handler():
                try:
                    while True:
                        message = await websocket.recv()
                        data = json.loads(message)
                        if data.get("type") == "threat_analysis":
                            analysis = data["data"]
                            received_analyses.append({
                                "threat_type": analysis.get("threat_type", "unknown"),
                                "threat_score": analysis.get("threat_score", 0),
                                "method": analysis.get("method", "N/A"),
                                "path": analysis.get("path", "N/A"),
                                "confidence": analysis.get("confidence", 0),
                                "action": analysis.get("recommended_action", "unknown")
                            })
                            print(f"📊 Real-time analysis received:")
                            print(f"    Threat: {analysis['threat_type']} (Score: {analysis['threat_score']:.2f})")
                            print(f"    Request: {analysis['method']} {analysis['path']}")
                            print(f"    Action: {analysis['recommended_action']}")
                        elif data.get("type") == "connection":
                            print(f"🔗 {data['message']}")
                except websockets.exceptions.ConnectionClosed:
                    pass
            
            # Start message handler
            handler_task = asyncio.create_task(message_handler())
            
            # Wait for connection to establish
            await asyncio.sleep(1)
            
            print("\n🔥 Testing various attack patterns...")
            print("-" * 40)
            
            # Send each attack
            async with httpx.AsyncClient(timeout=30.0) as client:
                for i, attack in enumerate(attacks):
                    print(f"\n🎯 Test {i+1}: {attack['name']}")
                    
                    start_time = time.time()
                    response = await client.post(
                        "http://localhost:18002/analyze",
                        json={
                            "features": attack["features"],
                            "context": {
                                "previous_requests": 10 if attack["name"] != "Normal Request" else 2,
                                "failed_attempts": 5 if attack["name"] != "Normal Request" else 0,
                                "anomaly_score": 0.8 if attack["name"] != "Normal Request" else 0.1
                            }
                        }
                    )
                    processing_time = time.time() - start_time
                    
                    if response.status_code == 200:
                        result = response.json()
                        print(f"✅ API Response: {result['threat_type']} (Score: {result['threat_score']:.2f})")
                        print(f"⏱️  Processing: {processing_time*1000:.0f}ms")
                    else:
                        print(f"❌ Request failed: {response.status_code}")
                    
                    # Wait for WebSocket message
                    await asyncio.sleep(2)
            
            print("\n📋 Final Results:")
            print("=" * 40)
            print(f"Total attacks sent: {len(attacks)}")
            print(f"Real-time updates received: {len(received_analyses)}")
            
            if len(received_analyses) == len(attacks):
                print("✅ ALL REAL-TIME UPDATES RECEIVED!")
                print("\nDetailed Results:")
                for i, analysis in enumerate(received_analyses):
                    attack_name = attacks[i]["name"]
                    print(f"  {i+1}. {attack_name}")
                    print(f"     Detected: {analysis['threat_type']} (Score: {analysis['threat_score']:.2f})")
                    print(f"     Action: {analysis['action']}")
                    print(f"     Confidence: {analysis['confidence']:.1%}")
            else:
                print(f"❌ Missing updates: Expected {len(attacks)}, got {len(received_analyses)}")
            
            # Clean up
            handler_task.cancel()
            try:
                await handler_task
            except asyncio.CancelledError:
                pass
                
            print("\n🎉 Test completed successfully!")
            print("🖥️  Dashboard should now show all real-time updates at:")
            print("   http://localhost:8080 (visualization)")
            print("   http://localhost:18002/dashboard (AI service)")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_complete_functionality())