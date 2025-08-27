#!/usr/bin/env python3
"""
Test WebSocket connection and attack simulation for Kong Guard AI
"""
import asyncio
import websockets
import json
import httpx

async def test_websocket_connection():
    """Test WebSocket connection and attack simulation"""
    print("🔌 Testing WebSocket connection to Kong Guard AI...")
    
    try:
        # Connect to WebSocket
        uri = "ws://localhost:18002/ws"
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully!")
            
            # Set up message handler
            async def listen_for_messages():
                try:
                    while True:
                        message = await websocket.recv()
                        data = json.loads(message)
                        if data.get("type") == "threat_analysis":
                            print(f"📊 Received threat analysis: {data['data']['threat_type']} (Score: {data['data']['threat_score']:.2f})")
                        elif data.get("type") == "connection":
                            print(f"🔗 Connection established: {data['message']}")
                        else:
                            print(f"📨 Message: {data}")
                except websockets.exceptions.ConnectionClosed:
                    print("🔌 WebSocket connection closed")
            
            # Start listening in background
            listen_task = asyncio.create_task(listen_for_messages())
            
            # Wait a moment to establish connection
            await asyncio.sleep(1)
            
            # Send test attack via HTTP API
            print("🔥 Sending SQL injection attack...")
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:18002/analyze",
                    json={
                        "features": {
                            "method": "GET",
                            "path": "/api/users",
                            "client_ip": "192.168.1.100",
                            "user_agent": "AttackBot/1.0",
                            "requests_per_minute": 10,
                            "content_length": 0,
                            "query_param_count": 1,
                            "header_count": 5,
                            "hour_of_day": 14,
                            "query": "id=1' OR '1'='1",
                            "body": ""
                        },
                        "context": {
                            "previous_requests": 5,
                            "failed_attempts": 2,
                            "anomaly_score": 0.3
                        }
                    }
                )
                
                if response.status_code == 200:
                    print("✅ HTTP request successful")
                    result = response.json()
                    print(f"📈 API Response: {result['threat_type']} (Score: {result['threat_score']:.2f})")
                else:
                    print(f"❌ HTTP request failed: {response.status_code}")
                    print(response.text)
            
            # Wait for WebSocket messages
            print("⏳ Waiting for WebSocket messages...")
            await asyncio.sleep(3)
            
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
                
    except Exception as e:
        print(f"❌ WebSocket connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket_connection())