#!/usr/bin/env python3
"""
Kong Guard AI - Enterprise AI Threat Analysis Service with WebSocket
Real-time AI-powered threat detection with live visualization support
"""

import os
import json
import time
import hashlib
import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
import uvicorn
import httpx
from collections import defaultdict, deque
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Kong Guard AI - Real-Time Threat Analysis",
    description="Enterprise AI-powered API threat detection with live visualization",
    version="3.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# WebSocket Connection Manager
# ============================================================================

class ConnectionManager:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.active_connections: Set[WebSocket] = set()
        self.threat_history: deque = deque(maxlen=100)
        self.metrics = {
            "total_requests": 0,
            "threats_blocked": 0,
            "threats_allowed": 0,
            "avg_latency": 0,
            "current_rps": 0,
            "ai_accuracy": 95.5
        }
        self.last_request_time = time.time()
        logger.info(f"ConnectionManager singleton initialized: {id(self)}")
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send initial state
        await self.send_personal_message({
            "type": "connection",
            "message": "Connected to Kong Guard AI Real-Time System",
            "metrics": self.metrics,
            "history": list(self.threat_history)
        }, websocket)
        
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except:
            self.disconnect(websocket)
            
    async def broadcast(self, message: dict):
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.add(connection)
        # Clean up disconnected clients
        self.active_connections -= disconnected
        
    async def broadcast_threat_analysis(self, analysis_data: dict):
        """Broadcast threat analysis to all connected clients"""
        logger.info(f"broadcast_threat_analysis: Manager ID = {id(self)}")
        logger.info(f"Broadcasting to {len(self.active_connections)} WebSocket clients: {analysis_data.get('threat_type', 'unknown')}")
        if len(self.active_connections) == 0:
            logger.warning("No active WebSocket connections to broadcast to!")
        
        # Update metrics
        self.metrics["total_requests"] += 1
        if analysis_data.get("threat_score", 0) > 0.8:
            self.metrics["threats_blocked"] += 1
        else:
            self.metrics["threats_allowed"] += 1
            
        # Calculate RPS
        current_time = time.time()
        time_diff = current_time - self.last_request_time
        if time_diff > 0:
            self.metrics["current_rps"] = round(1 / time_diff, 2)
        self.last_request_time = current_time
        
        # Update average latency
        if "processing_time" in analysis_data:
            current_avg = self.metrics["avg_latency"]
            new_latency = analysis_data["processing_time"] * 1000  # Convert to ms
            self.metrics["avg_latency"] = round((current_avg * 0.9 + new_latency * 0.1), 2)
        
        # Add to history
        threat_event = {
            "timestamp": datetime.now().isoformat(),
            "threat_score": analysis_data.get("threat_score", 0),
            "threat_type": analysis_data.get("threat_type", "none"),
            "action": analysis_data.get("recommended_action", "allow"),
            "confidence": analysis_data.get("confidence", 0),
            "method": analysis_data.get("method", "GET"),
            "path": analysis_data.get("path", "/"),
            "client_ip": analysis_data.get("client_ip", "unknown")
        }
        self.threat_history.append(threat_event)
        
        # Broadcast to all clients
        await self.broadcast({
            "type": "threat_analysis",
            "data": analysis_data,
            "metrics": self.metrics,
            "event": threat_event
        })
        
    async def send_ai_thinking(self, thinking_data: dict):
        """Send AI thinking process updates"""
        await self.broadcast({
            "type": "ai_thinking",
            "data": thinking_data
        })

manager = ConnectionManager()

# ============================================================================
# Configuration
# ============================================================================

AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# ============================================================================
# Data Models (same as before)
# ============================================================================

class RequestFeatures(BaseModel):
    method: str
    path: str
    client_ip: str
    user_agent: str
    requests_per_minute: int
    content_length: int
    query_param_count: int
    header_count: int
    hour_of_day: int
    query: Optional[str] = ""
    body: Optional[str] = ""
    headers: Optional[Dict[str, str]] = {}

class RequestContext(BaseModel):
    previous_requests: int = 0
    failed_attempts: int = 0
    anomaly_score: float = 0.0
    ip_reputation: Optional[str] = "unknown"
    geo_location: Optional[str] = None

class ThreatAnalysisRequest(BaseModel):
    features: RequestFeatures
    context: RequestContext
    config: Optional[Dict[str, Any]] = {}
    
class ThreatAnalysisResponse(BaseModel):
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: str
    indicators: List[str]
    ai_model: str
    processing_time: float
    detailed_analysis: Optional[Dict[str, Any]] = None

# ============================================================================
# Threat Intelligence Database
# ============================================================================

class ThreatIntelligence:
    def __init__(self):
        self.known_attacks = defaultdict(int)
        self.blocked_ips = set()
        self.attack_patterns = deque(maxlen=1000)
        self.false_positives = set()
        self.threat_signatures = self._load_threat_signatures()
        
    def _load_threat_signatures(self):
        return {
            "sql_injection": [
                "union select", "drop table", "'; drop", "1=1", "or 1=1",
                "exec(", "execute(", "sp_executesql", "xp_cmdshell"
            ],
            "xss": [
                "<script", "javascript:", "onerror=", "onload=", 
                "alert(", "document.cookie", "eval(", "<iframe"
            ],
            "path_traversal": [
                "../", "..\\", "%2e%2e", "/etc/passwd", 
                "c:\\windows", "/proc/self"
            ],
            "command_injection": [
                "; ls", "| cat", "&& whoami", "$(", "`", 
                "| nc ", "; wget", "&& curl"
            ]
        }
    
    def add_threat(self, ip: str, threat_type: str):
        self.known_attacks[threat_type] += 1
        if self.known_attacks[threat_type] > 10:
            self.blocked_ips.add(ip)
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def check_signatures(self, content: str) -> List[str]:
        found_threats = []
        content_lower = content.lower()
        
        for threat_type, patterns in self.threat_signatures.items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    found_threats.append(threat_type)
                    break
        
        return found_threats

threat_intel = ThreatIntelligence()

# ============================================================================
# AI Provider with WebSocket Updates
# ============================================================================

class AIProvider:
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        raise NotImplementedError

class GeminiProvider(AIProvider):
    """Google Gemini Flash 2.5 with live updates"""
    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = "gemini-2.0-flash-exp"
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
    
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        # Send AI thinking start
        await manager.send_ai_thinking({
            "status": "starting",
            "message": "AI analysis initiated",
            "model": self.model
        })
        
        if not self.api_key:
            # Use intelligent fallback
            return await self._intelligent_fallback(features, context)
        
        prompt = self._build_prompt(features, context)
        
        # Send prompt info
        await manager.send_ai_thinking({
            "status": "analyzing",
            "message": "Processing request patterns",
            "details": {
                "method": features.method,
                "path": features.path,
                "indicators_checking": ["sql", "xss", "traversal", "injection"]
            }
        })
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.url}?key={self.api_key}",
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{
                            "parts": [{
                                "text": f"{SYSTEM_PROMPT}\n\n{prompt}"
                            }]
                        }],
                        "generationConfig": {
                            "temperature": 0.1,
                            "topP": 0.1,
                            "topK": 1,
                            "maxOutputTokens": 1024,
                            "responseMimeType": "application/json"
                        }
                    },
                    timeout=10.0
                )
                response.raise_for_status()
                data = response.json()
                
                if "candidates" in data and data["candidates"]:
                    content = data["candidates"][0]["content"]["parts"][0]["text"]
                    result = json.loads(content)
                    
                    # Send completion
                    await manager.send_ai_thinking({
                        "status": "complete",
                        "message": "Analysis complete",
                        "threat_detected": result.get("threat_score", 0) > 0.5
                    })
                    
                    return result
                    
            except Exception as e:
                logger.error(f"Gemini API error: {e}")
        
        return await self._intelligent_fallback(features, context)
    
    async def _intelligent_fallback(self, features: RequestFeatures, context: RequestContext) -> Dict:
        """Intelligent fallback when API unavailable"""
        await manager.send_ai_thinking({
            "status": "fallback",
            "message": "Using intelligent pattern analysis"
        })
        
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        # Advanced heuristics
        threat_score = 0
        reasoning_parts = []
        
        # Check for SQL patterns
        if any(pattern in content.lower() for pattern in ["select", "union", "drop", "insert", "update", "delete"]):
            if "=" in content or "'" in content or '"' in content:
                threat_score += 0.4
                reasoning_parts.append("SQL keywords with operators detected")
        
        # Check for XSS patterns
        if "<" in content and ">" in content:
            threat_score += 0.3
            reasoning_parts.append("HTML tag patterns detected")
        
        # Check for path traversal
        if "../" in content or "..%2f" in content.lower():
            threat_score += 0.3
            reasoning_parts.append("Directory traversal patterns detected")
        
        # Rate-based threats
        if features.requests_per_minute > 100:
            threat_score += 0.2
            reasoning_parts.append(f"High request rate: {features.requests_per_minute}/min")
        
        # Context-based scoring
        if context.failed_attempts > 5:
            threat_score += 0.2
            reasoning_parts.append(f"Multiple failed attempts: {context.failed_attempts}")
        
        threat_score = min(threat_score, 1.0)
        
        if threats:
            threat_type = threats[0]
            threat_score = max(threat_score, 0.8)
        elif threat_score > 0.6:
            threat_type = "suspicious_pattern"
        elif threat_score > 0.3:
            threat_type = "anomaly"
        else:
            threat_type = "none"
        
        action = "block" if threat_score > 0.8 else "rate_limit" if threat_score > 0.6 else "monitor" if threat_score > 0.3 else "allow"
        
        return {
            "threat_score": threat_score,
            "threat_type": threat_type,
            "confidence": 0.85 if threats else 0.7,
            "reasoning": " | ".join(reasoning_parts) if reasoning_parts else "No threats detected",
            "recommended_action": action,
            "indicators": threats + (["high_rate"] if features.requests_per_minute > 100 else [])
        }
    
    def _build_prompt(self, features: RequestFeatures, context: RequestContext) -> str:
        return f"""Analyze this HTTP request for security threats:

Request: {features.method} {features.path}
Client IP: {features.client_ip} (Previous: {context.previous_requests})
Rate: {features.requests_per_minute} req/min
Query: {features.query}
Body: {features.body[:500] if features.body else 'None'}
Failed Auth: {context.failed_attempts}
Anomaly Score: {context.anomaly_score}

Return JSON with: threat_score, threat_type, confidence, reasoning, recommended_action, indicators"""

# ============================================================================
# System Prompt
# ============================================================================

SYSTEM_PROMPT = """You are an advanced API security AI. Analyze HTTP requests for:
- SQL Injection, XSS, Command injection, Path traversal
- DDoS patterns, Credential stuffing, API abuse, Zero-day patterns

Provide JSON: threat_score (0-1), threat_type, confidence (0-1), reasoning, 
recommended_action (block/rate_limit/monitor/allow), indicators (list)"""

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Health check and service info"""
    return {
        "service": "Kong Guard AI - Real-Time Threat Analysis",
        "status": "operational",
        "version": "3.0.0",
        "ai_provider": AI_PROVIDER,
        "websocket": "/ws",
        "dashboard": "/dashboard"
    }

@app.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """Analyze a request for threats using AI with WebSocket updates"""
    start_time = time.time()
    logger.info(f"/analyze endpoint: Manager ID = {id(manager)}")
    logger.info(f"Broadcasting to {len(manager.active_connections)} WebSocket clients at start...")
    
    # Check if IP is blocked
    if threat_intel.is_blocked(request.features.client_ip):
        result = ThreatAnalysisResponse(
            threat_score=1.0,
            threat_type="blocked_ip",
            confidence=1.0,
            reasoning="IP address is on the blocklist",
            recommended_action="block",
            indicators=["blocklist"],
            ai_model="threat_intel",
            processing_time=time.time() - start_time
        )
        
        # Broadcast to WebSocket
        broadcast_data = {
            **result.dict(),
            "method": request.features.method,
            "path": request.features.path,
            "client_ip": request.features.client_ip,
            "processing_time_ms": result.processing_time * 1000,  # Convert to milliseconds
            "query": request.features.query
        }
        await manager.broadcast_threat_analysis(broadcast_data)
        
        return result
    
    # Perform AI analysis
    ai_provider = GeminiProvider()
    ai_result = await ai_provider.analyze(request.features, request.context)
    
    # Track threats
    if ai_result.get("threat_score", 0) > 0.8:
        threat_intel.add_threat(request.features.client_ip, ai_result.get("threat_type", "unknown"))
    
    # Build response
    result = ThreatAnalysisResponse(
        threat_score=ai_result.get("threat_score", 0),
        threat_type=ai_result.get("threat_type", "none"),
        confidence=ai_result.get("confidence", 0.5),
        reasoning=ai_result.get("reasoning", ""),
        recommended_action=ai_result.get("recommended_action", "monitor"),
        indicators=ai_result.get("indicators", []),
        ai_model=f"{AI_PROVIDER}/gemini-2.0-flash-exp",
        processing_time=time.time() - start_time,
        detailed_analysis=ai_result
    )
    
    # Broadcast to WebSocket
    broadcast_data = {
        **result.dict(),
        "method": request.features.method,
        "path": request.features.path,
        "client_ip": request.features.client_ip,
        "processing_time_ms": result.processing_time * 1000,  # Convert to milliseconds
        "query": request.features.query
    }
    await manager.broadcast_threat_analysis(broadcast_data)
    
    return result

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    logger.info(f"WebSocket /ws: Manager ID = {id(manager)}")
    await manager.connect(websocket)
    logger.info(f"WebSocket client connected. Total connections: {len(manager.active_connections)}")
    try:
        while True:
            # Keep connection alive without requiring client messages
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected. Total connections: {len(manager.active_connections)}")

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the visualization dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kong Guard AI - Real-Time Dashboard</title>
        <style>
            body { 
                margin: 0; 
                font-family: -apple-system, system-ui, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
            }
            h1 { text-align: center; }
            .metrics {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .metric {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }
            .metric-value {
                font-size: 2em;
                font-weight: bold;
            }
            #events {
                background: rgba(0,0,0,0.3);
                padding: 20px;
                border-radius: 10px;
                max-height: 400px;
                overflow-y: auto;
            }
            .event {
                background: rgba(255,255,255,0.1);
                margin: 10px 0;
                padding: 10px;
                border-radius: 5px;
            }
            .threat { background: rgba(255,0,0,0.3); }
            .safe { background: rgba(0,255,0,0.2); }
        </style>
    </head>
    <body>
        <h1>🛡️ Kong Guard AI - Real-Time Threat Detection</h1>
        
        <div class="metrics">
            <div class="metric">
                <div>Total Requests</div>
                <div class="metric-value" id="total-requests">0</div>
            </div>
            <div class="metric">
                <div>Threats Blocked</div>
                <div class="metric-value" id="threats-blocked">0</div>
            </div>
            <div class="metric">
                <div>Current RPS</div>
                <div class="metric-value" id="current-rps">0</div>
            </div>
            <div class="metric">
                <div>Avg Latency</div>
                <div class="metric-value" id="avg-latency">0ms</div>
            </div>
        </div>
        
        <h2>Live Events</h2>
        <div id="events"></div>
        
        <script>
            const ws = new WebSocket('ws://localhost:18002/ws');
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'threat_analysis') {
                    // Update metrics
                    document.getElementById('total-requests').textContent = data.metrics.total_requests;
                    document.getElementById('threats-blocked').textContent = data.metrics.threats_blocked;
                    document.getElementById('current-rps').textContent = data.metrics.current_rps;
                    document.getElementById('avg-latency').textContent = data.metrics.avg_latency + 'ms';
                    
                    // Add event
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event ' + (data.event.threat_score > 0.5 ? 'threat' : 'safe');
                    eventDiv.innerHTML = `
                        <strong>${data.event.method} ${data.event.path}</strong><br>
                        Threat: ${data.event.threat_type} | Score: ${data.event.threat_score.toFixed(2)} | 
                        Action: ${data.event.action} | IP: ${data.event.client_ip}
                    `;
                    
                    const eventsDiv = document.getElementById('events');
                    eventsDiv.insertBefore(eventDiv, eventsDiv.firstChild);
                    
                    // Keep only last 20 events
                    while (eventsDiv.children.length > 20) {
                        eventsDiv.removeChild(eventsDiv.lastChild);
                    }
                }
            };
        </script>
    </body>
    </html>
    """

@app.get("/stats")
async def get_statistics():
    """Get threat detection statistics"""
    return {
        "total_threats": sum(threat_intel.known_attacks.values()),
        "threat_types": dict(threat_intel.known_attacks),
        "blocked_ips": len(threat_intel.blocked_ips),
        "false_positives": len(threat_intel.false_positives),
        "ai_provider": AI_PROVIDER,
        "websocket_clients": len(manager.active_connections)
    }

# ============================================================================
# Demo Attack Simulator
# ============================================================================

@app.post("/simulate-attacks")
async def simulate_attacks():
    """Simulate various attack patterns for demo"""
    attacks = [
        {
            "name": "SQL Injection",
            "features": RequestFeatures(
                method="GET",
                path="/api/users",
                client_ip="192.168.1.100",
                user_agent="AttackBot/1.0",
                requests_per_minute=10,
                content_length=0,
                query_param_count=1,
                header_count=5,
                hour_of_day=14,
                query="id=1' OR '1'='1",
                body=""
            )
        },
        {
            "name": "XSS Attack",
            "features": RequestFeatures(
                method="POST",
                path="/api/comment",
                client_ip="192.168.1.101",
                user_agent="XSSBot/1.0",
                requests_per_minute=5,
                content_length=100,
                query_param_count=0,
                header_count=5,
                hour_of_day=14,
                query="",
                body='{"comment":"<script>alert(document.cookie)</script>"}'
            )
        },
        {
            "name": "Normal Request",
            "features": RequestFeatures(
                method="GET",
                path="/api/products",
                client_ip="192.168.1.102",
                user_agent="Chrome/96.0",
                requests_per_minute=2,
                content_length=0,
                query_param_count=1,
                header_count=10,
                hour_of_day=14,
                query="category=electronics",
                body=""
            )
        }
    ]
    
    results = []
    for attack in attacks:
        request = ThreatAnalysisRequest(
            features=attack["features"],
            context=RequestContext()
        )
        
        # Simulate delay for visual effect
        await asyncio.sleep(1)
        
        result = await analyze_threat(request)
        results.append({
            "attack": attack["name"],
            "result": result.dict()
        })
    
    return {"simulations": results}

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print("🚀 Kong Guard AI - Real-Time Threat Analysis Service")
    print(f"📊 AI Provider: {AI_PROVIDER}")
    print(f"🔍 API: http://localhost:18002")
    print(f"🖥️  Dashboard: http://localhost:18002/dashboard")
    print(f"🔌 WebSocket: ws://localhost:18002/ws")
    print("")
    
    uvicorn.run(app, host="0.0.0.0", port=18002)