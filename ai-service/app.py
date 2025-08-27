#!/usr/bin/env python3
"""
Kong Guard AI - Enterprise AI Threat Analysis Service
Real-time AI-powered threat detection using LLMs
"""

import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import httpx
from collections import defaultdict, deque
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Kong Guard AI - Threat Analysis Service",
    description="Enterprise AI-powered API threat detection",
    version="2.0.0"
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
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove dead connections
                self.active_connections.remove(connection)

manager = ConnectionManager()

# ============================================================================
# Configuration
# ============================================================================

AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")  # openai, anthropic, ollama, groq, gemini
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# ============================================================================
# Data Models
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
# Threat Intelligence Database (In-Memory)
# ============================================================================

class ThreatIntelligence:
    def __init__(self):
        self.known_attacks = defaultdict(int)
        self.blocked_ips = set()
        self.attack_patterns = deque(maxlen=1000)
        self.false_positives = set()
        self.threat_signatures = self._load_threat_signatures()
        
    def _load_threat_signatures(self):
        """Load known threat signatures"""
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
            ],
            "xxe": [
                "<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://", 
                "php://", "expect://", "data:text"
            ],
            "log4j": [
                "${jndi:", "${ldap:", "${rmi:", "${dns:", "${env:"
            ]
        }
    
    def add_threat(self, ip: str, threat_type: str):
        self.known_attacks[threat_type] += 1
        if self.known_attacks[threat_type] > 10:
            self.blocked_ips.add(ip)
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def check_signatures(self, content: str) -> List[str]:
        """Check content against threat signatures"""
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
# AI Providers
# ============================================================================

class AIProvider:
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        raise NotImplementedError

class OpenAIProvider(AIProvider):
    def __init__(self):
        self.api_key = OPENAI_API_KEY
        self.model = "gpt-4o-mini"  # Fast and cost-effective
        self.url = "https://api.openai.com/v1/chat/completions"
    
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="OpenAI API key not configured")
        
        prompt = self._build_prompt(features, context)
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.1,
                        "max_tokens": 500,
                        "response_format": {"type": "json_object"}
                    },
                    timeout=10.0
                )
                response.raise_for_status()
                data = response.json()
                
                # Parse the AI response
                ai_content = data["choices"][0]["message"]["content"]
                return json.loads(ai_content)
                
            except Exception as e:
                logger.error(f"OpenAI API error: {e}")
                return self._fallback_analysis(features, context)
    
    def _build_prompt(self, features: RequestFeatures, context: RequestContext) -> str:
        return f"""Analyze this HTTP request for security threats:

Request: {features.method} {features.path}
Client IP: {features.client_ip} (Previous requests: {context.previous_requests})
Rate: {features.requests_per_minute} req/min
Query: {features.query}
Body: {features.body[:500] if features.body else 'None'}
Failed Auth Attempts: {context.failed_attempts}
Anomaly Score: {context.anomaly_score}

Identify threats and return JSON with: threat_score (0-1), threat_type, confidence (0-1), reasoning, recommended_action (block/rate_limit/monitor/allow), indicators (list)"""
    
    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> Dict:
        """Fallback to signature-based detection"""
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": []
        }

class GroqProvider(AIProvider):
    """Ultra-fast inference with Groq"""
    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model = "mixtral-8x7b-32768"  # Fast Mixtral model
        self.url = "https://api.groq.com/openai/v1/chat/completions"
    
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="Groq API key not configured")
        
        prompt = self._build_prompt(features, context)
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.1,
                        "max_tokens": 500
                    },
                    timeout=5.0  # Groq is very fast
                )
                response.raise_for_status()
                data = response.json()
                
                # Parse the AI response
                ai_content = data["choices"][0]["message"]["content"]
                return self._parse_ai_response(ai_content)
                
            except Exception as e:
                logger.error(f"Groq API error: {e}")
                return self._fallback_analysis(features, context)
    
    def _build_prompt(self, features: RequestFeatures, context: RequestContext) -> str:
        return f"""Analyze HTTP request for threats:
Method: {features.method} {features.path}
IP: {features.client_ip} | Rate: {features.requests_per_minute}/min
Query: {features.query}
Body: {features.body[:200] if features.body else 'None'}

Return JSON: threat_score, threat_type, confidence, reasoning, recommended_action, indicators"""
    
    def _parse_ai_response(self, content: str) -> Dict:
        try:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        # Fallback parsing
        return {
            "threat_score": 0.5,
            "threat_type": "unknown",
            "confidence": 0.5,
            "reasoning": content[:200],
            "recommended_action": "monitor",
            "indicators": []
        }
    
    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> Dict:
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": []
        }

class GeminiProvider(AIProvider):
    """Google Gemini Flash 2.5 - Fast and efficient"""
    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = "gemini-2.0-flash-exp"  # Latest Flash 2.5 model
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
    
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="Gemini API key not configured")
        
        prompt = self._build_prompt(features, context)
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.url}?key={self.api_key}",
                    headers={
                        "Content-Type": "application/json"
                    },
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
                        },
                        "safetySettings": [
                            {
                                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                                "threshold": "BLOCK_NONE"
                            }
                        ]
                    },
                    timeout=10.0
                )
                response.raise_for_status()
                data = response.json()
                
                # Parse Gemini response
                if "candidates" in data and data["candidates"]:
                    content = data["candidates"][0]["content"]["parts"][0]["text"]
                    return json.loads(content)
                else:
                    return self._fallback_analysis(features, context)
                    
            except Exception as e:
                logger.error(f"Gemini API error: {e}")
                return self._fallback_analysis(features, context)
    
    def _build_prompt(self, features: RequestFeatures, context: RequestContext) -> str:
        return f"""Analyze this HTTP request for security threats:

Request Details:
- Method: {features.method}
- Path: {features.path}
- Client IP: {features.client_ip}
- Request Rate: {features.requests_per_minute} requests/minute
- Query: {features.query}
- Body: {features.body[:500] if features.body else 'None'}
- Previous requests from IP: {context.previous_requests}
- Failed auth attempts: {context.failed_attempts}
- Anomaly score: {context.anomaly_score}

Identify all security threats and return a JSON response with these exact fields:
{{
    "threat_score": (0.0 to 1.0),
    "threat_type": "(sql_injection|xss|path_traversal|command_injection|ddos|credential_stuffing|api_abuse|none)",
    "confidence": (0.0 to 1.0),
    "reasoning": "explanation of the threat",
    "recommended_action": "(block|rate_limit|monitor|allow)",
    "indicators": ["list", "of", "threat", "indicators"]
}}"""
    
    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> Dict:
        """Fallback to signature-based detection"""
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats
            }
        
        # Check for rate-based threats
        if features.requests_per_minute > 100:
            return {
                "threat_score": 0.7,
                "threat_type": "ddos",
                "confidence": 0.75,
                "reasoning": f"High request rate: {features.requests_per_minute}/min",
                "recommended_action": "rate_limit",
                "indicators": ["high_request_rate"]
            }
        
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": []
        }

class OllamaProvider(AIProvider):
    """Local LLM with Ollama"""
    def __init__(self):
        self.url = f"{OLLAMA_URL}/api/generate"
        self.model = "llama2"  # or "mistral", "codellama", etc.
    
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> Dict:
        prompt = self._build_prompt(features, context)
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "temperature": 0.1
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                
                # Parse the response
                return self._parse_response(data.get("response", ""))
                
            except Exception as e:
                logger.error(f"Ollama error: {e}")
                return self._fallback_analysis(features, context)
    
    def _build_prompt(self, features: RequestFeatures, context: RequestContext) -> str:
        return f"""Analyze this HTTP request for security threats. Return only JSON.

Request: {features.method} {features.path}
Query: {features.query}
Body: {features.body[:200] if features.body else 'None'}
Client: {features.client_ip} ({features.requests_per_minute} req/min)

JSON format: {{"threat_score": 0-1, "threat_type": "type", "confidence": 0-1, "reasoning": "why", "recommended_action": "block|allow|monitor", "indicators": ["list"]}}"""
    
    def _parse_response(self, response: str) -> Dict:
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        # Basic analysis if JSON parsing fails
        response_lower = response.lower()
        if any(word in response_lower for word in ["sql", "injection", "attack", "malicious"]):
            return {
                "threat_score": 0.8,
                "threat_type": "potential_threat",
                "confidence": 0.6,
                "reasoning": "AI detected suspicious patterns",
                "recommended_action": "block",
                "indicators": ["ai_detection"]
            }
        
        return {
            "threat_score": 0.1,
            "threat_type": "none",
            "confidence": 0.7,
            "reasoning": "No clear threats identified",
            "recommended_action": "allow",
            "indicators": []
        }
    
    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> Dict:
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": []
        }

# ============================================================================
# System Prompt for AI
# ============================================================================

SYSTEM_PROMPT = """You are an advanced API security AI specializing in threat detection.
Analyze HTTP requests for security threats including:
- SQL Injection
- XSS (Cross-site scripting)  
- Command injection
- Path traversal
- XXE attacks
- Log4Shell and similar exploits
- DDoS patterns
- Credential stuffing
- API abuse
- Zero-day patterns

Provide analysis as JSON with these fields:
- threat_score: 0.0 to 1.0 (confidence that this is a threat)
- threat_type: specific threat category or "none"
- confidence: your confidence in the assessment (0-1)
- reasoning: brief explanation
- recommended_action: "block", "rate_limit", "monitor", or "allow"
- indicators: list of specific threat indicators found"""

# ============================================================================
# AI Provider Factory
# ============================================================================

def get_ai_provider() -> AIProvider:
    """Get the configured AI provider"""
    if AI_PROVIDER == "openai" and OPENAI_API_KEY:
        return OpenAIProvider()
    elif AI_PROVIDER == "groq" and GROQ_API_KEY:
        return GroqProvider()
    elif AI_PROVIDER == "gemini" and GEMINI_API_KEY:
        return GeminiProvider()
    elif AI_PROVIDER == "ollama":
        return OllamaProvider()
    else:
        # Default to signature-based detection when no API keys are available
        return SignatureBasedProvider()

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Health check and service info"""
    return {
        "service": "Kong Guard AI - Threat Analysis Service",
        "status": "operational",
        "version": "2.0.0",
        "ai_provider": AI_PROVIDER,
        "features": [
            "Real-time AI threat analysis",
            "Multiple AI provider support",
            "Threat signature detection",
            "Learning from feedback",
            "High-performance inference"
        ]
    }

@app.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """Analyze a request for threats using AI"""
    start_time = time.time()
    
    # Check if IP is already blocked
    if threat_intel.is_blocked(request.features.client_ip):
        return ThreatAnalysisResponse(
            threat_score=1.0,
            threat_type="blocked_ip",
            confidence=1.0,
            reasoning="IP address is on the blocklist due to previous attacks",
            recommended_action="block",
            indicators=["blocklist"],
            ai_model="threat_intel",
            processing_time=time.time() - start_time
        )
    
    # Get AI provider
    ai_provider = get_ai_provider()
    
    try:
        # Perform AI analysis
        ai_result = await ai_provider.analyze(request.features, request.context)
        
        # Track threats
        if ai_result.get("threat_score", 0) > 0.8:
            threat_intel.add_threat(
                request.features.client_ip,
                ai_result.get("threat_type", "unknown")
            )
        
        # Build response
        response = ThreatAnalysisResponse(
            threat_score=ai_result.get("threat_score", 0),
            threat_type=ai_result.get("threat_type", "none"),
            confidence=ai_result.get("confidence", 0.5),
            reasoning=ai_result.get("reasoning", ""),
            recommended_action=ai_result.get("recommended_action", "monitor"),
            indicators=ai_result.get("indicators", []),
            ai_model=f"{AI_PROVIDER}/{getattr(ai_provider, 'model', 'unknown')}",
            processing_time=time.time() - start_time,
            detailed_analysis=ai_result
        )
        
        # Broadcast to WebSocket clients
        try:
            await broadcast_threat_analysis({
                "type": "threat_analysis",
                "threat_score": response.threat_score,
                "threat_type": response.threat_type,
                "confidence": response.confidence,
                "reasoning": response.reasoning,
                "recommended_action": response.recommended_action,
                "method": request.features.method,
                "path": request.features.path,
                "client_ip": request.features.client_ip,
                "query": request.features.query,
                "processing_time_ms": response.processing_time * 1000,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as ws_error:
            logger.warning(f"WebSocket broadcast failed: {ws_error}")
        
        return response
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        
        # Fallback to signature detection
        content = f"{request.features.path} {request.features.query} {request.features.body or ''}"
        threats = threat_intel.check_signatures(content)
        
        if threats:
            return ThreatAnalysisResponse(
                threat_score=0.9,
                threat_type=threats[0],
                confidence=0.8,
                reasoning=f"Signature-based detection: {threats[0]}",
                recommended_action="block",
                indicators=threats,
                ai_model="signature_detection",
                processing_time=time.time() - start_time
            )
        
        return ThreatAnalysisResponse(
            threat_score=0.0,
            threat_type="none",
            confidence=0.5,
            reasoning="Unable to perform AI analysis, no signatures matched",
            recommended_action="allow",
            indicators=[],
            ai_model="fallback",
            processing_time=time.time() - start_time
        )

@app.post("/feedback")
async def provide_feedback(
    threat_id: str,
    false_positive: bool = False,
    confirmed_threat: bool = False
):
    """Provide feedback on threat detection"""
    # In production, this would update the model or adjust thresholds
    if false_positive:
        threat_intel.false_positives.add(threat_id)
        return {"status": "recorded", "action": "false_positive_noted"}
    elif confirmed_threat:
        return {"status": "recorded", "action": "threat_confirmed"}
    return {"status": "no_action"}

@app.get("/stats")
async def get_statistics():
    """Get threat detection statistics"""
    return {
        "total_threats": sum(threat_intel.known_attacks.values()),
        "threat_types": dict(threat_intel.known_attacks),
        "blocked_ips": len(threat_intel.blocked_ips),
        "false_positives": len(threat_intel.false_positives),
        "ai_provider": AI_PROVIDER
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat analysis updates"""
    await manager.connect(websocket)
    logger.info(f"WebSocket client connected. Total connections: {len(manager.active_connections)}")
    try:
        # Send initial connection message
        await manager.send_personal_message(json.dumps({
            "type": "connection",
            "message": "Connected to Kong Guard AI Real-Time System",
            "timestamp": datetime.now().isoformat()
        }), websocket)
        
        # Keep connection alive indefinitely
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected. Total connections: {len(manager.active_connections)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Function to broadcast threat analysis results
async def broadcast_threat_analysis(analysis_result: dict):
    """Broadcast threat analysis results to all connected WebSocket clients"""
    message = json.dumps(analysis_result)
    logger.info(f"Broadcasting to {len(manager.active_connections)} WebSocket clients: {message[:100]}...")
    if len(manager.active_connections) == 0:
        logger.warning("No active WebSocket connections to broadcast to!")
    else:
        await manager.broadcast(message)

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print("🚀 Kong Guard AI - Threat Analysis Service")
    print(f"📊 AI Provider: {AI_PROVIDER}")
    print(f"🔍 Starting on http://localhost:8000")
    print("")
    print("Available providers:")
    print("  - OpenAI (GPT-4): Set OPENAI_API_KEY")
    print("  - Groq (Fast): Set GROQ_API_KEY")
    print("  - Gemini Flash 2.5: Set GEMINI_API_KEY")
    print("  - Ollama (Local): Install and run Ollama")
    print("")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)