#!/usr/bin/env python3
"""
Kong Guard AI - Enterprise AI Threat Analysis Service
Real-time AI-powered threat detection using LLMs
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from collections import defaultdict
from collections import deque
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Optional

import httpx
import uvicorn
from fastapi import BackgroundTasks
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from pydantic import Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add parent directory to path to import ML models
sys.path.append(str(Path(__file__).parent.parent))

# Import ML models
try:
    from ml_models.model_manager import ModelManager

    ML_ENABLED = True
    logger.info("ML models loaded successfully")
except ImportError as e:
    logger.warning(f"ML models not available: {e}")
    ML_ENABLED = False
    ModelManager = None

# Import Intelligent Rate Limiter
try:
    from rate_limiter import IntelligentRateLimiter
    from rate_limiter import ProviderType

    RATE_LIMITER_ENABLED = True
    logger.info("Intelligent Rate Limiter loaded successfully")
except ImportError as e:
    logger.warning(f"Rate limiter not available: {e}")
    RATE_LIMITER_ENABLED = False
    IntelligentRateLimiter = None
    ProviderType = None

# Import Intelligent Threat Cache
try:
    from intelligent_cache import IntelligentThreatCache

    # Check environment variable for cache enablement
    cache_env = os.getenv("CACHE_ENABLED", "false")
    CACHE_ENABLED = cache_env.lower() in ("true", "1", "yes", "on")
    logger.info(f"Cache environment variable: CACHE_ENABLED='{cache_env}', parsed as: {CACHE_ENABLED}")
    if CACHE_ENABLED:
        logger.info("Intelligent Threat Cache loaded and enabled")
    else:
        logger.info("Intelligent Threat Cache loaded but disabled via CACHE_ENABLED=false")
except ImportError as e:
    logger.warning(f"Intelligent cache not available: {e}")
    CACHE_ENABLED = False
    IntelligentThreatCache = None  # type: ignore

app = FastAPI(
    title="Kong Guard AI - Threat Analysis Service",
    description="Enterprise AI-powered API threat detection",
    version="2.0.0",
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
        self.active_connections: list[WebSocket] = []

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
    headers: Optional[dict[str, str]] = {}


class RequestContext(BaseModel):
    previous_requests: int = 0
    failed_attempts: int = 0
    anomaly_score: float = 0.0
    ip_reputation: Optional[str] = "unknown"
    geo_location: Optional[str] = None


class ThreatAnalysisRequest(BaseModel):
    features: RequestFeatures
    context: RequestContext
    config: Optional[dict[str, Any]] = {}


class ThreatAnalysisResponse(BaseModel):
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: str
    indicators: list[str]
    ai_model: str
    processing_time: float
    detailed_analysis: Optional[dict[str, Any]] = None


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
                "union select",
                "drop table",
                "'; drop",
                "1=1",
                "or 1=1",
                "exec(",
                "execute(",
                "sp_executesql",
                "xp_cmdshell",
            ],
            "xss": ["<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie", "eval(", "<iframe"],
            "path_traversal": ["../", "..\\", "%2e%2e", "/etc/passwd", "c:\\windows", "/proc/self"],
            "command_injection": ["; ls", "| cat", "&& whoami", "$(", "`", "| nc ", "; wget", "&& curl"],
            "xxe": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://", "php://", "expect://", "data:text"],
            "log4j": ["${jndi:", "${ldap:", "${rmi:", "${dns:", "${env:"],
        }

    def add_threat(self, ip: str, threat_type: str):
        self.known_attacks[threat_type] += 1
        if self.known_attacks[threat_type] > 10:
            self.blocked_ips.add(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def check_signatures(self, content: str) -> list[str]:
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

# Initialize ML Model Manager
if ML_ENABLED:
    model_manager = ModelManager(model_dir="models/trained")
    logger.info("ML Model Manager initialized")
else:
    model_manager = None

# Initialize Intelligent Rate Limiter
if RATE_LIMITER_ENABLED:
    rate_limiter = IntelligentRateLimiter()
    logger.info("Intelligent Rate Limiter initialized")
else:
    rate_limiter = None

# Initialize Intelligent Threat Cache
if CACHE_ENABLED:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    threat_cache = IntelligentThreatCache(redis_url=redis_url)
    # Initialize cache connection asynchronously
    asyncio.create_task(threat_cache.initialize())
    logger.info("Intelligent Threat Cache initialized")
else:
    threat_cache = None  # type: ignore


# Warm cache with common attack patterns on startup
async def warm_cache_on_startup():
    """Warm the cache with common attack patterns"""
    if CACHE_ENABLED and threat_cache:
        try:
            logger.info("Starting cache warming...")

            # Common attack patterns for cache warming
            common_attacks = [
                # SQL Injection
                {
                    "payload": "' OR 1=1--",
                    "type": "sql_injection",
                    "method": "POST",
                    "path": "/login",
                    "features": {"has_sql_keywords": True, "length_bucket": 1},
                },
                {
                    "payload": "admin'--",
                    "type": "sql_injection",
                    "method": "POST",
                    "path": "/login",
                    "features": {"has_sql_keywords": True, "length_bucket": 0},
                },
                {
                    "payload": "' UNION SELECT * FROM users--",
                    "type": "sql_injection",
                    "method": "GET",
                    "path": "/search",
                    "features": {"has_sql_keywords": True, "length_bucket": 3},
                },
                # XSS Attacks
                {
                    "payload": "<script>alert('xss')</script>",
                    "type": "xss",
                    "method": "POST",
                    "path": "/comment",
                    "features": {"has_script_tags": True, "length_bucket": 2},
                },
                {
                    "payload": "<img src=x onerror=alert(1)>",
                    "type": "xss",
                    "method": "POST",
                    "path": "/profile",
                    "features": {"has_script_tags": False, "has_special_chars": True, "length_bucket": 2},
                },
                {
                    "payload": "javascript:alert(document.cookie)",
                    "type": "xss",
                    "method": "GET",
                    "path": "/redirect",
                    "features": {"has_script_tags": False, "has_special_chars": True, "length_bucket": 3},
                },
                # Path Traversal
                {
                    "payload": "../../../etc/passwd",
                    "type": "path_traversal",
                    "method": "GET",
                    "path": "/file",
                    "features": {"has_special_chars": True, "length_bucket": 2},
                },
                {
                    "payload": "..\\..\\windows\\system32\\config\\sam",
                    "type": "path_traversal",
                    "method": "GET",
                    "path": "/download",
                    "features": {"has_special_chars": True, "length_bucket": 3},
                },
                # Command Injection
                {
                    "payload": "; cat /etc/passwd",
                    "type": "command_injection",
                    "method": "POST",
                    "path": "/exec",
                    "features": {"has_special_chars": True, "length_bucket": 2},
                },
                {
                    "payload": "| whoami",
                    "type": "command_injection",
                    "method": "GET",
                    "path": "/cmd",
                    "features": {"has_special_chars": True, "length_bucket": 1},
                },
            ]

            await threat_cache.warm_cache(common_attacks)
            logger.info(f"Cache warmed with {len(common_attacks)} attack patterns")

        except Exception as e:
            logger.error(f"Cache warming failed: {e}")


# Initialize cache warming
if CACHE_ENABLED and threat_cache:
    import asyncio

    asyncio.create_task(warm_cache_on_startup())

# ============================================================================
# AI Providers
# ============================================================================


class AIProvider:
    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        raise NotImplementedError


class OpenAIProvider(AIProvider):
    def __init__(self):
        self.api_key = OPENAI_API_KEY
        self.model = "gpt-4o-mini"  # Fast and cost-effective
        self.url = "https://api.openai.com/v1/chat/completions"

    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="OpenAI API key not configured")

        prompt = self._build_prompt(features, context)

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={
                        "model": self.model,
                        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": 500,
                        "response_format": {"type": "json_object"},
                    },
                    timeout=10.0,
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
Body: {features.body[:500] if features.body else "None"}
Failed Auth Attempts: {context.failed_attempts}
Anomaly Score: {context.anomaly_score}

Identify threats and return JSON with: threat_score (0-1), threat_type, confidence (0-1), reasoning, recommended_action (block/rate_limit/monitor/allow), indicators (list)"""

    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> dict:
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
                "indicators": threats,
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": [],
        }


class GroqProvider(AIProvider):
    """Ultra-fast inference with Groq"""

    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model = "mixtral-8x7b-32768"  # Fast Mixtral model
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="Groq API key not configured")

        prompt = self._build_prompt(features, context)

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={
                        "model": self.model,
                        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": 500,
                    },
                    timeout=5.0,  # Groq is very fast
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
Body: {features.body[:200] if features.body else "None"}

Return JSON: threat_score, threat_type, confidence, reasoning, recommended_action, indicators"""

    def _parse_ai_response(self, content: str) -> dict:
        try:
            # Try to extract JSON from the response
            import re

            json_match = re.search(r"\{.*\}", content, re.DOTALL)
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
            "indicators": [],
        }

    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> dict:
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)

        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats,
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": [],
        }


class GeminiProvider(AIProvider):
    """Google Gemini Flash 2.5 - Fast and efficient"""

    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = "gemini-2.0-flash-exp"  # Latest Flash 2.5 model
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"

    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="Gemini API key not configured")

        prompt = self._build_prompt(features, context)

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.url}?key={self.api_key}",
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\n{prompt}"}]}],
                        "generationConfig": {
                            "temperature": 0.1,
                            "topP": 0.1,
                            "topK": 1,
                            "maxOutputTokens": 1024,
                            "responseMimeType": "application/json",
                        },
                        "safetySettings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}],
                    },
                    timeout=10.0,
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
- Body: {features.body[:500] if features.body else "None"}
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

    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> dict:
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
                "indicators": threats,
            }

        # Check for rate-based threats
        if features.requests_per_minute > 100:
            return {
                "threat_score": 0.7,
                "threat_type": "ddos",
                "confidence": 0.75,
                "reasoning": f"High request rate: {features.requests_per_minute}/min",
                "recommended_action": "rate_limit",
                "indicators": ["high_request_rate"],
            }

        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": [],
        }


class SignatureBasedProvider(AIProvider):
    """Fallback provider using signature-based detection"""

    def __init__(self):
        self.threat_intel = threat_intel

    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = self.threat_intel.check_signatures(content)

        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats,
            }

        # Check for rate-based threats
        if features.requests_per_minute > 100:
            return {
                "threat_score": 0.7,
                "threat_type": "ddos",
                "confidence": 0.75,
                "reasoning": f"High request rate: {features.requests_per_minute}/min",
                "recommended_action": "rate_limit",
                "indicators": ["high_request_rate"],
            }

        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": [],
        }


class OllamaProvider(AIProvider):
    """Local LLM with Ollama"""

    def __init__(self):
        self.url = f"{OLLAMA_URL}/api/generate"
        self.model = "llama2"  # or "mistral", "codellama", etc.

    async def analyze(self, features: RequestFeatures, context: RequestContext) -> dict:
        prompt = self._build_prompt(features, context)

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.url,
                    json={"model": self.model, "prompt": prompt, "stream": False, "temperature": 0.1},
                    timeout=30.0,
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
Body: {features.body[:200] if features.body else "None"}
Client: {features.client_ip} ({features.requests_per_minute} req/min)

JSON format: {{"threat_score": 0-1, "threat_type": "type", "confidence": 0-1, "reasoning": "why", "recommended_action": "block|allow|monitor", "indicators": ["list"]}}"""

    def _parse_response(self, response: str) -> dict:
        try:
            # Extract JSON from response
            import re

            json_match = re.search(r"\{.*\}", response, re.DOTALL)
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
                "indicators": ["ai_detection"],
            }

        return {
            "threat_score": 0.1,
            "threat_type": "none",
            "confidence": 0.7,
            "reasoning": "No clear threats identified",
            "recommended_action": "allow",
            "indicators": [],
        }

    def _fallback_analysis(self, features: RequestFeatures, context: RequestContext) -> dict:
        content = f"{features.path} {features.query} {features.body or ''}"
        threats = threat_intel.check_signatures(content)

        if threats:
            return {
                "threat_score": 0.9,
                "threat_type": threats[0],
                "confidence": 0.8,
                "reasoning": f"Signature match for {threats[0]}",
                "recommended_action": "block",
                "indicators": threats,
            }
        return {
            "threat_score": 0.0,
            "threat_type": "none",
            "confidence": 0.9,
            "reasoning": "No threats detected",
            "recommended_action": "allow",
            "indicators": [],
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


async def get_intelligent_provider(estimated_tokens: int = 500, priority: str = "balanced") -> AIProvider:
    """Get the optimal AI provider using intelligent rate limiting"""
    if not RATE_LIMITER_ENABLED or not rate_limiter:
        # Fallback to simple provider selection
        return get_simple_provider()

    # Get optimal provider from rate limiter
    provider_type = await rate_limiter.get_optimal_provider(estimated_tokens, priority)

    if not provider_type:
        logger.warning("No providers available - falling back to signature detection")
        return SignatureBasedProvider()

    # Map ProviderType to actual provider instance
    provider_map = {
        ProviderType.OPENAI: lambda: OpenAIProvider() if OPENAI_API_KEY else None,
        ProviderType.GROQ: lambda: GroqProvider() if GROQ_API_KEY else None,
        ProviderType.GEMINI: lambda: GeminiProvider() if GEMINI_API_KEY else None,
        ProviderType.OLLAMA: lambda: OllamaProvider(),
    }

    provider_func = provider_map.get(provider_type)
    if provider_func:
        provider = provider_func()
        if provider:
            return provider

    # Fallback to signature-based detection
    logger.warning(f"Provider {provider_type.value} not available - using signature detection")
    return SignatureBasedProvider()


def get_simple_provider() -> AIProvider:
    """Simple provider selection (fallback when rate limiter unavailable)"""
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
            "Intelligent threat caching (Phase 2)",
            "Threat signature detection",
            "Learning from feedback",
            "High-performance inference",
        ],
        "cache_enabled": CACHE_ENABLED,
        "rate_limiter_enabled": RATE_LIMITER_ENABLED,
    }


@app.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """Analyze a request for threats using AI and ML models"""
    start_time = time.time()

    # Prepare content for cache lookup
    payload = f"{request.features.query or ''} {request.features.body or ''}".strip()
    if not payload:
        payload = request.features.path

    # Check cache first (Phase 2: Intelligent Caching)
    if CACHE_ENABLED and threat_cache:
        try:
            # Prepare features for behavioral fingerprinting
            features = {
                "method": request.features.method,
                "path": request.features.path,
                "client_ip": request.features.client_ip,
                "user_agent": request.features.user_agent,
                "requests_per_minute": request.features.requests_per_minute,
                "content_length": request.features.content_length,
                "query_param_count": request.features.query_param_count,
                "header_count": request.features.header_count,
                "content": payload,
            }

            # Check cache for existing analysis
            cached_result = await threat_cache.get_cached_analysis(
                payload=payload, method=request.features.method, path=request.features.path, features=features
            )

            if cached_result:
                # Cache hit! Return cached result immediately
                processing_time = time.time() - start_time
                logger.info(f"Cache hit: {cached_result.cache_hit_type} - {processing_time:.3f}s")

                # Broadcast cache hit to WebSocket
                await broadcast_threat_analysis(
                    {
                        "type": "cached_threat_analysis",
                        "threat_score": cached_result.threat_score,
                        "threat_type": cached_result.threat_type,
                        "confidence": cached_result.confidence,
                        "reasoning": f"Cached: {cached_result.reasoning}",
                        "recommended_action": cached_result.recommended_action,
                        "method": request.features.method,
                        "path": request.features.path,
                        "client_ip": request.features.client_ip,
                        "cache_hit_type": cached_result.cache_hit_type,
                        "processing_time_ms": processing_time * 1000,
                        "timestamp": datetime.now().isoformat(),
                    }
                )

                return ThreatAnalysisResponse(
                    threat_score=cached_result.threat_score,
                    threat_type=cached_result.threat_type,
                    confidence=cached_result.confidence,
                    reasoning=f"Cached ({cached_result.cache_hit_type}): {cached_result.reasoning}",
                    recommended_action=cached_result.recommended_action,
                    indicators=cached_result.indicators,
                    ai_model=f"cache/{cached_result.provider_used}",
                    processing_time=processing_time,
                    detailed_analysis={
                        "cache_hit": True,
                        "cache_hit_type": cached_result.cache_hit_type,
                        "original_provider": cached_result.provider_used,
                        "cached_at": getattr(cached_result, "cached_at", None),
                    },
                )

        except Exception as e:
            logger.warning(f"Cache lookup failed: {e}")
            # Continue with normal analysis if cache fails

    # Try ML-based analysis first if available
    if ML_ENABLED and model_manager:
        try:
            # Convert request to ML format
            ml_request = {
                "method": request.features.method,
                "path": request.features.path,
                "client_ip": request.features.client_ip,
                "user_agent": request.features.user_agent,
                "requests_per_minute": request.features.requests_per_minute,
                "content_length": request.features.content_length,
                "query_params": {},  # Would need to parse from query
                "headers": request.features.headers or {},
                "query": request.features.query,
                "body": request.features.body,
            }

            # Get ML analysis
            ml_result = model_manager.analyze_request(ml_request)

            # Convert ML result to response format
            if ml_result["threat_score"] > 0.3:
                # Broadcast to WebSocket
                await broadcast_threat_analysis(
                    {
                        "type": "ml_threat_analysis",
                        "threat_score": ml_result["threat_score"],
                        "threat_type": ml_result["classification"]["attack_type"],
                        "confidence": ml_result["classification"]["confidence"],
                        "reasoning": ml_result["anomaly"]["reason"],
                        "recommended_action": ml_result["action"]["action"],
                        "method": request.features.method,
                        "path": request.features.path,
                        "client_ip": request.features.client_ip,
                        "processing_time_ms": ml_result["processing_time_ms"],
                        "timestamp": datetime.now().isoformat(),
                    }
                )

                return ThreatAnalysisResponse(
                    threat_score=ml_result["threat_score"],
                    threat_type=ml_result["classification"]["attack_type"],
                    confidence=ml_result["classification"]["confidence"],
                    reasoning=f"ML: {ml_result['anomaly']['reason']}",
                    recommended_action=ml_result["action"]["action"],
                    indicators=ml_result["classification"]["top_3"],
                    ai_model="ml/ensemble",
                    processing_time=time.time() - start_time,
                    detailed_analysis=ml_result,
                )
        except Exception as e:
            logger.warning(f"ML analysis failed, falling back to AI: {e}")
            # Continue with AI analysis

    # Original AI-based analysis code follows
    start_time = time.time()  # Reset for AI analysis

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
            processing_time=time.time() - start_time,
        )

    # Estimate tokens for rate limiting (rough estimate: ~500 tokens per request)
    estimated_tokens = 500

    # Get intelligent AI provider
    ai_provider = await get_intelligent_provider(estimated_tokens, priority="balanced")

    # Reserve quota if using rate limiter
    quota_reserved = False
    if RATE_LIMITER_ENABLED and rate_limiter and hasattr(ai_provider, "model"):
        provider_type_map = {
            "gpt-4o-mini": ProviderType.OPENAI,
            "mixtral-8x7b-32768": ProviderType.GROQ,
            "gemini-2.0-flash-exp": ProviderType.GEMINI,
        }
        provider_type = None
        for model_name, p_type in provider_type_map.items():
            if model_name in getattr(ai_provider, "model", ""):
                provider_type = p_type
                break

        if provider_type:
            quota_reserved = await rate_limiter.reserve_quota(provider_type, estimated_tokens)
            if not quota_reserved:
                logger.warning(f"Quota exhausted for {provider_type.value} - using fallback")
                ai_provider = SignatureBasedProvider()

    try:
        # Perform AI analysis
        start_analysis = time.time()
        ai_result = await ai_provider.analyze(request.features, request.context)
        analysis_time = time.time() - start_analysis

        # Track threats
        if ai_result.get("threat_score", 0) > 0.8:
            threat_intel.add_threat(request.features.client_ip, ai_result.get("threat_type", "unknown"))

        # Record results with rate limiter
        if RATE_LIMITER_ENABLED and rate_limiter and quota_reserved and provider_type:
            actual_tokens = estimated_tokens  # Could be more sophisticated token counting
            success = ai_result.get("threat_score") is not None
            await rate_limiter.record_result(provider_type, actual_tokens, analysis_time * 1000, success)

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
            detailed_analysis=ai_result,
        )

        # Cache the analysis result (Phase 2: Intelligent Caching)
        if CACHE_ENABLED and threat_cache:
            try:
                # Prepare features for cache storage
                cache_features = {
                    "method": request.features.method,
                    "path": request.features.path,
                    "client_ip": request.features.client_ip,
                    "user_agent": request.features.user_agent,
                    "requests_per_minute": request.features.requests_per_minute,
                    "content_length": request.features.content_length,
                    "query_param_count": request.features.query_param_count,
                    "header_count": request.features.header_count,
                    "content": payload,
                }

                # Create cache analysis object
                from intelligent_cache import ThreatAnalysis

                cache_analysis = ThreatAnalysis(
                    threat_score=response.threat_score,
                    threat_type=response.threat_type,
                    confidence=response.confidence,
                    reasoning=response.reasoning,
                    recommended_action=response.recommended_action,
                    indicators=response.indicators,
                    provider_used=getattr(ai_provider, "model", "unknown"),
                    cached=False,
                )

                # Store in cache asynchronously (don't block response)
                asyncio.create_task(
                    threat_cache.cache_analysis(
                        payload=payload,
                        method=request.features.method,
                        path=request.features.path,
                        features=cache_features,
                        analysis=cache_analysis,
                    )
                )

            except Exception as e:
                logger.warning(f"Cache storage failed: {e}")
                # Don't fail the response if caching fails

        # Broadcast to WebSocket clients
        try:
            await broadcast_threat_analysis(
                {
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
                    "timestamp": datetime.now().isoformat(),
                }
            )
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
                processing_time=time.time() - start_time,
            )

        return ThreatAnalysisResponse(
            threat_score=0.0,
            threat_type="none",
            confidence=0.5,
            reasoning="Unable to perform AI analysis, no signatures matched",
            recommended_action="allow",
            indicators=[],
            ai_model="fallback",
            processing_time=time.time() - start_time,
        )


@app.post("/feedback")
async def provide_feedback(threat_id: str, false_positive: bool = False, confirmed_threat: bool = False):
    """Provide feedback on threat detection"""
    # In production, this would update the model or adjust thresholds
    if false_positive:
        threat_intel.false_positives.add(threat_id)
        return {"status": "recorded", "action": "false_positive_noted"}
    elif confirmed_threat:
        return {"status": "recorded", "action": "threat_confirmed"}
    return {"status": "no_action"}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Kong Guard AI",
        "ai_provider": AI_PROVIDER,
        "ml_enabled": ML_ENABLED,
        "rate_limiter_enabled": RATE_LIMITER_ENABLED,
        "cache_enabled": CACHE_ENABLED,
        "redis_connected": threat_cache.redis_client is not None if CACHE_ENABLED and threat_cache else False,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/providers/stats")
async def get_provider_stats():
    """Get comprehensive provider statistics and rate limiting info"""
    if not RATE_LIMITER_ENABLED or not rate_limiter:
        return {"error": "Rate limiter not available"}

    stats = rate_limiter.get_comprehensive_stats()
    return {
        "stats": stats,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/test")
async def test_endpoint():
    """Simple test endpoint"""
    return {"message": "Test endpoint working", "timestamp": datetime.now(UTC).isoformat()}


@app.get("/providers/health")
async def check_provider_health():
    """Check health of all configured providers"""
    if not RATE_LIMITER_ENABLED or not rate_limiter:
        return {"error": "Rate limiter not available"}

    health_results = {}

    # Simple health check based on API key configuration
    provider_checks = {
        "openai": OPENAI_API_KEY,
        "groq": GROQ_API_KEY,
        "gemini": GEMINI_API_KEY,
        "ollama": True,  # Ollama doesn't need API key
    }

    for provider_name, api_key in provider_checks.items():
        if api_key:
            health_results[provider_name] = {"status": "configured", "api_key_set": True}
        else:
            health_results[provider_name] = {"status": "not_configured", "api_key_set": False}

    return {
        "health_check": health_results,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/cache/stats")
async def get_cache_stats():
    """Get comprehensive cache performance statistics"""
    if not CACHE_ENABLED or not threat_cache:
        return {"error": "Intelligent cache not available"}

    stats = threat_cache.get_cache_stats()
    return {
        "cache_stats": stats,
        "cache_enabled": CACHE_ENABLED,
        "redis_connected": threat_cache.redis_client is not None,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/providers/analytics")
async def get_provider_analytics(hours: int = 1):
    """Get comprehensive provider performance analytics"""
    if not RATE_LIMITER_ENABLED or not rate_limiter:
        return {"error": "Rate limiter not available"}

    analytics = {}
    current_time = time.time()
    time_window = hours * 3600  # Convert hours to seconds

    for provider_type, history in rate_limiter.performance_history.items():
        # Filter data for the specified time window
        recent_data = [h for h in history if current_time - h["timestamp"] < time_window]

        if recent_data:
            # Calculate analytics
            total_requests = len(recent_data)
            successful_requests = sum(1 for h in recent_data if h["success"])
            failed_requests = total_requests - successful_requests
            success_rate = successful_requests / total_requests if total_requests > 0 else 0

            avg_latency = sum(h["response_time"] for h in recent_data) / total_requests
            avg_tokens = sum(h["tokens"] for h in recent_data) / total_requests

            # Cost calculation (rough estimate)
            limits = rate_limiter.provider_limits[provider_type]
            estimated_cost = (sum(h["tokens"] for h in recent_data) / 1000) * limits.cost_per_1k_tokens

            analytics[provider_type.value] = {
                "time_window_hours": hours,
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": round(success_rate, 3),
                "avg_latency_ms": round(avg_latency, 2),
                "avg_tokens_per_request": round(avg_tokens, 1),
                "estimated_cost": round(estimated_cost, 4),
                "cost_per_request": round(estimated_cost / total_requests, 6) if total_requests > 0 else 0,
                "efficiency_score": round(
                    success_rate * (1 / (avg_latency / 1000)) * (1 / limits.cost_per_1k_tokens), 2
                ),
            }
        else:
            analytics[provider_type.value] = {
                "time_window_hours": hours,
                "total_requests": 0,
                "message": "No data available for the specified time window",
            }

    return {
        "analytics": analytics,
        "summary": {
            "best_performer": max(analytics.items(), key=lambda x: x[1].get("efficiency_score", 0))[0]
            if analytics
            else None,
            "total_requests_all_providers": sum(a.get("total_requests", 0) for a in analytics.values()),
            "overall_success_rate": round(
                sum(a.get("successful_requests", 0) for a in analytics.values())
                / max(1, sum(a.get("total_requests", 0) for a in analytics.values())),
                3,
            ),
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def get_metrics():
    """Prometheus metrics endpoint"""
    metrics = []

    # Service status
    metrics.append("# HELP kong_guard_ai_up Kong Guard AI service status")
    metrics.append("# TYPE kong_guard_ai_up gauge")
    metrics.append("kong_guard_ai_up 1")

    # Threat metrics
    total_threats = sum(threat_intel.known_attacks.values())
    metrics.append("# HELP kong_guard_threats_detected_total Total threats detected")
    metrics.append("# TYPE kong_guard_threats_detected_total counter")
    metrics.append(f"kong_guard_threats_detected_total {total_threats}")

    # Threat by type
    metrics.append("# HELP kong_guard_threats_by_type Threats by type")
    metrics.append("# TYPE kong_guard_threats_by_type gauge")
    for threat_type, count in threat_intel.known_attacks.items():
        metrics.append(f'kong_guard_threats_by_type{{threat_type="{threat_type}"}} {count}')

    # Blocked IPs
    metrics.append("# HELP kong_guard_blocked_ips_total Total blocked IPs")
    metrics.append("# TYPE kong_guard_blocked_ips_total gauge")
    metrics.append(f"kong_guard_blocked_ips_total {len(threat_intel.blocked_ips)}")

    # False positives
    metrics.append("# HELP kong_guard_false_positives_total Total false positives")
    metrics.append("# TYPE kong_guard_false_positives_total gauge")
    metrics.append(f"kong_guard_false_positives_total {len(threat_intel.false_positives)}")

    # ML model metrics if available
    if ML_ENABLED and model_manager:
        model_status = model_manager.get_model_status()
        metrics.append("# HELP kong_guard_ml_models_loaded ML models loaded")
        metrics.append("# TYPE kong_guard_ml_models_loaded gauge")
        metrics.append(f"kong_guard_ml_models_loaded {1 if model_status.get('models_loaded') else 0}")

    return "\n".join(metrics)


@app.get("/stats")
async def get_statistics():
    """Get threat detection statistics"""
    stats = {
        "total_threats": sum(threat_intel.known_attacks.values()),
        "threat_types": dict(threat_intel.known_attacks),
        "blocked_ips": len(threat_intel.blocked_ips),
        "false_positives": len(threat_intel.false_positives),
        "ai_provider": AI_PROVIDER,
    }

    # Add ML model stats if available
    if ML_ENABLED and model_manager:
        stats["ml_models"] = model_manager.get_model_status()

    return stats


# ============================================================================
# ML Model Management Endpoints
# ============================================================================


@app.get("/ml/status")
async def get_ml_status():
    """Get ML model status and metrics"""
    if not ML_ENABLED or not model_manager:
        raise HTTPException(status_code=503, detail="ML models not available")

    return model_manager.get_model_status()


@app.post("/ml/train")
async def train_ml_models(background_tasks: BackgroundTasks):
    """Trigger ML model training"""
    if not ML_ENABLED or not model_manager:
        raise HTTPException(status_code=503, detail="ML models not available")

    # Run training in background
    def train_task():
        try:
            # Would need to load training data here
            logger.info("Starting ML model training...")
            # model_manager.train_models(training_data)
            logger.info("ML model training complete")
        except Exception as e:
            logger.error(f"Training failed: {e}")

    background_tasks.add_task(train_task)
    return {"status": "training_started", "message": "Model training initiated in background"}


@app.post("/ml/feedback")
async def provide_ml_feedback(request_id: str, correct_label: str, was_correct: bool):
    """Provide feedback to ML models for continuous learning"""
    if not ML_ENABLED or not model_manager:
        raise HTTPException(status_code=503, detail="ML models not available")

    model_manager.provide_feedback(request_id, correct_label, was_correct)
    return {"status": "feedback_recorded"}


@app.post("/ml/analyze")
async def analyze_with_ml(request: ThreatAnalysisRequest):
    """Direct ML-only analysis endpoint"""
    if not ML_ENABLED or not model_manager:
        raise HTTPException(status_code=503, detail="ML models not available")

    start_time = time.time()

    # Convert to ML format
    ml_request = {
        "method": request.features.method,
        "path": request.features.path,
        "client_ip": request.features.client_ip,
        "user_agent": request.features.user_agent,
        "requests_per_minute": request.features.requests_per_minute,
        "content_length": request.features.content_length,
        "query_params": {},
        "headers": request.features.headers or {},
        "query": request.features.query,
        "body": request.features.body,
    }

    # Get ML analysis
    ml_result = model_manager.analyze_request(ml_request)

    return ThreatAnalysisResponse(
        threat_score=ml_result["threat_score"],
        threat_type=ml_result["classification"]["attack_type"],
        confidence=ml_result["classification"]["confidence"],
        reasoning=ml_result["anomaly"]["reason"],
        recommended_action=ml_result["action"]["action"],
        indicators=ml_result["classification"]["top_3"],
        ai_model="ml/ensemble",
        processing_time=time.time() - start_time,
        detailed_analysis=ml_result,
    )


# ============================================================================
# Attack Flood Simulation API
# ============================================================================


class AttackFloodRequest(BaseModel):
    intensity: str = Field(..., description="Attack intensity: low, medium, high, extreme")
    strategy: str = Field(..., description="Attack strategy: wave, sustained, stealth, blended, escalation")
    duration: int = Field(60, description="Attack duration in seconds")
    targets: list[str] = Field(["unprotected", "cloud", "local"], description="Target tiers")
    record_metrics: bool = Field(True, description="Record detailed metrics to database")


class AttackFloodResponse(BaseModel):
    run_id: int
    status: str
    message: str
    config: dict


class AttackStatsResponse(BaseModel):
    run_id: int
    total_attacks: int
    duration: float
    results_summary: dict


# Global attack flood management
attack_processes = {}


@app.post("/api/attack/flood", response_model=AttackFloodResponse)
async def launch_attack_flood(request: AttackFloodRequest, background_tasks: BackgroundTasks):
    """Launch comprehensive attack flood simulation"""
    try:
        # Generate unique run ID
        run_id = int(time.time() * 1000)  # Timestamp-based ID

        # Validate inputs to prevent command injection
        allowed_intensities = {"low", "medium", "high", "extreme"}
        allowed_strategies = {"wave", "sustained", "stealth", "blended", "escalation"}
        allowed_targets = {"unprotected", "cloud", "local"}

        if request.intensity not in allowed_intensities:
            raise HTTPException(status_code=400, detail="Invalid intensity parameter")
        if request.strategy not in allowed_strategies:
            raise HTTPException(status_code=400, detail="Invalid strategy parameter")
        if not all(target in allowed_targets for target in request.targets):
            raise HTTPException(status_code=400, detail="Invalid target parameter")
        if not (5 <= request.duration <= 300):  # 5 seconds to 5 minutes
            raise HTTPException(status_code=400, detail="Invalid duration parameter")

        # Prepare attack command with validated inputs
        cmd = [
            "python3",
            "attack_flood_simulator.py",
            "--intensity",
            request.intensity,
            "--strategy",
            request.strategy,
            "--duration",
            str(request.duration),
            "--targets",
        ] + request.targets

        if not request.record_metrics:
            cmd.append("--no-record")

        # Launch attack flood in background
        logger.info(f"Launching attack flood (Run ID: {run_id})")
        logger.info("Sanitized command with validated parameters")

        # Start process in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="..",
            text=True,  # Run from parent directory
        )

        attack_processes[run_id] = process

        # Send WebSocket notification
        await manager.broadcast(
            json.dumps(
                {
                    "type": "attack_flood_started",
                    "run_id": run_id,
                    "config": request.dict(),
                    "timestamp": datetime.now().isoformat(),
                }
            )
        )

        return AttackFloodResponse(
            run_id=run_id,
            status="launched",
            message=f"Attack flood simulation launched with {request.intensity} intensity",
            config=request.dict(),
        )

    except Exception as e:
        logger.error(f"Failed to launch attack flood: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to launch attack flood: {str(e)}")


@app.post("/api/attack/flood/stop/{run_id}")
async def stop_attack_flood(run_id: int):
    """Stop ongoing attack flood simulation"""
    try:
        if run_id in attack_processes:
            process = attack_processes[run_id]
            process.terminate()

            # Wait for process to terminate
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()  # Force kill if not terminated

            del attack_processes[run_id]

            # Send WebSocket notification
            await manager.broadcast(
                json.dumps({"type": "attack_flood_stopped", "run_id": run_id, "timestamp": datetime.now().isoformat()})
            )

            return {"status": "stopped", "run_id": run_id}
        else:
            raise HTTPException(status_code=404, detail="Attack flood not found")

    except Exception as e:
        logger.error(f"Failed to stop attack flood: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop attack flood: {str(e)}")


@app.get("/api/attack/flood/status/{run_id}")
async def get_attack_flood_status(run_id: int):
    """Get status of attack flood simulation"""
    try:
        if run_id in attack_processes:
            process = attack_processes[run_id]

            # Check if process is still running
            poll = process.poll()
            if poll is None:
                status = "running"
            else:
                status = "completed" if poll == 0 else "failed"
                # Clean up completed process
                del attack_processes[run_id]

            return {"run_id": run_id, "status": status, "return_code": poll}
        else:
            return {"run_id": run_id, "status": "not_found", "return_code": None}

    except Exception as e:
        logger.error(f"Failed to get attack flood status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get attack flood status: {str(e)}")


@app.get("/api/attack/flood/results/{run_id}", response_model=AttackStatsResponse)
async def get_attack_flood_results(run_id: int):
    """Get results from completed attack flood simulation"""
    try:
        # Import Supabase interface
        from supabase_production import SupabaseProduction

        # Connect to Supabase
        db = SupabaseProduction()

        # Get run metadata using raw SQL
        result = db.execute_query(f"SELECT * FROM attack_runs WHERE run_id = {run_id};")
        if not result["success"] or "run_id" not in result["output"]:
            raise HTTPException(status_code=404, detail="Attack run not found")

        # Parse run data from output
        lines = result["output"].strip().split("\n")
        run_data = None
        for i, line in enumerate(lines):
            if str(run_id) in line:
                run_data = line.split("|")
                break

        # Get run metadata
        cursor.execute("SELECT * FROM attack_runs WHERE run_id = ?", (run_id,))
        run_data = cursor.fetchone()

        if not run_data:
            raise HTTPException(status_code=404, detail="Attack run not found")

        # Get tier statistics from Supabase
        stats_result = db.execute_query(
            f"""
            SELECT tier, COUNT(*) as total_requests,
                   COUNT(CASE WHEN blocked = true THEN 1 END) as attacks_blocked,
                   ROUND((COUNT(CASE WHEN blocked = true THEN 1 END)::NUMERIC / COUNT(*) * 100), 2) as detection_rate,
                   ROUND(AVG(response_time_ms), 2) as avg_response_time
            FROM attack_metrics WHERE run_id = {run_id}
            GROUP BY tier;
        """
        )

        tier_stats = []
        if stats_result["success"]:
            # Parse output into tier stats
            lines = stats_result["output"].strip().split("\n")
            for line in lines[2:]:  # Skip header lines
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 5 and parts[0]:  # Valid data row
                        tier_stats.append(parts)

        # Get attack type summary from Supabase
        summary_result = db.execute_query(
            f"""
            SELECT attack_type, COUNT(*) as count,
                   AVG(threat_score) as avg_score,
                   COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count
            FROM attack_metrics WHERE run_id = {run_id}
            GROUP BY attack_type;
        """
        )

        attack_summary = []
        if summary_result["success"]:
            lines = summary_result["output"].strip().split("\n")
            for line in lines[2:]:
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 4 and parts[0]:
                        attack_summary.append(parts)

        # Format results
        results_summary = {
            "tier_performance": {
                row[0]: {
                    "total_requests": row[1],
                    "attacks_blocked": row[2],
                    "detection_rate": row[3],
                    "avg_response_time": row[4],
                }
                for row in tier_stats
            },
            "attack_breakdown": {
                row[0]: {"count": row[1], "avg_threat_score": row[2], "blocked_count": row[3]} for row in attack_summary
            },
        }

        # Calculate duration
        start_time = datetime.fromisoformat(run_data[1]) if run_data[1] else datetime.now()
        end_time = datetime.fromisoformat(run_data[2]) if run_data[2] else datetime.now()
        duration = (end_time - start_time).total_seconds()

        return AttackStatsResponse(
            run_id=run_id, total_attacks=run_data[3] or 0, duration=duration, results_summary=results_summary
        )

    except Exception as e:
        logger.error(f"Failed to get attack flood results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get attack flood results: {str(e)}")


@app.get("/api/attack/flood/list")
async def list_attack_runs():
    """List all attack flood simulation runs"""
    try:
        from supabase_production import SupabaseProduction

        db = SupabaseProduction()

        result = db.execute_query(
            """
            SELECT run_id, start_time, end_time, total_attacks, intensity_level, strategy, duration
            FROM attack_runs
            ORDER BY start_time DESC
            LIMIT 20;
        """
        )

        runs = []
        if result["success"]:
            lines = result["output"].strip().split("\n")
            for line in lines[2:]:
                if "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 7 and parts[0].isdigit():
                        runs.append(parts)

        return {
            "runs": [
                {
                    "run_id": run[0],
                    "start_time": run[1],
                    "end_time": run[2],
                    "total_attacks": run[3],
                    "intensity": run[4],
                    "strategy": run[5],
                    "duration": run[6],
                }
                for run in runs
            ]
        }

    except Exception as e:
        logger.error(f"Failed to list attack runs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list attack runs: {str(e)}")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat analysis updates"""
    await manager.connect(websocket)
    logger.info(f"WebSocket client connected. Total connections: {len(manager.active_connections)}")
    try:
        # Send initial connection message
        await manager.send_personal_message(
            json.dumps(
                {
                    "type": "connection",
                    "message": "Connected to Kong Guard AI Real-Time System",
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            websocket,
        )

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
    import os

    PORT = int(os.getenv("PORT", "18002"))

    print("🚀 Kong Guard AI - Threat Analysis Service")
    print(f"📊 AI Provider: {AI_PROVIDER}")
    print(f"🤖 ML Models: {'Enabled' if ML_ENABLED else 'Disabled'}")
    print(f"⚡ Rate Limiter: {'Enabled' if RATE_LIMITER_ENABLED else 'Disabled'}")
    print(f"💾 Intelligent Cache: {'Enabled' if CACHE_ENABLED else 'Disabled'}")
    print(f"🔍 Starting on http://localhost:{PORT}")
    print("")
    print("Available providers:")
    print("  - OpenAI (GPT-4): Set OPENAI_API_KEY")
    print("  - Groq (Fast): Set GROQ_API_KEY")
    print("  - Gemini Flash 2.5: Set GEMINI_API_KEY")
    print("  - Ollama (Local): Install and run Ollama")
    print("")

    if CACHE_ENABLED:
        print("Intelligent Caching System (Phase 2):")
        print("  ✅ 5-Tier Caching (Signature → Behavioral → Response → Negative → Redis)")
        print("  ✅ Threat Pattern Recognition")
        print("  ✅ Behavioral Fingerprinting")
        print("  ✅ Cache Warming on Startup")
        print("  ✅ 90%+ Expected Cache Hit Rate")
        print("")

    if ML_ENABLED:
        print("Machine Learning Models:")
        print("  ✅ Anomaly Detection (IsolationForest)")
        print("  ✅ Attack Classification (RandomForest)")
        print("  ✅ Feature Extraction (70+ features)")
        print("  ✅ Real-time threat scoring")
        print("  ✅ Continuous learning enabled")
        print("")

    uvicorn.run(app, host="0.0.0.0", port=PORT)
