#!/usr/bin/env python3
"""
Kong Guard AI - Local Ollama Service
Privacy-focused local AI threat detection using Ollama models
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Any
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic import Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Kong Guard AI - Local Ollama Service",
    description="Privacy-focused local AI threat detection",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ollama configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")


# Models for API compatibility with cloud service
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


class OllamaService:
    def __init__(self):
        self.model = OLLAMA_MODEL
        self.base_url = OLLAMA_BASE_URL
        self.client = httpx.AsyncClient(timeout=30.0)

        # Threat patterns for local analysis
        self.threat_patterns = {
            "sql_injection": [
                "union select",
                "drop table",
                "or 1=1",
                "' or '1'='1",
                "insert into",
                "delete from",
                "update set",
                "create table",
                "alter table",
                "exec(",
                "sp_",
                "xp_",
                "information_schema",
            ],
            "xss": [
                "<script",
                "</script>",
                "javascript:",
                "onerror=",
                "onload=",
                "eval(",
                "document.cookie",
                "window.location",
                "innerHTML=",
                "setTimeout(",
                "setInterval(",
                "alert(",
                "prompt(",
                "confirm(",
            ],
            "command_injection": [
                ";",
                "|",
                "&",
                "`",
                "$(",
                "rm -rf",
                "cat /etc/passwd",
                "nc ",
                "netcat",
                "wget ",
                "curl ",
                "/bin/sh",
                "/bin/bash",
                "ping ",
                "nslookup",
                "dig ",
                "whoami",
                "id",
                "ps aux",
            ],
            "path_traversal": [
                "../",
                "..\\",
                "%2e%2e%2f",
                "%2e%2e%5c",
                "....//",
                "/etc/passwd",
                "/etc/shadow",
                "\\windows\\system32",
                "boot.ini",
                "web.config",
                ".htaccess",
                "php.ini",
            ],
            "ldap_injection": [
                "*)(&",
                "*)(|",
                "admin*",
                "*)(cn=*",
                "*)(objectclass=*)",
                "*(|(objectclass=*))",
                "*))%00",
                "*))(|",
                "*)(uid=*",
            ],
        }

    async def check_ollama_health(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    async def ensure_model_loaded(self) -> bool:
        """Ensure the model is loaded in Ollama"""
        try:
            # Check if model is available
            response = await self.client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                tags = response.json()
                models = [model["name"] for model in tags.get("models", [])]

                if self.model not in models:
                    logger.warning(f"Model {self.model} not found. Available models: {models}")
                    # Use first available model or default to mistral
                    if models:
                        self.model = models[0]
                        logger.info(f"Using model: {self.model}")
                    else:
                        logger.error("No models available in Ollama")
                        return False

            return True
        except Exception as e:
            logger.error(f"Failed to ensure model loaded: {e}")
            return False

    def pattern_based_analysis(self, request: ThreatAnalysisRequest) -> dict[str, Any]:
        """Fast pattern-based threat analysis as fallback"""
        threat_score = 0.0
        threat_type = "none"
        indicators = []

        # Combine all text for analysis
        text_content = f"{request.features.query} {request.features.body} {request.features.path}".lower()

        # Check each threat category
        for category, patterns in self.threat_patterns.items():
            category_matches = 0
            for pattern in patterns:
                if pattern.lower() in text_content:
                    category_matches += 1
                    indicators.append(f"Pattern match: {pattern}")

            if category_matches > 0:
                # Calculate threat score based on pattern matches
                category_score = min(0.9, category_matches * 0.2 + 0.5)
                if category_score > threat_score:
                    threat_score = category_score
                    threat_type = category.replace("_", " ").title()

        # Additional heuristics
        if request.features.requests_per_minute > 100:
            threat_score += 0.1
            indicators.append("High request rate detected")

        if "AttackBot" in request.features.user_agent:
            threat_score += 0.2
            indicators.append("Suspicious user agent")

        if request.context.failed_attempts > 5:
            threat_score += 0.15
            indicators.append("Multiple failed attempts")

        threat_score = min(1.0, threat_score)

        return {
            "threat_score": threat_score,
            "threat_type": threat_type if threat_score > 0.3 else "none",
            "confidence": min(0.85, threat_score + 0.1),
            "reasoning": f"Pattern-based analysis detected {len(indicators)} suspicious indicators"
            if indicators
            else "No suspicious patterns detected",
            "indicators": indicators[:5],  # Limit indicators
        }

    async def analyze_with_ollama(self, request: ThreatAnalysisRequest) -> dict[str, Any]:
        """Analyze request using Ollama LLM"""
        try:
            # Prepare prompt for threat analysis
            prompt = f"""
You are a cybersecurity expert analyzing an API request for potential threats.

Request Details:
- Method: {request.features.method}
- Path: {request.features.path}
- Query: {request.features.query}
- Body: {request.features.body}
- User Agent: {request.features.user_agent}
- Client IP: {request.features.client_ip}
- Request Rate: {request.features.requests_per_minute}/min

Analyze this request and respond with a JSON object containing:
1. threat_score: 0.0-1.0 (0=safe, 1=extremely malicious)
2. threat_type: category of threat (SQL Injection, XSS, Command Injection, Path Traversal, etc., or "none")
3. reasoning: brief explanation of your analysis
4. indicators: list of suspicious elements found

Focus on detecting: SQL injection, XSS, command injection, path traversal, LDAP injection, and other API attacks.

Response format: {{"threat_score": 0.85, "threat_type": "SQL Injection", "reasoning": "Contains SQL union select statement", "indicators": ["union select", "or 1=1"]}}
"""

            # Send request to Ollama
            response = await self.client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 200},
                },
            )

            if response.status_code == 200:
                result = response.json()
                ollama_response = result.get("response", "").strip()

                # Try to parse JSON response from Ollama
                try:
                    # Extract JSON from response (Ollama sometimes adds extra text)
                    json_start = ollama_response.find("{")
                    json_end = ollama_response.rfind("}") + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = ollama_response[json_start:json_end]
                        ollama_analysis = json.loads(json_str)

                        return {
                            "threat_score": float(ollama_analysis.get("threat_score", 0.0)),
                            "threat_type": str(ollama_analysis.get("threat_type", "none")),
                            "reasoning": str(ollama_analysis.get("reasoning", "Local AI analysis completed")),
                            "indicators": list(ollama_analysis.get("indicators", [])),
                            "confidence": min(0.95, float(ollama_analysis.get("threat_score", 0.0)) + 0.05),
                        }
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Ollama JSON response: {e}")
                    logger.debug(f"Raw response: {ollama_response}")

        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")

        # Fallback to pattern-based analysis
        return self.pattern_based_analysis(request)


# Initialize service
ollama_service = OllamaService()


@app.on_event("startup")
async def startup_event():
    """Initialize Ollama service on startup"""
    logger.info("Starting Kong Guard AI - Local Ollama Service")

    # Check Ollama availability
    if await ollama_service.check_ollama_health():
        logger.info("✅ Ollama service is available")
        if await ollama_service.ensure_model_loaded():
            logger.info(f"✅ Model {ollama_service.model} is ready")
        else:
            logger.warning("⚠️ Model not available, using pattern-based fallback")
    else:
        logger.warning("⚠️ Ollama not available, using pattern-based analysis only")


@app.get("/")
async def root():
    """Service health check"""
    return {
        "service": "Kong Guard AI - Local Ollama Service",
        "status": "operational",
        "version": "1.0.0",
        "ai_provider": "ollama",
        "model": ollama_service.model,
        "privacy": "fully_local",
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    ollama_healthy = await ollama_service.check_ollama_health()

    return {
        "status": "healthy" if ollama_healthy else "degraded",
        "ollama_available": ollama_healthy,
        "model": ollama_service.model,
        "fallback_mode": not ollama_healthy,
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """Analyze a request for threats using local Ollama"""
    start_time = time.time()

    try:
        # Perform analysis
        if await ollama_service.check_ollama_health():
            analysis = await ollama_service.analyze_with_ollama(request)
        else:
            logger.info("Using pattern-based fallback analysis")
            analysis = ollama_service.pattern_based_analysis(request)

        processing_time = time.time() - start_time

        # Determine recommended action
        threat_score = analysis["threat_score"]
        if threat_score >= 0.8:
            recommended_action = "block"
        elif threat_score >= 0.5:
            recommended_action = "monitor"
        else:
            recommended_action = "allow"

        # Determine actual AI model being used
        is_fallback = not await ollama_service.check_ollama_health()
        actual_model = "pattern-based/regex" if is_fallback else f"ollama/{ollama_service.model}"

        # Build response
        response = ThreatAnalysisResponse(
            threat_score=threat_score,
            threat_type=analysis["threat_type"],
            confidence=analysis["confidence"],
            reasoning=analysis["reasoning"],
            recommended_action=recommended_action,
            indicators=analysis["indicators"],
            ai_model=actual_model,
            processing_time=processing_time,
            detailed_analysis={
                "local_processing": True,
                "privacy_preserved": True,
                "model_used": ollama_service.model if not is_fallback else "pattern-based",
                "fallback_mode": is_fallback,
            },
        )

        logger.info(
            f"Local analysis completed: {analysis['threat_type']} (score: {threat_score:.2f}, time: {processing_time:.3f}s)"
        )

        return response

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/models")
async def list_models():
    """List available Ollama models"""
    try:
        if await ollama_service.check_ollama_health():
            response = await ollama_service.client.get(f"{ollama_service.base_url}/api/tags")
            if response.status_code == 200:
                return response.json()
        return {"models": [], "error": "Ollama not available"}
    except Exception as e:
        return {"models": [], "error": str(e)}


if __name__ == "__main__":
    uvicorn.run("ollama_service:app", host="0.0.0.0", port=18003, reload=False, log_level="info")
