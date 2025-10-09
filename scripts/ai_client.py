#!/usr/bin/env python3
"""
Async AI client for Kong Guard AI with caching and deadline handling
"""

import asyncio
import aiohttp
import time
import hashlib
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class AIResponse:
    """Standardized AI response structure"""
    action: str
    confidence: float
    threat_type: str
    reason: Optional[str] = None
    latency_ms: float = 0.0
    ai_model: Optional[str] = None
    cached: bool = False


class AIClient:
    """Async AI client with caching and deadline handling"""
    
    def __init__(self, cache_ttl: int = 300, default_timeout_ms: int = 250):
        self.cache_ttl = cache_ttl
        self.default_timeout_ms = default_timeout_ms
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._session:
            await self._session.close()
    
    def _hash_payload(self, payload: Dict[str, Any]) -> str:
        """Create hash key for payload caching"""
        # Create deterministic hash of payload
        payload_str = json.dumps(payload, sort_keys=True)
        return hashlib.md5(payload_str.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[AIResponse]:
        """Get cached response if available and not expired"""
        if cache_key not in self._cache:
            return None
        
        cached = self._cache[cache_key]
        if time.time() - cached["timestamp"] > self.cache_ttl:
            # Expired, remove from cache
            del self._cache[cache_key]
            return None
        
        # Return cached response
        response_data = cached["response"]
        return AIResponse(
            action=response_data.get("action", "monitor"),
            confidence=response_data.get("confidence", 0.0),
            threat_type=response_data.get("threat_type", "unknown"),
            reason=response_data.get("reason"),
            latency_ms=0.1,  # Cache hit latency
            ai_model=response_data.get("ai_model"),
            cached=True
        )
    
    def _cache_response(self, cache_key: str, response: AIResponse):
        """Cache response for future use"""
        self._cache[cache_key] = {
            "timestamp": time.time(),
            "response": {
                "action": response.action,
                "confidence": response.confidence,
                "threat_type": response.threat_type,
                "reason": response.reason,
                "ai_model": response.ai_model,
            }
        }
    
    async def analyze_with_deadline(
        self, 
        url: str, 
        payload: Dict[str, Any], 
        timeout_ms: Optional[int] = None
    ) -> AIResponse:
        """
        Analyze request with deadline and caching
        
        Args:
            url: AI service endpoint URL
            payload: Request payload for analysis
            timeout_ms: Timeout in milliseconds
            
        Returns:
            AIResponse with analysis results
        """
        if timeout_ms is None:
            timeout_ms = self.default_timeout_ms
        
        if not self._session:
            raise RuntimeError("AIClient must be used as async context manager")
        
        # Check cache first
        cache_key = self._hash_payload(payload)
        cached_response = self._get_cached_response(cache_key)
        if cached_response:
            logger.debug(f"Cache hit for key: {cache_key[:8]}...")
            return cached_response
        
        # Make request with deadline
        start_time = time.time()
        try:
            timeout_seconds = timeout_ms / 1000.0
            async with asyncio.timeout(timeout_seconds):
                async with self._session.post(
                    url, 
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        latency_ms = (time.time() - start_time) * 1000
                        
                        ai_response = AIResponse(
                            action=data.get("action", "monitor"),
                            confidence=data.get("confidence", 0.0),
                            threat_type=data.get("threat_type", "unknown"),
                            reason=data.get("reason"),
                            latency_ms=latency_ms,
                            ai_model=data.get("ai_model"),
                            cached=False
                        )
                        
                        # Cache successful response
                        self._cache_response(cache_key, ai_response)
                        return ai_response
                    else:
                        logger.warning(f"AI service returned status {response.status}")
                        return AIResponse(
                            action="monitor",
                            confidence=0.0,
                            threat_type="unknown",
                            reason=f"http_error_{response.status}",
                            latency_ms=(time.time() - start_time) * 1000
                        )
        
        except asyncio.TimeoutError:
            logger.warning(f"AI analysis timeout after {timeout_ms}ms")
            return AIResponse(
                action="monitor",
                confidence=0.0,
                threat_type="unknown",
                reason="deadline_exceeded",
                latency_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return AIResponse(
                action="monitor",
                confidence=0.0,
                threat_type="unknown",
                reason=f"error_{type(e).__name__}",
                latency_ms=(time.time() - start_time) * 1000
            )
    
    async def analyze_batch(
        self, 
        requests: list[tuple[str, Dict[str, Any]]], 
        timeout_ms: Optional[int] = None
    ) -> list[AIResponse]:
        """
        Analyze multiple requests concurrently
        
        Args:
            requests: List of (url, payload) tuples
            timeout_ms: Timeout per request
            
        Returns:
            List of AIResponse objects
        """
        tasks = [
            self.analyze_with_deadline(url, payload, timeout_ms)
            for url, payload in requests
        ]
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(self._cache)
        if total_entries == 0:
            return {"total_entries": 0, "hit_rate": 0.0}
        
        # Calculate hit rate (simplified)
        current_time = time.time()
        valid_entries = sum(
            1 for entry in self._cache.values()
            if current_time - entry["timestamp"] <= self.cache_ttl
        )
        
        return {
            "total_entries": total_entries,
            "valid_entries": valid_entries,
            "hit_rate": valid_entries / total_entries if total_entries > 0 else 0.0
        }
    
    def clear_cache(self):
        """Clear all cached responses"""
        self._cache.clear()
        logger.info("AI client cache cleared")


# Convenience functions for backward compatibility
async def analyze_with_deadline(
    session: aiohttp.ClientSession,
    url: str, 
    payload: Dict[str, Any], 
    timeout_ms: int = 250
) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility
    
    Args:
        session: aiohttp session
        url: AI service endpoint URL
        payload: Request payload
        timeout_ms: Timeout in milliseconds
        
    Returns:
        Response dictionary
    """
    async with AIClient() as client:
        response = await client.analyze_with_deadline(url, payload, timeout_ms)
        return {
            "action": response.action,
            "confidence": response.confidence,
            "threat_type": response.threat_type,
            "reason": response.reason,
            "latency_ms": response.latency_ms,
            "ai_model": response.ai_model,
            "cached": response.cached
        }


if __name__ == "__main__":
    # Test the AI client
    async def test_client():
        async with AIClient() as client:
            # Test payload
            payload = {
                "features": {
                    "method": "POST",
                    "path": "/api/users",
                    "query": "id=1; DROP TABLE users; --",
                    "body": "SELECT * FROM users",
                },
                "context": {
                    "attack_type": "sql_injection"
                }
            }
            
            # Test analysis
            response = await client.analyze_with_deadline(
                "http://localhost:28100/analyze",
                payload,
                timeout_ms=5000
            )
            
            print(f"Response: {response}")
            print(f"Cache stats: {client.get_cache_stats()}")
    
    # Run test
    asyncio.run(test_client())
