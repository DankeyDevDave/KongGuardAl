#!/usr/bin/env python3
"""
Kong Guard AI - Intelligent Multi-Tier Caching System
Reduces LLM API calls by 90%+ through smart threat pattern caching
"""

import asyncio
import hashlib
import json
import time
import pickle
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, asdict
from collections import OrderedDict
import logging
import redis.asyncio as redis

logger = logging.getLogger(__name__)

@dataclass
class ThreatAnalysis:
    threat_score: float
    threat_type: str
    confidence: float
    reasoning: str
    recommended_action: str
    indicators: List[str]
    provider_used: str
    cached: bool = False
    cache_hit_type: Optional[str] = None

@dataclass
class CacheStats:
    signature_hits: int = 0
    behavioral_hits: int = 0
    response_hits: int = 0
    negative_hits: int = 0
    total_requests: int = 0
    cache_hit_rate: float = 0.0
    cost_savings_usd: float = 0.0

class IntelligentThreatCache:
    """Multi-tier caching system for threat analysis optimization"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_client = None
        self.redis_url = redis_url
        
        # Local memory caches (LRU)
        self.signature_cache = OrderedDict()  # Exact payload matches
        self.behavioral_cache = OrderedDict() # Pattern fingerprints  
        self.response_cache = OrderedDict()   # Recent responses
        self.negative_cache = OrderedDict()   # Known safe patterns
        
        # Cache size limits
        self.max_signature_cache = 10000
        self.max_behavioral_cache = 5000
        self.max_response_cache = 1000
        self.max_negative_cache = 2000
        
        # Cache TTLs (seconds)
        self.signature_ttl = 86400 * 7  # 7 days
        self.behavioral_ttl = 86400     # 24 hours
        self.response_ttl = 300         # 5 minutes
        self.negative_ttl = 3600        # 1 hour
        
        # Statistics
        self.stats = CacheStats()
        
        # Known threat signatures (high-confidence patterns)
        self.threat_signatures = {
            'sql_injection_patterns': [
                "union select", "' or 1=1", "'; drop table",
                "admin'--", "1' and '1'='1", "or 1=1#"
            ],
            'xss_patterns': [
                "<script>", "javascript:", "onerror=",
                "onload=", "<img src=x onerror=", "eval("
            ],
            'command_injection_patterns': [
                "; cat /etc/passwd", "&& whoami", "| nc ",
                "; rm -rf", "$(curl", "`wget"
            ],
            'path_traversal_patterns': [
                "../../../etc/passwd", "..\\..\\windows\\system32",
                "%2e%2e%2f", "....//", "..;/"
            ]
        }
    
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = await redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis cache initialized successfully")
        except Exception as e:
            logger.warning(f"Redis initialization failed: {e}. Using memory-only cache")
            self.redis_client = None
    
    def _generate_signature_key(self, payload: str, method: str, path: str) -> str:
        """Generate cache key for exact signature matching"""
        content = f"{method}:{path}:{payload}"
        return f"sig:{hashlib.sha256(content.encode()).hexdigest()[:16]}"
    
    def _generate_behavioral_key(self, features: Dict[str, Any]) -> str:
        """Generate cache key for behavioral pattern matching"""
        # Extract behavioral fingerprint
        fingerprint = {
            'has_sql_keywords': any(kw in features.get('content', '').lower() 
                                  for kw in ['select', 'union', 'insert', 'update', 'delete']),
            'has_script_tags': '<script' in features.get('content', '').lower(),
            'has_special_chars': any(char in features.get('content', '') 
                                   for char in ['<', '>', '"', "'", '&', ';']),
            'length_bucket': len(features.get('content', '')) // 100,
            'request_method': features.get('method', 'GET'),
            'content_type': features.get('content_type', '').split(';')[0],
            'rate_bucket': min(features.get('requests_per_minute', 0) // 10, 10)
        }
        
        content = json.dumps(fingerprint, sort_keys=True)
        return f"beh:{hashlib.sha256(content.encode()).hexdigest()[:16]}"
    
    def _check_threat_signatures(self, payload: str) -> Optional[ThreatAnalysis]:
        """Fast signature-based threat detection"""
        payload_lower = payload.lower()
        
        for category, patterns in self.threat_signatures.items():
            for pattern in patterns:
                if pattern in payload_lower:
                    threat_type = category.replace('_patterns', '').replace('_', ' ')
                    
                    return ThreatAnalysis(
                        threat_score=0.95,
                        threat_type=threat_type,
                        confidence=0.98,
                        reasoning=f"Known {threat_type} signature detected: {pattern}",
                        recommended_action="block",
                        indicators=[pattern],
                        provider_used="signature_cache",
                        cached=True,
                        cache_hit_type="signature"
                    )
        
        return None
    
    async def get_cached_analysis(
        self, 
        payload: str, 
        method: str = "POST",
        path: str = "/",
        features: Optional[Dict[str, Any]] = None
    ) -> Optional[ThreatAnalysis]:
        """Attempt to retrieve analysis from multi-tier cache"""
        
        self.stats.total_requests += 1
        
        # Tier 1: Signature Cache (exact matches for known threats)
        signature_result = self._check_threat_signatures(payload)
        if signature_result:
            self.stats.signature_hits += 1
            self._update_hit_rate()
            return signature_result
        
        # Tier 2: Exact payload cache
        sig_key = self._generate_signature_key(payload, method, path)
        cached_result = await self._get_from_cache(sig_key, self.signature_cache, "signature")
        if cached_result:
            self.stats.signature_hits += 1
            self._update_hit_rate()
            return cached_result
        
        # Tier 3: Behavioral pattern cache
        if features:
            beh_key = self._generate_behavioral_key(features)
            cached_result = await self._get_from_cache(beh_key, self.behavioral_cache, "behavioral")
            if cached_result:
                self.stats.behavioral_hits += 1
                self._update_hit_rate()
                return cached_result
        
        # Tier 4: Recent response cache
        resp_key = f"resp:{hashlib.sha256(payload.encode()).hexdigest()[:12]}"
        cached_result = await self._get_from_cache(resp_key, self.response_cache, "response")
        if cached_result:
            self.stats.response_hits += 1
            self._update_hit_rate()
            return cached_result
        
        # Tier 5: Negative cache (known safe patterns)
        neg_key = f"neg:{hashlib.sha256(payload.encode()).hexdigest()[:12]}"
        cached_result = await self._get_from_cache(neg_key, self.negative_cache, "negative")
        if cached_result:
            self.stats.negative_hits += 1
            self._update_hit_rate()
            return cached_result
        
        return None
    
    async def cache_analysis(
        self, 
        payload: str,
        method: str,
        path: str,
        features: Dict[str, Any],
        analysis: ThreatAnalysis
    ):
        """Cache analysis result in appropriate tiers"""
        
        analysis.cached = True
        
        # Determine cache strategy based on threat score
        if analysis.threat_score >= 0.8:
            # High-confidence threats: signature + behavioral cache
            sig_key = self._generate_signature_key(payload, method, path)
            await self._store_in_cache(
                sig_key, analysis, self.signature_cache, 
                self.max_signature_cache, self.signature_ttl
            )
            
            beh_key = self._generate_behavioral_key(features)
            await self._store_in_cache(
                beh_key, analysis, self.behavioral_cache,
                self.max_behavioral_cache, self.behavioral_ttl
            )
            
        elif analysis.threat_score <= 0.2:
            # Low threat: negative cache (safe patterns)
            neg_key = f"neg:{hashlib.sha256(payload.encode()).hexdigest()[:12]}"
            await self._store_in_cache(
                neg_key, analysis, self.negative_cache,
                self.max_negative_cache, self.negative_ttl
            )
            
        else:
            # Medium confidence: response cache only
            resp_key = f"resp:{hashlib.sha256(payload.encode()).hexdigest()[:12]}"
            await self._store_in_cache(
                resp_key, analysis, self.response_cache,
                self.max_response_cache, self.response_ttl
            )
    
    async def _get_from_cache(
        self, 
        key: str, 
        local_cache: OrderedDict, 
        cache_type: str
    ) -> Optional[ThreatAnalysis]:
        """Get item from cache with Redis fallback"""
        
        # Check local memory cache first
        if key in local_cache:
            item, timestamp = local_cache[key]
            ttl = getattr(self, f"{cache_type}_ttl")
            
            if time.time() - timestamp < ttl:
                # Move to end (LRU)
                local_cache.move_to_end(key)
                item.cache_hit_type = cache_type
                return item
            else:
                # Expired
                del local_cache[key]
        
        # Check Redis if available
        if self.redis_client:
            try:
                cached_data = await self.redis_client.get(key)
                if cached_data:
                    analysis = pickle.loads(cached_data)
                    analysis.cache_hit_type = f"{cache_type}_redis"
                    # Update local cache
                    local_cache[key] = (analysis, time.time())
                    return analysis
            except Exception as e:
                logger.warning(f"Redis get failed: {e}")
        
        return None
    
    async def _store_in_cache(
        self, 
        key: str, 
        analysis: ThreatAnalysis,
        local_cache: OrderedDict, 
        max_size: int,
        ttl: int
    ):
        """Store item in cache with Redis persistence"""
        
        # Store in local memory cache
        local_cache[key] = (analysis, time.time())
        
        # Evict oldest items if over limit
        while len(local_cache) > max_size:
            local_cache.popitem(last=False)
        
        # Store in Redis if available
        if self.redis_client:
            try:
                await self.redis_client.setex(
                    key, 
                    ttl, 
                    pickle.dumps(analysis)
                )
            except Exception as e:
                logger.warning(f"Redis set failed: {e}")
    
    def _update_hit_rate(self):
        """Update cache hit rate statistics"""
        total_hits = (self.stats.signature_hits + self.stats.behavioral_hits + 
                     self.stats.response_hits + self.stats.negative_hits)
        
        if self.stats.total_requests > 0:
            self.stats.cache_hit_rate = total_hits / self.stats.total_requests
            # Estimate cost savings (avg $0.01 per API call avoided)
            self.stats.cost_savings_usd = total_hits * 0.01
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get detailed cache statistics"""
        return {
            'cache_hit_rate': round(self.stats.cache_hit_rate * 100, 2),
            'total_requests': self.stats.total_requests,
            'signature_hits': self.stats.signature_hits,
            'behavioral_hits': self.stats.behavioral_hits,
            'response_hits': self.stats.response_hits,
            'negative_hits': self.stats.negative_hits,
            'estimated_cost_savings_usd': round(self.stats.cost_savings_usd, 2),
            'cache_sizes': {
                'signature': len(self.signature_cache),
                'behavioral': len(self.behavioral_cache),
                'response': len(self.response_cache),
                'negative': len(self.negative_cache)
            }
        }
    
    async def warm_cache(self, common_attacks: List[Dict[str, Any]]):
        """Pre-populate cache with common attack patterns"""
        logger.info("Warming threat signature cache...")
        
        for attack in common_attacks:
            # Simulate analysis for common patterns
            analysis = ThreatAnalysis(
                threat_score=0.9,
                threat_type=attack.get('type', 'unknown'),
                confidence=0.95,
                reasoning=f"Pre-cached {attack.get('type')} pattern",
                recommended_action="block",
                indicators=[attack.get('pattern', '')],
                provider_used="cache_warmer"
            )
            
            await self.cache_analysis(
                payload=attack.get('payload', ''),
                method=attack.get('method', 'POST'),
                path=attack.get('path', '/'),
                features=attack.get('features', {}),
                analysis=analysis
            )
        
        logger.info(f"Cache warmed with {len(common_attacks)} attack patterns")

# Usage example
async def main():
    cache = IntelligentThreatCache()
    await cache.initialize()
    
    # Warm cache with common attacks
    common_attacks = [
        {
            'payload': "' OR 1=1--",
            'type': 'sql_injection',
            'method': 'POST',
            'path': '/login',
            'pattern': "' OR 1=1"
        },
        {
            'payload': "<script>alert('xss')</script>",
            'type': 'xss',
            'method': 'POST', 
            'path': '/comment',
            'pattern': '<script>'
        }
    ]
    
    await cache.warm_cache(common_attacks)
    
    # Test cache hits
    for i in range(1000):
        result = await cache.get_cached_analysis(
            payload="' OR 1=1--",
            method="POST",
            path="/login"
        )
        if result:
            print(f"Cache hit #{i}: {result.cache_hit_type}")
        else:
            # Simulate LLM analysis
            analysis = ThreatAnalysis(
                threat_score=0.9,
                threat_type="sql_injection",
                confidence=0.95,
                reasoning="Detected SQL injection",
                recommended_action="block",
                indicators=["' OR 1=1"],
                provider_used="openai"
            )
            await cache.cache_analysis("' OR 1=1--", "POST", "/login", {}, analysis)
    
    print("\nCache Statistics:")
    print(json.dumps(cache.get_cache_stats(), indent=2))

if __name__ == "__main__":
    asyncio.run(main())