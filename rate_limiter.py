#!/usr/bin/env python3
"""
Kong Guard AI - Intelligent Rate Limiter & API Manager
Handles multi-provider API rate limiting with intelligent fallbacks
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ProviderType(Enum):
    OPENAI = "openai"
    CLAUDE = "claude"
    GROQ = "groq"
    GEMINI = "gemini"
    OLLAMA = "ollama"


@dataclass
class ProviderLimits:
    rpm: int  # Requests per minute
    tpm: int  # Tokens per minute
    cost_per_1k_tokens: float
    latency_p95: float  # milliseconds
    accuracy_score: float  # 0-1


@dataclass
class APIQuota:
    requests_used: int = 0
    tokens_used: int = 0
    reset_time: float = 0
    is_available: bool = True
    consecutive_failures: int = 0


class IntelligentRateLimiter:
    """Multi-provider rate limiter with intelligent fallbacks"""

    def __init__(self):
        self.provider_limits = {
            ProviderType.OPENAI: ProviderLimits(
                rpm=10000, tpm=2000000, cost_per_1k_tokens=30.0, latency_p95=1200, accuracy_score=0.95
            ),
            ProviderType.CLAUDE: ProviderLimits(
                rpm=4000, tpm=800000, cost_per_1k_tokens=15.0, latency_p95=800, accuracy_score=0.96
            ),
            ProviderType.GROQ: ProviderLimits(
                rpm=6000, tpm=1000000, cost_per_1k_tokens=0.27, latency_p95=300, accuracy_score=0.88
            ),
            ProviderType.GEMINI: ProviderLimits(
                rpm=1500, tpm=400000, cost_per_1k_tokens=0.15, latency_p95=1500, accuracy_score=0.85
            ),
            ProviderType.OLLAMA: ProviderLimits(
                rpm=1000, tpm=100000, cost_per_1k_tokens=0.0, latency_p95=2000, accuracy_score=0.75
            ),
        }

        self.quotas: dict[ProviderType, APIQuota] = {provider: APIQuota() for provider in ProviderType}

        # Request queues for each provider
        self.request_queues: dict[ProviderType, deque] = {provider: deque() for provider in ProviderType}

        # Performance tracking
        self.performance_history = defaultdict(list)

    async def get_optimal_provider(
        self,
        estimated_tokens: int,
        priority: str = "balanced",  # balanced, speed, accuracy, cost
    ) -> Optional[ProviderType]:
        """Select optimal provider based on availability and requirements"""

        available_providers = []
        current_time = time.time()

        for provider, quota in self.quotas.items():
            limits = self.provider_limits[provider]

            # Reset quota if time window expired
            if current_time >= quota.reset_time:
                quota.requests_used = 0
                quota.tokens_used = 0
                quota.reset_time = current_time + 60  # 1 minute window
                quota.is_available = True
                quota.consecutive_failures = max(0, quota.consecutive_failures - 1)

            # Check availability
            if (
                quota.is_available
                and quota.requests_used < limits.rpm
                and quota.tokens_used + estimated_tokens < limits.tpm
                and quota.consecutive_failures < 3
            ):
                available_providers.append(provider)

        if not available_providers:
            logger.warning("No providers available - all rate limited")
            return None

        # Sort by priority strategy
        if priority == "speed":
            available_providers.sort(key=lambda p: self.provider_limits[p].latency_p95)
        elif priority == "accuracy":
            available_providers.sort(key=lambda p: self.provider_limits[p].accuracy_score, reverse=True)
        elif priority == "cost":
            available_providers.sort(key=lambda p: self.provider_limits[p].cost_per_1k_tokens)
        else:  # balanced

            def balance_score(provider):
                limits = self.provider_limits[provider]
                quota = self.quotas[provider]

                # Weighted scoring: speed(30%) + accuracy(40%) + cost(20%) + availability(10%)
                speed_score = 1.0 - (limits.latency_p95 / 3000)  # normalized
                accuracy_score = limits.accuracy_score
                cost_score = 1.0 - (limits.cost_per_1k_tokens / 30)  # normalized
                availability_score = 1.0 - (quota.requests_used / limits.rpm)

                return speed_score * 0.3 + accuracy_score * 0.4 + cost_score * 0.2 + availability_score * 0.1

            available_providers.sort(key=balance_score, reverse=True)

        return available_providers[0]

    async def reserve_quota(self, provider: ProviderType, estimated_tokens: int) -> bool:
        """Reserve API quota for a request"""
        quota = self.quotas[provider]
        limits = self.provider_limits[provider]

        if quota.requests_used >= limits.rpm or quota.tokens_used + estimated_tokens > limits.tpm:
            return False

        quota.requests_used += 1
        quota.tokens_used += estimated_tokens
        return True

    async def record_result(self, provider: ProviderType, actual_tokens: int, response_time_ms: float, success: bool):
        """Record API call results for learning"""
        quota = self.quotas[provider]

        # Adjust token usage with actual consumption
        estimated_tokens = quota.tokens_used
        quota.tokens_used = quota.tokens_used - estimated_tokens + actual_tokens

        if success:
            quota.consecutive_failures = 0
            quota.is_available = True
        else:
            quota.consecutive_failures += 1
            if quota.consecutive_failures >= 3:
                quota.is_available = False
                logger.warning(f"Provider {provider.value} marked unavailable after 3 failures")

        # Track performance
        self.performance_history[provider].append(
            {"timestamp": time.time(), "response_time": response_time_ms, "tokens": actual_tokens, "success": success}
        )

        # Keep only last 100 entries per provider
        if len(self.performance_history[provider]) > 100:
            self.performance_history[provider].pop(0)

    def get_provider_stats(self) -> dict:
        """Get current provider statistics"""
        stats = {}
        current_time = time.time()

        for provider, quota in self.quotas.items():
            limits = self.provider_limits[provider]
            history = self.performance_history[provider]

            recent_history = [h for h in history if current_time - h["timestamp"] < 300]  # Last 5 minutes

            avg_latency = (
                sum(h["response_time"] for h in recent_history) / len(recent_history)
                if recent_history
                else limits.latency_p95
            )

            success_rate = (
                sum(1 for h in recent_history if h["success"]) / len(recent_history) if recent_history else 1.0
            )

            stats[provider.value] = {
                "rpm_used": quota.requests_used,
                "rpm_limit": limits.rpm,
                "tpm_used": quota.tokens_used,
                "tpm_limit": limits.tpm,
                "available": quota.is_available,
                "consecutive_failures": quota.consecutive_failures,
                "avg_latency_5min": round(avg_latency, 1),
                "success_rate_5min": round(success_rate, 3),
                "estimated_cost_per_request": limits.cost_per_1k_tokens * 0.5,  # ~500 tokens avg
            }

        return stats


# Usage example
async def main():
    limiter = IntelligentRateLimiter()

    # Simulate high-load scenario
    for i in range(1000):
        provider = await limiter.get_optimal_provider(estimated_tokens=500, priority="balanced")

        if provider:
            reserved = await limiter.reserve_quota(provider, 500)
            if reserved:
                # Simulate API call
                await asyncio.sleep(0.1)
                await limiter.record_result(provider, actual_tokens=450, response_time_ms=800, success=True)
                print(f"Request {i}: Used {provider.value}")
            else:
                print(f"Request {i}: Quota exhausted for {provider.value}")
        else:
            print(f"Request {i}: No providers available")
            await asyncio.sleep(1)  # Wait for quota reset

    print("\nProvider Statistics:")
    print(json.dumps(limiter.get_provider_stats(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
