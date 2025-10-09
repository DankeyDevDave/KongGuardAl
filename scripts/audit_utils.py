#!/usr/bin/env python3
"""
Audit utilities for Kong Guard AI
Provides action normalization, risk tier management, and enforcement logic
"""

from enum import Enum
from typing import Dict, Tuple, Optional
import fnmatch
import re


class Action(Enum):
    """Standardized action types for threat response"""
    BLOCK = "block"
    ALLOW = "allow"
    MONITOR = "monitor"


def normalize_action(action: str) -> Action:
    """
    Normalize provider action strings to standard enum values
    
    Args:
        action: Raw action string from AI provider
        
    Returns:
        Normalized Action enum value
    """
    if not action:
        return Action.MONITOR
        
    action = action.lower().strip()
    
    # Block actions
    if action in {"blocked", "block", "deny", "forbid", "reject"}:
        return Action.BLOCK
    
    # Allow actions  
    if action in {"allow", "allowed", "pass", "permit", "accept"}:
        return Action.ALLOW
    
    # Default to monitor for unknown actions
    return Action.MONITOR


def decide_enforcement(confidence: float, attack_type: str) -> Action:
    """
    Decide enforcement action based on confidence score and attack type
    
    Args:
        confidence: Threat confidence score (0.0-1.0)
        attack_type: Type of attack detected
        
    Returns:
        Enforcement action to take
    """
    # Risk-tier thresholds (tune per attack type)
    # Format: (block_threshold, monitor_threshold)
    tiers = {
        "sql_injection": (0.45, 0.25),     # block, monitor
        "xss":           (0.50, 0.30),
        "cmd_injection": (0.45, 0.25),
        "path_traversal":(0.40, 0.25),
        "ldap_injection":(0.45, 0.25),
        "ransomware":    (0.35, 0.20),
        "business_logic":(0.55, 0.35),
        "normal":        (1.01, 0.80),     # never block normal by model score alone
    }
    
    block_threshold, monitor_threshold = tiers.get(attack_type, (0.5, 0.3))
    
    if confidence >= block_threshold:
        return Action.BLOCK
    elif confidence >= monitor_threshold:
        return Action.MONITOR
    else:
        return Action.ALLOW


def is_allowlisted(method: str, path: str, headers: Optional[Dict[str, str]] = None) -> bool:
    """
    Check if request matches allowlist patterns for normal traffic
    
    Args:
        method: HTTP method
        path: Request path
        headers: Optional request headers
        
    Returns:
        True if request should be allowlisted
    """
    allowlist_patterns = [
        "GET /healthz",
        "GET /health",
        "GET /metrics", 
        "GET /status",
        "POST /auth/refresh",
        "GET /static/*",
        "GET /public/*",
        "GET /favicon.ico",
        "GET /robots.txt",
        "OPTIONS *",  # CORS preflight
    ]
    
    # Check method + path patterns
    request_pattern = f"{method.upper()} {path}"
    for pattern in allowlist_patterns:
        if fnmatch.fnmatch(request_pattern, pattern):
            return True
    
    # Check for trusted internal headers
    if headers:
        if headers.get("X-GuardAI-Skip") == "true":
            return True
        if headers.get("X-Internal-Request") == "true":
            return True
    
    return False


def optimize_payload(features: Dict, context: Dict, max_bytes: int = 8192) -> Dict:
    """
    Optimize payload for AI analysis by trimming and structuring data
    Preserves the original structure expected by the AI service
    
    Args:
        features: Raw request features
        context: Request context
        max_bytes: Maximum payload size in bytes
        
    Returns:
        Optimized payload structure
    """
    import json
    
    # Create optimized features by trimming large fields
    optimized_features = features.copy()
    
    # Trim query parameters
    if "query" in optimized_features:
        query = optimized_features["query"]
        if len(query) > max_bytes // 4:  # Use 1/4 of budget for query
            optimized_features["query"] = query[:max_bytes // 4] + "...[truncated]"
    
    # Trim body content
    if "body" in optimized_features:
        body = optimized_features["body"]
        if len(body) > max_bytes // 2:  # Use 1/2 of budget for body
            optimized_features["body"] = body[:max_bytes // 2] + "...[truncated]"
    
    # Limit headers to essential ones
    if "headers" in optimized_features:
        essential_headers = {}
        for key, value in optimized_features["headers"].items():
            if key.lower() in ["content-type", "user-agent", "authorization", "x-forwarded-for"]:
                essential_headers[key] = value
        optimized_features["headers"] = essential_headers
    
    # Create optimized context
    optimized_context = context.copy()
    
    # Add optimization metadata
    optimized_context["optimized"] = True
    optimized_context["max_bytes"] = max_bytes
    
    # Build final payload
    optimized = {
        "features": optimized_features,
        "context": optimized_context
    }
    
    # Ensure payload size is within limits
    payload_str = json.dumps(optimized)
    if len(payload_str) > max_bytes:
        # Further trim if needed
        if "body" in optimized["features"]:
            optimized["features"]["body"] = optimized["features"]["body"][:max_bytes//3]
        if "query" in optimized["features"]:
            optimized["features"]["query"] = optimized["features"]["query"][:max_bytes//3]
    
    return optimized


def validate_action(action: str) -> bool:
    """
    Validate that action is in allowed set
    
    Args:
        action: Action string to validate
        
    Returns:
        True if action is valid
    """
    ALLOWED_ACTIONS = {
        "block", "blocked", "allow", "allowed", "monitor", "monitored", 
        "challenge", "rate_limit", "deny", "forbid", "pass", "permit"
    }
    
    return action.lower() in ALLOWED_ACTIONS


def calculate_risk_score(features: Dict, context: Dict) -> float:
    """
    Calculate risk score based on request features and context
    
    Args:
        features: Request features
        context: Request context
        
    Returns:
        Risk score between 0.0 and 1.0
    """
    score = 0.0
    
    # Base score from AI confidence
    ai_confidence = context.get("ai_confidence", 0.0)
    score += ai_confidence * 0.7
    
    # Content length anomaly
    content_length = features.get("content_length", 0)
    if content_length > 10000:  # Large payload
        score += 0.1
    elif content_length > 50000:  # Very large payload
        score += 0.2
    
    # Query parameter count
    param_count = features.get("query_param_count", 0)
    if param_count > 20:  # Many parameters
        score += 0.1
    
    # Header count
    header_count = features.get("header_count", 0)
    if header_count > 15:  # Many headers
        score += 0.05
    
    # Time-based factors
    hour = features.get("hour_of_day", 12)
    if hour < 6 or hour > 22:  # Off-hours
        score += 0.05
    
    # IP reputation (if available)
    ip_reputation = context.get("ip_reputation", "unknown")
    if ip_reputation == "malicious":
        score += 0.2
    elif ip_reputation == "suspicious":
        score += 0.1
    
    # Failed attempts
    failed_attempts = context.get("failed_attempts", 0)
    if failed_attempts > 3:
        score += 0.1
    
    return min(score, 1.0)


if __name__ == "__main__":
    # Test the utilities
    print("Testing audit utilities...")
    
    # Test action normalization
    assert normalize_action("blocked") == Action.BLOCK
    assert normalize_action("allow") == Action.ALLOW
    assert normalize_action("unknown") == Action.MONITOR
    
    # Test enforcement decision
    assert decide_enforcement(0.5, "sql_injection") == Action.BLOCK
    assert decide_enforcement(0.3, "sql_injection") == Action.MONITOR
    assert decide_enforcement(0.1, "sql_injection") == Action.ALLOW
    
    # Test allowlist
    assert is_allowlisted("GET", "/healthz")
    assert is_allowlisted("GET", "/static/image.png")
    assert not is_allowlisted("POST", "/api/users")
    
    # Test payload optimization
    features = {
        "method": "POST",
        "path": "/api/users",
        "headers": {"Content-Type": "application/json"},
        "query": "id=1",
        "body": "{\"name\":\"test\"}",
        "content_length": 100,
        "query_param_count": 1,
        "header_count": 1,
    }
    context = {"attack_type": "normal"}
    optimized = optimize_payload(features, context)
    assert "features" in optimized
    assert "context" in optimized
    
    print("✅ All tests passed!")
