"""
Canonical attack payloads matching the Kong Guard AI dashboard UI.
These payloads are used by the automated audit runner to ensure consistency
with manual testing results.
"""

from typing import Dict, List, Any

# Attack payloads matching the AI service API schema
ATTACK_PAYLOADS: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "features": {
            "method": "POST",
            "path": "/api/users",
            "client_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "requests_per_minute": 5,
            "content_length": 150,
            "query_param_count": 2,
            "header_count": 8,
            "hour_of_day": 14,
            "query": "id=1; DROP TABLE users; --",
            "body": "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
            "headers": {"Content-Type": "application/json", "Authorization": "Bearer token123"}
        },
        "context": {
            "previous_requests": 0,
            "failed_attempts": 0,
            "anomaly_score": 0.0,
            "ip_reputation": "unknown",
            "geo_location": "US"
        }
    },
    "xss": {
        "features": {
            "method": "POST",
            "path": "/api/comments",
            "client_ip": "192.168.1.101",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "requests_per_minute": 3,
            "content_length": 200,
            "query_param_count": 1,
            "header_count": 6,
            "hour_of_day": 15,
            "query": "comment=<script>alert('XSS')</script>",
            "body": "<script>alert('XSS')</script><img src=x onerror=alert('XSS')>",
            "headers": {"Content-Type": "application/json", "User-Agent": "AttackerBot/1.0"}
        },
        "context": {
            "previous_requests": 1,
            "failed_attempts": 0,
            "anomaly_score": 0.2,
            "ip_reputation": "suspicious",
            "geo_location": "Unknown"
        }
    },
    "cmd_injection": {
        "features": {
            "method": "POST",
            "path": "/api/system",
            "client_ip": "192.168.1.102",
            "user_agent": "curl/7.68.0",
            "requests_per_minute": 2,
            "content_length": 180,
            "query_param_count": 3,
            "header_count": 4,
            "hour_of_day": 16,
            "query": "cmd=ls -la; cat /etc/passwd",
            "body": "ls -la; cat /etc/passwd; rm -rf /",
            "headers": {"Content-Type": "application/json", "X-Forwarded-For": "10.0.0.1"}
        },
        "context": {
            "previous_requests": 0,
            "failed_attempts": 2,
            "anomaly_score": 0.8,
            "ip_reputation": "malicious",
            "geo_location": "Unknown"
        }
    },
    "path_traversal": {
        "features": {
            "method": "GET",
            "path": "/api/files",
            "client_ip": "192.168.1.103",
            "user_agent": "Mozilla/5.0 (compatible; PathTraversalBot/1.0)",
            "requests_per_minute": 4,
            "content_length": 0,
            "query_param_count": 1,
            "header_count": 5,
            "hour_of_day": 17,
            "query": "file=../../../etc/passwd",
            "body": "",
            "headers": {"Accept": "*/*", "Referer": "http://evil.com"}
        },
        "context": {
            "previous_requests": 3,
            "failed_attempts": 1,
            "anomaly_score": 0.6,
            "ip_reputation": "suspicious",
            "geo_location": "Unknown"
        }
    },
    "ldap_injection": {
        "features": {
            "method": "POST",
            "path": "/api/auth",
            "client_ip": "192.168.1.104",
            "user_agent": "LDAP-Injector/1.0",
            "requests_per_minute": 6,
            "content_length": 120,
            "query_param_count": 2,
            "header_count": 7,
            "hour_of_day": 18,
            "query": "username=admin)(&(password=*))",
            "body": "admin)(&(password=*))",
            "headers": {"Content-Type": "application/json", "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}
        },
        "context": {
            "previous_requests": 2,
            "failed_attempts": 3,
            "anomaly_score": 0.9,
            "ip_reputation": "malicious",
            "geo_location": "Unknown"
        }
    },
    "business_logic": {
        "features": {
            "method": "POST",
            "path": "/api/transfer",
            "client_ip": "192.168.1.105",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "requests_per_minute": 1,
            "content_length": 100,
            "query_param_count": 0,
            "header_count": 9,
            "hour_of_day": 19,
            "query": "",
            "body": "{\"from_account\":\"user123\",\"to_account\":\"attacker456\",\"amount\":-1000}",
            "headers": {"Content-Type": "application/json", "X-API-Key": "stolen_key_123"}
        },
        "context": {
            "previous_requests": 5,
            "failed_attempts": 0,
            "anomaly_score": 0.3,
            "ip_reputation": "unknown",
            "geo_location": "US"
        }
    },
    "ransomware": {
        "features": {
            "method": "POST",
            "path": "/api/encrypt",
            "client_ip": "192.168.1.106",
            "user_agent": "RansomwareBot/2.0",
            "requests_per_minute": 10,
            "content_length": 300,
            "query_param_count": 0,
            "header_count": 3,
            "hour_of_day": 20,
            "query": "",
            "body": "Your files have been encrypted. Pay 1 BTC to decrypt. Files: *.txt, *.doc, *.pdf",
            "headers": {"Content-Type": "application/json", "X-Ransomware": "true"}
        },
        "context": {
            "previous_requests": 0,
            "failed_attempts": 0,
            "anomaly_score": 1.0,
            "ip_reputation": "malicious",
            "geo_location": "Unknown"
        }
    },
    "normal": {
        "features": {
            "method": "POST",
            "path": "/api/users",
            "client_ip": "192.168.1.200",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "requests_per_minute": 2,
            "content_length": 80,
            "query_param_count": 0,
            "header_count": 8,
            "hour_of_day": 14,
            "query": "",
            "body": "{\"username\":\"john_doe\",\"email\":\"john@example.com\"}",
            "headers": {"Content-Type": "application/json", "Accept": "application/json"}
        },
        "context": {
            "previous_requests": 0,
            "failed_attempts": 0,
            "anomaly_score": 0.0,
            "ip_reputation": "trusted",
            "geo_location": "US"
        }
    }
}

# Tier configurations
TIER_CONFIGS: Dict[str, Dict[str, Any]] = {
    "unprotected": {
        "base_url": "http://localhost:28080",
        "simulate": True,  # Simulate allow responses
        "latency_ms": 2
    },
    "cloud": {
        "base_url": "http://localhost:28100",
        "analyze_endpoint": "/analyze",
        "simulate": False
    },
    "local": {
        "base_url": "http://localhost:28101", 
        "analyze_endpoint": "/analyze",
        "simulate": False
    }
}

def get_attack_payload(attack_type: str) -> Dict[str, Any]:
    """Get the payload for a specific attack type."""
    if attack_type not in ATTACK_PAYLOADS:
        raise ValueError(f"Unknown attack type: {attack_type}")
    return ATTACK_PAYLOADS[attack_type].copy()

def get_tier_config(tier: str) -> Dict[str, Any]:
    """Get the configuration for a specific tier."""
    if tier not in TIER_CONFIGS:
        raise ValueError(f"Unknown tier: {tier}")
    return TIER_CONFIGS[tier].copy()

def get_all_attack_types() -> List[str]:
    """Get all available attack types."""
    return list(ATTACK_PAYLOADS.keys())

def get_all_tiers() -> List[str]:
    """Get all available tiers."""
    return list(TIER_CONFIGS.keys())

def validate_payload(payload: Dict[str, Any]) -> bool:
    """Validate that a payload has required fields."""
    required_fields = ["method", "path", "headers", "body"]
    return all(field in payload for field in required_fields)
