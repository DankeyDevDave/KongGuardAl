import re
from typing import Any, Dict


SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.=]+"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9\-_.=]+"),
    re.compile(r"(?i)authorization:\s*[A-Za-z0-9\-_.=\s:]+"),
]


def redact_text(text: str, max_len: int = 2000) -> str:
    t = text or ""
    for pat in SECRET_PATTERNS:
        t = pat.sub("[REDACTED]", t)
    if len(t) > max_len:
        t = t[: max_len - 15] + "...[TRUNCATED]"
    return t


def redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            redacted[k] = redact_text(v)
        elif isinstance(v, dict):
            redacted[k] = redact_dict(v)
        else:
            redacted[k] = v
    return redacted
