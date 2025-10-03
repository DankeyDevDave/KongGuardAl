"""
Thin wrapper around the Claude Agent SDK for optional runtime use.
Safe import: if SDK or API key missing, calls become no-ops.
"""
from __future__ import annotations

import os
from typing import Any, Optional


def _sdk_available() -> bool:
    try:
        import claude_agent_sdk  # type: ignore  # pragma: no cover
    except Exception:  # pragma: no cover
        return False  # pragma: no cover
    return bool(os.getenv("ANTHROPIC_API_KEY"))  # pragma: no cover


def run_security_triage_agent(summary: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Send the incident summary to the Security Triage agent and return structured suggestions.
    Returns None if SDK not available or disabled.
    """
    if not _sdk_available() or os.getenv("ENABLE_AGENT_SDK", "false").lower() not in ("1", "true", "yes"):
        return None

    try:  # lazy import to avoid hard dependency  # pragma: no cover
        from claude_agent_sdk import Agent  # type: ignore  # pragma: no cover
    except Exception:  # pragma: no cover
        return None  # pragma: no cover

    system_prompt = (  # pragma: no cover
        "You are the Security Triage Copilot for KongGuardAI. "
        "Provide concise, actionable suggestions only. Never apply changes."
    )

    agent = Agent(  # pragma: no cover
        name="security-triage",
        system_prompt=system_prompt,
        allowed_tools=["fs.read", "process.exec"],
        permission_mode="allowlist",
        setting_sources=["project"],
    )

    user_msg = {  # pragma: no cover
        "type": "incident_summary",
        "payload": summary,
        "constraints": {
            "max_actions": 0,
            "output_format": "json",
        },
    }

    try:  # pragma: no cover
        resp = agent.run(user_msg)  # type: ignore[attr-defined]
        # Expect JSON-like response; return as dictionary if possible
        if isinstance(resp, dict):
            return resp
        return {"message": str(resp)}
    except Exception:  # pragma: no cover
        return None
