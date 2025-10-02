#!/usr/bin/env python3
"""CLI: generate incident summary and (optionally) query the triage agent.

Usage:
  python ai-service/agents/run_security_triage.py --since-hours 24 --with-agent
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import importlib.util
from typing import Optional, Any


def _load_sdk_client() -> Optional[Any]:
    """Load sdk_client module by path to avoid package name issues."""
    from pathlib import Path
    sdk_path = Path(__file__).parent / "sdk_client.py"
    spec = importlib.util.spec_from_file_location("sdk_client", sdk_path)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod
    except Exception:
        return None


def run_get_incidents(since_hours: int) -> dict:
    script = Path(__file__).parent / "tools" / "get_incidents.py"
    cmd = [sys.executable, str(script), "--since-hours", str(since_hours)]
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--since-hours", type=int, default=24)
    p.add_argument("--with-agent", action="store_true", help="Send summary to agent if SDK enabled")
    args = p.parse_args()

    summary = run_get_incidents(args.since_hours)
    print(json.dumps({"summary": summary}, indent=2))

    if args.with_agent:
        sdk = _load_sdk_client()
        if sdk and hasattr(sdk, "run_security_triage_agent"):
            suggestions = sdk.run_security_triage_agent(summary) or {"note": "agent disabled or unavailable"}
        else:
            suggestions = {"note": "sdk client unavailable"}
        print(json.dumps({"agent_suggestions": suggestions}, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
