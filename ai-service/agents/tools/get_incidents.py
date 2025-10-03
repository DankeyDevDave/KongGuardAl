#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta

import re


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


def redact_dict(d: dict) -> dict:
    redacted = {}
    for k, v in d.items():
        if isinstance(v, str):
            redacted[k] = redact_text(v)
        elif isinstance(v, dict):
            redacted[k] = redact_dict(v)
        else:
            redacted[k] = v
    return redacted


def find_db_path() -> str:
    candidates = [
        os.path.join(os.getcwd(), "attack_metrics.db"),
        os.path.join(os.path.dirname(__file__), "../../../attack_metrics.db"),
    ]
    for p in candidates:
        p = os.path.abspath(p)
        if os.path.exists(p):
            return p
    return os.path.abspath(candidates[0])


def query_incidents(db_path: str, since_hours: int) -> dict:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    since_ts = datetime.utcnow() - timedelta(hours=since_hours)
    since_iso = since_ts.isoformat(sep=" ")

    # Totals
    cur.execute(
        """
        SELECT COUNT(*) FROM attack_metrics
        WHERE timestamp >= ?
        """,
        (since_iso,),
    )
    total_incidents = cur.fetchone()[0] or 0

    # Blocked vs Allowed
    cur.execute(
        """
        SELECT blocked, COUNT(*) FROM attack_metrics
        WHERE timestamp >= ?
        GROUP BY blocked
        """,
        (since_iso,),
    )
    ba = {bool(row[0]): row[1] for row in cur.fetchall()}

    # Top categories
    cur.execute(
        """
        SELECT attack_category, COUNT(*) as c FROM attack_metrics
        WHERE timestamp >= ? AND attack_category IS NOT NULL
        GROUP BY attack_category
        ORDER BY c DESC
        LIMIT 5
        """,
        (since_iso,),
    )
    top_categories = [{"attack_category": r[0] or "unknown", "count": r[1]} for r in cur.fetchall()]

    # Top source IPs
    cur.execute(
        """
        SELECT source_ip, COUNT(*) as c FROM attack_metrics
        WHERE timestamp >= ? AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY c DESC
        LIMIT 5
        """,
        (since_iso,),
    )
    top_source_ips = [{"source_ip": r[0] or "unknown", "count": r[1]} for r in cur.fetchall()]

    # Recent runs
    cur.execute(
        """
        SELECT run_id, start_time, end_time, total_attacks, intensity_level, strategy
        FROM attack_runs
        ORDER BY start_time DESC
        LIMIT 5
        """
    )
    runs = [
        {
            "run_id": r[0],
            "start_time": r[1],
            "end_time": r[2],
            "total_attacks": r[3],
            "intensity_level": r[4],
            "strategy": r[5],
        }
        for r in cur.fetchall()
    ]

    conn.close()

    summary = {
        "since_hours": since_hours,
        "total_incidents": total_incidents,
        "blocked": ba.get(True, 0),
        "allowed": ba.get(False, 0),
        "top_categories": top_categories,
        "top_source_ips": top_source_ips,
        "recent_runs": runs,
        "notes": "Payloads and secrets redacted; use DB to drill down if needed.",
    }
    return redact_dict(summary)


def main():
    parser = argparse.ArgumentParser(description="Summarize recent incidents from attack_metrics.db")
    parser.add_argument("--since-hours", type=int, default=24, help="Look back window in hours (default: 24)")
    parser.add_argument("--db", type=str, default=None, help="Path to attack_metrics.db (optional)")
    args = parser.parse_args()

    db_path = args.db or find_db_path()
    result = query_incidents(db_path, args.since_hours)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
