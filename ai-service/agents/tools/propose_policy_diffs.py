#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path


def load_summary(since_hours: int) -> dict:
    from subprocess import check_output
    import sys

    script = Path(__file__).parent / "get_incidents.py"
    out = check_output([sys.executable, str(script), "--since-hours", str(since_hours)], text=True)
    return json.loads(out)


def extract_thresholds(text: str) -> list[float]:
    # Find thresholds in _determine_action in descending order
    block_crit = re.search(r"if\s+threat_score\s*>=\s*([0-9.]+)\s*:\s*\n\s*return\s*{\s*\n\s*\"action\":\s*\"block\"", text)
    block_high = re.search(r"elif\s+threat_score\s*>=\s*([0-9.]+)\s*:\s*\n\s*return\s*{\s*\n\s*\"action\":\s*\"block\"", text)
    challenge = re.search(r"elif\s+threat_score\s*>=\s*([0-9.]+)\s*:\s*\n\s*return\s*{\s*\n\s*\"action\":\s*\"challenge\"", text)
    monitor = re.search(r"elif\s+threat_score\s*>=\s*([0-9.]+)\s*:\s*\n\s*return\s*{\s*\n\s*\"action\":\s*\"monitor\"", text)
    vals = []
    for m in (block_crit, block_high, challenge, monitor):
        vals.append(float(m.group(1)) if m else None)
    return vals  # [crit, high, chal, mon]


def decide_adjustment(summary: dict) -> tuple[str, float]:
    total = summary.get("total_incidents", 0)
    blocked = summary.get("blocked", 0)
    allowed = summary.get("allowed", 0)
    if total < 50:
        return ("no_change", 0.0)
    if allowed > blocked * 1.5:
        return ("lower", 0.05)
    if blocked > allowed * 2.0:
        return ("raise", 0.05)
    return ("no_change", 0.0)


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def propose_thresholds(current: list[float], mode: str, delta: float) -> list[float]:
    if not all(isinstance(x, float) for x in current):
        return current
    c = current[:]
    if mode == "lower":
        c = [clamp(x - delta, 0.1, 0.95) for x in c]
    elif mode == "raise":
        c = [clamp(x + delta, 0.15, 0.99) for x in c]
    # enforce descending order: crit >= high >= chal >= mon
    c[1] = min(c[1], c[0] - 0.01)
    c[2] = min(c[2], c[1] - 0.01)
    c[3] = min(c[3], c[2] - 0.01)
    return c


def build_diff(text: str, orig: list[float], newv: list[float], file_path: str) -> str:
    # Replace lines in function with new thresholds; keep minimal context
    lines = text.splitlines()
    def repl_line(pattern: str, new_thresh: float) -> None:
        nonlocal lines
        rx = re.compile(pattern)
        for i, ln in enumerate(lines):
            m = rx.search(ln)
            if m:
                start, end = m.span(1)
                prefix = ln[:start]
                suffix = ln[end:]
                lines[i] = f"{prefix}{new_thresh:.2f}{suffix}"
                break

    repl_line(r"(if\s+threat_score\s*>=\s*)([0-9.]+)(\s*:)", newv[0])
    # first elif block
    found_first_elif = False
    for i, ln in enumerate(lines):
        if re.search(r"elif\s+threat_score\s*>=\s*[0-9.]+\s*:\s*$", ln) and not found_first_elif:
            lines[i] = re.sub(r"(>=\s*)([0-9.]+)", f">= {newv[1]:.2f}", ln)
            found_first_elif = True
            break
    # second elif (challenge)
    changed = 0
    for i, ln in enumerate(lines):
        if re.search(r"elif\s+threat_score\s*>=\s*[0-9.]+\s*:\s*$", ln):
            if changed == 0 and found_first_elif:
                changed += 1
                continue
            lines[i] = re.sub(r"(>=\s*)([0-9.]+)", f">= {newv[2]:.2f}", ln)
            break
    # third elif (monitor)
    idxs = [i for i, ln in enumerate(lines) if re.search(r"elif\s+threat_score\s*>=\s*[0-9.]+\s*:\s*$", ln)]
    if len(idxs) >= 3:
        lines[idxs[2]] = re.sub(r"(>=\s*)([0-9.]+)", f">= {newv[3]:.2f}", lines[idxs[2]])

    new_text = "\n".join(lines)
    # Simple unified diff
    import difflib
    diff = difflib.unified_diff(
        text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff)


def main():
    ap = argparse.ArgumentParser(description="Propose policy diffs based on recent incidents (read-only)")
    ap.add_argument("--since-hours", type=int, default=24)
    args = ap.parse_args()

    summary = load_summary(args.since_hours)
    mode, delta = decide_adjustment(summary)

    file_path = "ml_models/model_manager.py"
    abs_path = Path(__file__).resolve().parents[3] / file_path
    text = abs_path.read_text()

    current = extract_thresholds(text)
    if mode == "no_change" or not all(isinstance(x, float) for x in current):
        result = {
            "decision": "no_change",
            "reason": "Insufficient data or balanced block/allow ratio",
            "summary": summary,
        }
        print(json.dumps(result, indent=2))
        return

    proposed = propose_thresholds(current, mode, delta)
    diff = build_diff(text, current, proposed, file_path)
    result = {
        "decision": "lower_thresholds" if mode == "lower" else "raise_thresholds",
        "delta": delta,
        "current_thresholds": {
            "block_critical": current[0],
            "block_high": current[1],
            "challenge": current[2],
            "monitor": current[3],
        },
        "proposed_thresholds": {
            "block_critical": proposed[0],
            "block_high": proposed[1],
            "challenge": proposed[2],
            "monitor": proposed[3],
        },
        "diff": diff,
        "summary": summary,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
