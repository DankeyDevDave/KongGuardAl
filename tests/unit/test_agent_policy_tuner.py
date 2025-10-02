import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ai-service"))

from agents.tools.propose_policy_diffs import (
    extract_thresholds,
    decide_adjustment,
    clamp,
    propose_thresholds,
)


class TestPolicyTunerLogic:
    def test_extract_thresholds_valid_code(self):
        code = """
def _determine_action(self, threat_score: float):
    if threat_score >= 0.90:
        return {
            "action": "block"
        }
    elif threat_score >= 0.75:
        return {
            "action": "block"
        }
    elif threat_score >= 0.60:
        return {
            "action": "challenge"
        }
    elif threat_score >= 0.40:
        return {
            "action": "monitor"
        }
"""
        result = extract_thresholds(code)
        assert result == [0.90, 0.75, 0.60, 0.40]

    def test_extract_thresholds_missing_patterns(self):
        code = "def foo(): pass"
        result = extract_thresholds(code)
        assert all(x is None for x in result)

    def test_decide_adjustment_insufficient_data(self):
        summary = {"total_incidents": 10, "blocked": 5, "allowed": 5}
        mode, delta = decide_adjustment(summary)
        assert mode == "no_change"
        assert delta == 0.0

    def test_decide_adjustment_too_many_allowed(self):
        summary = {"total_incidents": 100, "blocked": 20, "allowed": 60}
        mode, delta = decide_adjustment(summary)
        assert mode == "lower"
        assert delta == 0.05

    def test_decide_adjustment_too_many_blocked(self):
        summary = {"total_incidents": 100, "blocked": 80, "allowed": 20}
        mode, delta = decide_adjustment(summary)
        assert mode == "raise"
        assert delta == 0.05

    def test_decide_adjustment_balanced(self):
        summary = {"total_incidents": 100, "blocked": 50, "allowed": 50}
        mode, delta = decide_adjustment(summary)
        assert mode == "no_change"
        assert delta == 0.0

    def test_decide_adjustment_edge_case_exact_threshold(self):
        # allowed = blocked * 1.5 exactly
        summary = {"total_incidents": 100, "blocked": 40, "allowed": 60}
        mode, delta = decide_adjustment(summary)
        assert mode == "no_change"

    def test_clamp_within_bounds(self):
        assert clamp(0.5, 0.1, 0.9) == 0.5

    def test_clamp_below_minimum(self):
        assert clamp(0.05, 0.1, 0.9) == 0.1

    def test_clamp_above_maximum(self):
        assert clamp(0.95, 0.1, 0.9) == 0.9

    def test_clamp_at_boundaries(self):
        assert clamp(0.1, 0.1, 0.9) == 0.1
        assert clamp(0.9, 0.1, 0.9) == 0.9

    def test_propose_thresholds_lower(self):
        current = [0.90, 0.75, 0.60, 0.40]
        result = propose_thresholds(current, "lower", 0.05)
        assert abs(result[0] - 0.85) < 0.01
        assert abs(result[1] - 0.70) < 0.01
        assert abs(result[2] - 0.55) < 0.01
        assert abs(result[3] - 0.35) < 0.01

    def test_propose_thresholds_raise(self):
        current = [0.80, 0.65, 0.50, 0.30]
        result = propose_thresholds(current, "raise", 0.05)
        assert abs(result[0] - 0.85) < 0.01
        assert abs(result[1] - 0.70) < 0.01
        assert abs(result[2] - 0.55) < 0.01
        assert abs(result[3] - 0.35) < 0.01

    def test_propose_thresholds_no_change(self):
        current = [0.90, 0.75, 0.60, 0.40]
        result = propose_thresholds(current, "no_change", 0.05)
        assert result == current

    def test_propose_thresholds_enforces_ordering(self):
        current = [0.90, 0.75, 0.60, 0.40]
        result = propose_thresholds(current, "lower", 0.50)
        # Should be clamped and maintain descending order
        assert result[0] >= result[1]
        assert result[1] >= result[2]
        assert result[2] >= result[3]
        # Minimum gap of 0.01 between thresholds
        assert result[0] >= result[1] + 0.01
        assert result[1] >= result[2] + 0.01
        assert result[2] >= result[3] + 0.01

    def test_propose_thresholds_lower_bound_protection(self):
        current = [0.20, 0.15, 0.12, 0.10]
        result = propose_thresholds(current, "lower", 0.20)
        # After lowering and enforcing ordering, values might go below 0.1 due to ordering constraint
        # The key is that the first value is clamped to 0.1
        assert result[0] >= 0.1

    def test_propose_thresholds_upper_bound_protection(self):
        current = [0.95, 0.90, 0.85, 0.80]
        result = propose_thresholds(current, "raise", 0.20)
        # First value clamped to 0.99 max
        assert result[0] <= 0.99
        # Others should maintain ordering
        assert result[0] >= result[1]

    def test_propose_thresholds_invalid_input(self):
        current = [0.90, None, 0.60, 0.40]
        result = propose_thresholds(current, "lower", 0.05)
        assert result == current

    def test_decide_adjustment_missing_keys(self):
        summary = {"total_incidents": 100}
        mode, delta = decide_adjustment(summary)
        # Should handle missing blocked/allowed gracefully
        assert mode == "no_change"

    def test_decide_adjustment_zero_blocked(self):
        summary = {"total_incidents": 100, "blocked": 0, "allowed": 80}
        mode, delta = decide_adjustment(summary)
        assert mode == "lower"

    def test_decide_adjustment_zero_allowed(self):
        summary = {"total_incidents": 100, "blocked": 80, "allowed": 0}
        mode, delta = decide_adjustment(summary)
        assert mode == "raise"
