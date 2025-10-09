#!/usr/bin/env python3
"""
CI/CD gates for Kong Guard AI audit results
Enforces quality gates based on goals.yaml configuration
"""

import json
import yaml
import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class CIGates:
    """CI/CD quality gates for audit results"""
    
    def __init__(self, goals_file: str, report_file: str):
        self.goals_file = goals_file
        self.report_file = report_file
        self.goals = self._load_goals()
        self.report = self._load_report()
        self.violations = []
        self.warnings = []
    
    def _load_goals(self) -> Dict[str, Any]:
        """Load goals configuration from YAML file"""
        try:
            with open(self.goals_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load goals file {self.goals_file}: {e}")
            sys.exit(1)
    
    def _load_report(self) -> Dict[str, Any]:
        """Load audit report from JSON file"""
        try:
            with open(self.report_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load report file {self.report_file}: {e}")
            sys.exit(1)
    
    def check_p95_latency(self) -> bool:
        """Check if p95 latency exceeds goals"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        if not ci_gates.get('fail_on', {}).get('p95_latency_exceeds_goal', False):
            return True
        
        results = self.report.get('results', {})
        active_phase = self.goals.get('active_phase', 'phase_1')
        phase_goals = self.goals.get(active_phase, {})
        
        for tier_name, tier_results in results.items():
            if tier_name == 'unprotected':
                continue
            
            tier_goals = phase_goals.get(tier_name, {})
            p95_goal = tier_goals.get('p95_latency_ms', tier_goals.get('max_latency_ms', 1000))
            
            # Calculate p95 latency from individual results
            individual_results = []
            for attack_type, attack_results in tier_results.items():
                individual_results.extend(attack_results.get('individual_results', []))
            
            if individual_results:
                latencies = [r.get('latency_ms', 0) for r in individual_results]
                latencies.sort()
                p95_index = int(len(latencies) * 0.95)
                p95_latency = latencies[p95_index] if p95_index < len(latencies) else latencies[-1]
                
                if p95_latency > p95_goal:
                    self.violations.append(
                        f"❌ {tier_name.upper()}: p95 latency {p95_latency:.1f}ms exceeds goal {p95_goal}ms"
                    )
                    return False
        
        return True
    
    def check_false_positive_rate(self) -> bool:
        """Check if false positive rate exceeds goals"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        fp_threshold = ci_gates.get('fail_on', {}).get('false_positive_rate_exceeds', 0.02)
        
        if fp_threshold is None:
            return True
        
        results = self.report.get('results', {})
        total_false_positives = 0
        total_normal_requests = 0
        
        for tier_name, tier_results in results.items():
            if tier_name == 'unprotected':
                continue
            
            normal_results = tier_results.get('normal', {})
            blocked = normal_results.get('blocked', 0)
            total = normal_results.get('total_requests', 0)
            
            total_false_positives += blocked
            total_normal_requests += total
        
        if total_normal_requests > 0:
            fp_rate = total_false_positives / total_normal_requests
            if fp_rate > fp_threshold:
                self.violations.append(
                    f"❌ False positive rate {fp_rate:.1%} exceeds threshold {fp_threshold:.1%}"
                )
                return False
        
        return True
    
    def check_block_rate(self) -> bool:
        """Check if block rate meets goals"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        if not ci_gates.get('fail_on', {}).get('block_rate_below_goal', False):
            return True
        
        results = self.report.get('results', {})
        active_phase = self.goals.get('active_phase', 'phase_1')
        phase_goals = self.goals.get(active_phase, {})
        
        for tier_name, tier_results in results.items():
            if tier_name == 'unprotected':
                continue
            
            tier_goals = phase_goals.get(tier_name, {})
            block_rate_goal = tier_goals.get('block_rate', 0.0)
            
            # Calculate overall block rate for tier
            total_blocked = 0
            total_requests = 0
            
            for attack_type, attack_results in tier_results.items():
                total_blocked += attack_results.get('blocked', 0)
                total_requests += attack_results.get('total_requests', 0)
            
            if total_requests > 0:
                block_rate = total_blocked / total_requests
                if block_rate < block_rate_goal:
                    self.violations.append(
                        f"❌ {tier_name.upper()}: block rate {block_rate:.1%} below goal {block_rate_goal:.1%}"
                    )
                    return False
        
        return True
    
    def check_provider_variance(self) -> bool:
        """Check if provider variance exceeds threshold"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        variance_threshold = ci_gates.get('warn_on', {}).get('provider_variance_exceeds', 0.05)
        
        if variance_threshold is None:
            return True
        
        results = self.report.get('results', {})
        provider_scores = {}
        
        for tier_name, tier_results in results.items():
            if tier_name == 'unprotected':
                continue
            
            total_blocked = 0
            total_requests = 0
            
            for attack_type, attack_results in tier_results.items():
                total_blocked += attack_results.get('blocked', 0)
                total_requests += attack_results.get('total_requests', 0)
            
            if total_requests > 0:
                block_rate = total_blocked / total_requests
                provider_scores[tier_name] = block_rate
        
        if len(provider_scores) >= 2:
            scores = list(provider_scores.values())
            max_score = max(scores)
            min_score = min(scores)
            variance = (max_score - min_score) / max_score if max_score > 0 else 0
            
            if variance > variance_threshold:
                self.warnings.append(
                    f"⚠️  Provider variance {variance:.1%} exceeds threshold {variance_threshold:.1%}"
                )
        
        return True
    
    def check_cache_hit_rate(self) -> bool:
        """Check if cache hit rate meets goals"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        cache_threshold = ci_gates.get('warn_on', {}).get('cache_hit_rate_below', 0.70)
        
        if cache_threshold is None:
            return True
        
        # This would need to be implemented based on actual cache metrics
        # For now, we'll skip this check
        return True
    
    def check_availability(self) -> bool:
        """Check if availability meets goals"""
        ci_gates = self.goals.get('ci_gates', {})
        if not isinstance(ci_gates, dict):
            return True
        availability_threshold = ci_gates.get('warn_on', {}).get('availability_below', 0.995)
        
        if availability_threshold is None:
            return True
        
        # This would need to be implemented based on actual availability metrics
        # For now, we'll skip this check
        return True
    
    def run_all_checks(self) -> bool:
        """Run all CI/CD checks"""
        logger.info("Running CI/CD quality gates...")
        
        # Critical checks (fail on violation)
        critical_checks = [
            self.check_p95_latency,
            self.check_false_positive_rate,
            self.check_block_rate,
        ]
        
        # Warning checks (warn on violation)
        warning_checks = [
            self.check_provider_variance,
            self.check_cache_hit_rate,
            self.check_availability,
        ]
        
        # Run critical checks
        critical_passed = True
        for check in critical_checks:
            if not check():
                critical_passed = False
        
        # Run warning checks
        for check in warning_checks:
            check()
        
        # Print results
        if self.violations:
            logger.error("❌ CI/CD gates failed:")
            for violation in self.violations:
                logger.error(f"  {violation}")
        
        if self.warnings:
            logger.warning("⚠️  CI/CD warnings:")
            for warning in self.warnings:
                logger.warning(f"  {warning}")
        
        if not self.violations and not self.warnings:
            logger.info("✅ All CI/CD gates passed!")
        
        return critical_passed
    
    def generate_summary(self) -> str:
        """Generate markdown summary for PR comments"""
        results = self.report.get('results', {})
        providers = self.report.get('providers', {})
        
        summary = ["## Kong Guard AI Audit Results\n"]
        
        # Performance summary table
        summary.append("### Performance Summary")
        summary.append("| Tier | Total Requests | Blocked | Block Rate | Avg Latency | AI Model |")
        summary.append("|------|----------------|---------|------------|-------------|----------|")
        
        for tier_name, tier_results in results.items():
            total_blocked = sum(ar.get('blocked', 0) for ar in tier_results.values())
            total_requests = sum(ar.get('total_requests', 0) for ar in tier_results.values())
            avg_latency = sum(ar.get('avg_latency_ms', 0) for ar in tier_results.values()) / len(tier_results) if tier_results else 0
            ai_model = providers.get(tier_name, 'unknown')
            
            block_rate = total_blocked / total_requests if total_requests > 0 else 0
            
            summary.append(f"| {tier_name.upper()} | {total_requests} | {total_blocked} | {block_rate:.1%} | {avg_latency:.1f}ms | {ai_model} |")
        
        # Violations and warnings
        if self.violations:
            summary.append("\n### ❌ Critical Issues")
            for violation in self.violations:
                summary.append(f"- {violation}")
        
        if self.warnings:
            summary.append("\n### ⚠️  Warnings")
            for warning in self.warnings:
                summary.append(f"- {warning}")
        
        if not self.violations and not self.warnings:
            summary.append("\n### ✅ All Quality Gates Passed")
        
        return "\n".join(summary)


def main():
    parser = argparse.ArgumentParser(description="CI/CD gates for Kong Guard AI audit results")
    parser.add_argument("--goals", required=True, help="Path to goals.yaml file")
    parser.add_argument("--report", required=True, help="Path to audit report JSON file")
    parser.add_argument("--summary", action="store_true", help="Generate markdown summary")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Set up logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    
    # Run CI gates
    gates = CIGates(args.goals, args.report)
    passed = gates.run_all_checks()
    
    # Generate summary if requested
    if args.summary:
        summary = gates.generate_summary()
        print("\n" + "="*50)
        print(summary)
        print("="*50)
    
    # Exit with appropriate code
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
