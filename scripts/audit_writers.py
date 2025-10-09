"""
Helper functions for writing audit results to various formats.
Handles JSON reports, Markdown matrix patching, and live logging.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml

def write_json_report(data: Dict[str, Any], output_path: str) -> None:
    """Write audit results to a timestamped JSON file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def patch_matrix_markdown(matrix_path: str, results: Dict[str, Dict[str, Any]]) -> None:
    """Patch the demo-attack-matrix.md file with actual results."""
    if not os.path.exists(matrix_path):
        raise FileNotFoundError(f"Matrix file not found: {matrix_path}")
    
    # Create backup
    backup_path = f"{matrix_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.system(f"cp '{matrix_path}' '{backup_path}'")
    
    with open(matrix_path, 'r') as f:
        content = f.read()
    
    # Patch each tier section
    for tier, tier_results in results.items():
        tier_section = f"## {tier.replace('_', ' ').title()} Protection"
        
        # Find the tier section
        tier_match = re.search(f"{re.escape(tier_section)}.*?(?=## |$)", content, re.DOTALL)
        if not tier_match:
            continue
            
        tier_content = tier_match.group(0)
        
        # Patch each attack row
        for attack_type, attack_results in tier_results.items():
            # Find the attack row
            attack_pattern = rf"(\| {re.escape(attack_type)} \|).*?(\|.*?\|)"
            attack_match = re.search(attack_pattern, tier_content)
            
            if attack_match:
                # Format the actual result
                blocked = attack_results.get('blocked', 0)
                allowed = attack_results.get('allowed', 0)
                total = blocked + allowed
                block_rate = (blocked / total * 100) if total > 0 else 0
                avg_latency = attack_results.get('avg_latency_ms', 0)
                ai_model = attack_results.get('ai_model', 'N/A')
                
                actual_result = f"Requests: {total}; Blocked: {blocked}; Allowed: {allowed}; Block Rate: {block_rate:.1f}%; Avg Latency: {avg_latency:.0f}ms; Model: {ai_model}"
                
                # Replace the actual result column
                new_row = f"{attack_match.group(1)} Expected Result | {actual_result} |"
                tier_content = tier_content.replace(attack_match.group(0), new_row)
        
        # Replace the tier section in the main content
        content = content.replace(tier_match.group(0), tier_content)
    
    # Write the patched content
    with open(matrix_path, 'w') as f:
        f.write(content)

def append_live_log(log_path: str, entry: Dict[str, Any]) -> None:
    """Append a single log entry to the live markdown file."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tier = entry.get('tier', 'unknown')
    attack_type = entry.get('attack_type', 'unknown')
    action = entry.get('action', 'unknown')
    score = entry.get('threat_score', 0)
    latency_ms = entry.get('latency_ms', 0)
    
    log_line = f"- **{timestamp}** | {tier.upper()} | {attack_type} | {action.upper()} | Score: {score:.3f} | {latency_ms:.0f}ms\n"
    
    with open(log_path, 'a') as f:
        f.write(log_line)

def write_csv_report(data: Dict[str, Any], output_path: str) -> None:
    """Write audit results to CSV format."""
    import csv
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['timestamp', 'tier', 'attack_type', 'action', 'threat_score', 'latency_ms', 'ai_model'])
        
        # Write data rows
        for tier, tier_results in data.get('results', {}).items():
            for attack_type, attack_results in tier_results.items():
                for result in attack_results.get('individual_results', []):
                    writer.writerow([
                        result.get('timestamp', ''),
                        tier,
                        attack_type,
                        result.get('action', ''),
                        result.get('threat_score', 0),
                        result.get('latency_ms', 0),
                        result.get('ai_model', '')
                    ])

def load_goals(goals_path: str) -> Dict[str, Any]:
    """Load goals configuration from YAML file."""
    if not os.path.exists(goals_path):
        return {}
    
    with open(goals_path, 'r') as f:
        return yaml.safe_load(f) or {}

def compare_against_goals(results: Dict[str, Any], goals: Dict[str, Any]) -> Dict[str, Any]:
    """Compare audit results against goals and return status."""
    comparison = {
        'meets_goals': True,
        'violations': [],
        'summary': {}
    }
    
    for tier, tier_results in results.get('results', {}).items():
        tier_goals = goals.get(tier, {})
        tier_summary = {
            'total_requests': 0,
            'total_blocked': 0,
            'block_rate': 0.0,
            'avg_latency': 0.0,
            'goal_block_rate': tier_goals.get('min_block_rate', 0),
            'goal_max_latency': tier_goals.get('max_latency_ms', 1000),
            'meets_block_rate': True,
            'meets_latency': True
        }
        
        for attack_type, attack_results in tier_results.items():
            tier_summary['total_requests'] += attack_results.get('total_requests', 0)
            tier_summary['total_blocked'] += attack_results.get('blocked', 0)
            tier_summary['avg_latency'] += attack_results.get('avg_latency_ms', 0)
        
        if tier_summary['total_requests'] > 0:
            tier_summary['block_rate'] = (tier_summary['total_blocked'] / tier_summary['total_requests']) * 100
            tier_summary['avg_latency'] /= len(tier_results)
            
            # Check goals
            if tier_summary['block_rate'] < tier_summary['goal_block_rate']:
                tier_summary['meets_block_rate'] = False
                comparison['meets_goals'] = False
                comparison['violations'].append(f"{tier}: Block rate {tier_summary['block_rate']:.1f}% < goal {tier_summary['goal_block_rate']:.1f}%")
            
            if tier_summary['avg_latency'] > tier_summary['goal_max_latency']:
                tier_summary['meets_latency'] = False
                comparison['meets_goals'] = False
                comparison['violations'].append(f"{tier}: Avg latency {tier_summary['avg_latency']:.0f}ms > goal {tier_summary['goal_max_latency']:.0f}ms")
        
        comparison['summary'][tier] = tier_summary
    
    return comparison

def create_live_markdown_header(log_path: str) -> None:
    """Create the initial live markdown file with header."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    header = """# Live Audit Log

## Real-time Attack Results

| Timestamp | Tier | Attack Type | Action | Threat Score | Latency |
|-----------|------|-------------|--------|--------------|---------|

"""
    
    with open(log_path, 'w') as f:
        f.write(header)
