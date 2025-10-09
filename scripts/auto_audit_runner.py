#!/usr/bin/env python3
"""
Automated Audit Runner for Kong Guard AI
Orchestrates attack testing across tiers and generates comprehensive reports.
"""

import argparse
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel

from audit_payloads import get_attack_payload, get_tier_config, get_all_attack_types, get_all_tiers
from audit_writers import (
    write_json_report, patch_matrix_markdown, append_live_log, 
    write_csv_report, load_goals, compare_against_goals, create_live_markdown_header
)
from audit_utils import normalize_action, decide_enforcement, is_allowlisted, optimize_payload, validate_action
from ai_client import AIClient

console = Console()

class AuditRunner:
    def __init__(self, args):
        self.args = args
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'args': vars(args),
            'providers': {},
            'results': {}
        }
        
    def discover_providers(self) -> Dict[str, str]:
        """Discover AI providers from service endpoints."""
        providers = {}
        
        # Check cloud AI service
        try:
            response = requests.get("http://localhost:28100/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                providers['cloud'] = data.get('ai_provider', 'unknown')
        except Exception as e:
            console.print(f"[yellow]Warning: Could not discover cloud provider: {e}[/yellow]")
            providers['cloud'] = 'unknown'
        
        # Check local AI service
        try:
            response = requests.get("http://localhost:28101/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                providers['local'] = data.get('ai_provider', 'unknown')
        except Exception as e:
            console.print(f"[yellow]Warning: Could not discover local provider: {e}[/yellow]")
            providers['local'] = 'unknown'
        
        # Check WebSocket service
        try:
            response = requests.get("http://localhost:18002/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                providers['websocket'] = data.get('ai_provider', 'unknown')
        except Exception as e:
            console.print(f"[yellow]Warning: Could not discover WebSocket provider: {e}[/yellow]")
            providers['websocket'] = 'unknown'
        
        return providers
    
    def simulate_unprotected_request(self, attack_type: str) -> Dict[str, Any]:
        """Simulate an unprotected request (always allowed)."""
        config = get_tier_config('unprotected')
        time.sleep(config['latency_ms'] / 1000.0)  # Simulate latency
        
        # Check if this would be allowlisted in a real scenario
        payload = get_attack_payload(attack_type)
        features = payload.get('features', {})
        
        method = features.get('method', 'GET')
        path = features.get('path', '/')
        headers = features.get('headers', {})
        
        # In unprotected mode, everything is allowed
        # But we can still check what would happen with allowlist logic
        would_be_allowlisted = is_allowlisted(method, path, headers)
        
        return {
            'action': 'allowed',
            'threat_score': 0.0,
            'threat_type': attack_type,
            'latency_ms': config['latency_ms'],
            'ai_model': 'none',
            'timestamp': datetime.now().isoformat(),
            'would_be_allowlisted': would_be_allowlisted
        }
    
    def make_protected_request(self, tier: str, attack_type: str) -> Dict[str, Any]:
        """Make a request to a protected tier with optimization and normalization."""
        config = get_tier_config(tier)
        raw_payload = get_attack_payload(attack_type)
        
        # Optimize payload for better performance
        optimized_payload = optimize_payload(
            raw_payload.get('features', {}),
            raw_payload.get('context', {})
        )

        start_time = time.time()

        try:
            url = f"{config['base_url']}{config['analyze_endpoint']}"
            response = requests.post(
                url,
                json=optimized_payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            latency_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                data = response.json()
                raw_action = data.get('recommended_action', 'unknown')
                threat_score = data.get('threat_score', 0.0)
                threat_type = data.get('threat_type', attack_type)
                
                # Normalize action and apply risk tiers
                normalized_action = normalize_action(raw_action)
                enforcement_action = decide_enforcement(threat_score, threat_type)
                
                # Validate action
                if not validate_action(enforcement_action.value):
                    enforcement_action = normalized_action
                
                return {
                    'action': enforcement_action.value,
                    'threat_score': threat_score,
                    'threat_type': threat_type,
                    'latency_ms': latency_ms,
                    'ai_model': data.get('ai_model', 'unknown'),
                    'timestamp': datetime.now().isoformat(),
                    'raw_action': raw_action,
                    'normalized_action': normalized_action.value
                }
            else:
                return {
                    'action': 'error',
                    'threat_score': 0.0,
                    'threat_type': attack_type,
                    'latency_ms': latency_ms,
                    'ai_model': 'unknown',
                    'error': f"HTTP {response.status_code}",
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return {
                'action': 'error',
                'threat_score': 0.0,
                'threat_type': attack_type,
                'latency_ms': latency_ms,
                'ai_model': 'unknown',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def run_attack_tests(self, tier: str, attack_type: str, num_clicks: int) -> Dict[str, Any]:
        """Run multiple tests for a specific tier and attack type."""
        console.print(f"Testing {tier} tier with {attack_type} ({num_clicks} requests)")
        
        individual_results = []
        blocked_count = 0
        allowed_count = 0
        error_count = 0
        total_latency = 0
        total_score = 0
        
        for i in range(num_clicks):
            if tier == 'unprotected':
                result = self.simulate_unprotected_request(attack_type)
            else:
                result = self.make_protected_request(tier, attack_type)
            
            individual_results.append(result)
            
            # Count actions (normalize action values)
            action = result['action'].lower()
            if action in ['block', 'blocked']:
                blocked_count += 1
            elif action in ['allow', 'allowed']:
                allowed_count += 1
            else:
                error_count += 1
            
            # Accumulate metrics
            total_latency += result['latency_ms']
            total_score += result['threat_score']
            
            # Append to live log
            if self.args.live_md:
                append_live_log(self.args.live_md, {
                    'tier': tier,
                    'attack_type': attack_type,
                    'action': result['action'],
                    'threat_score': result['threat_score'],
                    'latency_ms': result['latency_ms']
                })
        
        # Calculate averages
        total_requests = len(individual_results)
        avg_latency = total_latency / total_requests if total_requests > 0 else 0
        avg_score = total_score / total_requests if total_requests > 0 else 0
        
        # Determine AI model (use most common)
        ai_models = [r.get('ai_model', 'unknown') for r in individual_results if r.get('ai_model') != 'unknown']
        ai_model = max(set(ai_models), key=ai_models.count) if ai_models else 'unknown'
        
        return {
            'total_requests': total_requests,
            'blocked': blocked_count,
            'allowed': allowed_count,
            'errors': error_count,
            'avg_latency_ms': avg_latency,
            'avg_threat_score': avg_score,
            'ai_model': ai_model,
            'individual_results': individual_results
        }
    
    def run_audit(self):
        """Run the complete audit."""
        console.print(Panel.fit("Kong Guard AI Automated Audit Runner", style="bold blue"))
        
        # Discover providers
        console.print("\n[bold]Discovering AI Providers...[/bold]")
        self.results['providers'] = self.discover_providers()
        
        for tier, provider in self.results['providers'].items():
            console.print(f"  {tier}: {provider}")
        
        # Initialize live log
        if self.args.live_md:
            create_live_markdown_header(self.args.live_md)
        
        # Run tests for each tier
        tiers = self.args.tiers.split(',') if self.args.tiers else get_all_tiers()
        
        with Progress() as progress:
            total_tasks = len(tiers) * len(get_all_attack_types())
            main_task = progress.add_task("Running audit...", total=total_tasks)
            
            for tier in tiers:
                tier_results = {}
                
                for attack_type in get_all_attack_types():
                    try:
                        attack_results = self.run_attack_tests(tier, attack_type, self.args.clicks)
                        tier_results[attack_type] = attack_results
                        
                        # Update progress
                        progress.update(main_task, advance=1)
                        
                    except Exception as e:
                        console.print(f"[red]Error testing {tier}/{attack_type}: {e}[/red]")
                        tier_results[attack_type] = {
                            'error': str(e),
                            'total_requests': 0,
                            'blocked': 0,
                            'allowed': 0,
                            'errors': 1
                        }
                        progress.update(main_task, advance=1)
                
                self.results['results'][tier] = tier_results
        
        # Load and compare against goals
        if self.args.goals:
            goals = load_goals(self.args.goals)
            self.results['goals_comparison'] = compare_against_goals(self.results, goals)
        
        # Write reports
        self.write_reports()
        
        # Display summary
        self.display_summary()
    
    def write_reports(self):
        """Write all output reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        json_path = f"{self.args.report_dir}/{timestamp}-audit.json"
        write_json_report(self.results, json_path)
        console.print(f"[green]JSON report written to: {json_path}[/green]")
        
        # CSV report
        csv_path = f"{self.args.report_dir}/{timestamp}-audit.csv"
        write_csv_report(self.results, csv_path)
        console.print(f"[green]CSV report written to: {csv_path}[/green]")
        
        # Patch matrix markdown
        if self.args.matrix:
            patch_matrix_markdown(self.args.matrix, self.results['results'])
            console.print(f"[green]Matrix updated: {self.args.matrix}[/green]")
    
    def display_summary(self):
        """Display audit summary."""
        console.print("\n[bold]Audit Summary[/bold]")
        
        # Create summary table
        table = Table(title="Tier Performance Summary")
        table.add_column("Tier", style="cyan")
        table.add_column("Total Requests", justify="right")
        table.add_column("Blocked", justify="right", style="red")
        table.add_column("Allowed", justify="right", style="green")
        table.add_column("Block Rate %", justify="right")
        table.add_column("Avg Latency (ms)", justify="right")
        table.add_column("AI Model", style="yellow")
        
        for tier, tier_results in self.results['results'].items():
            total_requests = sum(r.get('total_requests', 0) for r in tier_results.values())
            total_blocked = sum(r.get('blocked', 0) for r in tier_results.values())
            total_allowed = sum(r.get('allowed', 0) for r in tier_results.values())
            block_rate = (total_blocked / total_requests * 100) if total_requests > 0 else 0
            
            # Calculate average latency
            total_latency = sum(r.get('avg_latency_ms', 0) * r.get('total_requests', 0) for r in tier_results.values())
            avg_latency = total_latency / total_requests if total_requests > 0 else 0
            
            # Get most common AI model
            ai_models = [r.get('ai_model', 'unknown') for r in tier_results.values() if r.get('ai_model') != 'unknown']
            ai_model = max(set(ai_models), key=ai_models.count) if ai_models else 'unknown'
            
            table.add_row(
                tier,
                str(total_requests),
                str(total_blocked),
                str(total_allowed),
                f"{block_rate:.1f}%",
                f"{avg_latency:.0f}",
                ai_model
            )
        
        console.print(table)
        
        # Display goals comparison if available
        if 'goals_comparison' in self.results:
            comparison = self.results['goals_comparison']
            if comparison['violations']:
                console.print("\n[red]Goal Violations:[/red]")
                for violation in comparison['violations']:
                    console.print(f"  - {violation}")
            else:
                console.print("\n[green]All goals met![/green]")

def main():
    parser = argparse.ArgumentParser(description="Kong Guard AI Automated Audit Runner")
    parser.add_argument("--clicks", type=int, default=10, help="Number of requests per attack type")
    parser.add_argument("--tiers", type=str, default="unprotected,cloud,local", help="Comma-separated list of tiers to test")
    parser.add_argument("--matrix", type=str, help="Path to demo-attack-matrix.md file to update")
    parser.add_argument("--report-dir", type=str, default="docs/audit/runs", help="Directory for audit reports")
    parser.add_argument("--goals", type=str, default="docs/audit/goals.yaml", help="Path to goals YAML file")
    parser.add_argument("--live-md", type=str, help="Path to live markdown log file")
    
    args = parser.parse_args()
    
    # Create report directory
    Path(args.report_dir).mkdir(parents=True, exist_ok=True)
    
    # Run audit
    runner = AuditRunner(args)
    runner.run_audit()

if __name__ == "__main__":
    main()
