#!/usr/bin/env python3
"""
Update Grafana dashboard to use database metrics
"""
import json
from pathlib import Path

# Path to dashboard JSON
dashboard_path = Path(__file__).parent / "grafana-local/dashboards/kong-guard-ai-dashboard.json"

# Load dashboard
with open(dashboard_path) as f:
    dashboard = json.load(f)

# Metric mappings from runtime to database metrics
metric_mappings = {
    "kong_guard_threats_detected_total": "kong_guard_db_total_attacks",
    "kong_guard_threats_by_type": "kong_guard_db_attacks_by_category",
    "kong_guard_blocked_ips": "kong_guard_db_blocked_total",
    "kong_guard_false_positives_total": "kong_guard_db_allowed_total",  # Allowed attacks could be considered FPs
}

# Update all panel queries
updates_made = 0
for panel in dashboard.get("panels", []):
    if "targets" in panel:
        for target in panel["targets"]:
            if "expr" in target:
                original_expr = target["expr"]
                new_expr = original_expr
                
                # Replace metric names
                for old_metric, new_metric in metric_mappings.items():
                    if old_metric in new_expr:
                        new_expr = new_expr.replace(old_metric, new_metric)
                
                if new_expr != original_expr:
                    print(f"Panel '{panel.get('title', 'Unknown')}':")
                    print(f"  OLD: {original_expr}")
                    print(f"  NEW: {new_expr}")
                    target["expr"] = new_expr
                    updates_made += 1

# Update dashboard title to indicate it's using database metrics
dashboard["title"] = "Kong Guard AI - Historical Metrics"

# Save updated dashboard
with open(dashboard_path, "w") as f:
    json.dump(dashboard, f, indent=2)

print(f"\n✅ Updated {updates_made} queries in Grafana dashboard")
print(f"📊 Dashboard saved to: {dashboard_path}")
