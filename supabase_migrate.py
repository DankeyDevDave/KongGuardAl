#!/usr/bin/env python3
"""
Kong Guard AI - Supabase Migration Script
Migrates data from SQLite to Supabase PostgreSQL
"""

import os
import sqlite3
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Any

def get_sqlite_data(db_path: str) -> Dict[str, List]:
    """Extract data from SQLite database"""
    if not os.path.exists(db_path):
        print(f"SQLite database not found: {db_path}")
        return {"attack_runs": [], "attack_metrics": []}
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    cursor = conn.cursor()
    
    data = {"attack_runs": [], "attack_metrics": []}
    
    # Get attack runs
    try:
        cursor.execute("SELECT * FROM attack_runs")
        data["attack_runs"] = [dict(row) for row in cursor.fetchall()]
        print(f"✅ Found {len(data['attack_runs'])} attack runs")
    except sqlite3.Error as e:
        print(f"⚠️  No attack_runs table found: {e}")
    
    # Get attack metrics  
    try:
        cursor.execute("SELECT * FROM attack_metrics")
        data["attack_metrics"] = [dict(row) for row in cursor.fetchall()]
        print(f"✅ Found {len(data['attack_metrics'])} attack metrics")
    except sqlite3.Error as e:
        print(f"⚠️  No attack_metrics table found: {e}")
    
    conn.close()
    return data

def migrate_to_supabase(data: Dict[str, List], host: str = "198.51.100.201", container: str = "122"):
    """Migrate data to Supabase PostgreSQL"""
    
    print("🔄 Starting migration to Supabase...")
    
    # Migrate attack runs first
    for i, run in enumerate(data["attack_runs"]):
        print(f"📊 Migrating attack run {i+1}/{len(data['attack_runs'])}: {run.get('run_id', 'Unknown')}")
        
        # Build insert query
        columns = []
        values = []
        for key, value in run.items():
            if key == 'config_json' and isinstance(value, str):
                # Handle JSON string
                columns.append(key)
                values.append(f"'{value.replace(chr(39), chr(39)+chr(39))}'::jsonb")
            elif isinstance(value, str):
                columns.append(key)
                values.append(f"'{value.replace(chr(39), chr(39)+chr(39))}'")
            elif value is not None:
                columns.append(key)
                values.append(str(value))
        
        if columns:
            insert_sql = f"""
            INSERT INTO kongguard.attack_runs ({', '.join(columns)})
            VALUES ({', '.join(values)})
            ON CONFLICT (run_id) DO NOTHING;
            """
            
            cmd = f"ssh root@{host} 'pct exec {container} -- docker exec supabase-db psql -U supabase_admin -d postgres -c \"{insert_sql}\"'"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    print(f"❌ Failed to insert run {run.get('run_id')}: {result.stderr}")
                else:
                    print(f"✅ Migrated run {run.get('run_id')}")
            except subprocess.TimeoutExpired:
                print(f"⏰ Timeout migrating run {run.get('run_id')}")
            except Exception as e:
                print(f"❌ Error migrating run {run.get('run_id')}: {e}")
    
    # Migrate attack metrics
    batch_size = 10  # Process in batches to avoid command length issues
    total_metrics = len(data["attack_metrics"])
    
    for i in range(0, total_metrics, batch_size):
        batch = data["attack_metrics"][i:i+batch_size]
        print(f"📈 Migrating metrics batch {i//batch_size + 1}/{(total_metrics + batch_size - 1)//batch_size}")
        
        values_list = []
        for metric in batch:
            columns = []
            values = []
            for key, value in metric.items():
                if isinstance(value, str):
                    columns.append(key)
                    values.append(f"'{value.replace(chr(39), chr(39)+chr(39))}'")
                elif value is not None:
                    columns.append(key)
                    values.append(str(value))
            
            if columns:
                values_list.append(f"({', '.join(values)})")
        
        if values_list:
            # Use the columns from the first metric (assuming all have same structure)
            metric_columns = []
            for key, value in batch[0].items():
                if value is not None:
                    metric_columns.append(key)
            
            insert_sql = f"""
            INSERT INTO kongguard.attack_metrics ({', '.join(metric_columns)})
            VALUES {', '.join(values_list)}
            ON CONFLICT (id) DO NOTHING;
            """
            
            cmd = f"ssh root@{host} 'pct exec {container} -- docker exec supabase-db psql -U supabase_admin -d postgres -c \"{insert_sql}\"'"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    print(f"❌ Failed to insert metrics batch: {result.stderr}")
                else:
                    print(f"✅ Migrated {len(batch)} metrics")
            except subprocess.TimeoutExpired:
                print(f"⏰ Timeout migrating metrics batch")
            except Exception as e:
                print(f"❌ Error migrating metrics batch: {e}")

def main():
    """Main migration function"""
    print("🚀 Kong Guard AI - Supabase Migration")
    print("=" * 50)
    
    # Check for SQLite databases
    possible_db_paths = [
        "attack_metrics.db",
        "test_attacks.db",
        "attacks.db", 
        "kongguard.db",
        "data/attacks.db",
        "database/attacks.db"
    ]
    
    sqlite_db = None
    for path in possible_db_paths:
        if os.path.exists(path):
            sqlite_db = path
            break
    
    if not sqlite_db:
        print("❌ No SQLite database found. Checked paths:")
        for path in possible_db_paths:
            print(f"   - {path}")
        return
    
    print(f"📁 Using SQLite database: {sqlite_db}")
    
    # Extract SQLite data
    data = get_sqlite_data(sqlite_db)
    
    if not data["attack_runs"] and not data["attack_metrics"]:
        print("⚠️  No data found to migrate")
        return
    
    # Migrate to Supabase
    migrate_to_supabase(data)
    
    print("=" * 50)
    print("🎉 Migration completed!")
    
    # Verify migration
    print("\n🔍 Verifying migration...")
    cmd = 'ssh root@198.51.100.201 \'pct exec 122 -- docker exec supabase-db psql -U supabase_admin -d postgres -c "SELECT COUNT(*) as runs FROM kongguard.attack_runs; SELECT COUNT(*) as metrics FROM kongguard.attack_metrics;"\''
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ Verification successful:")
            print(result.stdout)
        else:
            print(f"❌ Verification failed: {result.stderr}")
    except Exception as e:
        print(f"❌ Verification error: {e}")

if __name__ == "__main__":
    main()