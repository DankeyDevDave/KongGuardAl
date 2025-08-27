#!/usr/bin/env python3
"""
Complete SQLite to Supabase migration
"""
import sqlite3
import subprocess
import sys

def migrate_all():
    # Connect to SQLite
    conn = sqlite3.connect("attack_metrics.db")
    cursor = conn.cursor()
    
    # Check data
    cursor.execute("SELECT COUNT(*) FROM attack_metrics")
    total_metrics = cursor.fetchone()[0]
    print(f"Found {total_metrics} metrics to migrate")
    
    if total_metrics == 0:
        print("No data to migrate")
        return
    
    # Get all metrics in batches
    batch_size = 100
    migrated = 0
    
    for offset in range(0, total_metrics, batch_size):
        cursor.execute(f"SELECT * FROM attack_metrics ORDER BY id LIMIT {batch_size} OFFSET {offset}")
        batch = cursor.fetchall()
        
        # Get column names
        cursor.execute("PRAGMA table_info(attack_metrics)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Build insert statements
        for row in batch:
            values = []
            for i, val in enumerate(row):
                if val is None:
                    values.append("NULL")
                elif isinstance(val, str):
                    # Escape for PostgreSQL
                    escaped = val.replace("'", "''").replace("\\", "\\\\")
                    values.append(f"'{escaped}'")
                elif isinstance(val, bool):
                    values.append("true" if val else "false")
                else:
                    values.append(str(val))
            
            # Skip id column, let PostgreSQL auto-generate
            col_list = [c for c in columns if c != 'id']
            val_list = [values[i] for i, c in enumerate(columns) if c != 'id']
            
            sql = f"INSERT INTO kongguard.attack_metrics ({', '.join(col_list)}) VALUES ({', '.join(val_list)}) ON CONFLICT DO NOTHING;"
            
            # Execute via SSH
            cmd = f"""ssh root@192.168.0.201 'pct exec 122 -- docker exec supabase-db psql -U supabase_admin -d postgres -c "{sql}"' 2>/dev/null"""
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                migrated += 1
        
        print(f"Progress: {migrated}/{total_metrics} metrics migrated")
    
    conn.close()
    print(f"✅ Migration complete: {migrated} metrics migrated")

if __name__ == "__main__":
    migrate_all()