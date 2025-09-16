#!/usr/bin/env python3
"""
Direct database migration using SSH execution
"""
import sqlite3
import subprocess


def main():
    # Connect to SQLite
    conn = sqlite3.connect("attack_metrics.db")
    cursor = conn.cursor()

    # Get count of data
    cursor.execute("SELECT COUNT(*) FROM attack_runs")
    runs_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM attack_metrics")
    metrics_count = cursor.fetchone()[0]

    print(f"📊 Found {runs_count} attack runs and {metrics_count} metrics to migrate")

    # Simple migration approach - copy run data first
    print("🔄 Starting migration...")

    # Create SQL insert file for runs
    cursor.execute("SELECT * FROM attack_runs")
    runs = cursor.fetchall()

    cursor.execute("PRAGMA table_info(attack_runs)")
    run_columns = [col[1] for col in cursor.fetchall()]

    with open("/tmp/migrate_runs.sql", "w") as f:
        f.write("BEGIN;\n")
        f.write("SET search_path TO kongguard, public;\n")
        for run in runs:
            values = []
            for val in run:
                if val is None:
                    values.append("NULL")
                elif isinstance(val, str):
                    # Escape single quotes by doubling them
                    escaped = val.replace("'", "''")
                    values.append(f"'{escaped}'")
                else:
                    values.append(str(val))

            sql = f"INSERT INTO attack_runs ({', '.join(run_columns)}) VALUES ({', '.join(values)}) ON CONFLICT (run_id) DO NOTHING;\n"
            f.write(sql)
        f.write("COMMIT;\n")

    # Execute runs migration
    print("📊 Migrating attack runs...")
    cmd = "scp /tmp/migrate_runs.sql root@198.51.100.201:/tmp/ && ssh root@198.51.100.201 'pct exec 122 -- docker exec -i supabase-db psql -U supabase_admin -d postgres -f /tmp/migrate_runs.sql'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print("✅ Attack runs migrated successfully")
    else:
        print(f"❌ Failed to migrate runs: {result.stderr}")

    # Migrate metrics in smaller batches
    cursor.execute("SELECT * FROM attack_metrics LIMIT 100")
    metrics_batch = cursor.fetchall()

    cursor.execute("PRAGMA table_info(attack_metrics)")
    metrics_columns = [col[1] for col in cursor.fetchall()]

    with open("/tmp/migrate_metrics.sql", "w") as f:
        f.write("BEGIN;\n")
        f.write("SET search_path TO kongguard, public;\n")
        for metric in metrics_batch:
            values = []
            for val in metric:
                if val is None:
                    values.append("NULL")
                elif isinstance(val, str):
                    # Escape single quotes and special characters
                    escaped = val.replace("'", "''").replace("\\", "\\\\")
                    values.append(f"'{escaped}'")
                else:
                    values.append(str(val))

            sql = f"INSERT INTO attack_metrics ({', '.join(metrics_columns)}) VALUES ({', '.join(values)}) ON CONFLICT (id) DO NOTHING;\n"
            f.write(sql)
        f.write("COMMIT;\n")

    # Execute metrics migration
    print("📈 Migrating attack metrics sample...")
    cmd = "scp /tmp/migrate_metrics.sql root@198.51.100.201:/tmp/ && ssh root@198.51.100.201 'pct exec 122 -- docker exec -i supabase-db psql -U supabase_admin -d postgres -f /tmp/migrate_metrics.sql'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print("✅ Attack metrics sample migrated successfully")
    else:
        print(f"❌ Failed to migrate metrics: {result.stderr}")

    # Verify migration
    print("\n🔍 Verifying migration...")
    cmd = "ssh root@198.51.100.201 'pct exec 122 -- docker exec supabase-db psql -U supabase_admin -d postgres -c \"SELECT COUNT(*) as runs FROM kongguard.attack_runs; SELECT COUNT(*) as metrics FROM kongguard.attack_metrics;\"'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print("✅ Migration verification:")
        print(result.stdout)
    else:
        print(f"❌ Verification failed: {result.stderr}")

    conn.close()
    print("🎉 Migration completed!")


if __name__ == "__main__":
    main()
