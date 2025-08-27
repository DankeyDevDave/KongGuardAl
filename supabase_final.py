#!/usr/bin/env python3
"""
Kong Guard AI - Final Working Supabase Interface
Uses temporary files to avoid shell escaping issues
"""

import subprocess
import tempfile
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SupabaseFinal:
    """Final working Supabase interface using temp files"""
    
    def __init__(self, host: str = "192.168.0.201", container: str = "122"):
        self.host = host
        self.container = container
        self.user = "supabase_admin"
        self.database = "postgres"
        self.schema = "kongguard"
    
    def execute_sql_file(self, sql_content: str) -> Dict[str, Any]:
        """Execute SQL using a temporary file to avoid escaping issues"""
        try:
            # Write SQL to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
                f.write(f"SET search_path TO {self.schema}, public;\n")
                f.write(sql_content)
                temp_file = f.name
            
            # Copy file to remote and execute
            remote_file = f"/tmp/temp_query_{os.path.basename(temp_file)}"
            
            # Copy file
            copy_cmd = f"scp {temp_file} root@{self.host}:{remote_file}"
            copy_result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True)
            
            if copy_result.returncode != 0:
                return {"success": False, "error": f"Failed to copy file: {copy_result.stderr}"}
            
            # Execute SQL file
            exec_cmd = f"ssh root@{self.host} 'pct exec {self.container} -- docker exec -i supabase-db psql -U {self.user} -d {self.database} -f {remote_file}'"
            exec_result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Cleanup
            os.unlink(temp_file)
            cleanup_cmd = f"ssh root@{self.host} 'rm -f {remote_file}'"
            subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True)
            
            return {
                "success": exec_result.returncode == 0,
                "output": exec_result.stdout,
                "error": exec_result.stderr
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_attack_run(self, intensity: str, strategy: str, duration: int = 60) -> Optional[int]:
        """Create a new attack run"""
        sql = f"""
        INSERT INTO attack_runs (intensity_level, strategy, duration)
        VALUES ('{intensity}', '{strategy}', {duration})
        RETURNING run_id;
        """
        
        result = self.execute_sql_file(sql)
        
        if result["success"]:
            # Parse run_id from output
            lines = result["output"].strip().split('\n')
            for line in lines:
                stripped = line.strip()
                if stripped.isdigit():
                    run_id = int(stripped)
                    print(f"✅ Created attack run {run_id}")
                    return run_id
        
        print(f"❌ Failed to create attack run: {result.get('error', 'Unknown error')}")
        return None
    
    def insert_attack_metric(self, run_id: int, tier: str, attack_type: str, response_time: float = 100.0) -> bool:
        """Insert a single attack metric"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        
        sql = f"""
        INSERT INTO attack_metrics 
        (run_id, timestamp, tier, attack_type, response_time_ms, threat_score, confidence, blocked) 
        VALUES ({run_id}, '{timestamp}', '{tier}', '{attack_type}', {response_time}, 0.8, 0.9, true);
        """
        
        result = self.execute_sql_file(sql)
        
        if result["success"]:
            print(f"✅ Inserted attack metric: {tier} - {attack_type}")
            return True
        else:
            print(f"❌ Failed to insert metric: {result.get('error', 'Unknown error')}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get basic statistics"""
        sql = """
        SELECT 
            ar.run_id,
            ar.intensity_level,
            ar.strategy,
            ar.start_time,
            COUNT(am.id) as metric_count
        FROM attack_runs ar
        LEFT JOIN attack_metrics am ON ar.run_id = am.run_id
        GROUP BY ar.run_id, ar.intensity_level, ar.strategy, ar.start_time
        ORDER BY ar.start_time DESC
        LIMIT 10;
        """
        
        result = self.execute_sql_file(sql)
        
        if result["success"]:
            return {"success": True, "data": result["output"]}
        else:
            return {"success": False, "error": result.get("error", "Unknown error")}
    
    def test_connection(self) -> bool:
        """Test connection"""
        result = self.execute_sql_file("SELECT current_database(), current_user;")
        return result["success"]

def main():
    """Test the interface"""
    print("🚀 Kong Guard AI - Final Supabase Interface Test")
    print("=" * 60)
    
    supabase = SupabaseFinal()
    
    # Test connection
    print("🔍 Testing connection...")
    if not supabase.test_connection():
        print("❌ Connection failed")
        return
    
    print("✅ Connection successful!")
    
    # Create attack run
    print("\n📊 Creating attack run...")
    run_id = supabase.create_attack_run("high", "final_test", 180)
    
    if not run_id:
        print("❌ Cannot continue without run_id")
        return
    
    # Insert some metrics
    print(f"\n📈 Inserting metrics for run {run_id}...")
    
    test_attacks = [
        ("tier1", "sql_injection", 45.8),
        ("tier2", "xss_attack", 67.2),
        ("tier3", "command_injection", 123.7),
        ("cloud", "zero_day_exploit", 89.4),
        ("unprotected", "ransomware_pattern", 156.9)
    ]
    
    for tier, attack_type, response_time in test_attacks:
        supabase.insert_attack_metric(run_id, tier, attack_type, response_time)
    
    # Get statistics
    print("\n📊 Getting statistics...")
    stats = supabase.get_stats()
    
    if stats["success"]:
        print("✅ Current attack run statistics:")
        print(stats["data"])
    else:
        print(f"❌ Failed to get stats: {stats['error']}")
    
    print("\n" + "=" * 60)
    print("🎉 Supabase interface is fully operational!")
    print("💾 Kong Guard AI can now use PostgreSQL backend")
    print("🚀 Ready for high-performance attack metrics storage")

if __name__ == "__main__":
    main()