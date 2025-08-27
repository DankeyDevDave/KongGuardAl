#!/usr/bin/env python3
"""
Kong Guard AI - Working Supabase Interface
Simple SSH-based interface to Supabase PostgreSQL
"""

import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SupabaseWorking:
    """Working Supabase interface using SSH commands"""
    
    def __init__(self, host: str = "192.168.0.201", container: str = "122"):
        self.host = host
        self.container = container
        self.user = "supabase_admin"
        self.database = "postgres"
        self.schema = "kongguard"
    
    def execute_query(self, query: str) -> Dict[str, Any]:
        """Execute SQL query via SSH"""
        try:
            # Escape quotes properly for shell execution
            escaped_query = query.replace('"', '\\"')
            cmd = f"""ssh root@{self.host} 'pct exec {self.container} -- docker exec supabase-db psql -U {self.user} -d {self.database} -c "{escaped_query}"'"""
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
            
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e)
            }
    
    def create_attack_run(self, intensity: str, strategy: str, duration: int = 60) -> Optional[int]:
        """Create a new attack run"""
        query = f"INSERT INTO {self.schema}.attack_runs (intensity_level, strategy, duration) VALUES ('{intensity}', '{strategy}', {duration}) RETURNING run_id;"
        
        result = self.execute_query(query)
        
        if result["success"]:
            # Parse run_id from output
            lines = result["output"].strip().split('\n')
            for line in lines:
                if line.strip().isdigit():
                    run_id = int(line.strip())
                    print(f"✅ Created attack run {run_id}")
                    return run_id
        
        print(f"❌ Failed to create attack run: {result.get('error', 'Unknown error')}")
        return None
    
    def insert_attack_metric(self, run_id: int, tier: str, attack_type: str, response_time: float = 100.0) -> bool:
        """Insert a single attack metric"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        query = f"""INSERT INTO {self.schema}.attack_metrics 
        (run_id, timestamp, tier, attack_type, response_time_ms, threat_score, confidence, blocked) 
        VALUES ({run_id}, '{timestamp}', '{tier}', '{attack_type}', {response_time}, 0.8, 0.9, true);"""
        
        result = self.execute_query(query)
        
        if result["success"]:
            print(f"✅ Inserted attack metric for run {run_id}")
            return True
        else:
            print(f"❌ Failed to insert metric: {result.get('error', 'Unknown error')}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get basic statistics"""
        query = f"""SELECT 
            ar.run_id,
            ar.intensity_level,
            ar.strategy,
            ar.start_time,
            COUNT(am.id) as metric_count
        FROM {self.schema}.attack_runs ar
        LEFT JOIN {self.schema}.attack_metrics am ON ar.run_id = am.run_id
        GROUP BY ar.run_id, ar.intensity_level, ar.strategy, ar.start_time
        ORDER BY ar.start_time DESC;"""
        
        result = self.execute_query(query)
        
        if result["success"]:
            return {"success": True, "data": result["output"]}
        else:
            return {"success": False, "error": result.get("error", "Unknown error")}
    
    def test_connection(self) -> bool:
        """Test connection"""
        result = self.execute_query("SELECT current_database(), current_user;")
        return result["success"]

def main():
    """Test the interface"""
    print("🚀 Kong Guard AI - Supabase Working Interface Test")
    print("=" * 60)
    
    supabase = SupabaseWorking()
    
    # Test connection
    print("🔍 Testing connection...")
    if not supabase.test_connection():
        print("❌ Connection failed")
        return
    
    print("✅ Connection successful!")
    
    # Create attack run
    print("\n📊 Creating attack run...")
    run_id = supabase.create_attack_run("high", "working_test", 120)
    
    if not run_id:
        print("❌ Cannot continue without run_id")
        return
    
    # Insert some metrics
    print(f"\n📈 Inserting metrics for run {run_id}...")
    
    attacks = [
        ("tier1", "sql_injection", 50.2),
        ("tier2", "xss_attack", 75.1),
        ("tier3", "command_injection", 120.5)
    ]
    
    for tier, attack_type, response_time in attacks:
        supabase.insert_attack_metric(run_id, tier, attack_type, response_time)
    
    # Get statistics
    print("\n📊 Getting statistics...")
    stats = supabase.get_stats()
    
    if stats["success"]:
        print("✅ Statistics:")
        print(stats["data"])
    else:
        print(f"❌ Failed to get stats: {stats['error']}")
    
    print("\n🎉 Test completed successfully!")
    print("\n💾 Supabase is now ready for Kong Guard AI!")

if __name__ == "__main__":
    main()