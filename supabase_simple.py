#!/usr/bin/env python3
"""
Kong Guard AI - Simple Supabase Interface
Works via SSH connection to remote Supabase instance
"""

import subprocess
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SupabaseSimple:
    """Simple Supabase interface using SSH commands"""
    
    def __init__(self, host: str = "192.168.0.201", container: str = "122"):
        self.host = host
        self.container = container
        self.user = "supabase_admin"
        self.database = "postgres"
        self.schema = "kongguard"
    
    def _execute_sql(self, sql: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute SQL command via SSH and return result"""
        try:
            cmd = f"ssh root@{self.host} 'pct exec {self.container} -- docker exec supabase-db psql -U {self.user} -d {self.database} -c \"{sql}\"'"
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout if result.returncode == 0 else result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "Command timed out",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "output": str(e),
                "returncode": -2
            }
    
    def create_attack_run(self, intensity: str, strategy: str, duration: int, config: Dict = None) -> Optional[int]:
        """Create a new attack run and return run_id"""
        # Skip JSON config for now to keep it simple
        sql = f"""
        INSERT INTO {self.schema}.attack_runs (intensity_level, strategy, duration)
        VALUES ('{intensity}', '{strategy}', {duration})
        RETURNING run_id;
        """
        
        result = self._execute_sql(sql)
        
        if result["success"] and "RETURNING" in result["output"]:
            try:
                # Extract run_id from output
                lines = result["output"].strip().split('\n')
                for line in lines:
                    if line.strip().isdigit():
                        return int(line.strip())
            except (ValueError, IndexError):
                logger.error(f"Failed to parse run_id from: {result['output']}")
        else:
            logger.error(f"Failed to create attack run: {result['output']}")
        
        return None
    
    def insert_attack_metrics(self, metrics: List[Dict[str, Any]]) -> bool:
        """Insert attack metrics in batches"""
        if not metrics:
            return True
        
        try:
            # Build INSERT statement
            values_list = []
            for metric in metrics:
                # Escape string values
                values = []
                for key in ['id', 'run_id', 'timestamp', 'tier', 'attack_type', 'attack_category', 
                           'payload', 'response_time_ms', 'threat_score', 'confidence', 
                           'action_taken', 'blocked', 'status_code', 'source_ip', 'user_agent', 'error_message']:
                    value = metric.get(key)
                    if value is None:
                        values.append("NULL")
                    elif isinstance(value, str):
                        escaped = value.replace("'", "''").replace("\\", "\\\\")
                        values.append(f"'{escaped}'")
                    elif isinstance(value, bool):
                        values.append("true" if value else "false")
                    else:
                        values.append(str(value))
                
                values_list.append(f"({', '.join(values)})")
            
            sql = f"""
            INSERT INTO {self.schema}.attack_metrics 
            (id, run_id, timestamp, tier, attack_type, attack_category, payload, 
             response_time_ms, threat_score, confidence, action_taken, blocked, 
             status_code, source_ip, user_agent, error_message)
            VALUES {', '.join(values_list[:10])}
            ON CONFLICT (id) DO NOTHING;
            """
            
            result = self._execute_sql(sql)
            
            if result["success"]:
                logger.info(f"✅ Inserted {min(10, len(metrics))} attack metrics")
                return True
            else:
                logger.error(f"❌ Failed to insert metrics: {result['output']}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error inserting metrics: {e}")
            return False
    
    def get_attack_run_stats(self, run_id: Optional[int] = None) -> Dict[str, Any]:
        """Get statistics for attack runs"""
        where_clause = f"WHERE ar.run_id = {run_id}" if run_id else ""
        
        sql = f"""
        SELECT 
            ar.run_id,
            ar.intensity_level,
            ar.strategy,
            ar.start_time,
            ar.duration,
            COUNT(am.id) as total_metrics,
            COUNT(CASE WHEN am.blocked = true THEN 1 END) as blocked_count,
            AVG(am.response_time_ms) as avg_response_time,
            AVG(am.threat_score) as avg_threat_score
        FROM {self.schema}.attack_runs ar
        LEFT JOIN {self.schema}.attack_metrics am ON ar.run_id = am.run_id
        {where_clause}
        GROUP BY ar.run_id, ar.intensity_level, ar.strategy, ar.start_time, ar.duration
        ORDER BY ar.start_time DESC;
        """
        
        result = self._execute_sql(sql)
        
        if result["success"]:
            return {"success": True, "data": result["output"]}
        else:
            return {"success": False, "error": result["output"]}
    
    def test_connection(self) -> bool:
        """Test connection to Supabase"""
        sql = "SELECT current_database(), current_user, version();"
        result = self._execute_sql(sql)
        
        if result["success"]:
            logger.info(f"✅ Connection successful: {result['output'][:100]}...")
            return True
        else:
            logger.error(f"❌ Connection failed: {result['output']}")
            return False

def main():
    """Test the Supabase interface"""
    print("🚀 Testing Kong Guard AI Supabase Interface")
    print("=" * 50)
    
    # Initialize Supabase interface
    supabase = SupabaseSimple()
    
    # Test connection
    print("🔍 Testing connection...")
    if not supabase.test_connection():
        print("❌ Connection test failed")
        return
    
    print("✅ Connection successful!")
    
    # Test creating attack run
    print("\n📊 Creating test attack run...")
    run_id = supabase.create_attack_run(
        intensity="medium",
        strategy="supabase_test", 
        duration=60,
        config={"test": True, "timestamp": datetime.now().isoformat()}
    )
    
    if run_id:
        print(f"✅ Created attack run: {run_id}")
    else:
        print("❌ Failed to create attack run")
        return
    
    # Test inserting metrics
    print("\n📈 Inserting test metrics...")
    test_metrics = [
        {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "tier": "test_tier",
            "attack_type": "test_attack",
            "attack_category": "test_category",
            "payload": "test payload",
            "response_time_ms": 100.5,
            "threat_score": 0.8,
            "confidence": 0.9,
            "action_taken": "block",
            "blocked": True,
            "status_code": 403,
            "source_ip": "127.0.0.1",
            "user_agent": "test-agent",
            "error_message": None
        }
    ]
    
    if supabase.insert_attack_metrics(test_metrics):
        print("✅ Test metrics inserted successfully")
    else:
        print("❌ Failed to insert test metrics")
    
    # Get stats
    print("\n📊 Getting attack run statistics...")
    stats = supabase.get_attack_run_stats()
    
    if stats["success"]:
        print("✅ Statistics retrieved:")
        print(stats["data"])
    else:
        print(f"❌ Failed to get stats: {stats['error']}")
    
    print("\n🎉 Interface test completed!")

if __name__ == "__main__":
    main()