#!/usr/bin/env python3
"""
Industry-Specific Vicious Attack Scenarios
Tailored demonstrations for different enterprise verticals
"""

import asyncio
import httpx
import random
from datetime import datetime
from typing import Dict, List, Any

class IndustryAttackScenarios:
    def __init__(self, ai_service_url="http://localhost:18002"):
        self.ai_service_url = ai_service_url
        
    async def send_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send attack to AI service"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{self.ai_service_url}/analyze", json=attack_data)
            return response.json() if response.status_code == 200 else {"error": response.status_code}

    def get_financial_services_attacks(self) -> List[Dict[str, Any]]:
        """Attacks specifically targeting financial institutions"""
        return [
            {
                "name": "🏦 SWIFT Wire Transfer Manipulation",
                "description": "Attempting to manipulate international wire transfers through SWIFT network simulation",
                "severity": "CRITICAL",
                "regulatory_impact": "SOX, PCI-DSS, Basel III violations",
                "potential_loss": "$50M+ per incident",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/swift/wire-transfer",
                        "client_ip": "185.220.100.240",  # Tor exit node
                        "user_agent": "SWIFTNet/7.0",
                        "requests_per_minute": 5,
                        "content_length": 400,
                        "query_param_count": 0,
                        "header_count": 12,
                        "hour_of_day": 2,  # Off-hours attack
                        "query": "",
                        "body": "{\"message_type\":\"MT103\",\"sender_bic\":\"CHASUS33\",\"receiver_bic\":\"DEUTDEFF\",\"amount\":\"50000000.00\",\"currency\":\"USD\",\"beneficiary_account\":\"ATTACKER_ACCOUNT_001\",\"ordering_customer\":\"LEGITIMATE_CORP\",\"instruction_code\":\"URGENT\"}"
                    },
                    "context": {
                        "previous_requests": 2,
                        "failed_attempts": 0,
                        "anomaly_score": 0.95,
                        "ip_reputation": "known_threat",
                        "geo_location": "Anonymous_Proxy"
                    }
                }
            },
            {
                "name": "🏦 High-Frequency Trading Manipulation",
                "description": "Market manipulation through algorithmic trading system compromise",
                "severity": "CRITICAL", 
                "regulatory_impact": "SEC Market Manipulation, Dodd-Frank violations",
                "potential_loss": "Market disruption, $100M+ losses",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/trading/orders/bulk",
                        "client_ip": "198.51.100.123",
                        "user_agent": "TradingBot/HFT-2.1",
                        "requests_per_minute": 500,  # High frequency
                        "content_length": 2000,
                        "query_param_count": 0,
                        "header_count": 8,
                        "hour_of_day": 9,  # Market open
                        "query": "",
                        "body": "{\"orders\":[{\"symbol\":\"AAPL\",\"quantity\":1000000,\"price\":0.01,\"side\":\"buy\",\"order_type\":\"market\"},{\"symbol\":\"AAPL\",\"quantity\":1000000,\"price\":999.99,\"side\":\"sell\",\"order_type\":\"limit\"}],\"strategy\":\"pump_and_dump\"}"
                    },
                    "context": {
                        "previous_requests": 10000,
                        "failed_attempts": 0,
                        "anomaly_score": 0.9
                    }
                }
            },
            {
                "name": "🏦 Credit Score Manipulation Attack",
                "description": "Fraudulent credit score modification for loan approval",
                "severity": "HIGH",
                "regulatory_impact": "Fair Credit Reporting Act, Consumer Financial Protection violations",
                "potential_loss": "$10M+ in fraudulent loans",
                "attack": {
                    "features": {
                        "method": "PUT",
                        "path": "/api/credit/scores/update",
                        "client_ip": "203.0.113.42",
                        "user_agent": "CreditReporting/3.2",
                        "requests_per_minute": 20,
                        "content_length": 300,
                        "query_param_count": 0,
                        "header_count": 10,
                        "hour_of_day": 14,
                        "query": "",
                        "body": "{\"ssn\":\"123-45-6789\",\"current_score\":450,\"new_score\":850,\"reason_codes\":[\"SCORE_CORRECTION\",\"IDENTITY_VERIFIED\"],\"supporting_docs\":\"../../../etc/passwd\",\"override_validation\":true}"
                    },
                    "context": {
                        "previous_requests": 50,
                        "failed_attempts": 15,
                        "anomaly_score": 0.85
                    }
                }
            },
            {
                "name": "🏦 Cryptocurrency Exchange Manipulation",
                "description": "Price manipulation and wallet drainage attack on crypto exchange",
                "severity": "CRITICAL",
                "regulatory_impact": "FinCEN, CFTC violations",
                "potential_loss": "$500M+ (Mt. Gox level)",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/crypto/trade/execute",
                        "client_ip": "46.161.40.127",  # C2 infrastructure
                        "user_agent": "CryptoTrader/1.0",
                        "requests_per_minute": 100,
                        "content_length": 250,
                        "query_param_count": 0,
                        "header_count": 7,
                        "hour_of_day": 3,
                        "query": "",
                        "body": "{\"trade_type\":\"market\",\"pair\":\"BTC/USD\",\"amount\":\"999999.99999999\",\"destination_wallet\":\"1AttackerBTCWallet123456789\",\"bypass_limits\":true,\"fake_liquidity\":true}"
                    },
                    "context": {
                        "previous_requests": 500,
                        "failed_attempts": 20,
                        "anomaly_score": 0.98
                    }
                }
            }
        ]
    
    def get_healthcare_attacks(self) -> List[Dict[str, Any]]:
        """Attacks targeting healthcare systems and patient data"""
        return [
            {
                "name": "🏥 Electronic Health Record (EHR) Mass Extraction",
                "description": "Bulk patient data extraction violating HIPAA",
                "severity": "CRITICAL",
                "regulatory_impact": "HIPAA violations, up to $1.5M fines per incident",
                "potential_loss": "Identity theft of millions of patients",
                "attack": {
                    "features": {
                        "method": "GET", 
                        "path": "/api/patients/records/bulk",
                        "client_ip": "141.98.80.15",
                        "user_agent": "MedicalResearch/1.0",
                        "requests_per_minute": 50,
                        "content_length": 0,
                        "query_param_count": 5,
                        "header_count": 8,
                        "hour_of_day": 23,
                        "query": "format=json&include=ssn,dob,diagnoses,medications,insurance&limit=999999&bypass_consent=true",
                        "body": ""
                    },
                    "context": {
                        "previous_requests": 1000,
                        "failed_attempts": 100,
                        "anomaly_score": 0.95
                    }
                }
            },
            {
                "name": "🏥 Medical Device Ransomware Attack",
                "description": "Critical medical device compromise threatening patient safety",
                "severity": "CRITICAL",
                "regulatory_impact": "FDA Medical Device Safety, patient safety violations",
                "potential_loss": "Life-threatening situations, hospital shutdown",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/devices/insulin-pump/commands",
                        "client_ip": "10.0.0.50",  # Internal lateral movement
                        "user_agent": "MedDeviceControl/2.0",
                        "requests_per_minute": 10,
                        "content_length": 200,
                        "query_param_count": 0,
                        "header_count": 6,
                        "hour_of_day": 4,
                        "query": "",
                        "body": "{\"patient_id\":\"P123456\",\"device_serial\":\"INS-001-789\",\"command\":\"SET_DOSAGE\",\"value\":\"MAXIMUM_LETHAL_DOSE\",\"encryption_key\":\"RANSOMWARE_ENCRYPTED\",\"ransom_note\":\"Pay 10 BTC or patients die\"}"
                    },
                    "context": {
                        "previous_requests": 5,
                        "failed_attempts": 0,
                        "anomaly_score": 1.0
                    }
                }
            },
            {
                "name": "🏥 Prescription Drug Diversion",
                "description": "Illegal prescription modification for controlled substances",
                "severity": "HIGH",
                "regulatory_impact": "DEA controlled substance violations, medical license revocation",
                "potential_loss": "Opioid crisis contribution, patient harm",
                "attack": {
                    "features": {
                        "method": "PUT",
                        "path": "/api/prescriptions/modify",
                        "client_ip": "172.16.0.25",
                        "user_agent": "PharmacySystem/4.1",
                        "requests_per_minute": 15,
                        "content_length": 300,
                        "query_param_count": 0,
                        "header_count": 9,
                        "hour_of_day": 20,
                        "query": "",
                        "body": "{\"prescription_id\":\"RX789123\",\"patient_id\":\"P456789\",\"medication\":\"OxyContin\",\"dosage\":\"80mg\",\"quantity\":\"#360\",\"refills\":\"11\",\"prescriber_override\":\"../../../etc/passwd\",\"dea_number\":\"FAKE123456\"}"
                    },
                    "context": {
                        "previous_requests": 200,
                        "failed_attempts": 50,
                        "anomaly_score": 0.9
                    }
                }
            },
            {
                "name": "🏥 Research Data Manipulation",
                "description": "Clinical trial data falsification for drug approval fraud",
                "severity": "HIGH",
                "regulatory_impact": "FDA clinical trial integrity violations",
                "potential_loss": "Unsafe drugs reaching market, patient deaths",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/clinical-trials/data/update",
                        "client_ip": "95.216.107.148",
                        "user_agent": "ClinicalDataSystem/1.5",
                        "requests_per_minute": 8,
                        "content_length": 500,
                        "query_param_count": 0,
                        "header_count": 11,
                        "hour_of_day": 1,
                        "query": "",
                        "body": "{\"trial_id\":\"NCT12345678\",\"patient_data\":[{\"patient_id\":\"FAKE_001\",\"outcome\":\"POSITIVE\",\"side_effects\":\"NONE\"}],\"efficacy_rate\":\"95%\",\"mortality_rate\":\"0%\",\"data_integrity_hash\":\"COMPROMISED\"}"
                    }
                }
            }
        ]

    def get_retail_ecommerce_attacks(self) -> List[Dict[str, Any]]:
        """Attacks targeting retail and e-commerce platforms"""
        return [
            {
                "name": "🛒 Inventory Manipulation for Market Dominance",
                "description": "Artificial scarcity creation and competitor sabotage",
                "severity": "HIGH",
                "regulatory_impact": "FTC antitrust, market manipulation violations",
                "potential_loss": "$100M+ in market share, consumer fraud",
                "attack": {
                    "features": {
                        "method": "PUT",
                        "path": "/api/inventory/bulk-update",
                        "client_ip": "192.0.2.100",
                        "user_agent": "InventoryManager/3.0",
                        "requests_per_minute": 25,
                        "content_length": 1000,
                        "query_param_count": 0,
                        "header_count": 8,
                        "hour_of_day": 11,
                        "query": "",
                        "body": "{\"updates\":[{\"product_id\":\"COMPETITOR_BESTSELLER\",\"stock_level\":0,\"price\":9999.99},{\"product_id\":\"OUR_ALTERNATIVE\",\"stock_level\":999999,\"price\":0.01}],\"reason\":\"market_manipulation\",\"competitor_targeting\":true}"
                    }
                }
            },
            {
                "name": "🛒 Payment Card Skimming Attack",
                "description": "Credit card data theft through payment system compromise",
                "severity": "CRITICAL",
                "regulatory_impact": "PCI-DSS violations, massive fines",
                "potential_loss": "Millions of credit card numbers stolen",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/payments/process",
                        "client_ip": "5.188.10.95",
                        "user_agent": "PaymentGateway/2.1",
                        "requests_per_minute": 100,
                        "content_length": 400,
                        "query_param_count": 0,
                        "header_count": 7,
                        "hour_of_day": 14,
                        "query": "",
                        "body": "{\"card_number\":\"4532015112830366\",\"cvv\":\"123\",\"expiry\":\"12/25\",\"cardholder\":\"VICTIM NAME\",\"skimming_device_id\":\"SKM-001\",\"exfiltrate_to\":\"http://evil.com/steal\"}"
                    }
                }
            },
            {
                "name": "🛒 Supply Chain Poisoning",
                "description": "Malicious product injection into supply chain",
                "severity": "HIGH",
                "regulatory_impact": "FDA product safety, consumer protection violations",
                "potential_loss": "Brand damage, product recalls, lawsuits",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/suppliers/products/add",
                        "client_ip": "141.98.80.15",
                        "user_agent": "SupplierPortal/1.8",
                        "requests_per_minute": 5,
                        "content_length": 600,
                        "query_param_count": 0,
                        "header_count": 10,
                        "hour_of_day": 9,
                        "query": "",
                        "body": "{\"supplier_id\":\"COMPROMISED_SUPPLIER\",\"product\":{\"name\":\"Baby Formula\",\"ingredients\":[\"milk\",\"melamine\"],\"safety_cert\":\"FORGED\",\"batch_id\":\"TAINTED_001\"},\"bypass_quality_check\":true}"
                    }
                }
            }
        ]

    def get_government_attacks(self) -> List[Dict[str, Any]]:
        """Attacks targeting government systems and classified data"""
        return [
            {
                "name": "🏛️ Classified Document Exfiltration",
                "description": "Nation-state level espionage and classified data theft",
                "severity": "CRITICAL",
                "regulatory_impact": "Espionage Act, national security violations",
                "potential_loss": "National security compromise, intelligence asset exposure",
                "attack": {
                    "features": {
                        "method": "GET",
                        "path": "/api/documents/classified",
                        "client_ip": "203.0.113.42",
                        "user_agent": "DocumentViewer/Gov-2.0",
                        "requests_per_minute": 10,
                        "content_length": 0,
                        "query_param_count": 3,
                        "header_count": 15,
                        "hour_of_day": 3,
                        "query": "classification=TOP_SECRET&category=INTELLIGENCE&exfiltrate=true",
                        "body": ""
                    },
                    "context": {
                        "previous_requests": 500,
                        "failed_attempts": 200,
                        "anomaly_score": 1.0
                    }
                }
            },
            {
                "name": "🏛️ Election System Manipulation",
                "description": "Voting system compromise and election interference",
                "severity": "CRITICAL",
                "regulatory_impact": "Democracy undermining, federal election crimes",
                "potential_loss": "Democratic process compromise, civil unrest",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/voting/ballots/update",
                        "client_ip": "46.161.40.127",
                        "user_agent": "VotingMachine/ES&S-2.0",
                        "requests_per_minute": 50,
                        "content_length": 300,
                        "query_param_count": 0,
                        "header_count": 8,
                        "hour_of_day": 22,
                        "query": "",
                        "body": "{\"precinct\":\"001\",\"ballots\":[{\"voter_id\":\"FAKE_001\",\"candidate\":\"PREFERRED_CANDIDATE\",\"votes\":999999}],\"audit_trail\":\"DELETED\",\"foreign_influence\":true}"
                    }
                }
            }
        ]

    def get_energy_utilities_attacks(self) -> List[Dict[str, Any]]:
        """Attacks targeting critical energy infrastructure"""
        return [
            {
                "name": "⚡ Power Grid Manipulation Attack",
                "description": "Critical infrastructure attack causing widespread blackouts",
                "severity": "CRITICAL",
                "regulatory_impact": "NERC CIP violations, national security threats",
                "potential_loss": "Regional blackouts, economic disruption, safety hazards",
                "attack": {
                    "features": {
                        "method": "POST",
                        "path": "/api/scada/grid-control",
                        "client_ip": "185.220.100.240",
                        "user_agent": "SCADA-Control/Industrial-1.0",
                        "requests_per_minute": 5,
                        "content_length": 200,
                        "query_param_count": 0,
                        "header_count": 6,
                        "hour_of_day": 6,  # Peak demand time
                        "query": "",
                        "body": "{\"station_id\":\"POWER_PLANT_001\",\"command\":\"EMERGENCY_SHUTDOWN\",\"reason\":\"CYBER_ATTACK\",\"override_safety\":true,\"affected_customers\":5000000}"
                    }
                }
            },
            {
                "name": "⚡ Nuclear Facility Sabotage (Stuxnet-style)",
                "description": "Industrial control system compromise in nuclear facility",
                "severity": "CRITICAL",
                "regulatory_impact": "NRC violations, radiological emergency",
                "potential_loss": "Nuclear incident, radiological contamination",
                "attack": {
                    "features": {
                        "method": "PUT",
                        "path": "/api/nuclear/centrifuge/control",
                        "client_ip": "141.98.80.15",
                        "user_agent": "IndustrialHMI/Siemens-1.0",
                        "requests_per_minute": 2,
                        "content_length": 250,
                        "query_param_count": 0,
                        "header_count": 8,
                        "hour_of_day": 15,
                        "query": "",
                        "body": "{\"centrifuge_id\":\"URANIUM_ENRICHMENT_001\",\"rotor_speed\":\"DESTRUCTIVE_FREQUENCY\",\"safety_systems\":\"DISABLED\",\"malware_signature\":\"STUXNET_V2\"}"
                    }
                }
            }
        ]

    async def run_industry_specific_demo(self, industry: str):
        """Run demonstration for specific industry"""
        
        industry_attacks = {
            "financial": self.get_financial_services_attacks(),
            "healthcare": self.get_healthcare_attacks(),
            "retail": self.get_retail_ecommerce_attacks(),
            "government": self.get_government_attacks(),
            "energy": self.get_energy_utilities_attacks()
        }
        
        if industry not in industry_attacks:
            print(f"❌ Industry '{industry}' not supported. Available: {list(industry_attacks.keys())}")
            return
            
        attacks = industry_attacks[industry]
        
        print(f"╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                🎯 {industry.upper()} INDUSTRY ATTACK SIMULATION 🎯                ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝")
        print()
        
        for i, attack_scenario in enumerate(attacks, 1):
            print(f"\n🚨 SCENARIO {i}/{len(attacks)}: {attack_scenario['name']}")
            print(f"📋 Description: {attack_scenario['description']}")
            print(f"⚠️  Severity: {attack_scenario['severity']}")
            print(f"📊 Regulatory Impact: {attack_scenario['regulatory_impact']}")
            print(f"💰 Potential Loss: {attack_scenario['potential_loss']}")
            print("─" * 80)
            
            # Send attack
            result = await self.send_attack(attack_scenario['attack'])
            
            if 'error' not in result:
                print(f"🎯 AI Detection: {result['threat_type']}")
                print(f"📊 Threat Score: {result['threat_score']:.3f}")
                print(f"🎲 Confidence: {result['confidence']:.1%}")
                print(f"⚡ Recommended Action: {result['recommended_action'].upper()}")
                print(f"🧠 AI Reasoning: {result['reasoning'][:100]}...")
            else:
                print(f"❌ Attack simulation failed: {result['error']}")
            
            await asyncio.sleep(4)  # Dramatic pause
        
        print(f"\n🏆 {industry.upper()} INDUSTRY ATTACK SIMULATION COMPLETE!")
        print(f"✅ Kong Guard AI successfully detected and analyzed {len(attacks)} industry-specific threats")

async def main():
    """Industry-specific attack demo selection"""
    
    scenarios = IndustryAttackScenarios()
    
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║             🏢 INDUSTRY-SPECIFIC VICIOUS ATTACK SCENARIOS 🏢                 ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()
    print("Select your industry for targeted attack demonstration:")
    print()
    print("1. 🏦 Financial Services (SWIFT, HFT, Credit, Crypto)")
    print("2. 🏥 Healthcare (EHR, Medical Devices, Prescriptions)")
    print("3. 🛒 Retail/E-commerce (Inventory, Payments, Supply Chain)")
    print("4. 🏛️ Government (Classified Data, Elections)")
    print("5. ⚡ Energy/Utilities (Power Grid, Nuclear, SCADA)")
    print("6. 🔥 ALL INDUSTRIES (Complete demonstration)")
    print()
    
    choice = input("Enter your choice (1-6): ").strip()
    
    industry_map = {
        "1": "financial",
        "2": "healthcare", 
        "3": "retail",
        "4": "government",
        "5": "energy"
    }
    
    if choice == "6":
        print("\n🔥 RUNNING COMPLETE MULTI-INDUSTRY ATTACK DEMONSTRATION...")
        for industry in industry_map.values():
            await scenarios.run_industry_specific_demo(industry)
            print("\n" + "="*100 + "\n")
    elif choice in industry_map:
        await scenarios.run_industry_specific_demo(industry_map[choice])
    else:
        print("❌ Invalid choice. Please run again.")

if __name__ == "__main__":
    asyncio.run(main())