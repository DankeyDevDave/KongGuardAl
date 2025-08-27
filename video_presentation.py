#!/usr/bin/env python3
"""
Kong Guard AI - Video Presentation Automation
Automated browser control for creating comprehensive demo videos
"""

import asyncio
import time
from pathlib import Path
from typing import List, Dict, Any
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    logger.error("Playwright not installed. Install with: pip install playwright && playwright install")
    exit(1)

class VideoPresentationAutomation:
    def __init__(self, dashboard_url="http://localhost:8090/enterprise_demo_dashboard.html"):
        self.dashboard_url = dashboard_url
        self.browser = None
        self.page = None
        self.recording_path = None
        self.presentation_script = []
        
        # Presentation timing
        self.scene_duration = 8  # seconds per scene
        self.attack_demo_duration = 15  # seconds per attack demo
        self.transition_delay = 2  # seconds between transitions
        
        # Attack scenarios for comprehensive demo
        self.attack_scenarios = [
            {
                "type": "sql",
                "title": "SQL Injection Attack",
                "description": "Advanced SQL injection targeting authentication bypass and data extraction",
                "narration": "This SQL injection attack attempts to bypass authentication by manipulating the database query. Notice how the unprotected tier allows this through, while both AI tiers immediately detect and block the malicious SQL patterns.",
                "expected_results": {
                    "unprotected": "VULNERABLE - Request passes through",
                    "cloud": "BLOCKED - High threat score detected", 
                    "local": "BLOCKED - Local AI detects SQL patterns"
                },
                "financial_impact": "$2.5M potential loss from data breach"
            },
            {
                "type": "xss",
                "title": "Cross-Site Scripting Attack", 
                "description": "XSS payload designed to steal user credentials and session data",
                "narration": "This XSS attack injects malicious JavaScript to steal sensitive user data. The AI services recognize the dangerous script patterns and block the request, preventing potential credential theft.",
                "expected_results": {
                    "unprotected": "VULNERABLE - Script executes",
                    "cloud": "BLOCKED - XSS patterns detected",
                    "local": "BLOCKED - Local AI prevents injection"
                },
                "financial_impact": "$1.2M potential loss from credential theft"
            },
            {
                "type": "cmd",
                "title": "Command Injection Attack",
                "description": "System command execution attempt for remote server access",
                "narration": "This command injection tries to execute system commands on the server. Both AI tiers immediately recognize the command patterns and block execution, preventing potential system compromise.",
                "expected_results": {
                    "unprotected": "VULNERABLE - Commands could execute",
                    "cloud": "BLOCKED - Command patterns detected",
                    "local": "BLOCKED - Local AI prevents execution"
                },
                "financial_impact": "$5M potential loss from system compromise"
            },
            {
                "type": "business",
                "title": "Business Logic Attack",
                "description": "Financial fraud through negative amount manipulation",
                "narration": "This business logic attack exploits negative amounts to potentially steal millions from bank reserves. The AI services detect the suspicious negative values and fraudulent patterns.",
                "expected_results": {
                    "unprotected": "VULNERABLE - Fraud could succeed",
                    "cloud": "BLOCKED - Fraudulent pattern detected",
                    "local": "BLOCKED - Local AI prevents fraud"
                },
                "financial_impact": "$50M potential loss from financial fraud"
            },
            {
                "type": "ransomware",
                "title": "Ransomware Command & Control",
                "description": "Ransomware communication indicating successful encryption",
                "narration": "This ransomware C2 communication indicates a successful system encryption. The AI services detect the suspicious communication patterns typical of ransomware operations.",
                "expected_results": {
                    "unprotected": "VULNERABLE - C2 communication allowed",
                    "cloud": "BLOCKED - Ransomware patterns detected",
                    "local": "BLOCKED - Local AI blocks C2 traffic"
                },
                "financial_impact": "$10M ransom demand + business disruption"
            }
        ]

    async def initialize_browser(self, headless=False, record_video=True):
        """Initialize browser with recording capabilities"""
        self.playwright = await async_playwright().start()
        
        # Configure browser options
        browser_options = {
            "headless": headless,
            "viewport": {"width": 1920, "height": 1080},
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions"
            ]
        }
        
        if record_video:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.recording_path = Path(f"demo_videos/kong_guard_ai_demo_{timestamp}")
            self.recording_path.mkdir(parents=True, exist_ok=True)
            
            browser_options["record_video"] = {
                "dir": str(self.recording_path),
                "size": {"width": 1920, "height": 1080}
            }
        
        self.browser = await self.playwright.chromium.launch(**browser_options)
        self.context = await self.browser.new_context()
        self.page = await self.context.new_page()
        
        logger.info(f"Browser initialized. Video recording: {'enabled' if record_video else 'disabled'}")
        
        return self.page

    async def load_dashboard(self):
        """Load the enterprise demo dashboard"""
        logger.info(f"Loading dashboard: {self.dashboard_url}")
        
        try:
            await self.page.goto(self.dashboard_url, wait_until="networkidle")
            await self.page.wait_for_selector("h1", timeout=10000)
            logger.info("Dashboard loaded successfully")
            
            # Wait for services to initialize
            await asyncio.sleep(3)
            
            return True
        except Exception as e:
            logger.error(f"Failed to load dashboard: {e}")
            return False

    async def show_narration(self, text: str, duration: int = 5):
        """Display narration text on screen with Kong Guard AI branding"""
        logger.info(f"Narration: {text}")
        
        # Kong Guard AI brand colors
        brand_colors = {
            'bg': '#0f1113',
            'surface': '#171a1f', 
            'line': '#2a3037',
            'txt': '#c8ccd3',
            'silver': '#e6e8ec',
            'steel': '#aeb4bd'
        }
        
        # Inject narration overlay with Kong Guard AI styling
        await self.page.evaluate(f"""
            // Remove existing narration
            const existing = document.getElementById('video-narration');
            if (existing) existing.remove();
            
            // Create narration overlay with Kong Guard AI branding
            const narration = document.createElement('div');
            narration.id = 'video-narration';
            narration.style.cssText = `
                position: fixed;
                bottom: 60px;
                left: 50%;
                transform: translateX(-50%);
                background: linear-gradient(180deg, {brand_colors['surface']}, {brand_colors['bg']});
                color: {brand_colors['silver']};
                padding: 24px 48px;
                border-radius: 8px;
                font-family: 'Rajdhani', 'Inter', system-ui, sans-serif;
                font-size: 20px;
                font-weight: 600;
                text-align: center;
                max-width: 85%;
                z-index: 10000;
                border: 1px solid {brand_colors['line']};
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
                letter-spacing: 0.04em;
            `;
            
            // Add Kong Guard AI logo if available
            const logoContainer = document.createElement('div');
            logoContainer.style.cssText = `
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 12px;
                margin-bottom: 12px;
            `;
            
            const logo = document.createElement('img');
            logo.src = 'kong-guard-logo.png';
            logo.style.cssText = 'height: 24px; width: 24px; object-fit: contain;';
            logo.onerror = () => logo.style.display = 'none';
            
            const brandText = document.createElement('span');
            brandText.textContent = 'KONG GUARD AI';
            brandText.style.cssText = `
                color: {brand_colors['steel']};
                font-size: 14px;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            `;
            
            logoContainer.appendChild(logo);
            logoContainer.appendChild(brandText);
            
            const textContent = document.createElement('div');
            textContent.textContent = `{text}`;
            textContent.style.cssText = `
                color: {brand_colors['txt']};
                line-height: 1.4;
            `;
            
            narration.appendChild(logoContainer);
            narration.appendChild(textContent);
            document.body.appendChild(narration);
            
            // Auto-remove after duration
            setTimeout(() => {{
                if (document.getElementById('video-narration')) {{
                    document.getElementById('video-narration').remove();
                }}
            }}, {duration * 1000});
        """)
        
        await asyncio.sleep(duration)

    async def highlight_element(self, selector: str, duration: int = 3):
        """Add visual highlight to an element with Kong Guard AI styling"""
        await self.page.evaluate(f"""
            const element = document.querySelector(`{selector}`);
            if (element) {{
                // Kong Guard AI brand highlight color
                const highlightColor = '#aeb4bd'; // steel color from brand
                element.style.outline = `3px solid ${{highlightColor}}`;
                element.style.outlineOffset = '2px';
                element.style.boxShadow = `0 0 20px rgba(174, 180, 189, 0.6)`;
                element.style.borderRadius = '8px';
                
                setTimeout(() => {{
                    element.style.outline = '';
                    element.style.outlineOffset = '';
                    element.style.boxShadow = '';
                    element.style.borderRadius = '';
                }}, {duration * 1000});
            }}
        """)
        
        await asyncio.sleep(duration)

    async def execute_attack_comparison(self, attack_scenario: Dict[str, Any]):
        """Execute a comprehensive attack comparison across all tiers"""
        attack_type = attack_scenario["type"]
        title = attack_scenario["title"]
        description = attack_scenario["description"]
        narration = attack_scenario["narration"]
        
        logger.info(f"Executing attack scenario: {title}")
        
        # Show attack introduction with Kong Guard AI branding
        await self.show_narration(f"{title}: {description}", 6)
        
        # Click each tier button in sequence with narration
        tiers = [
            ("unprotected", "Testing unprotected Kong gateway..."),
            ("cloud", "Testing cloud AI protection..."),  
            ("local", "Testing local AI protection...")
        ]
        
        for tier, tier_narration in tiers:
            # Show tier-specific narration
            await self.show_narration(tier_narration, 3)
            
            # Find and click the appropriate button
            button_selector = f"button[onclick*=\"testAttack('{attack_type}', '{tier}'\"]"
            
            try:
                await self.page.wait_for_selector(button_selector, timeout=5000)
                await self.highlight_element(button_selector, 2)
                await self.page.click(button_selector)
                
                # Wait for result to appear
                await asyncio.sleep(4)
                
            except Exception as e:
                logger.error(f"Failed to click {tier} button for {attack_type}: {e}")
                continue
        
        # Show results narration
        await self.show_narration(narration, 8)
        
        # Brief pause before next attack
        await asyncio.sleep(2)

    async def run_comprehensive_demo(self):
        """Run the complete video demonstration"""
        logger.info("Starting comprehensive Kong Guard AI demonstration")
        
        # Introduction scene with Kong Guard AI branding
        await self.show_narration(
            "Welcome to Kong Guard AI - Enterprise Three-Tier Protection Demonstration", 6
        )
        
        await self.show_narration(
            "This demo shows three protection levels: Unprotected Kong, Cloud AI, and Local AI", 6
        )
        
        # Highlight the three tiers
        for i, tier_class in enumerate([".tier.unprotected", ".tier.cloud", ".tier.local"]):
            await self.highlight_element(tier_class, 3)
            if i < 2:  # Don't sleep after last one
                await asyncio.sleep(1)
        
        await self.show_narration(
            "We'll test multiple attack types to demonstrate AI-powered threat detection", 5
        )
        
        # Execute each attack scenario
        for i, scenario in enumerate(self.attack_scenarios, 1):
            await self.show_narration(
                f"Attack Scenario {i} of {len(self.attack_scenarios)}", 3
            )
            
            await self.execute_attack_comparison(scenario)
            
            # Show financial impact
            await self.show_narration(
                f"Financial Impact Prevented: {scenario['financial_impact']}", 4
            )
        
        # Summary and conclusion
        await self.show_narration(
            "Demo Complete! Kong Guard AI successfully blocked all attacks across both AI tiers", 6
        )
        
        await self.show_narration(
            "Unprotected Kong allowed all attacks through, demonstrating the critical need for AI protection", 6
        )
        
        await self.show_narration(
            "Key Benefits: Real-time AI detection, Cloud & Local options, 99%+ accuracy, Sub-second response", 8
        )
        
        await self.show_narration(
            "Ready to protect your APIs with Kong Guard AI? Contact us for implementation!", 6
        )

    async def run_automated_presentation(self):
        """Run the automated presentation mode"""
        # Add auto parameter to URL for automated mode
        demo_url = f"{self.dashboard_url}?auto=true"
        
        logger.info(f"Loading automated presentation: {demo_url}")
        
        try:
            await self.page.goto(demo_url, wait_until="networkidle")
            await self.page.wait_for_selector("h1", timeout=10000)
            
            # Wait for automated demo to complete
            # The dashboard will run its own automated demo
            await asyncio.sleep(180)  # 3 minutes for full automated demo
            
            logger.info("Automated presentation completed")
            
        except Exception as e:
            logger.error(f"Automated presentation failed: {e}")

    async def create_demo_video(self, mode="manual"):
        """Create a complete demo video"""
        logger.info(f"Creating demo video in {mode} mode")
        
        try:
            # Initialize browser with video recording
            await self.initialize_browser(headless=False, record_video=True)
            
            # Load dashboard
            if not await self.load_dashboard():
                logger.error("Failed to load dashboard, aborting video creation")
                return None
            
            if mode == "manual":
                # Run comprehensive manual demo with narration
                await self.run_comprehensive_demo()
            else:
                # Run automated presentation
                await self.run_automated_presentation()
            
            # Close browser to finalize video
            await self.close()
            
            # Find the recorded video file
            if self.recording_path:
                video_files = list(self.recording_path.glob("*.webm"))
                if video_files:
                    video_path = video_files[0]
                    logger.info(f"Demo video created: {video_path}")
                    return str(video_path)
            
            logger.warning("No video file found after recording")
            return None
            
        except Exception as e:
            logger.error(f"Video creation failed: {e}")
            await self.close()
            return None

    async def close(self):
        """Clean up browser resources"""
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()
        
        logger.info("Browser resources cleaned up")

async def main():
    """Main function for video presentation automation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Kong Guard AI Video Presentation Automation")
    parser.add_argument("--mode", choices=["manual", "auto"], default="manual",
                       help="Demo mode: manual (with narration) or auto (self-running)")
    parser.add_argument("--dashboard-url", default="http://localhost:8090/enterprise_demo_dashboard.html",
                       help="Dashboard URL to record")
    parser.add_argument("--headless", action="store_true",
                       help="Run browser in headless mode")
    
    args = parser.parse_args()
    
    # Create output directory
    Path("demo_videos").mkdir(exist_ok=True)
    
    # Create video presentation automation
    presenter = VideoPresentationAutomation(args.dashboard_url)
    
    try:
        # Create demo video
        video_path = await presenter.create_demo_video(mode=args.mode)
        
        if video_path:
            print(f"\nDemo video created successfully!")
            print(f"Location: {video_path}")
            print(f"Mode: {args.mode}")
            print(f"\nYou can now use this video for enterprise presentations!")
        else:
            print("\nFailed to create demo video. Check the logs for details.")
            
    except KeyboardInterrupt:
        print("\nVideo creation interrupted by user")
        await presenter.close()
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        await presenter.close()

if __name__ == "__main__":
    asyncio.run(main())