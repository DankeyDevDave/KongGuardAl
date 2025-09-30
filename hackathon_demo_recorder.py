#!/usr/bin/env python3
"""
Kong Guard AI - Hackathon Demo Recorder
Professional Playwright-based demo recording with visual indicators and screenshots
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

try:
    from playwright.async_api import Browser
    from playwright.async_api import Page
    from playwright.async_api import async_playwright
except ImportError:
    logger.error("Playwright not installed. Install with: pip install playwright && playwright install")
    exit(1)


class HackathonDemoRecorder:
    """Records professional demos with visual indicators and screenshots"""

    def __init__(self, config_path: str = "narrator_timing.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.recording_path: Optional[Path] = None
        self.screenshots_path: Optional[Path] = None
        self.visual_effects_loaded = False
        self.timing_log: list[dict[str, Any]] = []

    def _load_config(self) -> dict[str, Any]:
        """Load narrator timing configuration"""
        try:
            with open(self.config_path) as f:
                config = json.load(f)
            logger.info(f"Loaded config: {config['demo_info']['title']}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config from {self.config_path}: {e}")
            raise

    async def initialize_browser(self, headed: bool = True, video: bool = True, screenshots: bool = True):
        """Initialize browser with recording capabilities"""
        self.playwright = await async_playwright().start()

        # Create output directories
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.recording_path = Path(f"demo_recordings/hackathon_demo_{timestamp}")
        self.recording_path.mkdir(parents=True, exist_ok=True)

        if screenshots:
            self.screenshots_path = self.recording_path / "screenshots"
            self.screenshots_path.mkdir(exist_ok=True)

        # Configure browser options
        browser_options = {
            "headless": not headed,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
                "--window-size=1920,1080",
            ],
        }

        # Configure context options
        context_options = {"viewport": {"width": 1920, "height": 1080}}

        if video:
            context_options["record_video_dir"] = str(self.recording_path)
            context_options["record_video_size"] = {"width": 1920, "height": 1080}

        self.browser = await self.playwright.chromium.launch(**browser_options)
        self.context = await self.browser.new_context(**context_options)
        self.page = await self.context.new_page()

        logger.info(f"Browser initialized in {'headed' if headed else 'headless'} mode")
        logger.info(f"Output directory: {self.recording_path}")

        return self.page

    async def load_dashboard(self):
        """Load the dashboard and inject visual effects"""
        dashboard_url = self.config["demo_info"]["dashboard_url"]
        logger.info(f"Loading dashboard: {dashboard_url}")

        try:
            await self.page.goto(dashboard_url, wait_until="networkidle", timeout=30000)
            await self.page.wait_for_selector("h1", timeout=10000)
            logger.info("Dashboard loaded successfully")

            # Inject visual effects
            await self._inject_visual_effects()

            # Wait for services to initialize
            await asyncio.sleep(3)

            return True
        except Exception as e:
            logger.error(f"Failed to load dashboard: {e}")
            return False

    async def _inject_visual_effects(self):
        """Inject visual effects JavaScript"""
        try:
            visual_effects_path = Path("demo_visual_effects.js")
            if not visual_effects_path.exists():
                logger.warning("Visual effects file not found, skipping injection")
                return

            with open(visual_effects_path) as f:
                visual_effects_js = f.read()

            await self.page.evaluate(visual_effects_js)
            self.visual_effects_loaded = True
            logger.info("Visual effects injected successfully")
        except Exception as e:
            logger.error(f"Failed to inject visual effects: {e}")

    async def highlight_element(self, selector: str, duration: int = 3):
        """Highlight an element with visual effect"""
        if not self.visual_effects_loaded:
            logger.warning("Visual effects not loaded, using basic highlight")
            await self.page.evaluate(
                f"""
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.style.outline = '3px solid #aeb4bd';
                    el.style.outlineOffset = '4px';
                    el.style.boxShadow = '0 0 30px rgba(174, 180, 189, 0.8)';
                    setTimeout(() => {{
                        el.style.outline = '';
                        el.style.outlineOffset = '';
                        el.style.boxShadow = '';
                    }}, {duration * 1000});
                }}
                """
            )
        else:
            await self.page.evaluate(f"window.kgVisualEffects.highlightElement('{selector}', {duration * 1000})")

        await asyncio.sleep(duration)

    async def click_with_visual(self, selector: str, label: str = "", wait_after: int = 2):
        """Click element with visual ripple effect"""
        try:
            # Wait for element
            await self.page.wait_for_selector(selector, timeout=5000)

            # Get element position for ripple
            element = await self.page.query_selector(selector)
            if not element:
                logger.warning(f"Element not found: {selector}")
                return

            box = await element.bounding_box()
            if box:
                x = box["x"] + box["width"] / 2
                y = box["y"] + box["height"] / 2

                # Show ripple effect
                if self.visual_effects_loaded:
                    await self.page.evaluate(f"window.kgVisualEffects.showClickRipple({x}, {y})")

            # Perform click
            await element.click()
            logger.info(f"Clicked: {label or selector}")

            # Wait after click
            await asyncio.sleep(wait_after)

        except Exception as e:
            logger.error(f"Failed to click {selector}: {e}")

    async def capture_screenshot(self, stage_name: str):
        """Capture screenshot with flash effect"""
        if not self.screenshots_path:
            return

        try:
            # Show screenshot flash
            if self.visual_effects_loaded:
                await self.page.evaluate("window.kgVisualEffects.showScreenshotFlash()")

            # Capture screenshot
            screenshot_path = self.screenshots_path / f"{stage_name}.png"
            await self.page.screenshot(path=str(screenshot_path), full_page=False)
            logger.info(f"Screenshot captured: {stage_name}.png")

        except Exception as e:
            logger.error(f"Failed to capture screenshot {stage_name}: {e}")

    async def wait_for_narration(self, duration: int, segment_name: str = ""):
        """Wait with progress indicator"""
        if segment_name:
            logger.info(f"Waiting {duration}s for narration: {segment_name}")

        # Update progress in small increments for smooth animation
        steps = min(duration * 10, 100)  # Update every 0.1s or less
        for i in range(steps):
            await asyncio.sleep(duration / steps)

    async def update_scene_progress(self, scene: dict[str, Any], progress: float):
        """Update on-screen progress indicator"""
        if not self.visual_effects_loaded:
            return

        try:
            await self.page.evaluate(
                f"""
                window.kgVisualEffects.updateProgress(
                    {{
                        number: {scene['number']},
                        title: "{scene['title']}",
                        narration: "{scene['narration'][:150]}...",
                        start_time: {scene['start_time']},
                        duration: {scene['duration']}
                    }},
                    {progress}
                )
                """
            )

            await self.page.evaluate(
                f"window.kgVisualEffects.updateSceneBadge({scene['number']}, {len(self.config['scenes'])})"
            )
        except Exception as e:
            logger.debug(f"Failed to update progress: {e}")

    async def execute_action(self, action: dict[str, Any], scene: dict[str, Any]):
        """Execute a single action from the scene"""
        action_type = action["type"]
        description = action.get("description", "")

        logger.info(f"  Action: {action_type} - {description}")

        if action_type == "wait":
            await self.wait_for_narration(action["duration"], description)

        elif action_type == "highlight":
            await self.highlight_element(action["selector"], action.get("duration", 3))

        elif action_type == "click":
            await self.click_with_visual(action["selector"], description, action.get("wait_after", 2))

        elif action_type == "screenshot":
            await self.capture_screenshot(action["name"])

        elif action_type == "hover":
            selector = action["selector"]
            try:
                await self.page.hover(selector)
                await asyncio.sleep(action.get("duration", 2))
            except Exception as e:
                logger.warning(f"Failed to hover {selector}: {e}")

        elif action_type == "scroll":
            to = action.get("to", "top")
            if to == "top":
                await self.page.evaluate("window.scrollTo({ top: 0, behavior: 'smooth' })")
            await asyncio.sleep(action.get("duration", 2))

        else:
            logger.warning(f"Unknown action type: {action_type}")

    async def execute_scene(self, scene: dict[str, Any]):
        """Execute a complete scene"""
        scene_number = scene["number"]
        scene_title = scene["title"]
        scene_duration = scene["duration"]

        logger.info(f"\n{'='*60}")
        logger.info(f"SCENE {scene_number}: {scene_title}")
        logger.info(f"Duration: {scene_duration}s")
        logger.info(f"{'='*60}")

        scene_start_time = datetime.now()

        # Update scene badge
        await self.update_scene_progress(scene, 0)

        # Execute all actions in the scene
        total_actions = len(scene["actions"])
        for idx, action in enumerate(scene["actions"]):
            progress = (idx / total_actions) * 100
            await self.update_scene_progress(scene, progress)
            await self.execute_action(action, scene)

        # Final progress update
        await self.update_scene_progress(scene, 100)

        scene_elapsed = (datetime.now() - scene_start_time).total_seconds()

        # Log timing
        timing_entry = {
            "scene_number": scene_number,
            "scene_title": scene_title,
            "planned_duration": scene_duration,
            "actual_duration": scene_elapsed,
            "variance": scene_elapsed - scene_duration,
        }
        self.timing_log.append(timing_entry)

        logger.info(f"Scene completed in {scene_elapsed:.1f}s (planned: {scene_duration}s)")

    async def run_full_demo(self):
        """Execute the complete demo recording"""
        logger.info("\n" + "=" * 80)
        logger.info("KONG GUARD AI - HACKATHON DEMO RECORDING")
        logger.info(f"Total Scenes: {len(self.config['scenes'])}")
        logger.info(f"Total Duration: ~{self.config['demo_info']['total_duration_seconds']}s")
        logger.info("=" * 80 + "\n")

        demo_start_time = datetime.now()

        # Execute each scene
        for scene in self.config["scenes"]:
            await self.execute_scene(scene)

        demo_elapsed = (datetime.now() - demo_start_time).total_seconds()

        logger.info("\n" + "=" * 80)
        logger.info("DEMO RECORDING COMPLETE")
        logger.info(f"Total time: {demo_elapsed:.1f}s")
        logger.info("=" * 80)

        # Save timing log
        await self._save_timing_log()

    async def _save_timing_log(self):
        """Save timing log to file"""
        if not self.recording_path:
            return

        timing_log_path = self.recording_path / "timing_log.json"

        summary = {
            "demo_info": self.config["demo_info"],
            "recording_date": datetime.now().isoformat(),
            "scenes": self.timing_log,
            "total_planned": sum(s["planned_duration"] for s in self.timing_log),
            "total_actual": sum(s["actual_duration"] for s in self.timing_log),
            "total_variance": sum(s["variance"] for s in self.timing_log),
        }

        with open(timing_log_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Timing log saved: {timing_log_path}")

    async def close(self):
        """Clean up browser resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, "playwright"):
            await self.playwright.stop()

        logger.info("Browser resources cleaned up")

        # Find and report video file
        if self.recording_path:
            video_files = list(self.recording_path.glob("*.webm"))
            if video_files:
                logger.info(f"\n{'='*80}")
                logger.info("RECORDING OUTPUT:")
                logger.info(f"  Video: {video_files[0]}")
                if self.screenshots_path:
                    screenshot_count = len(list(self.screenshots_path.glob("*.png")))
                    logger.info(f"  Screenshots: {screenshot_count} files in {self.screenshots_path}")
                logger.info(f"  Timing log: {self.recording_path / 'timing_log.json'}")
                logger.info("=" * 80)


async def main():
    """Main function for hackathon demo recording"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Kong Guard AI Hackathon Demo Recorder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Record with all features (headed, video, screenshots)
  python hackathon_demo_recorder.py --headed --screenshots --narrator-timing

  # Quick test run (headless, no video)
  python hackathon_demo_recorder.py --no-video

  # Record specific scenes only
  python hackathon_demo_recorder.py --scenes 1,3,5
        """,
    )

    parser.add_argument(
        "--headed", action="store_true", default=True, help="Run browser in headed mode (visible window)"
    )
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--screenshots", action="store_true", default=True, help="Capture screenshots at each stage")
    parser.add_argument("--no-screenshots", action="store_true", help="Disable screenshot capture")
    parser.add_argument("--video", action="store_true", default=True, help="Record video")
    parser.add_argument("--no-video", action="store_true", help="Disable video recording")
    parser.add_argument("--narrator-timing", action="store_true", default=True, help="Use narrator timing from config")
    parser.add_argument("--config", default="narrator_timing.json", help="Path to timing configuration file")
    parser.add_argument("--scenes", help='Comma-separated scene numbers to record (e.g., "1,3,5")')

    args = parser.parse_args()

    # Resolve contradictory flags
    headed = not args.headless if args.headless else args.headed
    video = not args.no_video if args.no_video else args.video
    screenshots = not args.no_screenshots if args.no_screenshots else args.screenshots

    logger.info("Kong Guard AI - Hackathon Demo Recorder")
    logger.info(f"Mode: {'Headed' if headed else 'Headless'}")
    logger.info(f"Video: {'Enabled' if video else 'Disabled'}")
    logger.info(f"Screenshots: {'Enabled' if screenshots else 'Disabled'}")

    # Create recorder
    recorder = HackathonDemoRecorder(args.config)

    # Filter scenes if requested
    if args.scenes:
        scene_numbers = [int(n.strip()) for n in args.scenes.split(",")]
        recorder.config["scenes"] = [s for s in recorder.config["scenes"] if s["number"] in scene_numbers]
        logger.info(f"Recording scenes: {scene_numbers}")

    try:
        # Initialize browser
        await recorder.initialize_browser(headed=headed, video=video, screenshots=screenshots)

        # Load dashboard
        if not await recorder.load_dashboard():
            logger.error("Failed to load dashboard, aborting")
            return

        # Run the full demo
        await recorder.run_full_demo()

        # Clean up
        await recorder.close()

        logger.info("\n✅ Demo recording completed successfully!")

    except KeyboardInterrupt:
        logger.warning("\n⚠️  Recording interrupted by user")
        await recorder.close()
    except Exception as e:
        logger.error(f"\n❌ Recording failed: {e}", exc_info=True)
        await recorder.close()


if __name__ == "__main__":
    asyncio.run(main())
