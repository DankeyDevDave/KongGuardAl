#!/usr/bin/env python3
"""
Kong Guard AI - Demo Narrator
Provides automated narration and presentation flow control
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PresentationMode(Enum):
    EXECUTIVE = "executive"  # Business-focused, ROI emphasis
    TECHNICAL = "technical"  # Technical details, architecture focus
    INDUSTRY = "industry"  # Industry-specific scenarios


@dataclass
class NarrationSegment:
    title: str
    content: str
    duration: int
    visual_cues: list[str]
    presenter_notes: Optional[str] = None


class DemoNarrator:
    def __init__(self, mode: PresentationMode = PresentationMode.EXECUTIVE):
        self.mode = mode
        self.current_segment = 0
        self.presentation_segments = []
        self.timing_log = []

        # Initialize presentation content based on mode
        self._initialize_presentation_content()

    def _initialize_presentation_content(self):
        """Initialize presentation content based on mode"""

        if self.mode == PresentationMode.EXECUTIVE:
            self.presentation_segments = [
                NarrationSegment(
                    title="Welcome & Problem Statement",
                    content="Welcome to Kong Guard AI's enterprise demonstration. Today's cyber threats cost organizations an average of $4.45 million per breach. Traditional rule-based security fails against sophisticated AI-powered attacks.",
                    duration=15,
                    visual_cues=["Show industry breach statistics", "Highlight cost metrics"],
                    presenter_notes="Emphasize financial impact and business risk",
                ),
                NarrationSegment(
                    title="Solution Overview",
                    content="Kong Guard AI provides three levels of protection: Unprotected baselines show vulnerability, Cloud AI delivers enterprise-grade protection, and Local AI ensures privacy compliance.",
                    duration=12,
                    visual_cues=["Highlight three-tier architecture", "Show protection levels"],
                    presenter_notes="Focus on flexibility and choice",
                ),
                NarrationSegment(
                    title="SQL Injection Attack Demo",
                    content="This SQL injection could expose your entire customer database. Notice how unprotected Kong allows this through, while our AI immediately detects and blocks the malicious SQL patterns, preventing potential data breaches worth millions.",
                    duration=18,
                    visual_cues=["Execute SQL injection on all tiers", "Show protection comparison"],
                    presenter_notes="Emphasize data protection and compliance",
                ),
                NarrationSegment(
                    title="Business Logic Attack Demo",
                    content="This business logic attack exploits negative amounts to steal $50 million from bank reserves. Traditional firewalls miss this, but Kong Guard AI's contextual understanding immediately flags the fraudulent transaction pattern.",
                    duration=16,
                    visual_cues=["Execute business logic attack", "Highlight financial fraud prevention"],
                    presenter_notes="Connect to real-world financial fraud cases",
                ),
                NarrationSegment(
                    title="ROI & Business Value",
                    content="Kong Guard AI prevents an average of $68 million in potential damages per year. With deployment costs under $100,000, you achieve 680x return on investment while ensuring regulatory compliance.",
                    duration=14,
                    visual_cues=["Show ROI calculations", "Display compliance benefits"],
                    presenter_notes="Present specific ROI numbers and compliance value",
                ),
                NarrationSegment(
                    title="Implementation Options",
                    content="Choose cloud AI for maximum accuracy and threat intelligence, or local AI for complete privacy and regulatory compliance. Both options provide enterprise-grade protection with sub-second response times.",
                    duration=12,
                    visual_cues=["Compare cloud vs local benefits", "Show deployment options"],
                    presenter_notes="Address privacy and sovereignty concerns",
                ),
            ]

        elif self.mode == PresentationMode.TECHNICAL:
            self.presentation_segments = [
                NarrationSegment(
                    title="Technical Architecture Overview",
                    content="Kong Guard AI integrates seamlessly with Kong Gateway using our custom Lua plugin. It analyzes requests in real-time using advanced AI models, providing contextual threat assessment beyond traditional signature-based detection.",
                    duration=16,
                    visual_cues=["Show architecture diagram", "Highlight integration points"],
                    presenter_notes="Explain technical implementation details",
                ),
                NarrationSegment(
                    title="AI Model Comparison",
                    content="Cloud deployment uses GPT-4 and Gemini for maximum accuracy with global threat intelligence. Local deployment uses Mistral 7B and Llama models, providing 88-95% accuracy with complete privacy and faster response times.",
                    duration=14,
                    visual_cues=["Compare model performance", "Show accuracy metrics"],
                    presenter_notes="Discuss model selection and performance trade-offs",
                ),
                NarrationSegment(
                    title="Advanced Threat Detection",
                    content="Watch how our AI analyzes context, not just patterns. It understands business logic, detects zero-day patterns, and provides detailed reasoning for each decision, enabling security teams to understand and refine protection strategies.",
                    duration=18,
                    visual_cues=["Execute complex attacks", "Show AI reasoning"],
                    presenter_notes="Highlight AI's contextual understanding",
                ),
                NarrationSegment(
                    title="Performance & Scalability",
                    content="Kong Guard AI processes requests in under 100ms with horizontal scaling capabilities. Local AI reduces latency to 45ms while cloud AI provides global threat intelligence updates.",
                    duration=12,
                    visual_cues=["Show performance metrics", "Highlight scalability"],
                    presenter_notes="Discuss technical performance requirements",
                ),
            ]

        else:  # INDUSTRY mode
            self.presentation_segments = [
                NarrationSegment(
                    title="Industry-Specific Threats",
                    content="Each industry faces unique attack patterns. Financial services see business logic attacks, healthcare faces ransomware, retail encounters card skimming, and government systems face nation-state attacks.",
                    duration=16,
                    visual_cues=["Show industry-specific attack patterns", "Highlight sector risks"],
                    presenter_notes="Customize for audience industry",
                ),
                NarrationSegment(
                    title="Regulatory Compliance",
                    content="Kong Guard AI ensures compliance with HIPAA, PCI-DSS, SOX, and GDPR requirements. Local AI deployment provides complete data sovereignty while cloud AI offers global threat intelligence compliance.",
                    duration=14,
                    visual_cues=["Show compliance frameworks", "Highlight regulatory benefits"],
                    presenter_notes="Focus on audience-specific regulations",
                ),
                NarrationSegment(
                    title="Industry Case Studies",
                    content="Financial institutions prevented $50M wire fraud, healthcare systems blocked ransomware affecting patient care, and government agencies protected classified data from nation-state actors.",
                    duration=16,
                    visual_cues=["Show case study results", "Highlight success metrics"],
                    presenter_notes="Use relevant industry examples",
                ),
            ]

    async def get_current_narration(self) -> Optional[NarrationSegment]:
        """Get the current narration segment"""
        if 0 <= self.current_segment < len(self.presentation_segments):
            return self.presentation_segments[self.current_segment]
        return None

    async def advance_narration(self) -> bool:
        """Advance to next narration segment"""
        self.current_segment += 1
        return self.current_segment < len(self.presentation_segments)

    async def get_presentation_script(self) -> str:
        """Generate complete presentation script"""
        script_lines = [
            f"# Kong Guard AI - {self.mode.value.title()} Presentation Script",
            "=" * 60,
            "",
            "## Presentation Overview",
            f"- Mode: {self.mode.value.title()}",
            f"- Duration: ~{sum(seg.duration for seg in self.presentation_segments)} seconds",
            f"- Segments: {len(self.presentation_segments)}",
            "",
            "## Detailed Script",
            "",
        ]

        for i, segment in enumerate(self.presentation_segments, 1):
            script_lines.extend(
                [
                    f"### Segment {i}: {segment.title}",
                    f"**Duration**: {segment.duration} seconds",
                    "",
                    "**Narration**:",
                    segment.content,
                    "",
                    "**Visual Cues**:",
                    *[f"- {cue}" for cue in segment.visual_cues],
                    "",
                ]
            )

            if segment.presenter_notes:
                script_lines.extend([f"**Presenter Notes**: {segment.presenter_notes}", ""])

            script_lines.append("")

        return "\n".join(script_lines)

    async def generate_demo_timeline(self) -> dict[str, Any]:
        """Generate detailed timeline for demo execution"""
        timeline = {
            "total_duration": sum(seg.duration for seg in self.presentation_segments),
            "mode": self.mode.value,
            "segments": [],
        }

        current_time = 0
        for i, segment in enumerate(self.presentation_segments):
            segment_data = {
                "sequence": i + 1,
                "title": segment.title,
                "start_time": current_time,
                "end_time": current_time + segment.duration,
                "duration": segment.duration,
                "content": segment.content,
                "visual_cues": segment.visual_cues,
                "presenter_notes": segment.presenter_notes,
            }

            timeline["segments"].append(segment_data)
            current_time += segment.duration

        return timeline

    async def export_presentation_materials(self, output_dir: str = "presentation_materials"):
        """Export all presentation materials"""
        from pathlib import Path

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Export script
        script_content = await self.get_presentation_script()
        script_file = output_path / f"kong_guard_ai_{self.mode.value}_script.md"
        script_file.write_text(script_content)

        # Export timeline
        timeline = await self.generate_demo_timeline()
        timeline_file = output_path / f"kong_guard_ai_{self.mode.value}_timeline.json"
        timeline_file.write_text(json.dumps(timeline, indent=2))

        # Export speaker notes
        notes_lines = [f"# Kong Guard AI - {self.mode.value.title()} Speaker Notes", "=" * 50, ""]

        for segment in self.presentation_segments:
            notes_lines.extend(
                [
                    f"## {segment.title}",
                    f"**Key Points**: {segment.presenter_notes or 'Standard presentation'}",
                    f"**Duration**: {segment.duration}s",
                    "**Visual Cues**:",
                    *[f"  - {cue}" for cue in segment.visual_cues],
                    "",
                ]
            )

        notes_file = output_path / f"kong_guard_ai_{self.mode.value}_speaker_notes.md"
        notes_file.write_text("\n".join(notes_lines))

        logger.info(f"Presentation materials exported to {output_path}")

        return {"script": str(script_file), "timeline": str(timeline_file), "speaker_notes": str(notes_file)}


class PresentationController:
    """Controls the flow of live presentations"""

    def __init__(self, narrator: DemoNarrator):
        self.narrator = narrator
        self.start_time = None
        self.paused = False

    async def start_presentation(self):
        """Start live presentation with timing control"""
        self.start_time = time.time()
        logger.info(f"Starting {self.narrator.mode.value} presentation")

        while True:
            segment = await self.narrator.get_current_narration()
            if not segment:
                break

            logger.info(f"Segment: {segment.title}")
            logger.info(f"Content: {segment.content}")
            logger.info(f"Duration: {segment.duration}s")

            # Wait for segment duration (could be replaced with manual control)
            await asyncio.sleep(segment.duration)

            if not await self.narrator.advance_narration():
                break

        total_time = time.time() - self.start_time
        logger.info(f"Presentation completed in {total_time:.1f} seconds")


async def main():
    """Main function for demo narration"""
    import argparse

    parser = argparse.ArgumentParser(description="Kong Guard AI Demo Narrator")
    parser.add_argument(
        "--mode", choices=["executive", "technical", "industry"], default="executive", help="Presentation mode"
    )
    parser.add_argument("--export", action="store_true", help="Export presentation materials")
    parser.add_argument("--run", action="store_true", help="Run live presentation")

    args = parser.parse_args()

    # Create narrator
    mode = PresentationMode(args.mode)
    narrator = DemoNarrator(mode)

    if args.export:
        # Export presentation materials
        materials = await narrator.export_presentation_materials()
        print("\n📚 Presentation materials exported:")
        print(f"  📝 Script: {materials['script']}")
        print(f"  ⏱️ Timeline: {materials['timeline']}")
        print(f"  📋 Speaker Notes: {materials['speaker_notes']}")

    if args.run:
        # Run live presentation
        controller = PresentationController(narrator)
        await controller.start_presentation()

    if not args.export and not args.run:
        # Default: show script preview
        script = await narrator.get_presentation_script()
        print(script)


if __name__ == "__main__":
    asyncio.run(main())
