#!/usr/bin/env python3
"""
Kong Guard AI - Voice Generation for Demo Scenes
Uses Google Gemini TTS to generate professional narration
"""

import argparse
import json
import mimetypes
import os
import struct
import sys
from pathlib import Path

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("❌ google-genai not installed")
    print("Install with: pip install google-genai")
    sys.exit(1)


# Available Gemini TTS voices
AVAILABLE_VOICES = {
    "Puck": "Casual American male",
    "Charon": "Calm mature male",
    "Kore": "Warm female",
    "Fenrir": "Confident male",
    "Aoede": "Bright female",
    "Gacrux": "Professional male (default)",
    "Algieba": "Energetic, exciting voice",
}


def save_binary_file(file_name, data):
    """Save binary data to file"""
    f = open(file_name, "wb")
    f.write(data)
    f.close()
    print(f"✓ File saved to: {file_name}")


def convert_to_wav(audio_data: bytes, mime_type: str) -> bytes:
    """Generates a WAV file header for the given audio data and parameters.

    Args:
        audio_data: The raw audio data as a bytes object.
        mime_type: Mime type of the audio data.

    Returns:
        A bytes object representing the WAV file header.
    """
    parameters = parse_audio_mime_type(mime_type)
    bits_per_sample = parameters["bits_per_sample"]
    sample_rate = parameters["rate"]
    num_channels = 1
    data_size = len(audio_data)
    bytes_per_sample = bits_per_sample // 8
    block_align = num_channels * bytes_per_sample
    byte_rate = sample_rate * block_align
    chunk_size = 36 + data_size  # 36 bytes for header fields before data chunk size

    # http://soundfile.sapp.org/doc/WaveFormat/

    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",  # ChunkID
        chunk_size,  # ChunkSize (total file size - 8 bytes)
        b"WAVE",  # Format
        b"fmt ",  # Subchunk1ID
        16,  # Subchunk1Size (16 for PCM)
        1,  # AudioFormat (1 for PCM)
        num_channels,  # NumChannels
        sample_rate,  # SampleRate
        byte_rate,  # ByteRate
        block_align,  # BlockAlign
        bits_per_sample,  # BitsPerSample
        b"data",  # Subchunk2ID
        data_size,  # Subchunk2Size (size of audio data)
    )
    return header + audio_data


def parse_audio_mime_type(mime_type: str) -> dict:
    """Parses bits per sample and rate from an audio MIME type string.

    Assumes bits per sample is encoded like "L16" and rate as "rate=xxxxx".

    Args:
        mime_type: The audio MIME type string (e.g., "audio/L16;rate=24000").

    Returns:
        A dictionary with "bits_per_sample" and "rate" keys.
    """
    bits_per_sample = 16
    rate = 24000

    # Extract rate from parameters
    parts = mime_type.split(";")
    for param in parts:
        param = param.strip()
        if param.lower().startswith("rate="):
            try:
                rate_str = param.split("=", 1)[1]
                rate = int(rate_str)
            except (ValueError, IndexError):
                pass
        elif param.startswith("audio/L"):
            try:
                bits_per_sample = int(param.split("L", 1)[1])
            except (ValueError, IndexError):
                pass

    return {"bits_per_sample": bits_per_sample, "rate": rate}


def load_narrator_config(config_path="narrator_timing.json"):
    """Load narrator timing configuration"""
    try:
        with open(config_path) as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        sys.exit(1)


def generate_scene_voice(scene_number, narration_text, voice_name="Gacrux", output_dir="demo_recordings/voiceovers"):
    """Generate voice narration for a scene using Gemini TTS"""

    # Get API key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set in environment")
        print("Set it with: export GEMINI_API_KEY='your-key-here'")
        sys.exit(1)

    print(f"\n🎤 Generating voice for Scene {scene_number}...")
    print(f"   Voice: {voice_name}")
    print(f"   Text: {narration_text[:80]}...")

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize Gemini client
    client = genai.Client(api_key=api_key)

    model = "gemini-2.5-pro-preview-tts"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=narration_text),
            ],
        ),
    ]

    generate_content_config = types.GenerateContentConfig(
        temperature=1,
        response_modalities=["audio"],
        speech_config=types.SpeechConfig(
            voice_config=types.VoiceConfig(prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name=voice_name))
        ),
    )

    # Generate audio
    print("   Generating audio...")
    audio_chunks = []

    try:
        for chunk in client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=generate_content_config,
        ):
            if (
                chunk.candidates is None
                or chunk.candidates[0].content is None
                or chunk.candidates[0].content.parts is None
            ):
                continue

            if (
                chunk.candidates[0].content.parts[0].inline_data
                and chunk.candidates[0].content.parts[0].inline_data.data
            ):
                inline_data = chunk.candidates[0].content.parts[0].inline_data
                data_buffer = inline_data.data

                # Convert to WAV if needed
                file_extension = mimetypes.guess_extension(inline_data.mime_type)
                if file_extension is None:
                    file_extension = ".wav"
                    data_buffer = convert_to_wav(inline_data.data, inline_data.mime_type)

                audio_chunks.append(data_buffer)
            else:
                # Text response
                if hasattr(chunk, "text"):
                    print(f"   {chunk.text}")

        # Combine all audio chunks
        if audio_chunks:
            final_audio = b"".join(audio_chunks)
            file_name = output_path / f"scene_{scene_number}_narration.wav"
            save_binary_file(str(file_name), final_audio)

            # Get file size
            file_size = len(final_audio) / 1024 / 1024
            print(f"   Size: {file_size:.2f} MB")
            print(f"✅ Scene {scene_number} voice generated successfully!")

            return str(file_name)
        else:
            print(f"❌ No audio data received for Scene {scene_number}")
            return None

    except Exception as e:
        print(f"❌ Failed to generate voice: {e}")
        return None


def generate_all_scenes(voice_name="Gacrux", output_dir="demo_recordings/voiceovers"):
    """Generate voice narration for all scenes"""

    # Load config
    config = load_narrator_config()
    scenes = config["scenes"]

    print(f"🎬 Generating voice for {len(scenes)} scenes...")
    print(f"   Voice: {voice_name} ({AVAILABLE_VOICES.get(voice_name, 'Unknown')})")
    print(f"   Output: {output_dir}")
    print("")

    generated_files = []

    for scene in scenes:
        scene_number = scene["number"]
        narration = scene["narration"]

        result = generate_scene_voice(scene_number, narration, voice_name, output_dir)

        if result:
            generated_files.append(result)

    print(f"\n{'='*60}")
    print(f"✅ Generated {len(generated_files)} voice files")
    print(f"{'='*60}")

    for file in generated_files:
        print(f"   📄 {file}")

    print("")
    print("💡 Next steps:")
    print("   1. Review generated audio files")
    print("   2. Combine with video using video editor")
    print("   3. Use timing_log.json for precise sync")


def list_voices():
    """List available TTS voices"""
    print("\n🎤 Available Gemini TTS Voices:\n")

    for voice, description in AVAILABLE_VOICES.items():
        print(f"   {voice:12} - {description}")

    print("\nUsage: --voice <name>")
    print("Example: --voice Gacrux\n")


def main():
    parser = argparse.ArgumentParser(
        description="Kong Guard AI - Voice Generation for Demo Scenes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate voice for Scene 1
  ./generate_scene_voice.py --scene 1

  # Generate all scenes
  ./generate_scene_voice.py --all

  # Generate specific scenes
  ./generate_scene_voice.py --scenes 1,3,5

  # Use different voice
  ./generate_scene_voice.py --scene 1 --voice Puck

  # List available voices
  ./generate_scene_voice.py --list-voices
        """,
    )

    parser.add_argument("--scene", type=int, help="Generate voice for specific scene number (1-7)")

    parser.add_argument("--scenes", help='Generate voice for multiple scenes (comma-separated, e.g., "1,3,5")')

    parser.add_argument("--all", action="store_true", help="Generate voice for all scenes")

    parser.add_argument(
        "--voice",
        default="Gacrux",
        choices=list(AVAILABLE_VOICES.keys()),
        help="Voice to use for narration (default: Gacrux)",
    )

    parser.add_argument("--output-dir", default="demo_recordings/voiceovers", help="Output directory for voice files")

    parser.add_argument("--config", default="narrator_timing.json", help="Path to narrator timing configuration")

    parser.add_argument("--list-voices", action="store_true", help="List available voices")

    args = parser.parse_args()

    # List voices
    if args.list_voices:
        list_voices()
        return

    # Check API key
    if not os.environ.get("GEMINI_API_KEY"):
        print("❌ GEMINI_API_KEY not set in environment")
        print("\nSet it with:")
        print("   export GEMINI_API_KEY='your-key-here'")
        print("\nOr in your .env file:")
        print("   GEMINI_API_KEY=your-key-here")
        sys.exit(1)

    # Load config
    config = load_narrator_config(args.config)
    scenes = config["scenes"]

    print("🎬 Kong Guard AI - Voice Generation")
    print(f"   Voice: {args.voice} ({AVAILABLE_VOICES.get(args.voice, 'Unknown')})")
    print(f"   Output: {args.output_dir}")

    # Generate voice
    if args.all:
        generate_all_scenes(args.voice, args.output_dir)

    elif args.scenes:
        scene_numbers = [int(n.strip()) for n in args.scenes.split(",")]
        print(f"\n🎤 Generating voice for scenes: {scene_numbers}")

        generated = []
        for scene_num in scene_numbers:
            scene = next((s for s in scenes if s["number"] == scene_num), None)
            if scene:
                result = generate_scene_voice(scene_num, scene["narration"], args.voice, args.output_dir)
                if result:
                    generated.append(result)
            else:
                print(f"⚠️  Scene {scene_num} not found")

        print(f"\n✅ Generated {len(generated)} voice file(s)")

    elif args.scene:
        scene = next((s for s in scenes if s["number"] == args.scene), None)
        if scene:
            result = generate_scene_voice(args.scene, scene["narration"], args.voice, args.output_dir)
            if result:
                print(f"\n✅ Voice generated: {result}")
                print("\n💡 Next steps:")
                print(f"   1. Listen to: {result}")
                print("   2. Combine with video in editor")
                print("   3. Use timing_log.json for sync")
        else:
            print(f"❌ Scene {args.scene} not found")
            print(f"Available scenes: 1-{len(scenes)}")

    else:
        parser.print_help()
        print("\n💡 Tip: Use --scene 1 to generate Scene 1 voice")


if __name__ == "__main__":
    main()
