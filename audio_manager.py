#!/usr/bin/env python3
"""
Audio Manager for Kong Guard AI Demo Recorder
Handles real-time audio playback during Playwright recording
"""

import asyncio
import logging
import subprocess
import wave
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class AudioManager:
    """Manages voice narration playback during demo recording"""
    
    def __init__(self, voice_dir: str = "demo_recordings/voiceovers"):
        """
        Initialize audio manager
        
        Args:
            voice_dir: Directory containing voice narration files
        """
        self.voice_dir = Path(voice_dir)
        self.initialized = True
        self.current_process: Optional[subprocess.Popen] = None
        logger.info(f"AudioManager initialized with voice directory: {self.voice_dir}")
    
    def get_audio_duration(self, scene_number: int) -> float:
        """
        Get duration of audio file for a scene
        
        Args:
            scene_number: Scene number (1-7)
            
        Returns:
            Duration in seconds, or 0 if file not found
        """
        audio_file = self.voice_dir / f"scene_{scene_number}_narration.wav"
        
        if not audio_file.exists():
            logger.warning(f"Audio file not found: {audio_file}")
            return 0.0
        
        try:
            with wave.open(str(audio_file), 'rb') as wf:
                frames = wf.getnframes()
                rate = wf.getframerate()
                duration = frames / float(rate)
                logger.debug(f"Scene {scene_number} audio duration: {duration:.2f}s")
                return duration
        except Exception as e:
            logger.error(f"Failed to get audio duration for scene {scene_number}: {e}")
            return 0.0
    
    async def play_scene_audio(self, scene_number: int) -> float:
        """
        Play voice narration for a scene using macOS afplay
        
        This starts playback in background. The caller should
        await the returned duration to ensure audio completes.
        
        Args:
            scene_number: Scene number (1-7)
            
        Returns:
            Duration of audio in seconds (0 if playback failed)
        """
        audio_file = self.voice_dir / f"scene_{scene_number}_narration.wav"
        
        if not audio_file.exists():
            logger.warning(f"Audio file not found: {audio_file}")
            return 0.0
        
        try:
            # Get duration first
            duration = self.get_audio_duration(scene_number)
            
            if duration == 0:
                return 0.0
            
            # Play audio using afplay (macOS built-in audio player)
            logger.info(f"🎤 Playing narration for Scene {scene_number} ({duration:.1f}s)")
            
            # Start playback in background (non-blocking)
            self.current_process = subprocess.Popen(
                ["afplay", str(audio_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            return duration
            
        except Exception as e:
            logger.error(f"Failed to play audio for scene {scene_number}: {e}")
            return 0.0
    
    async def play_scene_audio_and_wait(self, scene_number: int) -> float:
        """
        Play voice narration for a scene and wait for completion
        
        This is a convenience method that plays audio and blocks until finished.
        
        Args:
            scene_number: Scene number (1-7)
            
        Returns:
            Duration of audio in seconds (0 if playback failed)
        """
        duration = await self.play_scene_audio(scene_number)
        
        if duration > 0:
            # Wait for audio to complete
            await asyncio.sleep(duration)
            logger.debug(f"Audio playback completed for scene {scene_number}")
        
        return duration
    
    def stop_all_audio(self):
        """Stop all currently playing audio"""
        if self.current_process and self.current_process.poll() is None:
            try:
                self.current_process.terminate()
                self.current_process.wait(timeout=1)
                logger.debug("Audio playback stopped")
            except Exception as e:
                logger.error(f"Failed to stop audio: {e}")
    
    def cleanup(self):
        """Clean up audio resources"""
        self.stop_all_audio()
        logger.info("AudioManager cleaned up")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()


# Test function
async def test_audio_manager():
    """Test the audio manager with Scene 1"""
    print("Testing AudioManager...")
    
    manager = AudioManager()
    
    if not manager.initialized:
        print("❌ AudioManager not initialized (pygame might not be installed)")
        return
    
    print("✅ AudioManager initialized")
    
    # Test Scene 1
    duration = await manager.play_scene_audio_and_wait(1)
    
    if duration > 0:
        print(f"✅ Scene 1 audio played successfully ({duration:.2f}s)")
    else:
        print("❌ Failed to play Scene 1 audio")
    
    manager.cleanup()
    print("✅ AudioManager test complete")


if __name__ == "__main__":
    # Run test
    asyncio.run(test_audio_manager())
