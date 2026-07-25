"""Module 10 — Executive Video Summary (Local TTS & Image Synthesis).

Generates an executive video summary (.mp4) with offline TTS narration (pyttsx3)
and slide imagery (Pillow / moviepy). Gracefully handles missing dependencies.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class Script:
    segments: list[str]


class VideoSummaryGenerator:
    """Generate offline video summaries for security assessments."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        scan_result = kwargs.get("scan_result", {})
        output_path = kwargs.get("output_path", "summary.mp4")
        if scan_result:
            try:
                out = await self.generate(scan_result, output_path)
                logger.info("Generated executive video summary: %s", out)
            except Exception as exc:
                logger.error("Failed to generate video summary: %s", exc)
        return []

    async def generate(self, scan_result: dict[str, Any], output_path: str = "summary.mp4") -> str:
        """Build script, render slides, synthesize audio, and composite video."""
        target = scan_result.get("target", scan_result.get("scan_meta", {}).get("target", "Target"))
        script = self.build_script(scan_result)

        # Check dependencies
        try:
            import pyttsx3
            from PIL import Image, ImageDraw, ImageFont
            from moviepy.editor import AudioFileClip, ImageClip, concatenate_videoclips
        except ImportError as err:
            logger.warning("Video summary dependencies missing (pyttsx3, Pillow, moviepy): %s", err)
            raise RuntimeError(
                "Video summary requires pyttsx3, Pillow, and moviepy. "
                "Install via: pip install pyttsx3 Pillow moviepy"
            ) from err

        temp_dir = tempfile.mkdtemp(prefix="phantomscan_video_")
        audio_files: list[str] = []
        slide_files: list[str] = []

        try:
            engine = pyttsx3.init()

            for i, text in enumerate(script.segments):
                # 1. Audio generation
                audio_path = os.path.join(temp_dir, f"audio_{i}.wav")
                engine.save_to_file(text, audio_path)
                engine.runAndWait()
                audio_files.append(audio_path)

                # 2. Slide image generation
                img = Image.new("RGB", (1280, 720), color=(12, 12, 26))
                draw = ImageDraw.Draw(img)

                # Title
                draw.text((60, 60), "PhantomScan Executive Summary", fill=(6, 182, 212))
                draw.text((60, 110), f"Target: {target}", fill=(226, 226, 248))

                # Segment Text (word wrap)
                words = text.split(" ")
                lines = []
                curr_line = ""
                for w in words:
                    if len(curr_line) + len(w) > 50:
                        lines.append(curr_line)
                        curr_line = w + " "
                    else:
                        curr_line += w + " "
                lines.append(curr_line)

                y = 250
                for line in lines:
                    draw.text((60, y), line, fill=(255, 255, 255))
                    y += 45

                slide_path = os.path.join(temp_dir, f"slide_{i}.png")
                img.save(slide_path)
                slide_files.append(slide_path)

            # 3. Composite video clips
            clips = []
            for slide_p, audio_p in zip(slide_files, audio_files):
                if os.path.exists(audio_p) and os.path.getsize(audio_p) > 0:
                    audio_clip = AudioFileClip(audio_p)
                    img_clip = ImageClip(slide_p).set_duration(audio_clip.duration)
                    img_clip = img_clip.set_audio(audio_clip)
                    clips.append(img_clip)

            if clips:
                final = concatenate_videoclips(clips)
                final.write_videofile(output_path, fps=24, codec="libx264")
                return output_path
            else:
                raise RuntimeError("No valid audio clips created.")

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def build_script(self, scan_result: dict[str, Any]) -> Script:
        """Create structured narration segments from scan result."""
        target = scan_result.get("target", scan_result.get("scan_meta", {}).get("target", "Target"))
        score_val = scan_result.get("score", 0)
        grade_val = scan_result.get("grade", "N/A")
        findings = scan_result.get("findings", [])

        crit_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")

        segments = [
            f"Security assessment summary for {target}. Overall security score: {score_val} out of 100, grade {grade_val}."
        ]

        if crit_count > 0:
            segments.append(f"We identified {crit_count} critical issues requiring immediate attention.")
        if high_count > 0:
            segments.append(f"Additionally, {high_count} high severity issues were found.")
        if crit_count == 0 and high_count == 0:
            segments.append("No critical or high severity security vulnerabilities were detected.")

        segments.append("Full technical details and remediation guidance are available in the complete interactive report.")
        return Script(segments=segments)
