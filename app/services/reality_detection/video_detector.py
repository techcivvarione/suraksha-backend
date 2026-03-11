from __future__ import annotations

from .frame_analyzer import analyze_video_frames
from .risk_scoring import DetectionOutcome, VIDEO_WEIGHTS, combine_weighted_scores


class VideoDetector:
    def analyze(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        frame_result = analyze_video_frames(path, fast_mode=fast_mode)
        layers = {
            "face_boundary": frame_result.face_boundary,
            "temporal": frame_result.temporal,
            "lighting": frame_result.lighting,
            "texture": frame_result.texture,
        }
        outcome = combine_weighted_scores("video", layers, VIDEO_WEIGHTS)
        if frame_result.frames_sampled == 0 and "Video frame analysis unavailable" not in outcome.signals:
            outcome.signals.append("Video frame analysis unavailable")
        return outcome
