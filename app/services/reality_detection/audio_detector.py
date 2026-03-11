from __future__ import annotations

from .risk_scoring import AUDIO_WEIGHTS, DetectionOutcome, combine_weighted_scores
from .spectral_analysis import analyze_audio_spectrum


class AudioDetector:
    def analyze(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        spectral, pitch, phase = analyze_audio_spectrum(path)
        layers = {
            "spectral": spectral,
            "pitch": pitch,
            "phase": phase,
        }
        return combine_weighted_scores("audio", layers, AUDIO_WEIGHTS)
