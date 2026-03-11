from __future__ import annotations

from PIL import Image

from .metadata_analysis import analyze_image_metadata
from .risk_scoring import DetectionOutcome, combine_weighted_scores, IMAGE_WEIGHTS
from .texture_analysis import (
    analyze_eye_reflections,
    analyze_jpeg_compression,
    analyze_noise_distribution,
    analyze_skin_texture,
)


class ImageDetector:
    def analyze(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        with Image.open(path) as image:
            working = image.copy()
        working.thumbnail((768, 768) if fast_mode else (1024, 1024))

        layers = {
            "metadata": analyze_image_metadata(path),
            "noise": analyze_noise_distribution(working),
            "texture": analyze_skin_texture(working),
            "reflection": analyze_eye_reflections(working),
            "compression": analyze_jpeg_compression(working, path),
        }
        return combine_weighted_scores("image", layers, IMAGE_WEIGHTS)
