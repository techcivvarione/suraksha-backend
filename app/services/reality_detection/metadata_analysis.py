from __future__ import annotations

from datetime import datetime, timezone

from PIL import Image

from .risk_scoring import DetectionLayer


AI_METADATA_HINTS = (
    "midjourney",
    "stable diffusion",
    "dall-e",
    "comfyui",
    "automatic1111",
    "generative",
    "ai",
)

KNOWN_CAMERA_MAKES = {
    "apple",
    "samsung",
    "sony",
    "canon",
    "nikon",
    "google",
    "xiaomi",
    "oneplus",
    "vivo",
    "oppo",
}


def _safe_lower(value: object) -> str:
    return str(value or "").strip().lower()


def analyze_image_metadata(path: str) -> DetectionLayer:
    layer = DetectionLayer()
    with Image.open(path) as image:
        exif = image.getexif() or {}
        info = {str(key).lower(): _safe_lower(value) for key, value in image.info.items()}

    if not exif:
        layer.score += 0.40
        layer.signals.append("Missing EXIF metadata")

    make = _safe_lower(exif.get(271))
    model = _safe_lower(exif.get(272))
    software = " ".join(filter(None, [_safe_lower(exif.get(305)), info.get("software", "")]))

    if make and make not in KNOWN_CAMERA_MAKES:
        layer.score += 0.20
        layer.signals.append("Unrecognized camera make in metadata")
    if not model and exif:
        layer.score += 0.10
        layer.signals.append("Camera model metadata missing")

    if any(hint in software for hint in AI_METADATA_HINTS):
        layer.score += 0.70
        layer.signals.append("AI generator signature present in metadata")

    datetime_original = _safe_lower(exif.get(36867))
    datetime_digitized = _safe_lower(exif.get(36868))
    if datetime_original and datetime_digitized and datetime_original != datetime_digitized:
        layer.score += 0.15
        layer.signals.append("Timestamp inconsistencies detected")

    try:
        if datetime_original:
            parsed = datetime.strptime(datetime_original, "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if parsed > datetime.now(timezone.utc):
                layer.score += 0.30
                layer.signals.append("Future timestamp anomaly in metadata")
    except ValueError:
        layer.score += 0.10
        layer.signals.append("Malformed timestamp metadata")

    layer.score = min(layer.score, 1.0)
    return layer
