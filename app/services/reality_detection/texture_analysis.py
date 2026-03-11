from __future__ import annotations

from PIL import Image, ImageChops, ImageFilter, ImageStat

from .risk_scoring import DetectionLayer

try:
    import numpy as np
except Exception:  # pragma: no cover - optional dependency
    np = None


def _resize_for_analysis(image: Image.Image, max_dim: int = 1024) -> Image.Image:
    resized = image.copy()
    resized.thumbnail((max_dim, max_dim))
    return resized


def analyze_noise_distribution(image: Image.Image) -> DetectionLayer:
    layer = DetectionLayer()
    working = _resize_for_analysis(image).convert("L")
    blurred = working.filter(ImageFilter.GaussianBlur(radius=1))
    diff = ImageChops.difference(working, blurred)
    stat = ImageStat.Stat(diff)
    variance = stat.var[0] if stat.var else 0.0
    mean_diff = stat.mean[0] if stat.mean else 0.0

    if variance < 6 or mean_diff < 3:
        layer.score += 0.65
        layer.signals.append("Abnormal noise distribution")
    elif variance < 12:
        layer.score += 0.35
        layer.signals.append("Low natural sensor noise")

    if np is not None:
        pixels = np.asarray(working, dtype="float32")
        if pixels.size:
            local_var = float(pixels.var())
            if local_var < 450:
                layer.score += 0.15
    layer.score = min(layer.score, 1.0)
    return layer


def analyze_skin_texture(image: Image.Image) -> DetectionLayer:
    layer = DetectionLayer()
    working = _resize_for_analysis(image).convert("L")
    center = working.crop(
        (
            working.width * 0.2,
            working.height * 0.2,
            working.width * 0.8,
            working.height * 0.8,
        )
    )
    edges = center.filter(ImageFilter.FIND_EDGES)
    edge_stat = ImageStat.Stat(edges)
    texture_mean = edge_stat.mean[0] if edge_stat.mean else 0.0
    texture_var = edge_stat.var[0] if edge_stat.var else 0.0

    if texture_mean < 12 or texture_var < 120:
        layer.score += 0.70
        layer.signals.append("Unnatural skin texture")
    elif texture_mean < 18:
        layer.score += 0.35
        layer.signals.append("Loss of microtexture detail")

    layer.score = min(layer.score, 1.0)
    return layer


def analyze_eye_reflections(image: Image.Image) -> DetectionLayer:
    layer = DetectionLayer()
    working = _resize_for_analysis(image).convert("L")
    upper_band = working.crop((0, 0, working.width, max(1, working.height // 3)))
    left = upper_band.crop((0, 0, upper_band.width // 2, upper_band.height))
    right = upper_band.crop((upper_band.width // 2, 0, upper_band.width, upper_band.height))
    left_mean = ImageStat.Stat(left).mean[0]
    right_mean = ImageStat.Stat(right).mean[0]
    mismatch = abs(left_mean - right_mean)

    if mismatch > 24:
        layer.score += 0.70
        layer.signals.append("Reflection inconsistencies")
    elif mismatch > 14:
        layer.score += 0.35
        layer.signals.append("Minor reflection mismatch")

    layer.score = min(layer.score, 1.0)
    return layer


def analyze_jpeg_compression(image: Image.Image, path: str) -> DetectionLayer:
    layer = DetectionLayer()
    if not path.lower().endswith((".jpg", ".jpeg")):
        return layer

    working = _resize_for_analysis(image).convert("L")
    width = working.width - (working.width % 8)
    height = working.height - (working.height % 8)
    if width <= 0 or height <= 0:
        return layer

    trimmed = working.crop((0, 0, width, height))
    pixels = list(trimmed.getdata())
    row_stride = width
    block_means = []
    for y in range(0, height, 8):
        for x in range(0, width, 8):
            values = []
            for row in range(8):
                start = (y + row) * row_stride + x
                values.extend(pixels[start : start + 8])
            block_means.append(sum(values) / len(values))

    if not block_means:
        return layer

    transitions = [
        abs(block_means[index] - block_means[index - 1])
        for index in range(1, len(block_means))
    ]
    avg_transition = sum(transitions) / len(transitions) if transitions else 0.0
    if avg_transition > 30:
        layer.score += 0.55
        layer.signals.append("Inconsistent JPEG compression blocks")
    elif avg_transition > 18:
        layer.score += 0.25
        layer.signals.append("Mild JPEG block inconsistency")

    layer.score = min(layer.score, 1.0)
    return layer
