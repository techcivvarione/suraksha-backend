import io
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from app.services.reality_detection.engine import RealityDetectionEngine, RealityDetectionError


def _save_noise_image(path: Path, size=(256, 256)):
    image = Image.effect_noise(size, 48).convert("RGB")
    image.save(path, format="JPEG", quality=90)


def _save_ai_like_image(path: Path, size=(256, 256)):
    image = Image.new("RGB", size, color=(220, 200, 210))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Software", "Midjourney")
    image.save(path, format="PNG", pnginfo=meta)


def test_image_detection_real_media_has_low_risk(tmp_path):
    path = tmp_path / "camera.jpg"
    _save_noise_image(path)

    outcome = RealityDetectionEngine().analyze_image(str(path), "image/jpeg")

    assert outcome.analysis_type == "image"
    assert outcome.risk_level in {"LOW", "MEDIUM"}


def test_image_detection_ai_like_media_flags_signals(tmp_path):
    path = tmp_path / "synthetic.png"
    _save_ai_like_image(path)

    outcome = RealityDetectionEngine().analyze_image(str(path), "image/png")

    assert outcome.risk_level in {"MEDIUM", "HIGH"}
    assert any("AI generator" in signal or "texture" in signal.lower() or "noise" in signal.lower() for signal in outcome.signals)


def test_image_detection_rejects_corrupted_media(tmp_path):
    path = tmp_path / "broken.jpg"
    path.write_bytes(b"not-an-image")

    with pytest.raises(RealityDetectionError):
        RealityDetectionEngine().analyze_image(str(path), "image/jpeg")


def test_image_route_rejects_large_file(client, auth_token):
    big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/scan/reality/image",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("huge.png", io.BytesIO(big), "image/png")},
    )
    assert response.status_code in {400, 413}
