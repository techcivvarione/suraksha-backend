import io

from app.services.reality.providers.base_provider import RealityDetectionError


def _headers(token: str = "free-token") -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_reality_image_hive_error_returns_structured_response(client, monkeypatch):
    import app.routes.scan_reality_image as scan_reality_image

    class FailingDetector:
        async def detect(self, file_path, mime_type):
            raise RealityDetectionError(
                "AI detection service returned an error",
                provider="hive",
                status_code=400,
                response_body='{"error":"invalid file format"}',
            )

    monkeypatch.setattr(scan_reality_image, "image_detector", FailingDetector())

    payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    response = client.post(
        "/scan/reality/image",
        headers=_headers(),
        files={"file": ("test.png", io.BytesIO(payload), "image/png")},
    )

    assert response.status_code == 502
    assert response.json() == {
        "success": False,
        "error": "AI_PROVIDER_ERROR",
        "provider": "hive",
        "message": "AI detection service returned an error",
    }


def test_reality_video_hive_result_is_parsed(client, monkeypatch):
    import app.routes.scan_reality_video as scan_reality_video

    class PassingDetector:
        async def detect(self, file_path, mime_type):
            return {"probability": 0.91, "provider_used": "hive"}

    monkeypatch.setattr(scan_reality_video, "video_detector", PassingDetector())

    payload = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100
    response = client.post(
        "/scan/reality/video",
        headers=_headers(),
        files={"file": ("test.mp4", io.BytesIO(payload), "video/mp4")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_type"] == "REALITY_VIDEO"
    assert body["risk_level"] == "HIGH"


def test_reality_audio_hive_result_is_parsed(client, monkeypatch):
    import app.routes.scan_reality_audio as scan_reality_audio

    class PassingDetector:
        async def detect(self, file_path, mime_type):
            return {"probability": 0.61, "provider_used": "hive"}

    monkeypatch.setattr(scan_reality_audio, "audio_detector", PassingDetector())

    payload = b"ID3" + b"\x00" * 100
    response = client.post(
        "/scan/reality/audio",
        headers=_headers(),
        files={"file": ("test.mp3", io.BytesIO(payload), "audio/mpeg")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_type"] == "REALITY_AUDIO"
    assert body["risk_level"] == "MEDIUM"
