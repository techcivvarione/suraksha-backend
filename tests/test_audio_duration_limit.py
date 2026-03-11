import io
import wave


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _wav_payload(seconds: int) -> bytes:
    sample_rate = 16000
    frames = b"\x00\x00" * sample_rate * seconds
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(frames)
    return buffer.getvalue()


def test_audio_duration_over_sixty_seconds_returns_structured_error(client, monkeypatch):
    import app.routes.scan_reality_audio as scan_reality_audio
    from app.services.reality.voice_deepfake_detector import VoiceDeepfakeDetector

    monkeypatch.setattr(scan_reality_audio, "audio_detector", VoiceDeepfakeDetector())

    response = client.post(
        "/scan/reality/audio",
        headers=_headers("free-token"),
        files={"file": ("long.wav", io.BytesIO(_wav_payload(61)), "audio/wav")},
    )

    assert response.status_code == 400
    assert response.json() == {
        "success": False,
        "error": "SCAN_BAD_REQUEST",
        "message": "Audio duration exceeds 60 seconds",
    }
