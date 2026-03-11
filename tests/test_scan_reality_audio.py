"""
Illustrative tests; require client/auth fixtures.
"""
import io


def test_valid_audio_upload(client, auth_token):
    payload = b"ID3" + b"\x00" * 100
    resp = client.post(
        "/scan/reality/audio",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("audio.mp3", io.BytesIO(payload), "audio/mpeg")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_type"] == "REALITY_AUDIO"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "reasons" in data
    assert "recommendation" in data


def test_invalid_mime_audio(client, auth_token):
    resp = client.post(
        "/scan/reality/audio",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("audio.txt", io.BytesIO(b'abc'), "text/plain")},
    )
    assert resp.status_code == 400
