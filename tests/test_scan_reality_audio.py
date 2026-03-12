"""
Illustrative tests; require client/auth fixtures.
"""
import io


def test_valid_audio_upload(client, auth_token, monkeypatch):
    monkeypatch.setattr("app.routes.scan_reality_audio.upload_file", lambda file_bytes, filename: f"r2/{filename}")
    payload = b"ID3" + b"\x00" * 100
    resp = client.post(
        "/scan/reality/audio",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("audio.mp3", io.BytesIO(payload), "audio/mpeg")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "processing"
    assert "job_id" in data


def test_invalid_mime_audio(client, auth_token):
    resp = client.post(
        "/scan/reality/audio",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("audio.txt", io.BytesIO(b'abc'), "text/plain")},
    )
    assert resp.status_code == 400
