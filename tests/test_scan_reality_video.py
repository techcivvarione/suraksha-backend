"""
Illustrative tests; require client/auth fixtures.
"""
import io


def test_valid_video_upload(client, auth_token, monkeypatch):
    monkeypatch.setattr("app.routes.scan_reality_video.upload_file", lambda file_bytes, filename: f"r2/{filename}")
    payload = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100
    resp = client.post(
        "/scan/reality/video",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("video.mp4", io.BytesIO(payload), "video/mp4")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "processing"
    assert "job_id" in data


def test_oversized_video(client, auth_token):
    big = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * (26 * 1024 * 1024)
    resp = client.post(
        "/scan/reality/video",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("big.mp4", io.BytesIO(big), "video/mp4")},
    )
    assert resp.status_code in (400, 413)
