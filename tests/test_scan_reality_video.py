"""
Illustrative tests; require client/auth fixtures.
"""
import io


def test_valid_video_upload(client, auth_token):
    payload = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100
    resp = client.post(
        "/scan/reality/video",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("video.mp4", io.BytesIO(payload), "video/mp4")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_type"] == "REALITY_VIDEO"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "reasons" in data
    assert "recommendation" in data


def test_oversized_video(client, auth_token):
    big = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * (26 * 1024 * 1024)
    resp = client.post(
        "/scan/reality/video",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("big.mp4", io.BytesIO(big), "video/mp4")},
    )
    assert resp.status_code in (400, 413)
