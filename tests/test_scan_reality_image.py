"""
Illustrative tests; require client/auth fixtures.
"""
import io


def test_valid_image_upload(client, auth_token):
    payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    resp = client.post(
        "/scan/reality/image",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("test.png", io.BytesIO(payload), "image/png")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_type"] == "REALITY_IMAGE"


def test_invalid_mime_image(client, auth_token):
    resp = client.post(
        "/scan/reality/image",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("test.txt", io.BytesIO(b'text'), "text/plain")},
    )
    assert resp.status_code == 400
