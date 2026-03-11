import io


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_invalid_reality_upload_does_not_consume_quota(client):
    invalid = client.post(
        "/scan/reality/image",
        headers=_headers("free-token"),
        files={"file": ("bad.txt", io.BytesIO(b"not-an-image"), "text/plain")},
    )
    valid = client.post(
        "/scan/reality/image",
        headers=_headers("free-token"),
        files={"file": ("photo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32), "image/png")},
    )
    blocked = client.post(
        "/scan/reality/image",
        headers=_headers("free-token"),
        files={"file": ("photo2.png", io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32), "image/png")},
    )

    assert invalid.status_code == 400
    assert valid.status_code == 200
    assert blocked.status_code == 429
