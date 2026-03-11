import io


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _image_payload(name: str):
    return {"file": (name, io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64), "image/png")}


def test_reality_free_limit_is_monthly(client):
    first = client.post("/scan/reality/image", headers=_headers("free-token"), files=_image_payload("free-a.png"))
    second = client.post("/scan/reality/image", headers=_headers("free-token"), files=_image_payload("free-b.png"))

    assert first.status_code == 200
    assert second.status_code == 429


def test_reality_go_pro_limit_is_daily(client):
    responses = [
        client.post("/scan/reality/image", headers=_headers("pro-token"), files=_image_payload(f"pro-{index}.png"))
        for index in range(4)
    ]

    assert [response.status_code for response in responses[:3]] == [200, 200, 200]
    assert responses[3].status_code == 429


def test_reality_go_ultra_is_unlimited(client):
    responses = [
        client.post("/scan/reality/image", headers=_headers("ultra-token"), files=_image_payload(f"ultra-{index}.png"))
        for index in range(5)
    ]

    assert all(response.status_code == 200 for response in responses)
