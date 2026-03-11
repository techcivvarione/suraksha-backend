import io


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _image_payload(name: str) -> dict:
    return {"file": (name, io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32), "image/png")}


def test_free_plan_allows_one_scan_per_month(client):
    first = client.post(
        "/scan/reality/image",
        headers=_headers("free-token"),
        files=_image_payload("free-one.png"),
    )
    second = client.post(
        "/scan/reality/image",
        headers=_headers("free-token"),
        files=_image_payload("free-two.png"),
    )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {
        "success": False,
        "error": "SCAN_LIMIT_REACHED",
        "message": "Free scan limit reached.",
    }


def test_go_pro_allows_three_scans_per_day(client):
    responses = [
        client.post(
            "/scan/reality/image",
            headers=_headers("pro-token"),
            files=_image_payload(f"pro-{index}.png"),
        )
        for index in range(4)
    ]

    assert [response.status_code for response in responses[:3]] == [200, 200, 200]
    assert responses[3].status_code == 429
    assert responses[3].json() == {
        "success": False,
        "error": "SCAN_LIMIT_REACHED",
        "message": "Daily scan limit reached.",
    }


def test_go_ultra_is_unlimited(client):
    responses = [
        client.post(
            "/scan/reality/image",
            headers=_headers("ultra-token"),
            files=_image_payload(f"ultra-{index}.png"),
        )
        for index in range(6)
    ]

    assert all(response.status_code == 200 for response in responses)
