def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_password_free_limit_is_monthly(client):
    first = client.post(
        "/scan/password",
        headers=_headers("free-token"),
        json={"password": "FreePass123!"},
    )
    second = client.post(
        "/scan/password",
        headers=_headers("free-token"),
        json={"password": "FreePass456!"},
    )

    assert first.status_code == 200
    assert second.status_code == 429


def test_password_go_pro_limit_is_daily(client):
    responses = [
        client.post(
            "/scan/password",
            headers=_headers("pro-token"),
            json={"password": f"ProPass{index}!123"},
        )
        for index in range(4)
    ]

    assert [response.status_code for response in responses[:3]] == [200, 200, 200]
    assert responses[3].status_code == 429


def test_password_go_ultra_is_unlimited(client):
    responses = [
        client.post(
            "/scan/password",
            headers=_headers("ultra-token"),
            json={"password": f"UltraPass{index}!123"},
        )
        for index in range(5)
    ]

    assert all(response.status_code == 200 for response in responses)
