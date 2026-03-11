from datetime import datetime, timezone


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _stub_hibp(monkeypatch):
    from app.services.email.providers.hibp_provider import HIBPProvider

    monkeypatch.setattr(
        HIBPProvider,
        "lookup",
        lambda self, email: {
            "breach_count": 1,
            "latest_year": 2024,
            "breaches": [{"name": "Example", "domain": "example.com"}],
        },
    )


def test_email_free_limit_is_monthly(client, token_users, redis_mock, monkeypatch):
    _stub_hibp(monkeypatch)
    first = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "free-limit@example.com"},
    )
    second = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "free-limit@example.com"},
    )

    assert first.status_code == 200
    assert second.status_code == 429
    month_bucket = datetime.now(timezone.utc).strftime("%Y%m")
    expected_key = f"scan:{token_users['free-token'].id}:email:{month_bucket}"
    assert expected_key in redis_mock.values


def test_email_go_pro_limit_is_daily(client, monkeypatch):
    _stub_hibp(monkeypatch)
    responses = [
        client.post(
            "/scan/email",
            headers=_headers("pro-token"),
            json={"email": f"user{index}@example.com"},
        )
        for index in range(4)
    ]

    assert [response.status_code for response in responses[:3]] == [200, 200, 200]
    assert responses[3].status_code == 429


def test_email_go_ultra_is_unlimited(client, monkeypatch):
    _stub_hibp(monkeypatch)
    responses = [
        client.post(
            "/scan/email",
            headers=_headers("ultra-token"),
            json={"email": f"ultra{index}@example.com"},
        )
        for index in range(5)
    ]

    assert all(response.status_code == 200 for response in responses)
