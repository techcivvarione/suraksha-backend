from datetime import datetime, timezone


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _stub_hibp(monkeypatch):
    from app.services.email.providers.hibp_provider import HIBPProvider

    calls = {"count": 0}

    def lookup(self, email):
        calls["count"] += 1
        return {
            "breach_count": 1,
            "latest_year": 2024,
            "breaches": [{"name": "Example", "domain": "example.com"}],
        }

    monkeypatch.setattr(HIBPProvider, "lookup", lookup)
    return calls


def test_email_scan_limits_free(client, token_users, redis_mock, monkeypatch):
    calls = _stub_hibp(monkeypatch)

    first = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "free-cached@example.com"},
    )
    second = client.post(
        "/scan/email",
        headers=_headers("free-token"),
        json={"email": "free-cached@example.com"},
    )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"] == "SCAN_LIMIT_REACHED"
    assert calls["count"] == 1

    month_bucket = datetime.now(timezone.utc).strftime("%Y%m")
    key = f"scan:{token_users['free-token'].id}:email:{month_bucket}"
    assert redis_mock.values[key] == 1


def test_email_scan_limits_pro(client, token_users, redis_mock, monkeypatch):
    calls = _stub_hibp(monkeypatch)

    responses = [
        client.post(
            "/scan/email",
            headers=_headers("pro-token"),
            json={"email": "pro-cached@example.com"},
        )
        for _ in range(4)
    ]

    assert [response.status_code for response in responses] == [200, 200, 200, 429]
    assert responses[3].json()["error"] == "SCAN_LIMIT_REACHED"
    assert calls["count"] == 1

    day_bucket = datetime.now(timezone.utc).strftime("%Y%m%d")
    key = f"scan:{token_users['pro-token'].id}:email:{day_bucket}"
    assert redis_mock.values[key] == 3


def test_email_scan_limits_ultra(client, monkeypatch):
    calls = _stub_hibp(monkeypatch)

    responses = [
        client.post(
            "/scan/email",
            headers=_headers("ultra-token"),
            json={"email": "ultra-cached@example.com"},
        )
        for _ in range(5)
    ]

    assert all(response.status_code == 200 for response in responses)
    assert calls["count"] == 1
