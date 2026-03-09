"""
Illustrative extended tests; assume fixtures for redis, client, auth_token.
"""
import hashlib


def test_repeated_scan_uses_cache(client, auth_token, monkeypatch):
    from app.services.email import email_analyzer

    call_counter = {"count": 0}

    real_lookup = email_analyzer.HIBPProvider.lookup

    def fake_lookup(self, email):
        call_counter["count"] += 1
        return {"breach_count": 2, "latest_year": 2021}

    monkeypatch.setattr(email_analyzer.HIBPProvider, "lookup", fake_lookup)

    for _ in range(2):
        resp = client.post(
            "/scan/email",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"email": "cached@example.com"},
        )
        assert resp.status_code == 200

    assert call_counter["count"] == 1  # cache hit second time


def test_email_rate_limit(client, auth_token, monkeypatch):
    from app.services.email import email_analyzer
    monkeypatch.setattr(email_analyzer.HIBPProvider, "lookup", lambda self, email: {"breach_count": 0})
    resp1 = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "ratelimit@example.com"},
    )
    assert resp1.status_code == 200
    # trigger cooldown same email
    resp2 = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "ratelimit@example.com"},
    )
    assert resp2.status_code == 429


def test_email_normalization(client, auth_token, monkeypatch):
    from app.services.email import email_analyzer
    monkeypatch.setattr(email_analyzer.HIBPProvider, "lookup", lambda self, email: {"breach_count": 1, "latest_year": 2020})
    resp = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": " User+tag@Example.COM "},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "MEDIUM"


def test_email_invalid_format(client, auth_token):
    resp = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "invalid@@example"},
    )
    assert resp.status_code == 400
