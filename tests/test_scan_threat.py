"""
Illustrative tests; assume fixtures for client and auth_token.
"""


def test_phishing_message(client, auth_token):
    msg = "Your bank account will be blocked. Verify account now: https://bit.ly/phish"
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in {"MEDIUM", "HIGH"}


def test_safe_message(client, auth_token):
    msg = "Hello, meeting at 3pm to review the report."
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in {"LOW", "MEDIUM"}


def test_suspicious_url(client, auth_token):
    msg = "Pay now at https://example.com/pay"
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in {"MEDIUM", "HIGH"}


def test_invalid_empty(client, auth_token):
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "   "},
    )
    assert resp.status_code == 400


def test_threat_response_uses_unknown_when_risk_level_missing(client, auth_token, monkeypatch):
    from app.routes import scan_threat as scan_threat_route

    monkeypatch.setattr(
        scan_threat_route,
        "analyze_threat",
        lambda text: {
            "analysis_type": "THREAT",
            "risk_score": 0,
            "risk_level": None,
            "confidence": None,
            "reasons": ["No classifier output"],
            "recommendation": None,
        },
    )

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "test message"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "risk_level" in data
    assert data["risk_level"] == "UNKNOWN"
