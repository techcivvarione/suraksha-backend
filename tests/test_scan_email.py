"""
Illustrative tests; assume test client and fixtures for user auth and breach mocking.
"""


def test_breached_email(client, auth_token, monkeypatch):
    from app.services.email import email_analyzer

    monkeypatch.setattr(
        email_analyzer, "analyze_email", lambda email, user_plan="GO_FREE": {
            "analysis_type": "EMAIL",
            "risk_score": 90,
            "risk_level": "HIGH",
            "confidence": None,
            "reasons": ["Email found in 5 known data breaches"],
            "recommendation": "Reset passwords and enable MFA on all accounts using this email.",
        }
    )

    resp = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "test@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["analysis_type"] == "EMAIL"


def test_clean_email(client, auth_token, monkeypatch):
    from app.services.email import email_analyzer

    monkeypatch.setattr(
        email_analyzer, "analyze_email", lambda email, user_plan="GO_FREE": {
            "analysis_type": "EMAIL",
            "risk_score": 10,
            "risk_level": "LOW",
            "confidence": None,
            "reasons": ["No known data breaches for this email"],
            "recommendation": "No breaches detected; continue safe practices.",
        }
    )

    resp = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "clean@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "LOW"


def test_invalid_email_format(client, auth_token):
    resp = client.post(
        "/scan/email",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"email": "not-an-email"},
    )
    assert resp.status_code == 400
