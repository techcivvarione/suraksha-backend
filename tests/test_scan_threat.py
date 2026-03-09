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
