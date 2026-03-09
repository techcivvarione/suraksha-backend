"""
Illustrative tests; assume test client and fixtures for user auth and HIBP mocking.
"""


def test_breached_password(client, auth_token, monkeypatch):
    # Mock HIBP to return count 5
    from app.services.password import hibp_checker

    monkeypatch.setattr(hibp_checker, "check_password_pwned", lambda pwd: 5)

    resp = client.post(
        "/scan/password",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"password": "Password123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "MEDIUM"
    assert data["analysis_type"] == "PASSWORD"


def test_non_breached_password(client, auth_token, monkeypatch):
    from app.services.password import hibp_checker

    monkeypatch.setattr(hibp_checker, "check_password_pwned", lambda pwd: 0)

    resp = client.post(
        "/scan/password",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"password": "UniquePass!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "LOW"


def test_empty_password_validation(client, auth_token):
    resp = client.post(
        "/scan/password",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"password": "   "},
    )
    assert resp.status_code == 400
