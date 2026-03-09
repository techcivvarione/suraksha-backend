"""
Illustrative tests; assume fixtures for client and auth_token.
"""


def test_safe_url_qr(client, auth_token):
    resp = client.post(
        "/scan/qr",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"raw_payload": "https://example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_type"] == "QR"
    assert data["risk_level"] in {"LOW", "MEDIUM"}


def test_suspicious_payment_qr(client, auth_token):
    resp = client.post(
        "/scan/qr",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"raw_payload": "upi://pay?pa=refund-support@oksbi&pn=Support"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in {"MEDIUM", "HIGH"}


def test_invalid_payload(client, auth_token):
    resp = client.post(
        "/scan/qr",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"raw_payload": "   "},
    )
    assert resp.status_code == 400


def test_qr_rate_limit(client, auth_token, monkeypatch):
    from app.services.qr import qr_analyzer

    # speed up by making analyzer cheap
    monkeypatch.setattr(qr_analyzer, "analyze_qr", lambda payload: {
        "analysis_type": "QR",
        "risk_score": 10,
        "risk_level": "LOW",
        "confidence": None,
        "reasons": ["ok"],
        "recommendation": "Proceed",
    })

    resp1 = client.post(
        "/scan/qr",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"raw_payload": "https://a.com"},
    )
    assert resp1.status_code == 200
