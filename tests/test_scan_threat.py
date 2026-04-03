"""
Illustrative tests; assume fixtures for client and auth_token.
"""


def test_apk_scam_is_high_risk(client, auth_token):
    msg = "SBI alert: your account will be blocked tonight. Install app from link https://fast-update-payments.top/sbi_update.apk immediately."
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 90
    assert any("APK" in reason or "apk" in reason for reason in data["reasons"])
    assert "install malicious apps" in (data.get("summary") or "").lower()


def test_otp_scam_is_high_risk(client, auth_token):
    msg = "Dear Customer, share OTP immediately to verify your bank account and avoid suspension."
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 85
    assert any("OTP" in reason or "otp" in reason for reason in data["reasons"])


def test_upi_collect_scam_is_high_risk(client, auth_token):
    msg = "Refund pending. Approve payment collect request in your UPI app now to receive money."
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 80
    assert data.get("detected_type") in {"upi_collect", "payment_panic"}


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
    assert data["risk_score"] <= 45


def test_kyc_install_phrase_is_high_risk(client, auth_token):
    msg = "install app for KYC update"
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 85


def test_bank_verify_phrase_is_high_risk(client, auth_token):
    msg = "click link to verify bank account"
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 80


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


def test_threat_response_derives_risk_level_when_analyzer_omits_it(client, auth_token, monkeypatch):
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
    assert data["risk_level"] == "LOW"


def test_threat_response_is_not_enveloped(client, auth_token):
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "hello world"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "data" not in data
    assert "risk_level" in data
    assert "score" in data
    assert "confidence" in data
    assert "summary" in data


def test_threat_response_confidence_is_numeric_when_analyzer_omits_it(client, auth_token, monkeypatch):
    from app.routes import scan_threat as scan_threat_route

    monkeypatch.setattr(
        scan_threat_route,
        "analyze_threat",
        lambda text: {
            "analysis_type": "THREAT",
            "risk_score": 10,
            "risk_level": "LOW",
            "confidence": None,
            "reasons": ["No strong threat indicators detected"],
            "recommendation": "No major threats detected; stay cautious.",
        },
    )

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "hello world"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["confidence"] == 0.0
