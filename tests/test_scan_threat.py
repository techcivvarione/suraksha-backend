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
    assert "install malicious apps" in (data.get("detailed_explanation") or "").lower()


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
    assert data["risk_score"] >= 41
    assert "Shortened link hides real destination" in data["risk_reason"]
    assert data["original_url"] == "https://bit.ly/phish"
    assert data["final_url"] == "https://bit.ly/phish"
    assert data["redirect_detected"] is False
    assert data["simple_explanation"] == "This looks risky because this link hides its real destination."
    assert data["limited_analysis"] is True
    assert data["redirect_chain"] == ["https://bit.ly/phish"]
    assert isinstance(data["confidence_score"], int)


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


def test_low_risk_explanation_matches_final_score(client, auth_token):
    msg = "Hello, meeting at 3pm to review the report."
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": msg},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] <= 40
    assert data["risk_level"] == "LOW"
    assert data["summary"] == "No major threats detected, but stay cautious"
    assert "Final risk: LOW" in data["detailed_explanation"]


def test_redirect_mismatch_increases_risk(client, auth_token, monkeypatch):
    from app.services.threat import threat_analyzer

    monkeypatch.setattr(
        threat_analyzer,
        "_resolve_redirect_chain",
        lambda url, max_redirects=5: (["https://1kx.in/bajaj", "https://fake-bajaj-login.xyz/secure-login"], False, False),
    )
    monkeypatch.setattr(threat_analyzer, "_matches_safe_browsing", lambda url: False)
    monkeypatch.setattr(threat_analyzer, "_get_domain_age_days", lambda domain: None)

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "Check this payment link: https://1kx.in/bajaj"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["redirect_detected"] is True
    assert data["original_url"] == "https://1kx.in/bajaj"
    assert data["final_url"] == "https://fake-bajaj-login.xyz/secure-login"
    assert data["domain"] == "fake-bajaj-login.xyz"
    assert data["risk_level"] == "HIGH"
    assert data["redirect_chain"] == ["https://1kx.in/bajaj", "https://fake-bajaj-login.xyz/secure-login"]
    assert any("Redirect mismatch" in reason for reason in data["risk_reason"])
    assert "Final risk: HIGH" in data["detailed_explanation"]


def test_brand_impersonation_is_high_risk(client, auth_token, monkeypatch):
    from app.services.threat import threat_analyzer

    monkeypatch.setattr(
        threat_analyzer,
        "_resolve_redirect_chain",
        lambda url, max_redirects=5: ([url], False, False),
    )
    monkeypatch.setattr(threat_analyzer, "_matches_safe_browsing", lambda url: False)
    monkeypatch.setattr(threat_analyzer, "_get_domain_age_days", lambda domain: None)

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "SBI update required now: https://sbi-secure-login.xyz/verify"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert any("Brand mismatch" in reason for reason in data["risk_reason"])
    assert data["simple_explanation"] == "This looks risky because the link does not match the brand mentioned in the message."
    assert data["confidence_score"] >= 80


def test_brand_typo_domain_is_high_risk(client, auth_token, monkeypatch):
    from app.services.threat import threat_analyzer

    monkeypatch.setattr(
        threat_analyzer,
        "_resolve_redirect_chain",
        lambda url, max_redirects=5: ([url], False, False),
    )
    monkeypatch.setattr(threat_analyzer, "_matches_safe_browsing", lambda url: False)
    monkeypatch.setattr(threat_analyzer, "_get_domain_age_days", lambda domain: None)

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "amaz0n refund pending: https://amaz0n-login.top/refund"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] >= 70
    assert data["confidence_score"] >= 80
    assert any("Domain imitates the trusted brand AMAZON" in reason or "Brand mismatch" in reason for reason in data["risk_reason"])


def test_safe_browsing_availability_controls_limited_analysis(client, auth_token, monkeypatch):
    from app.services.threat import threat_analyzer

    monkeypatch.setattr(
        threat_analyzer,
        "_resolve_redirect_chain",
        lambda url, max_redirects=5: ([url], False, False),
    )
    monkeypatch.setattr(threat_analyzer, "_safe_browsing_available", lambda: True)
    monkeypatch.setattr(threat_analyzer, "_matches_safe_browsing", lambda url: False)
    monkeypatch.setattr(threat_analyzer, "_get_domain_age_days", lambda domain: None)

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "Check this link https://example.com/pay"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["limited_analysis"] is False


def test_financial_intent_with_no_link_is_not_low(client, auth_token):
    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "Your KYC update is pending for your bank account."},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] <= 40
    assert data["confidence_label"] == "LOW"


def test_confidence_penalties_apply_for_limited_analysis_and_redirect_failure(client, auth_token, monkeypatch):
    from app.services.threat import threat_analyzer

    monkeypatch.setattr(
        threat_analyzer,
        "_resolve_redirect_chain",
        lambda url, max_redirects=5: ([url], False, True),
    )
    monkeypatch.setattr(threat_analyzer, "_matches_safe_browsing", lambda url: False)
    monkeypatch.setattr(threat_analyzer, "_get_domain_age_days", lambda domain: None)

    resp = client.post(
        "/scan/threat",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"text": "Verify account now: https://bit.ly/phish"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["limited_analysis"] is True
    assert data["confidence_score"] <= 85
    assert data["confidence_label"] in {"MEDIUM", "HIGH"}


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
