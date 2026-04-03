from app.services.threat.threat_analyzer import analyze_threat


def test_apk_installation_is_never_underestimated():
    result = analyze_threat(
        "Install app from link now to avoid account block: https://verify-fast.top/update.apk"
    )

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 90
    assert result["is_scam_likely"] is True


def test_otp_request_is_high_risk():
    result = analyze_threat(
        "HDFC notice: share OTP immediately to complete account verification."
    )

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 85
    assert any("OTP" in signal or "otp" in signal for signal in result["signals"])


def test_upi_collect_request_is_high_risk():
    result = analyze_threat(
        "Refund pending. Approve collect request and enter UPI PIN to receive money."
    )

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 80
    assert result["detected_type"] in {"upi_collect", "payment_panic"}


def test_benign_message_remains_low_or_moderate():
    result = analyze_threat(
        "Hi, can we move the project review meeting to tomorrow afternoon?"
    )

    assert result["risk_level"] in {"LOW", "MEDIUM"}
    assert result["risk_score"] < 50


def test_install_app_for_kyc_update_is_high_risk():
    result = analyze_threat("install app for KYC update")

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 85
    assert any("KYC" in signal or "install" in signal.lower() for signal in result["signals"])


def test_click_link_to_verify_bank_account_is_high_risk():
    result = analyze_threat("click link to verify bank account")

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 80
    assert any("bank" in signal.lower() or "verify" in signal.lower() for signal in result["signals"])


def test_download_app_to_get_reward_is_high_risk():
    result = analyze_threat("download app to get reward")

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 80
    assert any("install" in signal.lower() or "reward" in signal.lower() for signal in result["signals"])


def test_simple_hello_message_stays_low():
    result = analyze_threat("hello how are you")

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 50
