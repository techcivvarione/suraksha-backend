from app.services.ai_explainer import generate_simple_explanation


def test_high_risk_apk_explanation_is_direct():
    result = generate_simple_explanation(
        risk_level="HIGH",
        signals=[
            "Requests APK installation or links to an APK file",
            "Creates a deadline like 'blocked today' or 'update immediately'",
        ],
    )

    assert result.startswith("⚠️ This is likely a scam.")
    assert "install an app from a link" in result
    assert "tries to rush you" in result
    assert result.endswith("Do not click, pay, reply, or share details.")


def test_high_risk_otp_explanation_never_calls_it_safe():
    result = generate_simple_explanation(
        risk_level="HIGH",
        signals=["Asks you to share or verify an OTP"],
    )

    assert "looks safe" not in result.lower()
    assert "otp" in result.lower()
    assert result.split("\n\n")[0] == "⚠️ This is likely a scam. Do not trust this."


def test_medium_risk_explanation_stays_cautious():
    result = generate_simple_explanation(
        risk_level="MODERATE",
        signals=["Unknown or non-official link detected: fake-offer.xyz"],
    )

    parts = result.split("\n\n")
    assert parts[0] == "⚠️ This looks suspicious. Be careful."
    assert "suspicious link" in parts[1].lower()
    assert parts[2] == "Check with the sender before taking action."


def test_low_risk_explanation_stays_reassuring():
    result = generate_simple_explanation(
        risk_level="LOW",
        signals=["No major scam indicators found"],
    )

    parts = result.split("\n\n")
    assert parts[0] == "✅ This looks safe."
    assert parts[1] == "No major risk was found."
    assert parts[2] == "Still stay alert for anything unusual."


def test_hindi_explanation_stays_fully_localized():
    result = generate_simple_explanation(
        risk_level="HIGH",
        signals=["Asks you to share or verify an OTP"],
        language="hi",
    )

    assert "धोखाधड़ी" in result
    assert "OTP" in result
    assert "Do not click" not in result


def test_telugu_explanation_uses_telugu_templates():
    result = generate_simple_explanation(
        risk_level="MODERATE",
        signals=["Uses a UPI collect or approval trick"],
        language="te",
    )

    assert "అనుమానాస్పదంగా" in result
    assert "చర్య" in result
    assert "suspicious" not in result.lower()


def test_unknown_language_falls_back_to_english():
    result = generate_simple_explanation(
        risk_level="LOW",
        signals=["No major scam indicators found"],
        language="xx",
    )

    assert result.startswith("✅ This looks safe.")
