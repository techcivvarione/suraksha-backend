from app.services.scam_network.message_detection import analyze_message_text


def test_check_message_engine_smoke():
    result = analyze_message_text('OTP needed now, verify immediately and click link')
    assert result['classification'] in {'phishing_suspected', 'suspicious'}
