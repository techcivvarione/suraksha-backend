from app.services.scam_network.message_detection import analyze_message_text
from app.services.scam_network.normalization import normalize_phone_number, normalize_url


def test_normalize_phone_number_india_local():
    normalized, display = normalize_phone_number('98765 43210')
    assert normalized == '+919876543210'
    assert display.endswith('3210')


def test_normalize_url_strips_query_params():
    assert normalize_url('https://Example.com/login?ref=1') == 'https://example.com/login'


def test_message_detection_flags_bank_impersonation():
    result = analyze_message_text('Your bank KYC will expire today. Click link to verify immediately.')
    assert result['risk_score'] >= 70
    assert result['classification'] == 'phishing_suspected'
