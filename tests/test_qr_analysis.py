import pytest

from app.services.qr_normalizer import normalize_payload
from app.services.qr_classifier import classify_payload, QrType
from app.services.qr_validators import validate_upi, validate_url


# SECURE QR START
def test_normalize_rejects_empty():
    with pytest.raises(ValueError):
        normalize_payload("   \u200b")


def test_normalize_trims_and_limits():
    assert normalize_payload("  test  ") == "test"
    with pytest.raises(ValueError):
        normalize_payload("a" * 513)


def test_classify_upi():
    t, _ = classify_payload("upi://pay?pa=test@oksbi")
    assert t == QrType.UPI


def test_classify_url():
    t, meta = classify_payload("https://example.com/path?utm_source=x")
    assert t == QrType.URL
    assert "utm_source" not in meta["url"]


def test_reject_javascript_scheme():
    ok, reasons, _ = validate_url("javascript:alert(1)")
    assert not ok
    assert "Unsupported scheme" in reasons


def test_data_uri_rejected():
    ok, reasons, _ = validate_url("data:text/html;base64,PHNjcmlwdA==")
    assert not ok


def test_homograph_detected():
    ok, reasons, meta = validate_url("http://xn--pple-43d.com/login")
    assert not ok
    assert meta["homograph"] is True


def test_zero_width_upi():
    ok, reasons = validate_upi("upi://pay?pa=test\u200b@oksbi")
    assert not ok
    assert any("Zero-width" in r for r in reasons)


def test_long_payload_rejected():
    with pytest.raises(ValueError):
        normalize_payload("x" * 600)


def test_malformed_upi():
    ok, reasons = validate_upi("upi://pay?pa=@@@")
    assert not ok
    assert "Invalid VPA format" in reasons
# SECURE QR END
