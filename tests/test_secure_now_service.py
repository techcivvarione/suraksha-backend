from app.services.secure_now import SECURE_NOW_TEMPLATES


def test_secure_now_templates_cover_core_high_risk_scans():
    assert "THREAT" in SECURE_NOW_TEMPLATES
    assert "PASSWORD" in SECURE_NOW_TEMPLATES
    assert "QR" in SECURE_NOW_TEMPLATES


def test_secure_now_password_template_is_actionable():
    item_type, title, description = SECURE_NOW_TEMPLATES["PASSWORD"]
    assert item_type == "WEAK_PASSWORD"
    assert "password" in title.lower()
    assert "strong" in description.lower() or "unique" in description.lower()
