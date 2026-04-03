from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services.family_protection_access import (
    FEATURE_AUTO_ALERTS,
    FEATURE_FAMILY_DASHBOARD,
    FEATURE_MANUAL_ALERTS,
    FEATURE_TRUSTED_CONTACTS,
    check_feature_access,
    get_family_protection_capabilities,
)


def test_free_user_cannot_add_trusted_contact():
    user = SimpleNamespace(plan="FREE")
    with pytest.raises(HTTPException):
        check_feature_access(user, FEATURE_TRUSTED_CONTACTS)


def test_pro_user_has_manual_alerts_only():
    user = SimpleNamespace(plan="GO_PRO")
    capabilities = get_family_protection_capabilities(user)
    assert capabilities["manual_alerts_enabled"] is True
    assert capabilities["auto_alerts_enabled"] is False
    assert capabilities["family_dashboard_enabled"] is True
    check_feature_access(user, FEATURE_MANUAL_ALERTS)
    with pytest.raises(HTTPException):
        check_feature_access(user, FEATURE_AUTO_ALERTS)


def test_ultra_user_has_full_family_access():
    user = SimpleNamespace(plan="GO_ULTRA")
    capabilities = get_family_protection_capabilities(user)
    assert capabilities["auto_alerts_enabled"] is True
    assert capabilities["family_mode"] == "FULL"
    check_feature_access(user, FEATURE_AUTO_ALERTS)
    check_feature_access(user, FEATURE_FAMILY_DASHBOARD)
