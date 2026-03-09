import pytest

from app.services.alert_rate_limiter import enforce_alert_limits, AlertRateLimiterError


def test_rate_limit_blocks_duplicate(redis_mock):
    user = "user1"
    ip = "1.1.1.1"
    media_hash = "a" * 64
    # first ok
    redis_mock.clear()
    enforce_alert_limits(user, ip, media_hash)
    with pytest.raises(AlertRateLimiterError):
        enforce_alert_limits(user, ip, media_hash)
