from __future__ import annotations

from datetime import datetime, timedelta

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.redis_store import acquire_cooldown, allow_sliding_window


class ScamNetworkAbuseError(Exception):
    pass


def enforce_report_limits(db: Session, *, user_id: str, ip: str | None, entity_key: str) -> None:
    try:
        if not allow_sliding_window('scam:report:user:day', 10, 86400, user_id):
            raise ScamNetworkAbuseError('Daily scam report limit reached')
        if not allow_sliding_window('scam:report:entity:user:hour', 3, 3600, user_id, entity_key):
            raise ScamNetworkAbuseError('Too many reports for the same entity')
        if ip and not allow_sliding_window('scam:report:ip:hour', 25, 3600, ip):
            raise ScamNetworkAbuseError('Rate limited')
    except RedisError:
        if _db_limit_exceeded(db, user_id=user_id, hours=24, limit=10):
            raise ScamNetworkAbuseError('Daily scam report limit reached')


def suppress_duplicate_report(report_hash: str, *, user_id: str) -> bool:
    try:
        return not acquire_cooldown('scam:report:duplicate', 3600, user_id, report_hash)
    except RedisError:
        return False


def _db_limit_exceeded(db: Session, *, user_id: str, hours: int, limit: int) -> bool:
    since = datetime.utcnow() - timedelta(hours=hours)
    count = db.execute(
        text(
            '''
            SELECT COUNT(*)
            FROM scam_reports
            WHERE user_id = CAST(:uid AS uuid)
              AND created_at >= :since
            '''
        ),
        {'uid': user_id, 'since': since},
    ).scalar()
    return int(count or 0) >= limit
