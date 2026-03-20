from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.alert_event import AlertEvent
from app.models.phishing_link import PhishingLink
from app.models.scam_number import ScamNumber
from app.services.notification_service import NotificationService
from app.services.scam_network.normalization import normalize_domain

notifier = NotificationService()


# Aggregation flow pseudocode:
# 1. Recount 24h / 7d / 30d windows for the normalized entity.
# 2. Upsert aggregate row.
# 3. If confirmation threshold is crossed and no recent alert exists, create alert_event.
# 4. Broadcast a cautious push message to affected users.

def update_aggregations(db: Session, report) -> dict:
    result = {'phone_alert_created': False, 'url_alert_created': False}
    if report.normalized_phone_number:
        result['phone_alert_created'] = _update_scam_number(db, report)
    if report.normalized_url:
        result['url_alert_created'] = _update_phishing_link(db, report)
    db.commit()
    return result


def get_number_intelligence(db: Session, normalized_phone_number: str) -> ScamNumber | None:
    return db.query(ScamNumber).filter(ScamNumber.normalized_phone_number == normalized_phone_number).first()


def _update_scam_number(db: Session, report) -> bool:
    counts = _phone_counts(db, report.normalized_phone_number)
    aggregate = get_number_intelligence(db, report.normalized_phone_number)
    if not aggregate:
        aggregate = ScamNumber(
            normalized_phone_number=report.normalized_phone_number,
            display_phone_number=report.scam_phone_number,
        )
        db.add(aggregate)
    aggregate.display_phone_number = report.scam_phone_number or aggregate.display_phone_number
    aggregate.report_count_24h = counts['report_count_24h']
    aggregate.report_count_7d = counts['report_count_7d']
    aggregate.report_count_30d = counts['report_count_30d']
    aggregate.first_reported_at = counts['first_reported_at']
    aggregate.last_reported_at = counts['last_reported_at']
    aggregate.risk_level = _risk_level_from_count(counts['report_count_24h'], counts['report_count_30d'])
    aggregate.top_category = counts['top_category']
    aggregate.top_regions = counts['top_regions']

    if counts['report_count_24h'] >= 5 and counts['distinct_users_24h'] >= 3:
        aggregate.status = 'CONFIRMED_PATTERN'
        if not aggregate.latest_alert_event_id:
            event = _create_alert_event(db, user_id=report.user_id, entity_key=report.normalized_phone_number, risk_score=85)
            aggregate.latest_alert_event_id = str(event.id)
            _broadcast_regional_alert(
                db,
                title='GO Suraksha Alert',
                body='Multiple users reported suspicious call activity in your region.',
                state=report.state,
                country=report.country,
            )
            return True
    else:
        aggregate.status = 'REPORTED_PATTERN'
    return False


def _update_phishing_link(db: Session, report) -> bool:
    counts = _url_counts(db, report.normalized_url)
    aggregate = db.query(PhishingLink).filter(PhishingLink.normalized_url == report.normalized_url).first()
    if not aggregate:
        aggregate = PhishingLink(normalized_url=report.normalized_url, domain=normalize_domain(report.normalized_url) or 'unknown')
        db.add(aggregate)
    aggregate.domain = normalize_domain(report.normalized_url) or aggregate.domain
    aggregate.report_count_24h = counts['report_count_24h']
    aggregate.report_count_7d = counts['report_count_7d']
    aggregate.report_count_30d = counts['report_count_30d']
    aggregate.first_reported_at = counts['first_reported_at']
    aggregate.last_reported_at = counts['last_reported_at']
    aggregate.risk_level = _risk_level_from_count(counts['report_count_24h'], counts['report_count_30d'])
    if counts['report_count_24h'] >= 3:
        aggregate.status = 'CONFIRMED_PATTERN'
        if not aggregate.latest_alert_event_id:
            event = _create_alert_event(db, user_id=report.user_id, entity_key=report.normalized_url, risk_score=80)
            aggregate.latest_alert_event_id = str(event.id)
            return True
    else:
        aggregate.status = 'REPORTED_PATTERN'
    return False
def fetch_trending(db: Session, limit: int = 10) -> list[dict]:
    """Return top scam campaigns ordered by 24h report count for the trending feed."""
    rows = db.execute(
        text(
            '''
            SELECT
                sn.normalized_phone_number,
                sn.display_phone_number,
                sn.top_category,
                sn.report_count_24h,
                sn.top_regions
            FROM scam_numbers sn
            WHERE sn.status = 'CONFIRMED_PATTERN'
            ORDER BY sn.report_count_24h DESC
            LIMIT :limit
            '''
        ),
        {'limit': limit},
    ).mappings().all()

    campaigns = []
    for i, row in enumerate(rows):
        top_regions = row['top_regions'] or []
        regions_affected = [
            r.get('state') or r.get('country') or 'Unknown'
            for r in top_regions
            if r.get('state') or r.get('country')
        ]
        category = row['top_category']
        report_count = int(row['report_count_24h'] or 0)
        campaigns.append({
            'id': row['normalized_phone_number'] or str(i),
            'scamType': category or 'Unknown',
            'reportCount': report_count,
            'regionsAffected': regions_affected[:5],
            'explanation': f'{report_count} user{"s" if report_count != 1 else ""} reported suspicious activity in the last 24 hours.',
            'preventionTips': _prevention_tips_for_category(category),
            'category': category,
            'recentActivityTimeline': [],
        })
    return campaigns


def _prevention_tips_for_category(category: str | None) -> list[str]:
    tips: dict[str, list[str]] = {
        'call': ['Never share your OTP over the phone', 'Verify caller identity independently'],
        'sms': ['Do not click links in unsolicited SMS', 'Report suspicious messages to your carrier'],
        'link': ['Check the URL before clicking', 'Keep your browser and antivirus updated'],
        'payment': ['Verify payment requests through official channels', 'Never transfer money under urgency'],
    }
    return tips.get((category or '').lower(), ['Stay alert', 'Report suspicious activity to authorities'])


def fetch_alerts(db: Session, *, state: str | None, country: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
    rows = db.execute(
        text(
            '''
            SELECT
                ae.id,
                ae.created_at,
                sn.display_phone_number,
                sn.top_category,
                sn.report_count_24h,
                sn.risk_level,
                COALESCE((sn.top_regions->0->>'state'), :state) AS state,
                COALESCE((sn.top_regions->0->>'country'), :country) AS country
            FROM alert_events ae
            LEFT JOIN scam_numbers sn
              ON sn.latest_alert_event_id = CAST(ae.id AS text)
            WHERE ae.analysis_type = 'SCAM'
              AND (:state IS NULL OR COALESCE((sn.top_regions->0->>'state'), '') = :state)
              AND (:country IS NULL OR COALESCE((sn.top_regions->0->>'country'), '') = :country)
            ORDER BY ae.created_at DESC
            LIMIT :limit OFFSET :offset
            '''
        ),
        {'state': state, 'country': country, 'limit': limit, 'offset': offset},
    ).mappings().all()
    total = db.execute(text("SELECT COUNT(*) FROM alert_events WHERE analysis_type = 'SCAM'")).scalar()
    items = [
        {
            'id': row['id'],
            'entity_type': 'phone_number',
            'entity_label': row['display_phone_number'] or 'Unknown',
            'category': row['top_category'],
            'risk_level': row['risk_level'] or 'medium',
            'report_count_24h': int(row['report_count_24h'] or 0),
            'region': {'state': row['state'], 'country': row['country']},
            'message': 'Reported by users as suspicious.',
            'created_at': row['created_at'],
        }
        for row in rows
    ]
    return items, int(total or 0)


def _phone_counts(db: Session, normalized_phone_number: str) -> dict:
    now = datetime.now(timezone.utc)
    row = db.execute(
        text(
            '''
            SELECT
                COUNT(*) FILTER (WHERE created_at >= :d1) AS report_count_24h,
                COUNT(*) FILTER (WHERE created_at >= :d7) AS report_count_7d,
                COUNT(*) FILTER (WHERE created_at >= :d30) AS report_count_30d,
                COUNT(DISTINCT user_id) FILTER (WHERE created_at >= :d1) AS distinct_users_24h,
                MIN(created_at) AS first_reported_at,
                MAX(created_at) AS last_reported_at,
                (ARRAY_AGG(category ORDER BY created_at DESC))[1] AS top_category,
                JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT('state', state, 'country', country)) FILTER (WHERE state IS NOT NULL OR country IS NOT NULL) AS top_regions
            FROM scam_reports
            WHERE normalized_phone_number = :phone
            '''
        ),
        {'phone': normalized_phone_number, 'd1': now - timedelta(days=1), 'd7': now - timedelta(days=7), 'd30': now - timedelta(days=30)},
    ).mappings().first()
    return dict(row or {})


def _url_counts(db: Session, normalized_url: str) -> dict:
    now = datetime.now(timezone.utc)
    row = db.execute(
        text(
            '''
            SELECT
                COUNT(*) FILTER (WHERE created_at >= :d1) AS report_count_24h,
                COUNT(*) FILTER (WHERE created_at >= :d7) AS report_count_7d,
                COUNT(*) FILTER (WHERE created_at >= :d30) AS report_count_30d,
                MIN(created_at) AS first_reported_at,
                MAX(created_at) AS last_reported_at
            FROM scam_reports
            WHERE normalized_url = :url
            '''
        ),
        {'url': normalized_url, 'd1': now - timedelta(days=1), 'd7': now - timedelta(days=7), 'd30': now - timedelta(days=30)},
    ).mappings().first()
    return dict(row or {})
def _risk_level_from_count(report_count_24h: int, report_count_30d: int) -> str:
    if report_count_24h >= 5 or report_count_30d >= 20:
        return 'high'
    if report_count_24h >= 2 or report_count_30d >= 5:
        return 'medium'
    return 'low'


def _create_alert_event(db: Session, *, user_id, entity_key: str, risk_score: int) -> AlertEvent:
    event = AlertEvent(
        user_id=user_id,
        media_hash=hashlib.sha256(entity_key.encode('utf-8')).hexdigest(),
        analysis_type='SCAM',
        risk_score=risk_score,
        status='SENT',
    )
    db.add(event)
    db.flush()
    return event


def _broadcast_regional_alert(db: Session, *, title: str, body: str, state: str | None, country: str | None) -> None:
    rows = db.execute(
        text(
            '''
            SELECT DISTINCT user_id
            FROM scam_reports
            WHERE created_at >= :since
              AND (:state IS NULL OR state = :state)
              AND (:country IS NULL OR country = :country)
            LIMIT 100
            '''
        ),
        {'since': datetime.now(timezone.utc) - timedelta(days=30), 'state': state, 'country': country},
    ).mappings().all()
    for row in rows:
        notifier.send_push_notification(db=db, contact_user_id=row['user_id'], title=title, body=body, user_id=str(row['user_id']))
