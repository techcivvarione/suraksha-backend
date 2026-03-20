from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.routes.auth import get_current_user
from app.schemas.scam_network import (
    ScamAlertsResponse,
    ScamCampaignItem,
    ScamCampaignPageResponse,
    ScamMessageCheckRequest,
    ScamMessageCheckResponse,
    ScamNumberCheckRequest,
    ScamNumberCheckResponse,
    ScamReportRequest,
    ScamReportResponse,
    ScamVerifyCallResponse,
)
from app.services.scam_network.abuse_guard import ScamNetworkAbuseError
from app.services.scam_network.aggregation_service import fetch_alerts, fetch_trending, get_number_intelligence
from app.services.scam_network.message_detection import analyze_message_text
from app.services.scam_network.normalization import normalize_phone_number
from app.services.scam_network.report_service import ScamReportService, record_scan_event

router = APIRouter(prefix='/scam', tags=['Scam Alert Network'])
report_service = ScamReportService()


@router.post('/report', response_model=ScamReportResponse, summary='Report suspicious scam activity')
def report_scam(
    payload: ScamReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        result = report_service.create_report(
            db,
            current_user=current_user,
            payload=payload,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
        )
    except ScamNetworkAbuseError as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    return ScamReportResponse(
        status='reported',
        report_id=str(result.report.id),
        duplicate=result.duplicate,
        message='Report recorded as suspicious.' if not result.duplicate else 'Duplicate suspicious report ignored.',
    )


@router.post('/check-number', response_model=ScamNumberCheckResponse, summary='Check whether a phone number was reported as suspicious')
def check_number(
    payload: ScamNumberCheckRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    normalized_phone, _ = normalize_phone_number(payload.phone_number)
    if not normalized_phone:
        raise HTTPException(status_code=400, detail='Invalid phone number')
    aggregate = get_number_intelligence(db, normalized_phone)
    record_scan_event(
        db,
        phone=normalized_phone,
        category=aggregate.top_category if aggregate else None,
        lat=payload.lat,
        lng=payload.lng,
        city=payload.city,
        state=payload.state,
        country=payload.country,
        source='scan',
    )
    db.commit()
    if not aggregate:
        return ScamNumberCheckResponse(
            suspicion_level='low',
            report_count_24h=0,
            report_count_30d=0,
            message='No user reports found for this number.',
        )
    return ScamNumberCheckResponse(
        suspicion_level=aggregate.risk_level,
        report_count_24h=aggregate.report_count_24h,
        report_count_30d=aggregate.report_count_30d,
        message='This number has been reported by users as suspicious.',
    )


@router.post('/check-message', response_model=ScamMessageCheckResponse, summary='Check a message for phishing patterns')
def check_message(
    payload: ScamMessageCheckRequest,
    current_user=Depends(get_current_user),
):
    result = analyze_message_text(payload.message_text)
    return ScamMessageCheckResponse(
        risk_score=result['risk_score'],
        classification=result['classification'],
        reason=result['reason'],
    )


@router.get('/trending', response_model=list[ScamCampaignItem], summary='Get trending scam campaigns')
def trending_scams(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    campaigns = fetch_trending(db, limit=limit)
    return campaigns


@router.get('/alerts', response_model=ScamCampaignPageResponse, summary='List scam alert network events')
def scam_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    state: str | None = Query(None),
    country: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    limit = page_size
    offset = (page - 1) * page_size
    raw_alerts, total = fetch_alerts(db, state=state, country=country, limit=limit, offset=offset)
    has_more = (offset + limit) < total
    items = [
        ScamCampaignItem(
            id=str(a['id']),
            scamType=a.get('category') or a.get('entity_type') or 'Unknown',
            reportCount=int(a.get('report_count_24h') or 0),
            regionsAffected=[a['region'].get('state') or a['region'].get('country') or 'Unknown']
            if a.get('region') else [],
            explanation=a.get('message') or 'Reported as suspicious.',
            preventionTips=[],
            category=a.get('category'),
            recentActivityTimeline=[],
        )
        for a in raw_alerts
    ]
    return ScamCampaignPageResponse(items=items, page=page, hasMore=has_more)


@router.post('/verify-call', response_model=ScamVerifyCallResponse, summary='Verify whether an incoming phone number was reported as suspicious')
def verify_call(
    payload: ScamNumberCheckRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    normalized_phone, _ = normalize_phone_number(payload.phone_number)
    if not normalized_phone:
        raise HTTPException(status_code=400, detail='Invalid phone number')
    aggregate = get_number_intelligence(db, normalized_phone)
    record_scan_event(
        db,
        phone=normalized_phone,
        category=aggregate.top_category if aggregate else None,
        lat=payload.lat,
        lng=payload.lng,
        city=payload.city,
        state=payload.state,
        country=payload.country,
        source='scan',
    )
    db.commit()
    if not aggregate:
        return ScamVerifyCallResponse(
            risk_level='low',
            reports=0,
            category=None,
            message='No suspicious activity reports found for this number.',
        )
    return ScamVerifyCallResponse(
        risk_level=aggregate.risk_level,
        reports=aggregate.report_count_30d,
        category=aggregate.top_category,
        message='Multiple users reported suspicious activity.' if aggregate.report_count_24h >= 5 else 'Reported by users as suspicious.',
    )
