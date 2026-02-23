import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.qr_models import QrReport, QrReputation, QrScanLog
from app.models.user import User
from app.routes.auth import get_current_user
from app.schemas.qr_schemas import (
    QrAnalyzeRequest,
    QrAnalyzeResponse,
    QrReportRequest,
    QrReportResponse,
)

router = APIRouter(prefix="/qr", tags=["QR"])
logger = logging.getLogger(__name__)

SCAM_FLAG_THRESHOLD = 5
FREE_WEEKLY_SCAN_LIMIT = 3
FREE_WEEKLY_REPORT_LIMIT = 3
TIER_FREE = "FREE"
TIER_PRO = "GO_PRO"
TIER_ULTRA = "GO_ULTRA"
BUSINESS_KEYWORDS = (
    "store",
    "shop",
    "mart",
    "enterprise",
    "traders",
    "solutions",
    "services",
    "agency",
    "pvt",
    "ltd",
    "llp",
    "corp",
    "company",
)


def _is_business_vpa(vpa: str) -> bool:
    normalized = vpa.strip().lower()
    return any(keyword in normalized for keyword in BUSINESS_KEYWORDS)


def _get_subscription_tier(current_user: User) -> str:
    tier = getattr(current_user, "subscription_tier", None)
    if not tier:
        tier = getattr(current_user, "plan", TIER_FREE)
    normalized_tier = str(tier).strip().upper()
    if normalized_tier not in {TIER_FREE, TIER_PRO, TIER_ULTRA}:
        return TIER_FREE
    return normalized_tier


def _get_reputation_snapshot(db: Session, qr_hash: str) -> tuple[int, bool]:
    snapshot = db.execute(
        select(QrReputation.reported_count, QrReputation.is_flagged).where(
            QrReputation.qr_hash == qr_hash
        )
    ).first()
    if not snapshot:
        return 0, False
    return int(snapshot.reported_count or 0), bool(snapshot.is_flagged)


@router.post("/pro/upi/analyze", response_model=QrAnalyzeResponse)
def analyze_upi_qr(
    payload: QrAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    user_id = current_user.id
    subscription_tier = _get_subscription_tier(current_user)

    logger.info(
        "QR analyze request: user_id=%s qr_hash=%s tier=%s",
        user_id,
        payload.qr_hash,
        subscription_tier,
    )
    try:
        with db.begin():
            db.execute(
                select(User.id).where(User.id == user_id).with_for_update()
            ).scalar_one()

            if subscription_tier == TIER_FREE:
                week_ago = datetime.utcnow() - timedelta(days=7)
                weekly_scan_count = db.query(QrScanLog).filter(
                    QrScanLog.user_id == user_id,
                    QrScanLog.created_at >= week_ago
                ).count()
                if weekly_scan_count >= FREE_WEEKLY_SCAN_LIMIT:
                    logger.warning(
                        "QR analyze weekly limit reached: user_id=%s tier=%s scans_last_7_days=%s",
                        user_id,
                        subscription_tier,
                        weekly_scan_count,
                    )
                    raise HTTPException(status_code=403, detail="Weekly QR scan limit reached.")

            db.execute(
                pg_insert(QrReputation)
                .values(qr_hash=payload.qr_hash)
                .on_conflict_do_nothing(index_elements=[QrReputation.qr_hash])
            )

            reputation = db.execute(
                select(QrReputation)
                .where(QrReputation.qr_hash == payload.qr_hash)
                .with_for_update()
            ).scalar_one()

            reported_count = int(reputation.reported_count or 0)
            scam_flag = reported_count >= SCAM_FLAG_THRESHOLD
            if scam_flag and not reputation.is_flagged:
                reputation.is_flagged = True

            is_business = _is_business_vpa(payload.vpa)

            db.add(
                QrScanLog(
                    user_id=user_id,
                    qr_hash=payload.qr_hash,
                    vpa=payload.vpa,
                    is_business=is_business,
                    scam_flag=scam_flag,
                )
            )

            response = QrAnalyzeResponse(
                qr_hash=payload.qr_hash,
                scam_flag=scam_flag,
                is_business=is_business,
                reported_count=reported_count,
                message="Analysis complete.",
            )

        return response
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        logger.exception(
            "QR analyze failed: user_id=%s qr_hash=%s error=%s",
            user_id,
            payload.qr_hash,
            str(exc),
        )
        raise HTTPException(status_code=500, detail="Unable to analyze QR code.")


@router.post("/pro/report", response_model=QrReportResponse)
def report_qr(
    payload: QrReportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    user_id = current_user.id
    subscription_tier = _get_subscription_tier(current_user)

    logger.info(
        "QR report attempt: user_id=%s qr_hash=%s tier=%s",
        user_id,
        payload.qr_hash,
        subscription_tier,
    )
    try:
        with db.begin():
            db.execute(
                select(User.id).where(User.id == user_id).with_for_update()
            ).scalar_one()

            existing_report = db.execute(
                select(QrReport.id).where(
                    QrReport.user_id == user_id,
                    QrReport.qr_hash == payload.qr_hash,
                )
            ).scalar_one_or_none()
            if existing_report:
                reported_count, is_flagged = _get_reputation_snapshot(
                    db=db,
                    qr_hash=payload.qr_hash,
                )
                return QrReportResponse(
                    qr_hash=payload.qr_hash,
                    message="Already reported.",
                    reported_count=reported_count,
                    is_flagged=is_flagged,
                )

            if subscription_tier == TIER_FREE:
                week_ago = datetime.utcnow() - timedelta(days=7)
                weekly_report_count = db.query(QrReport).filter(
                    QrReport.user_id == user_id,
                    QrReport.created_at >= week_ago
                ).count()
                if weekly_report_count >= FREE_WEEKLY_REPORT_LIMIT:
                    logger.warning(
                        "QR report weekly limit reached: user_id=%s tier=%s reports_last_7_days=%s",
                        user_id,
                        subscription_tier,
                        weekly_report_count,
                    )
                    raise HTTPException(status_code=403, detail="Weekly QR report limit reached.")

            db.add(
                QrReport(
                    user_id=user_id,
                    qr_hash=payload.qr_hash,
                    reason=payload.reason,
                )
            )
            db.flush()

            db.execute(
                pg_insert(QrReputation)
                .values(qr_hash=payload.qr_hash)
                .on_conflict_do_nothing(index_elements=[QrReputation.qr_hash])
            )

            reputation = db.execute(
                select(QrReputation)
                .where(QrReputation.qr_hash == payload.qr_hash)
                .with_for_update()
            ).scalar_one()

            reputation.reported_count = QrReputation.reported_count + 1
            reputation.is_flagged = case(
                (QrReputation.reported_count + 1 >= SCAM_FLAG_THRESHOLD, True),
                else_=QrReputation.is_flagged,
            )
            db.flush()
            db.refresh(reputation)

            return QrReportResponse(
                qr_hash=payload.qr_hash,
                message="Reported successfully.",
                reported_count=int(reputation.reported_count or 0),
                is_flagged=bool(reputation.is_flagged),
            )
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        logger.warning(
            "QR report integrity error: user_id=%s qr_hash=%s error=%s",
            user_id,
            payload.qr_hash,
            str(exc),
        )
        existing_report = db.execute(
            select(QrReport.id).where(
                QrReport.user_id == user_id,
                QrReport.qr_hash == payload.qr_hash,
            )
        ).scalar_one_or_none()
        if existing_report:
            reported_count, is_flagged = _get_reputation_snapshot(
                db=db,
                qr_hash=payload.qr_hash,
            )
            return QrReportResponse(
                qr_hash=payload.qr_hash,
                message="Already reported.",
                reported_count=reported_count,
                is_flagged=is_flagged,
            )
        raise HTTPException(status_code=409, detail="Could not report QR code.")
    except Exception as exc:
        db.rollback()
        logger.exception(
            "QR report failed: user_id=%s qr_hash=%s error=%s",
            user_id,
            payload.qr_hash,
            str(exc),
        )
        raise HTTPException(status_code=500, detail="Unable to report QR code.")
