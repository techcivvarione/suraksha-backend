import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.features import Feature, has_feature, normalize_plan
from app.db import get_db
from app.models.qr_models import QrReport, QrReputation, QrScanLog
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.plan_limits import LimitType, enforce_limit
from app.schemas.qr_schemas import (
    QrAnalyzeRequest,
    QrAnalyzeResponse,
    QrReportRequest,
    QrReportResponse,
)

router = APIRouter(prefix="/qr", tags=["QR"])
logger = logging.getLogger(__name__)

SCAM_FLAG_THRESHOLD = 5

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
    """Check if VPA belongs to a business based on keywords."""
    normalized = vpa.strip().lower()
    return any(keyword in normalized for keyword in BUSINESS_KEYWORDS)


def _get_subscription_tier(current_user: User) -> str:
    """
    Get normalized subscription tier with future-proof fallbacks.
    
    Checks multiple possible column names and normalizes tier values.
    Returns one of normalized plan aliases from app.core.features.
    """
    tier = None
    
    # Primary: subscription_tier
    tier = getattr(current_user, "subscription_tier", None)
    
    # Fallback 1: tier
    if not tier:
        tier = getattr(current_user, "tier", None)
    
    # Fallback 2: plan
    if not tier:
        tier = getattr(current_user, "plan", None)
    
    # Fallback 3: subscription_plan
    if not tier:
        tier = getattr(current_user, "subscription_plan", None)
    
    # Fallback 4: subscription_status
    if not tier:
        tier = getattr(current_user, "subscription_status", None)
    
    if not tier:
        logger.warning(
            f"No subscription tier found for user {current_user.id}, defaulting to FREE"
        )
        return normalize_plan(None)

    normalized = normalize_plan(str(tier))
    logger.info(f"User {current_user.id} tier resolved: {tier} -> {normalized}")
    return normalized


def _is_premium_user(subscription_tier: str) -> bool:
    """Check if user has unlimited QR access."""
    tier_ctx = type("TierCtx", (), {"plan": subscription_tier})()
    return has_feature(tier_ctx, Feature.QR_UNLIMITED)


def _get_reputation_snapshot(db: Session, qr_hash: str) -> tuple[int, bool]:
    """Get current reputation stats for a QR code."""
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
    request: Request,
    payload: QrAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    """
    Analyze a UPI QR code for scam signals.
    
    Free tier: Limited scans
    Pro/Ultra: Unlimited scans
    """
    user_id = current_user.id
    subscription_tier = _get_subscription_tier(current_user)
    is_premium = _is_premium_user(subscription_tier)

    logger.info(
        "QR analyze request: user_id=%s qr_hash=%s tier=%s is_premium=%s",
        user_id,
        payload.qr_hash,
        subscription_tier,
        is_premium,
    )
    
    try:
        with db.begin():
            # Lock user row to prevent race conditions
            db.execute(
                select(User.id).where(User.id == user_id).with_for_update()
            ).scalar_one()

            # Enforce plan limits via centralized limiter.
            enforce_limit(
                current_user,
                LimitType.QR_WEEKLY,
                db=db,
                endpoint=request.url.path,
            )

            # Upsert QR reputation record
            db.execute(
                pg_insert(QrReputation)
                .values(qr_hash=payload.qr_hash)
                .on_conflict_do_nothing(index_elements=[QrReputation.qr_hash])
            )

            # Get reputation data with lock
            reputation = db.execute(
                select(QrReputation)
                .where(QrReputation.qr_hash == payload.qr_hash)
                .with_for_update()
            ).scalar_one()

            reported_count = int(reputation.reported_count or 0)
            scam_flag = reported_count >= SCAM_FLAG_THRESHOLD
            
            # Update flag if threshold crossed
            if scam_flag and not reputation.is_flagged:
                reputation.is_flagged = True

            is_business = _is_business_vpa(payload.vpa)

            # Log the scan
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
        import traceback
        traceback.print_exc()

        logger.exception(
            "QR analyze crashed: user_id=%s qr_hash=%s error=%s",
            user_id,
            payload.qr_hash,
            str(exc),
        )

        db.rollback()
        raise HTTPException(status_code=500, detail=f"QR analysis failed: {str(exc)}")


@router.post("/pro/report", response_model=QrReportResponse)
def report_qr(
    request: Request,
    payload: QrReportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    """
    Report a QR code as suspicious/scam.
    
    Free tier: Limited reports
    Pro/Ultra: Unlimited reports
    """
    user_id = current_user.id
    subscription_tier = _get_subscription_tier(current_user)
    is_premium = _is_premium_user(subscription_tier)

    logger.info(
        "QR report attempt: user_id=%s qr_hash=%s tier=%s is_premium=%s",
        user_id,
        payload.qr_hash,
        subscription_tier,
        is_premium,
    )
    
    try:
        with db.begin():
            # Lock user row
            db.execute(
                select(User.id).where(User.id == user_id).with_for_update()
            ).scalar_one()

            # Check for duplicate report
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

            # Enforce plan limits via centralized limiter.
            enforce_limit(
                current_user,
                LimitType.QR_WEEKLY,
                db=db,
                endpoint=request.url.path,
            )

            # Create report
            db.add(
                QrReport(
                    user_id=user_id,
                    qr_hash=payload.qr_hash,
                    reason=payload.reason,
                )
            )
            db.flush()

            # Upsert reputation
            db.execute(
                pg_insert(QrReputation)
                .values(qr_hash=payload.qr_hash)
                .on_conflict_do_nothing(index_elements=[QrReputation.qr_hash])
            )

            # Update reputation counts
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
        
        # Check if duplicate was created during race
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
        raise HTTPException(status_code=500, detail=f"Unable to report QR code: {str(exc)}")
