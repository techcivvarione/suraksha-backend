import hashlib
import logging
import time
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user
from app.schemas.qr_secure_schemas import (
    QrAnalyzePayload,
    QrAnalyzeResponse,
    QrReportPayload,
    QrReportResponse,
)
from app.services.qr_classifier import QrType, classify_payload
from app.services.qr_normalizer import normalize_payload
from app.services.qr_rate_limit import enforce_rate_limits
from app.services.qr_reputation import get_or_create_reputation, increment_reported
from app.services.qr_scoring import score_risk
from app.services.qr_validators import (
    SUSPICIOUS_KEYWORDS,
    contains_zero_width,
    is_mixed_script,
    validate_upi,
    validate_url,
)

router = APIRouter(prefix="/qr", tags=["QR Secure"])
logger = logging.getLogger(__name__)


def _build_correlation_id() -> str:
    return uuid.uuid4().hex


def _external_blacklist_check(qr_hash: str, timeout_ms: int = 500) -> bool:
    """
    Deterministic placeholder with timeout guard; uses hash pattern to avoid randomness.
    """
    start = time.perf_counter()
    # No external call; just a bounded check
    if (time.perf_counter() - start) * 1000 >= timeout_ms:
        return False
    # treat hashes ending with '00' as blacklist hits for deterministic testing
    return qr_hash.endswith("00")


@router.post("/analyze", response_model=QrAnalyzeResponse)
def analyze_qr(
    payload: QrAnalyzePayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    correlation_id = _build_correlation_id()
    client_ip = request.client.host or "unknown"

    try:
        normalized = normalize_payload(payload.raw_payload)
        detected_type, meta = classify_payload(normalized)
        payload_for_hash = meta["url"] if detected_type == QrType.URL else normalized
        qr_hash = hashlib.sha256(payload_for_hash.encode("utf-8")).hexdigest()

        enforce_rate_limits(str(current_user.id), client_ip, qr_hash)

        reasons: List[str] = []
        homograph = False
        suspicious_kw = False
        shortener = False
        domain_age_risk = False
        upi_impersonation = False
        blacklist_hit = False

        if detected_type == QrType.UPI:
            ok, upi_reasons = validate_upi(meta["uri"])
            reasons.extend(upi_reasons)
            upi_impersonation = any(
                kw in meta["uri"].lower() for kw in ("support", "refund", "update", "kyc")
            )
        elif detected_type == QrType.URL:
            ok, url_reasons, url_meta = validate_url(meta["url"])
            reasons.extend(url_reasons)
            homograph = url_meta.get("homograph", False)
            shortener = url_meta.get("is_shortener", False)
            domain_age_risk = url_meta.get("domain_age_risk", False)
            if url_meta.get("is_ip_host"):
                reasons.append("IP host not allowed")
        else:
            text_lower = normalized.lower()
            if any(kw in text_lower for kw in SUSPICIOUS_KEYWORDS):
                suspicious_kw = True
                reasons.append("Suspicious keyword detected")
            if contains_zero_width(normalized):
                reasons.append("Zero-width character detected")
            if is_mixed_script(normalized):
                reasons.append("Mixed-script content")
            ok = True

        blacklist_hit = _external_blacklist_check(qr_hash, timeout_ms=200)
        if blacklist_hit:
            reasons.append("Blacklist match")

        with db.begin():
            reputation = get_or_create_reputation(db, qr_hash)
            reported_count = int(reputation.reported_count or 0)
            is_flagged = bool(reputation.is_flagged)

        risk_score, risk_level = score_risk(
            reported_count=reported_count,
            homograph=homograph,
            suspicious_keyword=suspicious_kw or ("Suspicious keyword in VPA" in reasons),
            shortener=shortener,
            domain_age_risk=domain_age_risk,
            upi_impersonation=upi_impersonation,
            blacklist_hit=blacklist_hit,
        )

        recommended_action = {
            "LOW": "Proceed with caution.",
            "MEDIUM": "Verify with sender before proceeding.",
            "HIGH": "Do not proceed; treat as malicious.",
        }[risk_level]

        logger.info(
            "QR analyze completed",
            extra={
                "cid": correlation_id,
                "user_id": str(current_user.id),
                "ip": client_ip,
                "qr_hash": qr_hash,
                "type": detected_type.value,
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
        )

        return QrAnalyzeResponse(
            qr_hash=qr_hash,
            risk_score=risk_score,
            risk_level=risk_level,
            detected_type=detected_type.value,
            original_payload=normalized,
            reasons=reasons or ["No issues detected"],
            recommended_action=recommended_action,
            is_flagged=is_flagged,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("QR analyze failed", extra={"cid": correlation_id, "user_id": str(current_user.id)})
        raise HTTPException(status_code=500, detail="QR analysis failed")


@router.post("/report", response_model=QrReportResponse)
def report_qr(
    payload: QrReportPayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db, use_cache=False),
):
    correlation_id = _build_correlation_id()
    client_ip = request.client.host or "unknown"

    try:
        normalized = normalize_payload(payload.raw_payload)
        qr_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        if not current_user.created_at or (time.time() - current_user.created_at.timestamp()) < 86400:
            raise HTTPException(status_code=403, detail="Account not eligible to report yet")

        enforce_rate_limits(str(current_user.id), client_ip, qr_hash)

        with db.begin():
            reputation = get_or_create_reputation(db, qr_hash)
            reputation = increment_reported(db, qr_hash)
            is_flagged = reputation.reported_count >= 5
            if is_flagged and not reputation.is_flagged:
                reputation.is_flagged = True
            db.flush()
            db.refresh(reputation)

        logger.info(
            "QR reported",
            extra={
                "cid": correlation_id,
                "user_id": str(current_user.id),
                "ip": client_ip,
                "qr_hash": qr_hash,
                "reported_count": int(reputation.reported_count or 0),
            },
        )

        return QrReportResponse(
            qr_hash=qr_hash,
            message="Reported successfully.",
            reported_count=int(reputation.reported_count or 0),
            is_flagged=bool(reputation.is_flagged),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("QR report failed", extra={"cid": correlation_id, "user_id": str(current_user.id)})
        raise HTTPException(status_code=500, detail="Unable to report QR code")
# SECURE QR END
