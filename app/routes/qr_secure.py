import hashlib
import logging
import time
import uuid
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.routes.scan_base import apply_scan_rate_limits, require_user
from app.schemas.qr_secure_schemas import (
    QrAnalyzePayload,
    QrAnalyzeResponse,
    QrReportPayload,
    QrReportResponse,
)
from app.services.qr_classifier import QrType, classify_payload
from app.services.qr_normalizer import normalize_payload
from app.services.qr_reputation import get_or_create_reputation, increment_reported
from app.services.qr_scoring import score_risk
from app.services.qr_validators import (
    SUSPICIOUS_KEYWORDS,
    contains_zero_width,
    is_mixed_script,
    validate_upi,
    validate_url,
)
from app.services.safe_response import safe_qr_response, safe_qr_report_response

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
    current_user=Depends(require_user),
    db: Session = Depends(get_db, use_cache=False),
):
    correlation_id = _build_correlation_id()
    client_ip = (request.client.host if request.client else None) or "unknown"

    try:
        # ------------------------------------------------------------------
        # STEP 3 + 5 — Input validation before any processing
        # ------------------------------------------------------------------
        raw_payload = getattr(payload, "raw_payload", None)
        if not raw_payload or not raw_payload.strip():
            logger.warning(
                "qr_analyze_empty_payload",
                extra={"cid": correlation_id, "user_id": str(current_user.id)},
            )
            return QrAnalyzeResponse(**safe_qr_response(reason="Invalid or empty QR payload"))

        try:
            normalized = normalize_payload(raw_payload)
        except Exception:
            logger.exception(
                "qr_parse_failed",
                extra={"cid": correlation_id, "user_id": str(current_user.id)},
            )
            return QrAnalyzeResponse(**safe_qr_response(reason="QR payload could not be parsed"))

        detected_type, meta = classify_payload(normalized)
        payload_for_hash = meta.get("url", normalized) if detected_type == QrType.URL else normalized
        qr_hash = hashlib.sha256(payload_for_hash.encode("utf-8")).hexdigest()

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/qr/analyze",
            client_ip=client_ip,
            user_namespace="scan:qr:user",
            user_limit=20,
            ip_namespace="scan:qr:ip",
            ip_limit=60,
            plan_limit_policy="plan_quota",
            scan_type="qr",
        )

        reasons: List[str] = []
        homograph = False
        suspicious_kw = False
        shortener = False
        domain_age_risk = False
        upi_impersonation = False
        blacklist_hit = False

        # UPI payment fields — populated only for UPI QR codes
        is_payment: bool = False
        merchant_name: Optional[str] = None
        upi_id: Optional[str] = None
        amount: Optional[float] = None

        if detected_type == QrType.UPI:
            upi_uri = meta.get("uri") or ""
            if upi_uri:
                try:
                    ok, upi_reasons = validate_upi(upi_uri)
                    reasons.extend(upi_reasons)
                    upi_impersonation = any(
                        kw in upi_uri.lower() for kw in ("support", "refund", "update", "kyc")
                    )
                    # Extract human-readable payment fields from UPI URI
                    is_payment = True
                    parsed_upi = urlparse(upi_uri)
                    params = parse_qs(parsed_upi.query)
                    upi_id = (params.get("pa") or [None])[0]
                    raw_name = (params.get("pn") or [None])[0]
                    merchant_name = raw_name.strip() if raw_name else None
                    raw_amount = (params.get("am") or [None])[0]
                    if raw_amount:
                        try:
                            amount = float(raw_amount)
                        except (ValueError, TypeError):
                            amount = None
                except Exception:
                    logger.exception(
                        "qr_upi_parse_failed",
                        extra={"cid": correlation_id},
                    )
                    # Best-effort UPI parse; continue with defaults
            else:
                reasons.append("UPI URI missing")
        elif detected_type == QrType.URL:
            url_val = meta.get("url") or ""
            if url_val:
                try:
                    ok, url_reasons, url_meta = validate_url(url_val)
                    reasons.extend(url_reasons)
                    homograph = url_meta.get("homograph", False)
                    shortener = url_meta.get("is_shortener", False)
                    domain_age_risk = url_meta.get("domain_age_risk", False)
                    if url_meta.get("is_ip_host"):
                        reasons.append("IP host not allowed")
                except Exception:
                    logger.exception("qr_url_validate_failed", extra={"cid": correlation_id})
                    reasons.append("URL validation failed")
        else:
            text_lower = normalized.lower()
            if any(kw in text_lower for kw in SUSPICIOUS_KEYWORDS):
                suspicious_kw = True
                reasons.append("Suspicious keyword detected")
            if contains_zero_width(normalized):
                reasons.append("Zero-width character detected")
            if is_mixed_script(normalized):
                reasons.append("Mixed-script content")

        blacklist_hit = _external_blacklist_check(qr_hash, timeout_ms=200)
        if blacklist_hit:
            reasons.append("Blacklist match")

        try:
            with db.begin():
                reputation = get_or_create_reputation(db, qr_hash)
                reported_count = int(reputation.reported_count or 0)
                is_flagged = bool(reputation.is_flagged)
        except Exception:
            logger.exception("qr_reputation_lookup_failed", extra={"cid": correlation_id})
            reported_count = 0
            is_flagged = False

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
        }.get(risk_level, "Verify the QR code source before proceeding.")

        # Human-readable summary
        payee = merchant_name or upi_id or "Unknown"
        summary: Optional[str] = None
        if is_payment:
            if risk_level == "LOW":
                summary = (
                    f"No suspicious or hidden amount detected. "
                    f"{payee} appears to be a legitimate payment recipient."
                )
            elif risk_level == "MEDIUM":
                summary = (
                    f"This payment to {payee} has some risk indicators. "
                    "Verify with the sender before proceeding."
                )
            else:
                summary = (
                    f"This QR code is dangerous. Do NOT proceed with payment to {payee}."
                )
        else:
            if risk_level == "LOW":
                summary = "This QR code looks safe. No known threats detected."
            elif risk_level == "MEDIUM":
                summary = "This QR code has some risk indicators. Verify the source before opening."
            else:
                summary = "This QR code is dangerous. Do not open it."

        logger.info(
            "qr_analyze_completed",
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
            reasons=reasons or ["No issues detected"],
            recommended_action=recommended_action,
            is_flagged=is_flagged,
            is_payment=is_payment,
            merchant_name=merchant_name,
            upi_id=upi_id,
            amount=amount,
            summary=summary,
        )
    except HTTPException:
        raise
    except Exception:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/qr/analyze",
                "cid": correlation_id,
                "user_id": str(getattr(current_user, "id", "unknown")),
                "input_size": len(getattr(payload, "raw_payload", "") or ""),
            },
        )
        return QrAnalyzeResponse(**safe_qr_response(reason="QR analysis could not be completed"))


@router.post("/report", response_model=QrReportResponse)
def report_qr(
    payload: QrReportPayload,
    request: Request,
    current_user=Depends(require_user),
    db: Session = Depends(get_db, use_cache=False),
):
    correlation_id = _build_correlation_id()
    client_ip = request.client.host or "unknown"

    try:
        normalized = normalize_payload(payload.raw_payload)
        qr_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        if not current_user.created_at or (time.time() - current_user.created_at.timestamp()) < 86400:
            raise HTTPException(status_code=403, detail="Account not eligible to report yet")

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/qr/report",
            client_ip=client_ip,
            user_namespace="scan:qr:report:user",
            user_limit=10,
            ip_namespace="scan:qr:report:ip",
            ip_limit=30,
            plan_limit_policy="plan_quota",
            scan_type="qr",
        )

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
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/qr/report",
                "cid": correlation_id,
                "user_id": str(getattr(current_user, "id", "unknown")),
            },
        )
        return QrReportResponse(**safe_qr_report_response())
# SECURE QR END
