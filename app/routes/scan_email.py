import logging
import hashlib
import unicodedata
from fastapi import APIRouter, Depends, HTTPException, Request
from email_validator import EmailNotValidError, validate_email

from app.core.features import normalize_plan
from app.routes.scan_base import (
    apply_scan_rate_limits,
    generate_scan_id,
    is_unlimited_scan_plan,
    raise_scan_error,
    require_user,
)
from app.schemas.scan_email import EmailScanRequest
from app.services.email import email_analyzer
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/email")
def scan_email(
    payload: EmailScanRequest,
    request: Request,
    current_user=Depends(require_user),
):
    raw_email = (payload.email or "").strip()
    if not raw_email:
        raise HTTPException(status_code=400, detail="Email required")
    if len(raw_email) > 320:
        raise HTTPException(status_code=400, detail="Email too long")

    try:
        normalized = validate_email(raw_email, check_deliverability=False).email.lower()
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email format")

    normalized = unicodedata.normalize("NFKC", normalized)

    scan_id = generate_scan_id()
    client_ip = request.client.host or "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    apply_scan_rate_limits(
        current_user=current_user,
        endpoint="/scan/email",
        client_ip=client_ip,
        user_namespace="scan:email:user",
        user_limit=50,
        ip_namespace="scan:email:ip",
        ip_limit=120,
    )

    try:
        result = email_analyzer.analyze_email(normalized, user_plan=plan)
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "scan_processing_failed",
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/email"},
        )
        raise_scan_error(500, "SCAN_PROCESSING_ERROR", "Scan could not be completed.")

    base_response = {
        "analysis_type": ScanType.EMAIL.value,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "reasons": result["reasons"],
        "recommendation": result["recommendation"],
        "confidence": result["confidence"],
        "breach_count": result.get("breach_count"),
    }
    if is_unlimited_scan_plan(current_user):
        base_response["breaches"] = result.get("breaches")

    response = build_scan_response(
        scan_id=scan_id,
        **base_response,
    )

    log_scan_event(
        scan_id=scan_id,
        user_id=str(current_user.id),
        scan_type=ScanType.EMAIL.value,
        risk_score=result["risk_score"],
        endpoint="/scan/email",
        plan=plan,
    )

    return response
