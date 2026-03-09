import hashlib
import unicodedata
from fastapi import APIRouter, Depends, HTTPException, Request
from email_validator import EmailNotValidError, validate_email

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.schemas.scan_email import EmailScanRequest
from app.services.email.email_analyzer import analyze_email
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType
from app.services.redis_store import acquire_cooldown

router = APIRouter(prefix="/scan", tags=["Scan"])


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

    apply_rate_limit("scan:email:user", 50, 3600, str(current_user.id))
    apply_rate_limit("scan:email:ip", 120, 3600, client_ip)
    try:
        email_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if not acquire_cooldown("scan:email:cooldown", 60, str(current_user.id), email_hash):
            raise HTTPException(status_code=429, detail="Please wait before rescanning this email")
    except HTTPException:
        raise
    except Exception:
        # fail closed on redis errors
        raise HTTPException(status_code=429, detail="Rate limited")

    user_plan = (current_user.plan or "GO_FREE").upper()
    is_paid_user = user_plan in {"GO_PRO", "GO_ULTRA"}
    result = analyze_email(normalized, user_plan=user_plan)

    base_response = {
        "analysis_type": ScanType.EMAIL.value,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "reasons": result["reasons"],
        "recommendation": result["recommendation"],
        "confidence": result["confidence"],
        "breach_count": result.get("breach_count"),
    }
    if is_paid_user:
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
    )

    return response
