import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException

from app.core.features import normalize_plan
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.schemas.scan_password import PasswordScanRequest
from app.services.password.password_analyzer import analyze_password
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/password")
def scan_password(
    payload: PasswordScanRequest,
    current_user=Depends(require_user),
):
    password = (payload.password or "").strip()
    if not password:
        raise HTTPException(status_code=400, detail="Password required")
    if len(password) > 256:
        raise HTTPException(status_code=400, detail="Password too long")

    scan_id = generate_scan_id()
    plan = normalize_plan(getattr(current_user, "plan", None))

    apply_scan_rate_limits(
        current_user=current_user,
        endpoint="/scan/password",
        client_ip="ip-unknown",
        user_namespace="scan:password:user",
        user_limit=20,
        ip_namespace="scan:password:ip",
        ip_limit=60,
        plan_limit_policy="plan_quota",
        scan_type="password",
    )

    try:
        result = analyze_password(password)
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "scan_processing_failed",
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/password"},
        )
        raise_scan_error(500, "SCAN_PROCESSING_ERROR", "Scan could not be completed.")
    response = build_scan_response(
        analysis_type=result["analysis_type"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        reasons=result["reasons"],
        recommendation=result["recommendation"],
        confidence=result["confidence"],
        scan_id=scan_id,
    )

    log_scan_event(
        scan_id=scan_id,
        user_id=str(current_user.id),
        scan_type=result["analysis_type"],
        risk_score=result["risk_score"],
        endpoint="/scan/password",
        plan=plan,
    )

    return response
