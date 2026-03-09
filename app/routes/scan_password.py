import uuid
from fastapi import APIRouter, Depends, HTTPException

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.schemas.scan_password import PasswordScanRequest
from app.services.password.password_analyzer import analyze_password
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event

router = APIRouter(prefix="/scan", tags=["Scan"])


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

    apply_rate_limit("scan:password:user", 20, 3600, str(current_user.id))
    apply_rate_limit("scan:password:ip", 60, 3600, "ip-unknown")

    result = analyze_password(password)
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
    )

    return response
