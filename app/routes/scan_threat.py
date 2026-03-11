import logging
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.features import normalize_plan
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.schemas.scan_threat import ThreatScanRequest
from app.services.threat.threat_analyzer import analyze_threat
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/threat")
def scan_threat(
    payload: ThreatScanRequest,
    request: Request,
    current_user=Depends(require_user),
):
    raw_text = (payload.text or "").strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Text required")
    if len(raw_text) > 2000:
        raise HTTPException(status_code=400, detail="Text too long")

    scan_id = generate_scan_id()
    client_ip = request.client.host or "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    apply_scan_rate_limits(
        current_user=current_user,
        endpoint="/scan/threat",
        client_ip=client_ip,
        user_namespace="scan:threat:user",
        user_limit=60,
        ip_namespace="scan:threat:ip",
        ip_limit=200,
    )

    try:
        result = analyze_threat(raw_text)
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "scan_processing_failed",
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/threat"},
        )
        raise_scan_error(500, "SCAN_PROCESSING_ERROR", "Scan could not be completed.")

    response = build_scan_response(
        analysis_type=ScanType.THREAT.value,
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
        scan_type=ScanType.THREAT.value,
        risk_score=result["risk_score"],
        endpoint="/scan/threat",
        plan=plan,
    )

    return response
