from fastapi import APIRouter, Depends, HTTPException, Request

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.schemas.scan_threat import ThreatScanRequest
from app.services.threat.threat_analyzer import analyze_threat
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan", tags=["Scan"])


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

    apply_rate_limit("scan:threat:user", 60, 3600, str(current_user.id))
    apply_rate_limit("scan:threat:ip", 200, 3600, client_ip)

    result = analyze_threat(raw_text)

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
    )

    return response
