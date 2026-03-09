from fastapi import APIRouter, Depends, HTTPException, Request

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.schemas.scan_qr import QRScanRequest
from app.services.qr.qr_analyzer import analyze_qr
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType
from app.services.reputation import update_scan_reputation
import hashlib
from sqlalchemy.orm import Session
from app.db import get_db

router = APIRouter(prefix="/scan", tags=["Scan"])


@router.post("/qr")
def scan_qr(
    payload: QRScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_user),
):
    raw_payload = (payload.raw_payload or "").strip()
    if not raw_payload:
        raise HTTPException(status_code=400, detail="Payload required")

    scan_id = generate_scan_id()
    client_ip = request.client.host or "unknown"

    apply_rate_limit("scan:qr:user", 60, 3600, str(current_user.id))
    apply_rate_limit("scan:qr:ip", 200, 3600, client_ip)

    result = analyze_qr(raw_payload)
    hash_value = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    rep_scan, rep_report, rep_flag = update_scan_reputation(db, hash_value, "QR")

    response = build_scan_response(
        analysis_type=ScanType.QR.value,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        reasons=result["reasons"],
        recommendation=result["recommendation"],
        confidence=result["confidence"],
        scan_id=scan_id,
        detected_type=result.get("detected_type"),
        original_payload=result.get("original_payload"),
        reputation_scan_count=rep_scan,
        reputation_report_count=rep_report,
        is_flagged=rep_flag,
    )

    log_scan_event(
        scan_id=scan_id,
        user_id=str(current_user.id),
        scan_type=ScanType.QR.value,
        risk_score=result["risk_score"],
    )

    return response
