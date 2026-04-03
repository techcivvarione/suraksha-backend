from fastapi import APIRouter, Depends, HTTPException, Request

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.schemas.scan_qr import QRScanRequest
from app.services.qr.qr_analyzer import analyze_qr
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.services.secure_now import create_secure_item_for_scan
from app.enums.scan_type import ScanType
import hashlib
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db import get_db

router = APIRouter(prefix="/scan", tags=["Scan"])


def _update_scan_reputation(db: Session, hash_value: str, hash_type: str):
    db.execute(
        text(
            """
            INSERT INTO scan_reputation (hash_value, hash_type, first_seen, last_seen, scan_count, report_count, is_flagged, created_at, updated_at)
            VALUES (:hv, :ht, now(), now(), 1, 0, false, now(), now())
            ON CONFLICT (hash_value, hash_type)
            DO UPDATE SET
                scan_count = scan_reputation.scan_count + 1,
                last_seen = now(),
                updated_at = now()
            """
        ),
        {"hv": hash_value, "ht": hash_type},
    )
    row = db.execute(
        text(
            """
            SELECT scan_count, report_count, is_flagged
            FROM scan_reputation
            WHERE hash_value = :hv AND hash_type = :ht
            """
        ),
        {"hv": hash_value, "ht": hash_type},
    ).mappings().first()
    db.commit()
    return int(row["scan_count"]), int(row["report_count"]), bool(row["is_flagged"])


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
    rep_scan, rep_report, rep_flag = _update_scan_reputation(db, hash_value, "QR")

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

    if int(result["risk_score"]) >= 70:
        try:
            create_secure_item_for_scan(
                db=db,
                user_id=current_user.id,
                analysis_type=ScanType.QR.value,
                risk_score=int(result["risk_score"]),
                source_scan_id=scan_id,
            )
        except Exception:
            pass

    return response
