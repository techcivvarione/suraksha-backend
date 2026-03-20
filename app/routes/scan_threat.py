import logging
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import normalize_plan
from app.db import get_db
from app.routes.scan_base import generate_scan_id, raise_scan_error, require_user
from app.schemas.scan_response import ScanResponse
from app.schemas.scan_threat import ThreatScanRequest
from app.services.alert_rate_limiter import enforce_alert_limits
from app.services.threat.threat_analyzer import analyze_threat
from app.services.response_builder import build_scan_response
from app.services.scan_logger import log_scan_event
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/threat", response_model=ScanResponse)
def scan_threat(
    payload: ThreatScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_user),
):
    raw_text = (payload.text or "").strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Text required")
    if len(raw_text) > 2000:
        raise HTTPException(status_code=400, detail="Text too long")

    scan_id = generate_scan_id()
    plan = normalize_plan(getattr(current_user, "plan", None))

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

    response = ScanResponse.model_validate(
        build_scan_response(
            analysis_type=ScanType.THREAT.value,
            risk_score=result.get("risk_score"),
            risk_level=result.get("risk_level") or "UNKNOWN",
            reasons=result.get("reasons"),
            recommendation=result.get("recommendation"),
            confidence=result.get("confidence"),
            scan_id=scan_id,
        )
    )

    log_scan_event(
        scan_id=scan_id,
        user_id=str(current_user.id),
        scan_type=ScanType.THREAT.value,
        risk_score=result["risk_score"],
        endpoint="/scan/threat",
        plan=plan,
    )

    db.execute(
        text(
            """
            INSERT INTO scan_history (
                id,
                user_id,
                input_text,
                risk,
                score,
                reasons,
                scan_type,
                created_at
            )
            VALUES (
                CAST(:id AS uuid),
                CAST(:user_id AS uuid),
                :input_text,
                :risk,
                :score,
                :reasons,
                :scan_type,
                now()
            )
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "id": scan_id,
            "user_id": str(current_user.id),
            "input_text": raw_text[:1000],
            "risk": str(response.risk_level or "UNKNOWN").lower(),
            "score": int(response.risk_score),
            "reasons": json.dumps(response.reasons),
            "scan_type": ScanType.THREAT.value,
        },
    )
    db.commit()

    if int(response.risk_score) >= 70:
        try:
            enforce_alert_limits(db, str(current_user.id), request.client.host if request.client else None, None)
            event = create_alert_event(
                db=db,
                user_id=current_user.id,
                trigger_type="THREAT_HIGH_RISK_SCAN",
                analysis_type="THREAT",
                risk_score=int(response.risk_score),
            )
            dispatch_plan_alerts(
                db=db,
                user=current_user,
                trigger_type="THREAT_HIGH_RISK_SCAN",
                risk_score=int(response.risk_score),
                scan_id=scan_id,
                alert_event_id=event.id,
            )
            event.status = "SENT"
            db.add(event)
            db.commit()
        except Exception:
            logger.exception("threat_scan_alert_failed", extra={"scan_id": scan_id, "user_id": str(current_user.id)})

    return response
