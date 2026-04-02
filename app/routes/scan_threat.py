import logging
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import normalize_plan
from app.db import get_db
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.schemas.scan_response import ScanResponse
from app.schemas.scan_threat import ThreatScanRequest
from app.services.alert_rate_limiter import enforce_alert_limits
from app.services.threat.threat_analyzer import analyze_threat
from app.services.response_builder import build_scan_response
from app.services.risk_mapper import derive_risk_level_from_score
from app.services.safe_response import safe_scan_response
from app.services.scan_logger import log_scan_event
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts, try_create_scan_alert
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
    scan_id = generate_scan_id()
    client_ip = (request.client.host if request.client else None) or "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    try:
        # ------------------------------------------------------------------
        # STEP 5 — Input validation: strict but safe (never 500 on bad input)
        # ------------------------------------------------------------------
        raw_text = (payload.text or "").strip()
        if not raw_text:
            raise HTTPException(status_code=400, detail="Text required")
        if len(raw_text) > 5000:
            raise HTTPException(status_code=400, detail="Text too long")

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/scan/threat",
            client_ip=client_ip,
            user_namespace="scan:threat:user",
            user_limit=100,
            ip_namespace="scan:threat:ip",
            ip_limit=300,
            plan_limit_policy="plan_quota",
            scan_type="threat",
        )

        result = analyze_threat(raw_text)

        response = ScanResponse.model_validate(
            build_scan_response(
                analysis_type=ScanType.THREAT.value,
                risk_score=result.get("risk_score"),
                risk_level=result.get("risk_level") or derive_risk_level_from_score(result.get("risk_score") or 0),
                reasons=result.get("reasons"),
                recommendation=result.get("recommendation"),
                confidence=float(result.get("confidence") or 0.0),
                summary=result.get("explanation") or result.get("summary"),
                signals=result.get("signals"),
                detected_type=result.get("detected_type"),
                is_flagged=bool(result.get("is_scam_likely")),
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

        try:
            db.execute(
                text(
                    """
                    INSERT INTO scan_history (
                        id, user_id, input_text, risk, score, reasons, scan_type, created_at
                    )
                    VALUES (
                        CAST(:id AS uuid), CAST(:user_id AS uuid),
                        :input_text, :risk, :score, :reasons, :scan_type, now()
                    )
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {
                    "id": scan_id,
                    "user_id": str(current_user.id),
                    "input_text": raw_text[:1000],
                    "risk": str(response.risk_level or derive_risk_level_from_score(int(response.risk_score or 0))).lower(),
                    "score": int(response.risk_score),
                    "reasons": json.dumps(response.reasons),
                    "scan_type": ScanType.THREAT.value,
                },
            )
            db.commit()
        except Exception:
            logger.exception(
                "scan_history_write_failed",
                extra={"endpoint": "/scan/threat", "user_id": str(current_user.id)},
            )
            # DB history write failure must NOT break the scan response

        final_payload = response.model_dump(mode="json", exclude_none=True)
        logger.info(
            "scan_threat_response",
            extra={
                "user_id": str(current_user.id),
                "scan_id": str(scan_id),
                "risk_score": int(response.risk_score),
                "risk_level": str(response.risk_level),
                "endpoint": "/scan/threat",
            },
        )

        # Create alert for MEDIUM (≥40) or HIGH (≥70) risk — safe helper, never raises
        try_create_scan_alert(
            db,
            user=current_user,
            client_ip=client_ip,
            risk_score=int(response.risk_score),
            analysis_type="THREAT",
            scan_id=scan_id,
        )

        return final_payload

    except HTTPException:
        # 400 / 429 / 401 — re-raise; these are intentional client errors
        raise
    except Exception:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/scan/threat",
                "user_id": str(getattr(current_user, "id", "unknown")),
                "input_size": len(getattr(payload, "text", "") or ""),
            },
        )
        return safe_scan_response(
            scan_id=scan_id,
            analysis_type=ScanType.THREAT.value,
            endpoint="/scan/threat",
        )
