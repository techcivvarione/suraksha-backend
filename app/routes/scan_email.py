import json
import logging
import hashlib
import unicodedata
from fastapi import APIRouter, Depends, HTTPException, Request
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature, has_feature, normalize_plan
from app.db import get_db
from app.routes.scan_base import (
    apply_scan_rate_limits,
    generate_scan_id,
    raise_scan_error,
    require_user,
)
from app.schemas.scan_email import EmailScanRequest
from app.services.email import email_analyzer
from app.services.response_builder import build_scan_response
from app.services.safe_response import safe_scan_response
from app.services.scan_logger import log_scan_event
from app.services.security_alerts import try_create_scan_alert
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/email")
def scan_email(
    payload: EmailScanRequest,
    request: Request,
    current_user=Depends(require_user),
    db: Session = Depends(get_db),
):
    scan_id = generate_scan_id()
    client_ip = (request.client.host if request.client else None) or "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    try:
        # ------------------------------------------------------------------
        # STEP 5 — Input validation: strict but safe (never 500 on bad input)
        # ------------------------------------------------------------------
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

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/scan/email",
            client_ip=client_ip,
            user_namespace="scan:email:user",
            user_limit=50,
            ip_namespace="scan:email:ip",
            ip_limit=120,
            plan_limit_policy="plan_quota",
            scan_type="email",
        )

        result = email_analyzer.analyze_email(normalized, user_plan=plan)

        base_response = {
            "analysis_type": ScanType.EMAIL.value,
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "reasons": result["reasons"],
            "recommendation": result["recommendation"],
            "confidence": result["confidence"],
            "breach_count": result.get("breach_count"),
        }
        if has_feature(current_user, Feature.EMAIL_BREACH_DETAILS):
            base_response["breaches"] = result.get("breaches")

        response = build_scan_response(scan_id=scan_id, **base_response)

        log_scan_event(
            scan_id=scan_id,
            user_id=str(current_user.id),
            scan_type=ScanType.EMAIL.value,
            risk_score=result["risk_score"],
            endpoint="/scan/email",
            plan=plan,
        )

        # ── Persist to scan_history ────────────────────────────────────────
        try:
            db.execute(
                text(
                    """
                    INSERT INTO scan_history (
                        id, user_id, input_text, risk, score, reasons, scan_type, created_at
                    )
                    VALUES (
                        CAST(:id AS uuid), CAST(:user_id AS uuid),
                        :input_text, :risk, :score, CAST(:reasons AS jsonb), :scan_type, now()
                    )
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {
                    "id": scan_id,
                    "user_id": str(current_user.id),
                    "input_text": normalized,
                    "risk": str(result["risk_level"]).lower(),
                    "score": int(result["risk_score"]),
                    "reasons": json.dumps(result["reasons"]),
                    "scan_type": ScanType.EMAIL.value,
                },
            )
            db.commit()
            logger.info(
                "scan_saved",
                extra={"user_id": str(current_user.id), "scan_type": ScanType.EMAIL.value},
            )
        except Exception as e:
            logger.exception(
                "scan_save_failed",
                extra={
                    "error": str(e),
                    "endpoint": "/scan/email",
                    "user_id": str(current_user.id),
                },
            )
            # DB write failure must NOT break the scan response

        # Create alert for MEDIUM / HIGH risk — never breaks scan (safe helper)
        try_create_scan_alert(
            db,
            user=current_user,
            client_ip=client_ip,
            risk_score=int(result["risk_score"]),
            analysis_type="EMAIL",
            scan_id=scan_id,
        )

        return response

    except HTTPException:
        # 400 / 429 / 401 — re-raise; these are intentional client errors
        raise
    except Exception:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/scan/email",
                "user_id": str(getattr(current_user, "id", "unknown")),
                "input_size": len(getattr(payload, "email", "") or ""),
            },
        )
        return safe_scan_response(
            scan_id=scan_id,
            analysis_type=ScanType.EMAIL.value,
            endpoint="/scan/email",
        )
