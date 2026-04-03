import json
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import normalize_plan
from app.db import get_db
from app.enums.scan_type import ScanType
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.schemas.scan_password import PasswordScanRequest
from app.services.password.password_analyzer import analyze_password
from app.services.response_builder import build_scan_response
from app.services.safe_response import safe_scan_response
from app.services.scan_logger import log_scan_event
from app.services.secure_now import create_secure_item_for_scan

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)


@router.post("/password")
def scan_password(
    payload: PasswordScanRequest,
    current_user=Depends(require_user),
    db: Session = Depends(get_db),
):
    scan_id = generate_scan_id()
    plan = normalize_plan(getattr(current_user, "plan", None))

    try:
        # ------------------------------------------------------------------
        # STEP 5 — Input validation: strict but safe
        # ------------------------------------------------------------------
        password = (payload.password or "").strip()
        if not password:
            raise HTTPException(status_code=400, detail="Password required")
        if len(password) > 256:
            raise HTTPException(status_code=400, detail="Password too long")

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
            scan_type=ScanType.PASSWORD.value,
            risk_score=result["risk_score"],
            endpoint="/scan/password",
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
                    "input_text": "[password]",  # never store the raw password
                    "risk": str(result["risk_level"]).lower(),
                    "score": int(result["risk_score"]),
                    "reasons": json.dumps(result["reasons"]),
                    "scan_type": ScanType.PASSWORD.value.lower(),
                },
            )
            db.commit()
            logger.info(
                "scan_saved",
                extra={"user_id": str(current_user.id), "scan_type": ScanType.PASSWORD.value},
            )
        except Exception as e:
            logger.exception(
                "scan_save_failed",
                extra={
                    "error": str(e),
                    "endpoint": "/scan/password",
                    "user_id": str(current_user.id),
                },
            )
            # DB write failure must NOT break the scan response

        if int(result["risk_score"]) >= 70:
            try:
                create_secure_item_for_scan(
                    db=db,
                    user_id=current_user.id,
                    analysis_type=ScanType.PASSWORD.value,
                    risk_score=int(result["risk_score"]),
                    source_scan_id=scan_id,
                )
            except Exception:
                logger.exception("secure_now_create_failed", extra={"user_id": str(current_user.id), "scan_type": ScanType.PASSWORD.value})

        return response

    except HTTPException:
        # 400 / 429 / 401 — re-raise; these are intentional client errors
        raise
    except Exception:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/scan/password",
                "user_id": str(getattr(current_user, "id", "unknown")),
                "input_size": len(getattr(payload, "password", "") or ""),
            },
        )
        return safe_scan_response(
            scan_id=scan_id,
            analysis_type=ScanType.PASSWORD.value,
            endpoint="/scan/password",
        )
