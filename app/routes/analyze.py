import json
import logging
import uuid

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import (
    Limit,
    get_global_limit,
)
from app.db import get_db
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.models.user import User
from app.routes.auth import get_current_user
from app.services.family_alerts import notify_family_head
from app.services.plan_limits import LimitType, enforce_limit
from app.services.redis_store import allow_sliding_window, acquire_cooldown
from app.services.trusted_alerts import notify_trusted_contacts

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


def validation_error(code: str, message: str, status_code: int = 400):
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": {
                "code": code,
                "message": message,
            }
        },
    )


def normalize_email_input(raw_email: str) -> str:
    value = (raw_email or "").strip()
    if not value:
        validation_error("EMAIL_REQUIRED", "Email is required")

    max_length = get_global_limit(Limit.EMAIL_MAX_LENGTH)
    if len(value) > max_length:
        validation_error("EMAIL_TOO_LONG", f"Email must be <= {max_length} characters")

    try:
        parsed = validate_email(value, check_deliverability=False)
    except EmailNotValidError:
        validation_error("INVALID_EMAIL", "Invalid email format")

    return parsed.email.lower()


def enforce_email_guardrails(
    user_id: str,
    client_ip: str,
    normalized_email: str,
):
    cooldown_seconds = get_global_limit(Limit.EMAIL_GLOBAL_COOLDOWN_SECONDS)
    duplicate_seconds = get_global_limit(Limit.EMAIL_DUPLICATE_SCAN_BLOCK_SECONDS)
    rate_window = get_global_limit(Limit.EMAIL_RATE_WINDOW_SECONDS)
    user_limit = get_global_limit(Limit.EMAIL_RATE_LIMIT_USER)
    ip_limit = get_global_limit(Limit.EMAIL_RATE_LIMIT_IP)

    try:
        global_ok = acquire_cooldown(
            "cooldown:email:global",
            cooldown_seconds,
            normalized_email,
        )
        if not global_ok:
            validation_error(
                "EMAIL_COOLDOWN",
                "Please wait before scanning this email again",
                status_code=429,
            )

        dedupe_ok = acquire_cooldown(
            "cooldown:email:user",
            duplicate_seconds,
            user_id,
            normalized_email,
        )
        if not dedupe_ok:
            validation_error(
                "EMAIL_DUPLICATE_SCAN",
                "This email was scanned recently. Please try again shortly.",
                status_code=429,
            )

        user_rate_ok = allow_sliding_window(
            "rate:email:user",
            user_limit,
            rate_window,
            user_id,
        )
        if not user_rate_ok:
            validation_error(
                "EMAIL_RATE_LIMIT",
                "Too many email scans. Please try again later.",
                status_code=429,
            )

        ip_rate_ok = allow_sliding_window(
            "rate:email:ip",
            ip_limit,
            rate_window,
            client_ip or "unknown",
        )
        if not ip_rate_ok:
            validation_error(
                "EMAIL_RATE_LIMIT",
                "Too many email scans. Please try again later.",
                status_code=429,
            )

    except RedisError:
        logging.exception("Redis email guardrails failed")
        raise HTTPException(status_code=503, detail="Rate limiter unavailable")


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(
    request_data: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.analyzer import analyze_input_full

    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    scan_type = request_data.type.upper()
    user_plan = (current_user.plan or "GO_FREE").upper()
    client_ip = request.client.host if request.client else "unknown"

    if scan_type == "EMAIL":
        normalized_email = normalize_email_input(request_data.content)
        enforce_email_guardrails(
            user_id=str(current_user.id),
            client_ip=client_ip,
            normalized_email=normalized_email,
        )
        content_to_scan = normalized_email
    else:
        content_to_scan = request_data.content

    scan_limit_type = {
        "THREAT": LimitType.THREAT_DAILY,
        "EMAIL": LimitType.EMAIL_MONTHLY,
        "PASSWORD": LimitType.PASSWORD_MONTHLY,
    }.get(scan_type)
    if scan_limit_type:
        enforce_limit(
            current_user,
            scan_limit_type,
            db=db,
            endpoint=request.url.path,
        )

    try:
        result = analyze_input_full(
            scan_type=scan_type,
            content=content_to_scan,
            user_plan=user_plan,
        )

        if result.get("risk") == "dangerous":
            result["risk"] = "high"

    except HTTPException:
        raise
    except Exception:
        logging.exception("Analyze failed")
        raise HTTPException(status_code=400, detail="Analyze failed")

    if scan_type == "THREAT":
        stored_input = request_data.content
    elif scan_type == "EMAIL":
        stored_input = "EMAIL_CHECK_REDACTED"
    elif scan_type == "PASSWORD":
        stored_input = "PASSWORD_CHECK_REDACTED"
    else:
        stored_input = "REDACTED"

    scan_id = str(uuid.uuid4())

    try:
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
                    :id,
                    :user_id,
                    :input_text,
                    :risk,
                    :score,
                    :reasons,
                    :scan_type,
                    now()
                )
            """
            ),
            {
                "id": scan_id,
                "user_id": str(current_user.id),
                "input_text": stored_input,
                "risk": result["risk"],
                "score": result["score"],
                "reasons": json.dumps(result["reasons"]),
                "scan_type": scan_type,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        logging.exception("Failed to save scan history")

    try:
        db.execute(
            text(
                """
                INSERT INTO daily_security_scores (
                    id,
                    user_id,
                    score,
                    level,
                    high_risk,
                    medium_risk,
                    low_risk,
                    total_scans,
                    score_date,
                    created_at
                )
                VALUES (
                    gen_random_uuid(),
                    :user_id,
                    0,
                    :level,
                    :high,
                    :medium,
                    :low,
                    1,
                    CURRENT_DATE,
                    now()
                )
                ON CONFLICT (user_id, score_date)
                DO UPDATE SET
                    high_risk = daily_security_scores.high_risk + :high,
                    medium_risk = daily_security_scores.medium_risk + :medium,
                    low_risk = daily_security_scores.low_risk + :low,
                    total_scans = daily_security_scores.total_scans + 1,
                    level = :level
            """
            ),
            {
                "user_id": str(current_user.id),
                "level": result["risk"],
                "high": 1 if result["risk"] == "high" else 0,
                "medium": 1 if result["risk"] == "medium" else 0,
                "low": 1 if result["risk"] == "low" else 0,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        logging.exception("Failed to update daily security scores")

    if result["risk"] == "high":
        try:
            notify_trusted_contacts(
                db=db,
                user_id=str(current_user.id),
                scan_id=scan_id,
            )

            notify_family_head(
                db=db,
                member_user_id=str(current_user.id),
                scan_id=scan_id,
            )
        except Exception:
            logging.exception("Trusted / family alert failed")

    return AnalyzeResponse(**result)
