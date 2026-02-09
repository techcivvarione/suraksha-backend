from fastapi import APIRouter, Request, Depends, HTTPException
import json
import logging
import uuid
from datetime import date
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.routes.auth import get_current_user
from app.models.user import User
from app.services.trusted_alerts import notify_trusted_contacts
from app.services.family_alerts import notify_family_head


router = APIRouter(prefix="/analyze", tags=["Analyzer"])

# =========================================================
# PLAN-BASED RATE LIMITS (DAILY)
# =========================================================

PLAN_LIMITS = {
    "FREE": {
        "THREAT": 10,
        "EMAIL": 3,
        "PASSWORD": 3,
    },
    "PAID": {
        "THREAT": 100,
        "EMAIL": 20,
        "PASSWORD": 20,
    },
}

# In-memory (safe for now, Redis later)
USAGE_COUNTER = {}

# =========================================================
# RATE LIMIT HELPERS
# =========================================================

def rate_limit_error(plan: str, scan_type: str, limit: int):
    payload = {
        "error": "RATE_LIMIT",
        "scan_type": scan_type,
        "message": f"You’ve reached today’s {scan_type.title()} scan limit",
        "limit": limit,
        "plan": plan,
    }

    if plan == "FREE":
        payload["upgrade"] = {
            "required": True,
            "message": "Upgrade to continue scanning",
            "benefits": [
                "Higher daily scan limits",
                "Full breach source visibility",
                "OCR scam detection",
                "Trusted family alerts",
            ],
        }

    raise HTTPException(status_code=429, detail=payload)


def enforce_rate_limit(user_id: str, plan: str, scan_type: str):
    today = date.today()
    plan = plan.upper()
    scan_type = scan_type.upper()

    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["FREE"])
    max_allowed = limits.get(scan_type)

    if max_allowed is None:
        return

    key = f"{user_id}:{scan_type}"
    record = USAGE_COUNTER.get(key)

    if not record or record["date"] != today:
        USAGE_COUNTER[key] = {"date": today, "count": 1}
        return

    if record["count"] >= max_allowed:
        rate_limit_error(plan, scan_type, max_allowed)

    record["count"] += 1


# =========================================================
# ROUTE
# =========================================================

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
    user_plan = (current_user.plan or "FREE").upper()

    # ---------- RATE LIMIT ----------
    enforce_rate_limit(
        user_id=str(current_user.id),
        plan=user_plan,
        scan_type=scan_type,
    )

    # ---------- ANALYZE ----------
    try:
        result = analyze_input_full(
            scan_type=scan_type,
            content=request_data.content,
            user_plan=user_plan,
        )

        # Normalize AI output
        if result.get("risk") == "dangerous":
            result["risk"] = "high"

    except HTTPException:
        raise
    except Exception:
        logging.exception("Analyze failed")
        raise HTTPException(status_code=400, detail="Analyze failed")

    # ---------- HISTORY REDACTION ----------
    if scan_type == "THREAT":
        stored_input = request_data.content
    elif scan_type == "EMAIL":
        stored_input = "EMAIL_CHECK_REDACTED"
    elif scan_type == "PASSWORD":
        stored_input = "PASSWORD_CHECK_REDACTED"
    else:
        stored_input = "REDACTED"

    # ---------- SAVE SCAN HISTORY ----------
    scan_id = str(uuid.uuid4())

    try:
        db.execute(
            text("""
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
            """),
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
        logging.exception("❌ Failed to save scan history")

    # ---------- UPDATE DAILY SECURITY SCORES ----------
    try:
        db.execute(
            text("""
                INSERT INTO daily_security_scores (
                    id,
                    user_id,
                    score,
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
                    total_scans = daily_security_scores.total_scans + 1
            """),
            {
                "user_id": str(current_user.id),
                "high": 1 if result["risk"] == "high" else 0,
                "medium": 1 if result["risk"] == "medium" else 0,
                "low": 1 if result["risk"] == "low" else 0,
            },
        )
        db.commit()
    except Exception:
        logging.exception("❌ Failed to update daily security scores")

    # ---------- TRUSTED + FAMILY ALERTS ----------
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
            logging.exception("⚠️ Trusted / family alert failed")

    # ---------- RESPONSE ----------
    return AnalyzeResponse(
        risk=result["risk"],
        score=result["score"],
        reasons=result["reasons"],
    )
