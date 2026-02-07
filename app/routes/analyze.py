from fastapi import APIRouter, Request, Depends, HTTPException
import json
import logging
from datetime import date
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

# ---------------- LIMITS ----------------
DAILY_ANALYZE_LIMIT = 20
USAGE_COUNTER = {}
ANALYZE_RATE = {}
MAX_ANALYZE = 20

# ---------------- RATE LIMIT ----------------
def analyze_rate_limit(user_id):
    count = ANALYZE_RATE.get(user_id, 0)
    if count >= MAX_ANALYZE:
        raise HTTPException(status_code=429, detail="Analyze limit reached")
    ANALYZE_RATE[user_id] = count + 1


def update_usage(user_id) -> int:
    today = date.today()
    record = USAGE_COUNTER.get(user_id)

    if not record or record["date"] != today:
        USAGE_COUNTER[user_id] = {"date": today, "count": 1}
    else:
        record["count"] += 1

    return USAGE_COUNTER[user_id]["count"]

# ---------------- ROUTE ----------------
@router.post("/", response_model=AnalyzeResponse)
def analyze_input(
    request_data: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # 🔒 AUTH REQUIRED
):
    # ✅ Railway-safe import
    from app.services.analyzer import analyze_input_full

    # 🚨 HARD BLOCK IF NO AUTH
    if not current_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required to analyze"
        )

    try:
        analyze_rate_limit(current_user.id)
        result = analyze_input_full(request_data.content)

    except HTTPException:
        raise

    except Exception:
        logging.exception("Analyze failed")
        raise HTTPException(
            status_code=400,
            detail="Unable to analyze input safely. Please try again."
        )

    # ---- STRUCTURED DATA FOR DB ----
    clean_reasons = {
        "summary": result["summary"],
        "flags": result["reasons"],
        "actions": [result["recommended_action"]],
    }

    # ---- FLAT DATA FOR UI ----
    response_reasons = [
        result["summary"],
        "Why this was flagged:",
        *result["reasons"],
        "What you should do:",
        result["recommended_action"],
    ]

    # ---- USAGE TRACKING ----
    count = update_usage(current_user.id)

    if count > DAILY_ANALYZE_LIMIT:
        response_reasons.insert(
            0,
            f"Usage notice: You have used {count} analyses today."
        )

    # ---- SAVE HISTORY (CRITICAL FIX APPLIED) ----
    try:
        db.execute(
            text("""
                INSERT INTO scan_history (
                    user_id,
                    input_text,
                    risk,
                    score,
                    reasons
                )
                VALUES (
                    :user_id,
                    :input_text,
                    :risk,
                    :score,
                    :reasons
                )
            """),
            {
                "user_id": current_user.id,   # ✅ FIX: NO str()
                "input_text": request_data.content,
                "risk": result["risk_level"].lower(),
                "score": result["confidence"],
                "reasons": json.dumps(clean_reasons),
            }
        )
        db.commit()

        logging.info(
            f"Scan history saved for user_id={current_user.id}"
        )

    except Exception:
        logging.exception("CRITICAL: Failed to save scan history")

    return AnalyzeResponse(
        risk=result["risk_level"].lower(),
        score=result["confidence"],
        reasons=response_reasons,
    )
