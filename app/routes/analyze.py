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
    current_user: User = Depends(get_current_user),
):
    from app.services.analyzer import analyze_input_full

    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        analyze_rate_limit(current_user.id)
        result = analyze_input_full(request_data.content)
    except HTTPException:
        raise
    except Exception:
        logging.exception("Analyze failed")
        raise HTTPException(status_code=400, detail="Analyze failed")

    clean_reasons = {
        "summary": result["summary"],
        "flags": result["reasons"],
        "actions": [result["recommended_action"]],
    }

    response_reasons = [
        result["summary"],
        "Why this was flagged:",
        *result["reasons"],
        "What you should do:",
        result["recommended_action"],
    ]

    count = update_usage(current_user.id)

    if count > DAILY_ANALYZE_LIMIT:
        response_reasons.insert(
            0,
            f"Usage notice: You have used {count} analyses today."
        )

    # 🔥 FINAL FIX: INSERT ALL REQUIRED COLUMNS
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
                    created_at
                )
                VALUES (
                    :id,
                    :user_id,
                    :input_text,
                    :risk,
                    :score,
                    :reasons,
                    now()
                )
            """),
            {
                "id": str(uuid.uuid4()),
                "user_id": current_user.id,
                "input_text": request_data.content,
                "risk": result["risk_level"].lower(),
                "score": result["confidence"],
                "reasons": json.dumps(clean_reasons),
            }
        )
        db.commit()

        logging.info(f"✅ Scan history saved for user {current_user.id}")

    except Exception:
        logging.exception("❌ Failed to save scan history")

    return AnalyzeResponse(
        risk=result["risk_level"].lower(),
        score=result["confidence"],
        reasons=response_reasons,
    )
