from fastapi import APIRouter, Request, Depends, HTTPException
import json
from datetime import date
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_input_full
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

DAILY_ANALYZE_LIMIT = 20
USAGE_COUNTER = {}
ANALYZE_RATE = {}
MAX_ANALYZE = 20


def analyze_rate_limit(user_id: str):
    count = ANALYZE_RATE.get(user_id, 0)
    if count >= MAX_ANALYZE:
        raise HTTPException(status_code=429, detail="Analyze limit reached")
    ANALYZE_RATE[user_id] = count + 1


def update_usage(user_id: str) -> int:
    today = date.today()
    record = USAGE_COUNTER.get(user_id)

    if not record or record["date"] != today:
        USAGE_COUNTER[user_id] = {"date": today, "count": 1}
    else:
        record["count"] += 1

    return USAGE_COUNTER[user_id]["count"]


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(
    request_data: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
):
    if current_user:
        analyze_rate_limit(str(current_user.id))

    result = analyze_input_full(request_data.content)

    reasons = [
        result["summary"],
        "Why this was flagged:",
        *result["reasons"],
        "Recommended action:",
        result["recommended_action"],
    ]

    if current_user:
        user_id = str(current_user.id)
        count = update_usage(user_id)

        if count > DAILY_ANALYZE_LIMIT:
            reasons.insert(0, f"Usage notice: You have used {count} analyses today.")

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
                "user_id": current_user.id,
                "input_text": request_data.content,
                "risk": result["risk_level"].lower(),
                "score": result["confidence"],
                "reasons": json.dumps(reasons),
            }
        )
        db.commit()

    return AnalyzeResponse(
        risk=result["risk_level"].lower(),
        score=result["confidence"],
        reasons=reasons,
    )
