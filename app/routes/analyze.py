from fastapi import APIRouter, Request, Depends, HTTPException
import re
from datetime import datetime, date
import uuid

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

URL_REGEX = r"(https?://[^\s]+)"

# ---------------- soft limits ----------------
DAILY_ANALYZE_LIMIT = 20
USAGE_COUNTER = {}   # user_id -> { "date": date, "count": int }

# ---------------- rate limiting ----------------
ANALYZE_RATE = {}    # user_id -> count
MAX_ANALYZE = 20


def analyze_rate_limit(user_id: str):
    count = ANALYZE_RATE.get(user_id, 0)
    if count >= MAX_ANALYZE:
        raise HTTPException(status_code=429, detail="Analyze limit reached")
    ANALYZE_RATE[user_id] = count + 1


# ---------- helpers ----------
def extract_url(text: str):
    match = re.search(URL_REGEX, text)
    return match.group(0) if match else None


def risk_summary(risk: str):
    if risk == "high":
        return "High-risk scam detected. Immediate action required."
    if risk == "medium":
        return "Potential scam detected. Please proceed with caution."
    return "No strong scam indicators found."


def emergency_actions_india(risk: str):
    if risk == "high":
        return [
            "Do not click links or reply to the message",
            "Call your bank/UPI helpline immediately if money was sent",
            "Report at cybercrime.gov.in or call 1930",
            "Block the sender and save evidence",
        ]
    if risk == "medium":
        return [
            "Verify from official sources",
            "Avoid clicking unknown links",
            "Do not share OTP or personal details",
        ]
    return [
        "No urgent action needed",
        "Stay alert and verify if unsure",
    ]


def update_usage(user_id: str) -> int:
    today = date.today()
    record = USAGE_COUNTER.get(user_id)

    if not record or record["date"] != today:
        USAGE_COUNTER[user_id] = {"date": today, "count": 1}
    else:
        record["count"] += 1

    return USAGE_COUNTER[user_id]["count"]


# ---------- route ----------
@router.post("/", response_model=AnalyzeResponse)
def analyze_input(
    request_data: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
):
    # ---------------- RATE LIMIT (AUTH USERS ONLY) ----------------
    if current_user:
        analyze_rate_limit(str(current_user.id))

    total_score = 0
    detected_reasons = []

    # ---- TEXT analysis ----
    if request_data.type == "text":
        text_result = analyze_text_message(request_data.content)
        total_score += text_result["score"]
        detected_reasons.extend(text_result["reasons"])

        extracted_url = extract_url(request_data.content)
        if extracted_url:
            url_result = analyze_url(extracted_url)
            total_score += url_result["score"]
            detected_reasons.extend(url_result["reasons"])

    # ---- URL-only analysis ----
    elif request_data.type == "url":
        url_result = analyze_url(request_data.content)
        total_score += url_result["score"]
        detected_reasons.extend(url_result["reasons"])

    else:
        return AnalyzeResponse(
            risk="low",
            score=0,
            reasons=["Unsupported input type"],
        )

    # ---- Risk mapping ----
    if total_score >= 70:
        risk = "high"
    elif total_score >= 30:
        risk = "medium"
    else:
        risk = "low"

    summary = risk_summary(risk)
    actions = emergency_actions_india(risk)

    reasons = [
        summary,
        "Why this was flagged:",
        *detected_reasons,
        "What you should do:",
        *actions,
    ]

    # ---------------- DB SAVE (AUTH USERS ONLY) ----------------
    if current_user:
        user_id = str(current_user.id)

        count = update_usage(user_id)
        if count > DAILY_ANALYZE_LIMIT:
            reasons.insert(
                0,
                f"Usage notice: You have used {count} analyses today.",
            )

        db.execute(
            """
            insert into scan_history (
                id,
                user_id,
                input_text,
                risk,
                score,
                reasons,
                created_at
            )
            values (
                :id,
                :user_id,
                :input_text,
                :risk,
                :score,
                :reasons,
                now()
            )
            """,
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "input_text": request_data.content,
                "risk": risk,
                "score": total_score,
                "reasons": {
                    "risk": risk,
                    "score": total_score,
                    "reasons": reasons,
                },
            },
        )
        db.commit()

    return AnalyzeResponse(
        risk=risk,
        score=total_score,
        reasons=reasons,
    )
