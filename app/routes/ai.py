from typing import List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from redis.exceptions import RedisError

from app.core.features import Limit, get_global_limit
from app.services.redis_store import allow_sliding_window

router = APIRouter(prefix="/ai", tags=["AI Insights"])


class InsightRequest(BaseModel):
    input_text: str
    analysis_result: dict


class InsightResponse(BaseModel):
    scam_type: str
    target_group: str
    risk_level: str
    why_dangerous: List[str]
    what_to_do: List[str]


def _enforce_rate_limit(client_ip: str):
    window_seconds = get_global_limit(Limit.AI_INSIGHT_RATE_WINDOW_SECONDS)
    max_requests = get_global_limit(Limit.AI_INSIGHT_RATE_LIMIT_IP)
    try:
        allowed = allow_sliding_window(
            "rate:ai_insight:ip",
            max_requests,
            window_seconds,
            client_ip or "unknown",
        )
    except RedisError:
        raise HTTPException(status_code=503, detail="Rate limiter unavailable")

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "RATE_LIMIT",
                "message": "Too many AI insight requests. Try again later.",
            },
        )


def derive_scam_type(text: str) -> str:
    lowered = text.lower()
    if "otp" in lowered or "bank" in lowered or "upi" in lowered:
        return "Banking / UPI Scam"
    if "job" in lowered or "offer" in lowered:
        return "Job Scam"
    if "crypto" in lowered or "investment" in lowered:
        return "Investment Scam"
    if "delivery" in lowered or "courier" in lowered:
        return "Courier Scam"
    return "General Scam"


def target_group_for(scam_type: str) -> str:
    mapping = {
        "Banking / UPI Scam": "General public",
        "Job Scam": "Job seekers",
        "Investment Scam": "Retail investors",
        "Courier Scam": "Online shoppers",
        "General Scam": "All users"
    }
    return mapping.get(scam_type, "All users")


def actions_for(scam_type: str) -> List[str]:
    mapping = {
        "Banking / UPI Scam": [
            "Do not share OTP or PIN",
            "Contact your bank immediately",
            "Block the sender"
        ],
        "Job Scam": [
            "Do not pay registration fees",
            "Verify company on official website",
            "Ignore unofficial recruiters"
        ],
        "Investment Scam": [
            "Do not send money",
            "Avoid guaranteed return promises",
            "Consult a financial advisor"
        ],
        "Courier Scam": [
            "Do not click tracking links",
            "Check courier status on official site",
            "Ignore urgent payment requests"
        ],
        "General Scam": [
            "Do not click unknown links",
            "Do not share personal information",
            "Report and block the sender"
        ]
    }
    return mapping.get(scam_type, [])


@router.post("/insight", response_model=InsightResponse)
def generate_insight(payload: InsightRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _enforce_rate_limit(client_ip)

    scam_type = derive_scam_type(payload.input_text)
    risk_level = payload.analysis_result.get("risk_level", "Unknown")

    return {
        "scam_type": scam_type,
        "target_group": target_group_for(scam_type),
        "risk_level": risk_level,
        "why_dangerous": payload.analysis_result.get(
            "reasons",
            ["Suspicious patterns detected"]
        ),
        "what_to_do": actions_for(scam_type)
    }
