from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/ai", tags=["AI Insights"])


# ---------- models ----------
class InsightRequest(BaseModel):
    input_text: str
    analysis_result: dict


class InsightResponse(BaseModel):
    scam_type: str
    target_group: str
    risk_level: str
    why_dangerous: List[str]
    what_to_do: List[str]


# ---------- core logic ----------
def derive_scam_type(text: str) -> str:
    t = text.lower()
    if "otp" in t or "bank" in t or "upi" in t:
        return "Banking / UPI Scam"
    if "job" in t or "offer" in t:
        return "Job Scam"
    if "crypto" in t or "investment" in t:
        return "Investment Scam"
    if "delivery" in t or "courier" in t:
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


# ---------- route ----------
@router.post("/insight", response_model=InsightResponse)
def generate_insight(payload: InsightRequest):
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
