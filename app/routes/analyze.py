from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


def emergency_actions_india(risk: str):
    if risk == "high":
        return {
            "immediate_actions": [
                "Do NOT click any links or reply to the message",
                "If money was sent, call your bank/UPI helpline immediately",
                "Block the sender and preserve evidence (screenshots, numbers)"
            ],
            "reporting": [
                "Report at https://www.cybercrime.gov.in",
                "Call 1930 (India cybercrime helpline)"
            ],
            "avoid": [
                "Sharing OTP, PIN, CVV, Aadhaar, PAN",
                "Installing apps or screen-sharing"
            ]
        }

    if risk == "medium":
        return {
            "immediate_actions": [
                "Pause and verify from official sources",
                "Check bank/app notifications directly (not via links)",
                "Warn family members if message is circulating"
            ],
            "reporting": [
                "If suspicious, report at https://www.cybercrime.gov.in"
            ],
            "avoid": [
                "Acting under urgency or threats",
                "Sharing personal details"
            ]
        }

    return {
        "immediate_actions": [
            "No urgent action needed",
            "Stay alert and verify if unsure"
        ],
        "reporting": [],
        "avoid": [
            "Blindly trusting unknown messages"
        ]
    }


def build_summary(risk: str):
    if risk == "high":
        return "High-risk scam suspected. Immediate action recommended."
    if risk == "medium":
        return "Potential scam. Proceed with caution."
    return "No strong scam indicators detected. Stay alert."


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):

    # Analyze input
    if request.type == "url":
        result = analyze_url(request.content)
        score = result["score"]
        reasons = result["reasons"]

    elif request.type == "text":
        result = analyze_text_message(request.content)
        score = result["score"]
        reasons = result["reasons"]

    else:
        return AnalyzeResponse(
            risk="low",
            score=0,
            reasons=["Unsupported input type"]
        )

    # Risk mapping
    if score >= 60:
        risk = "high"
    elif score >= 25:
        risk = "medium"
    else:
        risk = "low"

    summary = build_summary(risk)
    actions = emergency_actions_india(risk)

    # Combine output
    return AnalyzeResponse(
        risk=risk,
        score=score,
        reasons=reasons + [summary] + actions["immediate_actions"] + actions["reporting"]
    )
