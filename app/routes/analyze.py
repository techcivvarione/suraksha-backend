from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


def build_user_guidance(risk: str):
    if risk == "high":
        return {
            "summary": "This looks like a high-risk scam.",
            "do": [
                "Do NOT click links or reply to the message",
                "Block the sender immediately",
                "Contact your bank using official numbers",
                "Report this on the cybercrime portal (cybercrime.gov.in)"
            ],
            "avoid": [
                "Sharing OTP, PIN, CVV, or personal details",
                "Trusting urgency or threats"
            ]
        }

    if risk == "medium":
        return {
            "summary": "This may be a scam. Please be cautious.",
            "do": [
                "Verify the message from an official source",
                "Check the sender carefully",
                "Avoid clicking unknown links"
            ],
            "avoid": [
                "Acting in urgency",
                "Sharing sensitive information"
            ]
        }

    return {
        "summary": "This does not look dangerous, but stay alert.",
        "do": [
            "Continue with normal caution",
            "Verify if unsure"
        ],
        "avoid": [
            "Blindly trusting unknown messages"
        ]
    }


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

    guidance = build_user_guidance(risk)

    # Combine technical + user-friendly response
    return AnalyzeResponse(
        risk=risk,
        score=score,
        reasons=reasons + [guidance["summary"]]
    )
