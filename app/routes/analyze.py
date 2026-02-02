from fastapi import APIRouter
import re
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

URL_REGEX = r"(https?://[^\s]+)"


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
            "Block the sender and save evidence"
        ]
    if risk == "medium":
        return [
            "Verify from official sources",
            "Avoid clicking unknown links",
            "Do not share OTP or personal details"
        ]
    return [
        "No urgent action needed",
        "Stay alert and verify if unsure"
    ]


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):

    total_score = 0
    detected_reasons = []

    # TEXT analysis
    if request.type == "text":
        text_result = analyze_text_message(request.content)
        total_score += text_result["score"]
        detected_reasons.extend(text_result["reasons"])

        extracted_url = extract_url(request.content)
        if extracted_url:
            url_result = analyze_url(extracted_url)
            total_score += url_result["score"]
            detected_reasons.extend(url_result["reasons"])

    # URL-only analysis
    elif request.type == "url":
        url_result = analyze_url(request.content)
        total_score += url_result["score"]
        detected_reasons.extend(url_result["reasons"])

    else:
        return AnalyzeResponse(
            risk="low",
            score=0,
            reasons=["Unsupported input type"]
        )

    # Risk mapping
    if total_score >= 70:
        risk = "high"
    elif total_score >= 30:
        risk = "medium"
    else:
        risk = "low"

    summary = risk_summary(risk)
    actions = emergency_actions_india(risk)

    # Clean, UI-friendly response
    return AnalyzeResponse(
        risk=risk,
        score=total_score,
        reasons=[
            summary,
            "Why this was flagged:",
            *detected_reasons,
            "What you should do:",
            *actions
        ]
    )
