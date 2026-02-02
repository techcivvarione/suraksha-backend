from fastapi import APIRouter
import re
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


URL_REGEX = r"(https?://[^\s]+)"


def extract_url(text: str):
    match = re.search(URL_REGEX, text)
    return match.group(0) if match else None


def emergency_actions_india(risk: str):
    if risk == "high":
        return [
            "Do NOT click links or reply",
            "Call your bank/UPI helpline immediately if money was sent",
            "Report at https://www.cybercrime.gov.in or call 1930"
        ]
    if risk == "medium":
        return [
            "Verify from official sources",
            "Avoid clicking unknown links",
            "Report if suspicious"
        ]
    return [
        "No urgent action needed",
        "Stay alert"
    ]


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):

    total_score = 0
    reasons = []

    # TEXT analysis
    if request.type == "text":
        text_result = analyze_text_message(request.content)
        total_score += text_result["score"]
        reasons.extend(text_result["reasons"])

        # Extract URL from text if present
        extracted_url = extract_url(request.content)
        if extracted_url:
            url_result = analyze_url(extracted_url)
            total_score += url_result["score"]
            reasons.extend(url_result["reasons"])

    # URL-only analysis
    elif request.type == "url":
        url_result = analyze_url(request.content)
        total_score += url_result["score"]
        reasons.extend(url_result["reasons"])

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

    actions = emergency_actions_india(risk)

    return AnalyzeResponse(
        risk=risk,
        score=total_score,
        reasons=reasons + actions
    )
