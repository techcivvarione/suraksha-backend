from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url, analyze_text_message

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):

    # URL analysis
    if request.type == "url":
        result = analyze_url(request.content)

        score = result["score"]
        reasons = result["reasons"]

    # TEXT / MESSAGE analysis
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

    return AnalyzeResponse(
        risk=risk,
        score=score,
        reasons=reasons
    )
