from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_url

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):

    if request.type == "url":
        result = analyze_url(request.content)

        risk = "low"
        if result["score"] >= 50:
            risk = "high"
        elif result["score"] >= 20:
            risk = "medium"

        return AnalyzeResponse(
            risk=risk,
            score=result["score"],
            reasons=result["reasons"]
        )

    return AnalyzeResponse(
        risk="low",
        score=0,
        reasons=["Unsupported input type"]
    )
