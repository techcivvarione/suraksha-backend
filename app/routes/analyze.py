from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest, AnalyzeResponse

router = APIRouter(prefix="/analyze", tags=["Analyzer"])

@router.post("/", response_model=AnalyzeResponse)
def analyze_input(request: AnalyzeRequest):
    return AnalyzeResponse(
        risk="low",
        score=10,
        reasons=["Dummy response – real logic comes later"]
    )
