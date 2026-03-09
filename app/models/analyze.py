from pydantic import BaseModel
from typing import List, Optional, Dict


class AnalyzeRequest(BaseModel):
    input: str | None = None
    analysis_type: str | None = None
    type: str | None = None
    content: str | None = None
    is_paid: bool | None = None
    tier: str | None = None


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    reasons: List[str]
    recommendation: str
