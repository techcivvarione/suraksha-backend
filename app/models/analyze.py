from pydantic import BaseModel
from typing import List, Optional, Dict


class AnalyzeRequest(BaseModel):
    type: str
    content: str


class AnalyzeResponse(BaseModel):
    risk: str
    score: int
    reasons: List[str]

    # Basic breach info
    count: Optional[int] = None
    sites: Optional[List[str]] = None
    domains: Optional[List[str]] = None

    # Advanced analytics (PAID)
    breach_analysis: Optional[Dict] = None

    # Upgrade gating
    upgrade: Optional[Dict] = None
