from pydantic import BaseModel
from typing import List

class AnalyzeRequest(BaseModel):
    type: str
    content: str

class AnalyzeResponse(BaseModel):
    risk: str
    score: int
    reasons: List[str]
