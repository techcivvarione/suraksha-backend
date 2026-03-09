from pydantic import BaseModel, Field


class ThreatScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
