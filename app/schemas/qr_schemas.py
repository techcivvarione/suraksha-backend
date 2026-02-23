from typing import Optional

from pydantic import BaseModel, Field


class QrAnalyzeRequest(BaseModel):
    vpa: str = Field(..., min_length=1)
    qr_hash: str = Field(..., min_length=1)


class QrAnalyzeResponse(BaseModel):
    qr_hash: str
    scam_flag: bool
    is_business: bool
    reported_count: int
    message: str


class QrReportRequest(BaseModel):
    qr_hash: str = Field(..., min_length=1)
    reason: Optional[str] = Field(default=None, max_length=2000)


class QrReportResponse(BaseModel):
    qr_hash: str
    message: str
    reported_count: int
    is_flagged: bool
