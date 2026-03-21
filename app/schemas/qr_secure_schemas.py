from typing import List, Optional

from pydantic import BaseModel, Field


# SECURE QR START
class QrAnalyzePayload(BaseModel):
    raw_payload: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Raw QR payload string; UTF-8 text only.",
    )


class QrAnalyzeResponse(BaseModel):
    qr_hash: str
    risk_score: int
    risk_level: str
    detected_type: str
    # original_payload intentionally omitted from response — no raw data to client
    reasons: List[str]
    recommended_action: str
    is_flagged: bool
    # UPI / payment fields (populated only when detected_type == "UPI")
    is_payment: bool = False
    merchant_name: Optional[str] = None
    upi_id: Optional[str] = None
    amount: Optional[float] = None
    summary: Optional[str] = None


class QrReportPayload(BaseModel):
    raw_payload: str = Field(..., min_length=1, max_length=512)
    reason: Optional[str] = Field(default=None, max_length=2000)


class QrReportResponse(BaseModel):
    qr_hash: str
    message: str
    reported_count: int
    is_flagged: bool
# SECURE QR END
