import uuid
from typing import List, Optional

from pydantic import BaseModel


class ScanResponse(BaseModel):
    success: bool = True
    scan_id: uuid.UUID
    analysis_type: str
    risk_score: int = 0
    score: int = 0
    risk_level: str = "UNKNOWN"
    status: str = "completed"
    confidence: Optional[float] = None
    reasons: List[str]
    recommendation: str
    summary: Optional[str] = None
    ai_probability: Optional[float] = None
    risk: Optional[str] = None
    signals: Optional[List[str]] = None
    detected_type: Optional[str] = None
    original_payload: Optional[str] = None
    reputation_scan_count: Optional[int] = None
    reputation_report_count: Optional[int] = None
    is_flagged: Optional[bool] = None
    breach_count: Optional[int] = None
    breaches: Optional[list] = None
    original_url: Optional[str] = None
    final_url: Optional[str] = None
    domain: Optional[str] = None
    redirect_detected: Optional[bool] = None
    redirect_chain: Optional[List[str]] = None
    limited_analysis: Optional[bool] = None
    risk_reason: Optional[List[str]] = None
    confidence_score: Optional[int] = None
    confidence_label: Optional[str] = None
    simple_explanation: Optional[str] = None
    detailed_explanation: Optional[str] = None
