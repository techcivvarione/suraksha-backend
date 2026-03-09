import uuid
from typing import List, Optional

from pydantic import BaseModel


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    analysis_type: str
    risk_score: int
    risk_level: str
    confidence: Optional[float] = None
    reasons: List[str]
    recommendation: str
    detected_type: Optional[str] = None
    original_payload: Optional[str] = None
    reputation_scan_count: Optional[int] = None
    reputation_report_count: Optional[int] = None
    is_flagged: Optional[bool] = None
