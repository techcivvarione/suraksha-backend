import uuid
from typing import List, Optional

from app.schemas.scan_response import ScanResponse


SAFE_RISK_LEVEL = "UNKNOWN"
SAFE_STATUS = "completed"


def build_scan_response(
    analysis_type: str,
    risk_score: int | None,
    risk_level: str | None,
    reasons: List[str] | None,
    recommendation: str | None,
    confidence: Optional[float] = None,
    scan_id: uuid.UUID | None = None,
    **extra,
) -> ScanResponse:
    sid = scan_id or uuid.uuid4()
    safe_score = int(risk_score or 0)
    safe_risk_level = str(risk_level or SAFE_RISK_LEVEL)
    safe_reasons = reasons or []
    safe_recommendation = recommendation or "No recommendation available."
    status = extra.pop("status", SAFE_STATUS) or SAFE_STATUS
    return ScanResponse(
        scan_id=sid,
        analysis_type=analysis_type,
        risk_score=safe_score,
        score=safe_score,
        risk_level=safe_risk_level,
        status=status,
        confidence=confidence,
        reasons=safe_reasons,
        recommendation=safe_recommendation,
        **extra,
    )
