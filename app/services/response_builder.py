import uuid
from typing import List, Optional

from app.schemas.scan_response import ScanResponse


def build_scan_response(
    analysis_type: str,
    risk_score: int,
    risk_level: str,
    reasons: List[str],
    recommendation: str,
    confidence: Optional[float] = None,
    scan_id: uuid.UUID | None = None,
) -> ScanResponse:
    sid = scan_id or uuid.uuid4()
    return ScanResponse(
        scan_id=sid,
        analysis_type=analysis_type,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        reasons=reasons,
        recommendation=recommendation,
    )
