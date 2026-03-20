import uuid
from typing import List, Optional

from app.schemas.scan_response import ScanResponse
from app.services.risk_mapper import derive_risk_level_from_score


SAFE_STATUS = "completed"
_INVALID_RISK_LEVELS = {"", "UNKNOWN", "NONE", "NULL"}


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

    # Never emit "UNKNOWN". If the caller didn't supply a valid risk level
    # (e.g. a new analyzer that only computes a score), derive it from the
    # numeric score so the UI always renders LOW / MEDIUM / HIGH.
    normalised = (risk_level or "").strip().upper()
    if normalised not in _INVALID_RISK_LEVELS:
        safe_risk_level = normalised
    else:
        safe_risk_level = derive_risk_level_from_score(safe_score)

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
