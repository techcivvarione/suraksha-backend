import uuid
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.schemas.ai_explanations import ExplainScanRequest, ExplainScanResponse
from app.services.ai_explainer import generate_ai_explanation
from app.services.threat.threat_analyzer import analyze_threat

router = APIRouter(prefix="/ai", tags=["AI Explanations"])


@router.post("/explain", response_model=ExplainScanResponse)
def explain_scan(
    payload: ExplainScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_feature(Feature.AI_EXPLAIN)),
):
    if not payload.scan_id and not payload.text:
        raise HTTPException(status_code=400, detail="scan_id or text required")

    scan = db.execute(
        text(
            """
            SELECT risk, score, reasons
            FROM scan_history
            WHERE id = CAST(:sid AS uuid)
              AND user_id = CAST(:uid AS uuid)
            """
        ),
        {"sid": payload.scan_id or "00000000-0000-0000-0000-000000000000", "uid": str(current_user.id)},
    ).mappings().first()

    if not scan and not payload.text:
        raise HTTPException(status_code=404, detail="Scan not found")

    resolved_risk = scan["risk"] if scan else None
    resolved_score = scan["score"] if scan else None
    resolved_reasons = _coerce_scan_reasons(scan["reasons"] if scan else None)

    if not scan and payload.text:
        threat_result = analyze_threat(payload.text)
        resolved_risk = threat_result.get("risk_level")
        resolved_score = threat_result.get("risk_score")
        resolved_reasons = threat_result.get("signals") or threat_result.get("reasons") or []

    explanation = generate_ai_explanation(
        scan_type="SECURITY_SCAN",
        risk=resolved_risk,
        score=resolved_score,
        reasons=resolved_reasons,
        text=payload.text,
    )
    return ExplainScanResponse(scan_id=payload.scan_id or str(uuid.uuid4()), ai_explanation=explanation)


def _coerce_scan_reasons(raw_reasons):
    if raw_reasons is None:
        return []
    if isinstance(raw_reasons, list):
        return raw_reasons
    if isinstance(raw_reasons, str):
        try:
            parsed = json.loads(raw_reasons)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [raw_reasons]
    return []
