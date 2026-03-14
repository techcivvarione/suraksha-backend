import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.schemas.ai_explanations import ExplainScanRequest, ExplainScanResponse
from app.services.ai_explainer import generate_ai_explanation

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

    explanation = generate_ai_explanation(
        scan_type="SECURITY_SCAN",
        risk=scan["risk"] if scan else None,
        score=scan["score"] if scan else None,
        reasons=scan["reasons"] if scan else [],
        text=payload.text,
    )
    return ExplainScanResponse(scan_id=payload.scan_id or str(uuid.uuid4()), ai_explanation=explanation)
