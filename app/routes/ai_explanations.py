import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.features import Feature
from app.db import get_db
from app.dependencies.access import require_feature
from app.models.user import User
from app.services.ai_explainer import generate_ai_explanation

router = APIRouter(prefix="/ai", tags=["AI Explanations"])


@router.post("/explain")
def explain_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_feature(Feature.AI_EXPLAIN)
    ),
):
    scan = db.execute(
        text(
            """
            SELECT risk, score, reasons
            FROM scan_history
            WHERE id = CAST(:sid AS uuid)
              AND user_id = CAST(:uid AS uuid)
        """
        ),
        {"sid": scan_id, "uid": str(current_user.id)},
    ).mappings().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    explanation = generate_ai_explanation(
        scan_type="SECURITY_SCAN",
        risk=scan["risk"],
        score=scan["score"],
        reasons=scan["reasons"],
    )

    db.execute(
        text(
            """
            INSERT INTO ai_explanations (id, scan_id, user_id, explanation)
            VALUES (:id, :sid, :uid, :exp)
        """
        ),
        {
            "id": str(uuid.uuid4()),
            "sid": scan_id,
            "uid": str(current_user.id),
            "exp": explanation,
        },
    )
    db.commit()

    return {
        "scan_id": scan_id,
        "ai_explanation": explanation,
    }
