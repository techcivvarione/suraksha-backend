import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.services.ai_explainer import generate_ai_explanation

router = APIRouter(prefix="/ai", tags=["AI Explanations"])


@router.post("/explain")
def explain_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 🔐 PAID ONLY
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail={
                "upgrade_required": True,
                "message": "Upgrade to unlock AI-powered explanations",
                "features": [
                    "Human-readable security explanations",
                    "Attack intent analysis",
                    "Clear next steps",
                ],
            },
        )

    # -------- FETCH SCAN --------
    scan = db.execute(
        text("""
            SELECT risk, score, reasons
            FROM scan_history
            WHERE id = CAST(:sid AS uuid)
              AND user_id = CAST(:uid AS uuid)
        """),
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

    # -------- SAVE (OPTIONAL CACHE) --------
    db.execute(
        text("""
            INSERT INTO ai_explanations (id, scan_id, user_id, explanation)
            VALUES (:id, :sid, :uid, :exp)
        """),
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
