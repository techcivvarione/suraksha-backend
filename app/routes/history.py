from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/history", tags=["History"])


# ---------- MODELS ----------
class HistoryItem(BaseModel):
    id: str
    input_text: str
    risk: str
    score: int
    reasons: dict
    created_at: datetime


# =====================================================
# LIST HISTORY
# =====================================================
@router.get("/")
def list_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        text("""
            SELECT
                id,
                input_text,
                risk,
                score,
                reasons,
                created_at
            FROM scan_history
            WHERE user_id = CAST(:user_id AS uuid)
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {
            "user_id": str(current_user.id),
            "limit": limit,
            "offset": offset,
        },
    ).mappings().all()

    count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = CAST(:user_id AS uuid)
        """),
        {
            "user_id": str(current_user.id),
        },
    ).scalar()

    return {
        "count": count,
        "limit": limit,
        "offset": offset,
        "history": rows,
    }


# =====================================================
# GET SINGLE HISTORY ITEM
# =====================================================
@router.get("/{history_id}")
def get_history(
    history_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = db.execute(
        text("""
            SELECT
                id,
                input_text,
                risk,
                score,
                reasons,
                created_at
            FROM scan_history
            WHERE id = CAST(:id AS uuid)
              AND user_id = CAST(:user_id AS uuid)
        """),
        {
            "id": history_id,
            "user_id": str(current_user.id),
        },
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="History not found")

    return row


# =====================================================
# DELETE HISTORY
# =====================================================
@router.delete("/{history_id}")
def delete_history(
    history_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.execute(
        text("""
            DELETE FROM scan_history
            WHERE id = CAST(:id AS uuid)
              AND user_id = CAST(:user_id AS uuid)
        """),
        {
            "id": history_id,
            "user_id": str(current_user.id),
        },
    )

    db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="History not found")

    return {"status": "deleted"}
