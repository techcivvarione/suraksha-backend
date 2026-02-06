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


# ---------- MODELS (KEPT FOR COMPATIBILITY) ----------
class HistorySaveRequest(BaseModel):
    input_text: str
    result: dict


class HistoryItem(BaseModel):
    id: str
    input_text: str
    risk: str
    score: int
    reasons: dict
    created_at: datetime


# =====================================================
# ⚠️ DEPRECATED: DO NOT USE FROM ANDROID
# History is saved via /analyze only
# =====================================================
@router.post("/save", deprecated=True)
def save_history(
    payload: HistorySaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    ⚠️ Deprecated.
    History MUST be saved via /analyze.
    This exists only for backward compatibility.
    """

    record_id = str(uuid.uuid4())

    db.execute(
        text("""
            INSERT INTO scan_history (
                id,
                user_id,
                input_text,
                risk,
                score,
                reasons,
                created_at
            )
            VALUES (
                :id,
                :user_id,
                :input_text,
                :risk,
                :score,
                :reasons,
                now()
            )
        """),
        {
            "id": record_id,
            "user_id": current_user.id,
            "input_text": payload.input_text,
            "risk": payload.result.get("risk"),
            "score": payload.result.get("score"),
            "reasons": payload.result,
        },
    )

    db.commit()

    return {"status": "saved", "id": record_id}


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
            WHERE user_id = :user_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {
            "user_id": current_user.id,
            "limit": limit,
            "offset": offset,
        },
    ).mappings().all()

    count = db.execute(
        text("""
            SELECT COUNT(*)
            FROM scan_history
            WHERE user_id = :user_id
        """),
        {"user_id": current_user.id},
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
            WHERE id = :id AND user_id = :user_id
        """),
        {
            "id": history_id,
            "user_id": current_user.id,
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
            WHERE id = :id AND user_id = :user_id
        """),
        {
            "id": history_id,
            "user_id": current_user.id,
        },
    )

    db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="History not found")

    return {"status": "deleted"}
