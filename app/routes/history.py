from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import List
from datetime import datetime
import uuid

from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/history", tags=["History"])


# ---------- models ----------
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


# ---------- routes ----------

@router.post("/save")
def save_history(
    payload: HistorySaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    record_id = str(uuid.uuid4())

    db.execute(
        """
        insert into scan_history (
            id,
            user_id,
            input_text,
            risk,
            score,
            reasons,
            created_at
        )
        values (
            :id,
            :user_id,
            :input_text,
            :risk,
            :score,
            :reasons,
            now()
        )
        """,
        {
            "id": record_id,
            "user_id": str(current_user.id),
            "input_text": payload.input_text,
            "risk": payload.result.get("risk"),
            "score": payload.result.get("score"),
            "reasons": payload.result,
        },
    )

    db.commit()

    return {"status": "saved", "id": record_id}


@router.get("/")
def list_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.execute(
        """
        select
            id,
            input_text,
            risk,
            score,
            reasons,
            created_at
        from scan_history
        where user_id = :user_id
        order by created_at desc
        limit :limit offset :offset
        """,
        {
            "user_id": str(current_user.id),
            "limit": limit,
            "offset": offset,
        },
    ).mappings().all()

    count = db.execute(
        """
        select count(*)
        from scan_history
        where user_id = :user_id
        """,
        {"user_id": str(current_user.id)},
    ).scalar()

    return {
        "count": count,
        "limit": limit,
        "offset": offset,
        "history": rows,
    }


@router.get("/{history_id}")
def get_history(
    history_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = db.execute(
        """
        select
            id,
            input_text,
            risk,
            score,
            reasons,
            created_at
        from scan_history
        where id = :id and user_id = :user_id
        """,
        {
            "id": history_id,
            "user_id": str(current_user.id),
        },
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="History not found")

    return row


@router.delete("/{history_id}")
def delete_history(
    history_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.execute(
        """
        delete from scan_history
        where id = :id and user_id = :user_id
        """,
        {
            "id": history_id,
            "user_id": str(current_user.id),
        },
    )

    db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="History not found")

    return {"status": "deleted"}
