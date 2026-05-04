from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.scam import Scam

router = APIRouter(prefix="/api/scams", tags=["Scams"])


def _serialize_scam(record: Scam) -> dict:
    return {
        "id": record.id,
        "title_en": record.title_en,
        "title_hi": record.title_hi,
        "title_te": record.title_te,
        "description_en": record.description_en,
        "description_hi": record.description_hi,
        "description_te": record.description_te,
        "category": record.category,
        "risk_level": record.risk_level,
        "read_time": int(record.read_time),
        "content_en": record.content_en,
        "content_hi": record.content_hi,
        "content_te": record.content_te,
        "related": record.related,
        "quick_tips": record.quick_tips,
    }


@router.get("")
def list_scams(db: Session = Depends(get_db)):
    rows = db.query(Scam).order_by(Scam.title_en.asc()).all()
    return {"items": [_serialize_scam(row) for row in rows], "count": len(rows)}


@router.get("/{scam_id}")
def get_scam(scam_id: str, db: Session = Depends(get_db)):
    row = db.query(Scam).filter(Scam.id == scam_id).first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "SCAM_NOT_FOUND", "message": "Scam not found"},
        )
    return _serialize_scam(row)
