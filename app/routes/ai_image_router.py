from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
import uuid
import json
import logging

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.services.ai_image_service import detect_ai_image
from app.services.plan_limits import LimitType, enforce_limit

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


@router.post("/ai-image")
def analyze_ai_image(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_limit(
        current_user,
        LimitType.AI_IMAGE_LIFETIME,
        db=db,
        endpoint=request.url.path,
    )

    # Validate file
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are supported")

    image_bytes = file.file.read()

    if len(image_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image too large (max 10MB)")

    try:
        detection = detect_ai_image(image_bytes)
    except Exception:
        logging.exception("AI image detection failed")
        raise HTTPException(status_code=500, detail="Detection failed")

    response = {
        "scan_type": "AI_IMAGE",
        "result": detection["result"],
        "confidence": detection["confidence"],
        "method": detection["method"],
        "signals": detection.get("signals", []),
    }

    # Save history
    try:
        db.execute(
            text("""
                INSERT INTO scan_history (
                    id, user_id, input_text,
                    risk, score, reasons,
                    scan_type, created_at
                )
                VALUES (
                    :id, :user_id, :input_text,
                    :risk, :score, :reasons,
                    'AI_IMAGE', now()
                )
            """),
            {
                "id": str(uuid.uuid4()),
                "user_id": str(current_user.id),
                "input_text": "AI_IMAGE_REDACTED",
                "risk": _result_to_risk(detection["result"]),
                "score": detection["confidence"],
                "reasons": json.dumps(detection.get("signals", [])),
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        logging.exception("Failed to save AI image scan history")

    return response


def _result_to_risk(result: str) -> str:
    return {
        "AI_GENERATED": "high",
        "UNCERTAIN": "medium",
        "REAL": "low",
    }.get(result, "medium")
