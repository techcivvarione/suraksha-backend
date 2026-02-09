from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
import json
import uuid
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_db
from app.routes.auth import get_current_user
from app.models.user import User
from app.services.ocr_service import extract_text_from_image, OCRException
from app.services.analyzer import analyze_input_full

router = APIRouter(prefix="/analyze", tags=["Analyzer"])


@router.post("/ocr")
def analyze_ocr(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # ---------- PLAN CHECK ----------
    if current_user.plan != "PAID":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "UPGRADE_REQUIRED",
                "message": "OCR scan is available for paid users only",
                "upgrade": {
                    "required": True,
                    "features": [
                        "OCR scam detection",
                        "Screenshot analysis",
                        "Higher scan limits"
                    ]
                }
            }
        )

    # ---------- FILE VALIDATION ----------
    if not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Only image files are supported for OCR scan"
        )

    # ---------- READ IMAGE ----------
    try:
        image_bytes = file.file.read()
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to read uploaded image")

    # ---------- OCR ----------
    try:
        extracted_text = extract_text_from_image(image_bytes)
    except OCRException as e:
        raise HTTPException(status_code=400, detail=str(e))

    # ---------- THREAT SCAN ----------
    try:
        result = analyze_input_full(
            scan_type="THREAT",
            content=extracted_text,
            user_plan=current_user.plan,
        )
    except Exception:
        logging.exception("OCR threat scan failed")
        raise HTTPException(status_code=400, detail="OCR scan failed")

    # ---------- SAVE HISTORY (REDACTED) ----------
    try:
        db.execute(
    text("""
        INSERT INTO scan_history (
            id,
            user_id,
            input_text,
            risk,
            score,
            reasons,
            scan_type,
            created_at
        )
        VALUES (
            :id,
            :user_id,
            :input_text,
            :risk,
            :score,
            :reasons,
            'OCR',
            now()
        )
    """),
    {
        "id": str(uuid.uuid4()),
        "user_id": str(current_user.id),
        "input_text": "OCR_IMAGE_REDACTED",
        "risk": result["risk"],
        "score": result["score"],
        "reasons": json.dumps(result["reasons"]),
    },
)

        db.commit()
    except Exception:
        logging.exception("Failed to save OCR scan history")

    # ---------- RESPONSE ----------
    return {
        "scan_type": "OCR",
        "extracted_text_preview": extracted_text[:300],
        "risk": result["risk"],
        "score": result["score"],
        "reasons": result["reasons"],
    }
