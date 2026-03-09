import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.services.media_analysis_store import fetch_recent_analysis

HEX_64 = re.compile(r"^[A-Fa-f0-9]{64}$")


def validate_request_payload(payload: dict):
    if payload.get("risk_level") != "HIGH":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Risk level not high")
    try:
        score = int(payload.get("risk_score", -1))
    except Exception:
        score = -1
    if score < 70:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Risk score too low")
    media_hash = payload.get("media_hash", "")
    if not HEX_64.fullmatch(media_hash or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid media hash")
    analysis_type = payload.get("analysis_type")
    if analysis_type not in {"VIDEO", "AUDIO"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid analysis type")


def validate_recent_analysis(db: Session, user_id: str, media_hash: str):
    # Use Redis-backed recent analysis cache to ensure freshness and ownership.
    analysis = fetch_recent_analysis(user_id, media_hash)
    if not analysis:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No recent analysis found")
    if analysis["risk_level"] != "HIGH" or analysis["risk_score"] < 70:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Risk not high enough")
