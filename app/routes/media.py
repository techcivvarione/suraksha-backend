import logging
import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from redis.exceptions import RedisError

from app.routes.auth import get_current_user
from app.services.deepfake_service import DeepfakeService, DeepfakeServiceError
from app.services.media_validator import validate_upload
from app.services.risk_mapper import map_probability_to_risk
from app.services.redis_store import acquire_cooldown, allow_daily_limit, allow_sliding_window
from app.services.media_analysis_store import store_recent_analysis
from app.services.safe_response import safe_scan_response

router = APIRouter(prefix="/media", tags=["Media"])
logger = logging.getLogger(__name__)

deepfake_service = DeepfakeService(
    api_url=os.getenv("DEEPFAKE_API_URL") or "",
    api_key=os.getenv("DEEPFAKE_API_KEY"),
    timeout=15.0,
)


@router.post("/analyze", status_code=200)
async def analyze_media(
    request: Request,
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    correlation_id = uuid.uuid4().hex
    client_ip = request.client.host or "unknown"
    user_id = str(current_user.id)

    try:
        if not allow_daily_limit("media:user:daily", 10, user_id):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
        if not allow_sliding_window("media:ip", 30, 3600, client_ip):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limited")
    except RedisError:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limiter unavailable")

    validation = validate_upload(file)

    try:
        if not acquire_cooldown("media:cooldown", 30, user_id, validation.file_hash):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Duplicate upload cooldown")
    except RedisError:
        # fail closed
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limiter unavailable")

    try:
        api_resp = await deepfake_service.analyze(validation.path, validation.mime)
        prob = float(api_resp.get("synthetic_probability", 0.0))
        prob = max(0.0, min(1.0, prob))
        risk = map_probability_to_risk(prob)
        score, level = risk["risk_score"], risk["risk_level"]
        mapped = {
            "risk_score": score,
            "risk_level": level,
            "analysis_type": validation.analysis_type,
            "confidence": prob,
            "reasons": [f"Synthetic probability {prob:.2f}"],
            "recommendation": "Do not trust this media without verification." if level == "HIGH" else "Verify source before acting." if level == "MEDIUM" else "No strong manipulation indicators detected.",
            "scan_id": correlation_id,
        }

        logger.info(
            "media_analyze_complete",
            extra={
                "cid": correlation_id,
                "user_id": user_id,
                "ip": client_ip,
                "mime": validation.mime,
                "size": validation.size,
                "risk_score": score,
                "risk_level": level,
            },
        )
        store_recent_analysis(user_id, validation.file_hash, validation.analysis_type, score, level)
        return mapped
    except DeepfakeServiceError:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/media/analyze",
                "cid": correlation_id,
                "user_id": user_id,
            },
        )
        return safe_scan_response(analysis_type="MEDIA", endpoint="/media/analyze")
    finally:
        if os.path.exists(validation.path):
            try:
                os.remove(validation.path)
            except Exception:
                pass
