from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import engine
from app.enums.scan_type import ScanType
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.alert_rate_limiter import AlertRateLimiterError, enforce_alert_limits
from app.services.ai_explainer import generate_ai_explanation
from app.services.ocr_service import OCRException, extract_text_from_image
from app.services.reality.image_ai_detector import ImageAIDetector
from app.services.reality.video_deepfake_detector import VideoDeepfakeDetector
from app.services.reality.voice_deepfake_detector import VoiceDeepfakeDetector
from app.services.scan_logger import log_scan_event
from app.services.security_alerts import create_alert_event, dispatch_plan_alerts
from app.services.security_plan_limits import allows_realtime_alerts
from app.services.storage_service import delete_file, download_file

logger = logging.getLogger(__name__)

_image_detector = ImageAIDetector()
_video_detector = VideoDeepfakeDetector()
_audio_detector = VoiceDeepfakeDetector()

_SCAN_TYPE_TO_ANALYSIS = {
    "image": ScanType.REALITY_IMAGE.value,
    "video": ScanType.REALITY_VIDEO.value,
    "audio": ScanType.REALITY_AUDIO.value,
}

_SCAN_TYPE_TO_ENDPOINT = {
    "image": "/scan/reality/image",
    "video": "/scan/reality/video",
    "audio": "/scan/reality/audio",
}

_SCAN_TYPE_TO_MIME = {
    "image": {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    },
    "video": {
        ".mp4": "video/mp4",
        ".webm": "video/webm",
    },
    "audio": {
        ".mp3": "audio/mpeg",
        ".wav": "audio/wav",
    },
}


def ensure_scan_jobs_table() -> None:
    ScanJob.__table__.create(bind=engine, checkfirst=True)


def create_scan_job(db: Session, *, user_id, file_path: str, scan_type: str) -> ScanJob:
    ensure_scan_jobs_table()
    job = ScanJob(
        user_id=uuid.UUID(str(user_id)),
        file_path=file_path,
        scan_type=scan_type,
        status="pending",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_job_for_user(db: Session, *, job_id: str, user_id) -> ScanJob | None:
    ensure_scan_jobs_table()
    return (
        db.query(ScanJob)
        .filter(ScanJob.id == uuid.UUID(str(job_id)), ScanJob.user_id == uuid.UUID(str(user_id)))
        .first()
    )


def claim_next_pending_job(db: Session) -> ScanJob | None:
    ensure_scan_jobs_table()
    with db.begin():
        job = (
            db.query(ScanJob)
            .filter(ScanJob.status == "pending")
            .order_by(ScanJob.created_at.asc())
            .with_for_update(skip_locked=True)
            .first()
        )
        if not job:
            return None
        job.status = "processing"
        db.add(job)
    db.refresh(job)
    return job


def process_scan_job(db: Session, job: ScanJob) -> None:
    temp_path = None
    try:
        media_bytes = download_file(job.file_path)
        temp_path = _write_temp_media(job, media_bytes)
        result = _run_detection(job, temp_path)
        payload = json.dumps(result)

        with db.begin():
            job.status = "completed"
            job.result_json = payload
            db.add(job)
            _insert_scan_history(db, job=job, result=result)

        _trigger_realtime_alerts(db, job=job, result=result)

        log_scan_event(
            scan_id=job.id,
            user_id=str(job.user_id),
            scan_type=result["analysis_type"],
            risk_score=int(result["risk_score"]),
            endpoint=_SCAN_TYPE_TO_ENDPOINT[job.scan_type],
            media_size=_file_size(temp_path),
            provider_used=result.get("provider_used"),
        )
    except Exception as exc:
        logger.exception("scan_job_failed", extra={"job_id": str(job.id), "scan_type": job.scan_type})
        error_payload = {
            "error": "AI_DETECTION_FAILED",
            "message": str(exc) or "Unable to analyze media",
        }
        with db.begin():
            job.status = "failed"
            job.result_json = json.dumps(error_payload)
            db.add(job)
    finally:
        try:
            delete_file(job.file_path)
        except Exception:
            logger.warning("scan_job_object_cleanup_failed", extra={"job_id": str(job.id), "object_key": job.file_path})
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                logger.warning("scan_job_file_cleanup_failed", extra={"job_id": str(job.id), "file_path": temp_path})


def _run_detection(job: ScanJob, file_path: str) -> dict:
    mime_type = _infer_mime_type(file_path, job.scan_type)
    detector = _detector_for(job.scan_type)
    detection = asyncio.run(detector.detect(file_path, mime_type, filename=Path(file_path).name, fast_mode=False))

    probability = float(detection.get("probability", 0.0))
    signals = list(detection.get("signals") or [_default_signal(job.scan_type, probability)])
    explanation = _generate_explanation(job.scan_type, detection.get("risk_level"), detection.get("risk_score"), signals)

    result = {
        "scan_id": str(job.id),
        "analysis_type": _SCAN_TYPE_TO_ANALYSIS[job.scan_type],
        "risk_score": int(detection.get("risk_score") or 0),
        "risk_level": detection.get("risk_level") or "MEDIUM",
        "confidence": probability,
        "reasons": signals,
        "recommendation": _recommendation_for(job.scan_type, detection.get("risk_level") or "MEDIUM"),
        "ai_probability": probability,
        "risk": (detection.get("risk_level") or "MEDIUM"),
        "signals": signals,
        "provider_used": detection.get("provider_used", "internal-hybrid"),
        "ocr_text_preview": _extract_ocr_preview(job.scan_type, file_path),
        "ai_explanation": explanation,
    }
    return result


def _detector_for(scan_type: str):
    if scan_type == "image":
        return _image_detector
    if scan_type == "video":
        return _video_detector
    if scan_type == "audio":
        return _audio_detector
    raise ValueError(f"Unsupported scan type: {scan_type}")


def _infer_mime_type(file_path: str, scan_type: str) -> str:
    extension = Path(file_path).suffix.lower()
    mime_type = _SCAN_TYPE_TO_MIME.get(scan_type, {}).get(extension)
    if not mime_type:
        raise ValueError(f"Unsupported file extension for {scan_type}: {extension}")
    return mime_type


def _extract_ocr_preview(scan_type: str, file_path: str) -> str | None:
    if scan_type != "image":
        return None
    try:
        with open(file_path, "rb") as handle:
            extracted = extract_text_from_image(handle.read()).strip()
        return extracted[:300] if extracted else None
    except OCRException:
        return None
    except Exception:
        logger.exception("scan_job_ocr_failed", extra={"file_path": file_path})
        return None


def _generate_explanation(scan_type: str, risk_level: str | None, risk_score: int | None, reasons: list[str]) -> str | None:
    try:
        return generate_ai_explanation(
            scan_type=_SCAN_TYPE_TO_ANALYSIS[scan_type],
            risk=risk_level or "MEDIUM",
            score=int(risk_score or 0),
            reasons=reasons,
        )
    except Exception:
        logger.exception("scan_job_ai_explanation_failed", extra={"scan_type": scan_type})
        return None


def _insert_scan_history(db: Session, *, job: ScanJob, result: dict) -> None:
    db.execute(
        text(
            """
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
                :scan_type,
                now()
            )
            """
        ),
        {
            "id": str(job.id),
            "user_id": str(job.user_id),
            "input_text": f"{job.scan_type.upper()}_FILE_REDACTED",
            "risk": str(result["risk_level"]).lower(),
            "score": int(result["risk_score"]),
            "reasons": json.dumps(result.get("signals") or result.get("reasons") or []),
            "scan_type": result["analysis_type"],
        },
    )


def _recommendation_for(scan_type: str, risk_level: str) -> str:
    if scan_type == "image":
        return "Treat with caution; verify source." if risk_level != "LOW" else "No strong manipulation signs detected."
    if scan_type == "video":
        return (
            "Do not trust this video without independent verification."
            if risk_level != "LOW"
            else "No strong deepfake indicators detected."
        )
    return "Do not trust this audio without verification." if risk_level != "LOW" else "No strong synthetic indicators detected."


def _default_signal(scan_type: str, probability: float) -> str:
    if scan_type == "image":
        return f"Synthetic probability {probability:.2f}"
    if scan_type == "video":
        return f"Deepfake probability {probability:.2f}"
    return f"Voice synthesis probability {probability:.2f}"


def _file_size(path: str) -> int | None:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _write_temp_media(job: ScanJob, media_bytes: bytes) -> str:
    extension = _extension_for(job.file_path, job.scan_type)
    fd, path = tempfile.mkstemp(prefix="gosuraksha_scan_", suffix=extension)
    with os.fdopen(fd, "wb") as handle:
        handle.write(media_bytes)
    return path


def _extension_for(file_key: str, scan_type: str) -> str:
    extension = Path(file_key).suffix.lower()
    if extension:
        return extension
    return next(iter(_SCAN_TYPE_TO_MIME[scan_type].keys()))


def _trigger_realtime_alerts(db: Session, *, job: ScanJob, result: dict) -> None:
    risk_score = int(result.get("risk_score") or 0)
    if risk_score < 70:
        return

    user = db.query(User).filter(User.id == job.user_id).first()
    if not user or not allows_realtime_alerts(user.plan):
        return

    try:
        enforce_alert_limits(db, str(user.id), None, None)
        event = create_alert_event(
            db=db,
            user_id=user.id,
            trigger_type=f"{job.scan_type.upper()}_HIGH_RISK_SCAN",
            analysis_type=job.scan_type.upper(),
            risk_score=risk_score,
            media_hash=str(job.id).replace("-", ""),
        )
        dispatch_plan_alerts(
            db=db,
            user=user,
            trigger_type=f"{job.scan_type.upper()}_HIGH_RISK_SCAN",
            risk_score=risk_score,
            scan_id=str(job.id),
            alert_event_id=event.id,
        )
        event.status = "SENT"
        db.add(event)
        db.commit()
    except AlertRateLimiterError:
        logger.info("scan_job_realtime_alert_rate_limited", extra={"job_id": str(job.id), "user_id": str(job.user_id)})
    except Exception:
        logger.exception("scan_job_realtime_alert_failed", extra={"job_id": str(job.id), "user_id": str(job.user_id)})
