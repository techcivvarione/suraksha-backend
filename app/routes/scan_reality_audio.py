import logging
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request
from sqlalchemy.orm import Session

from app.core.features import normalize_plan
from app.db import get_db
from app.routes.scan_base import apply_scan_rate_limits, raise_scan_error, require_user
from app.services.reality.media_pipeline import process_upload
from app.services.scan_jobs import create_scan_job
from app.services.storage_service import delete_file, upload_file

router = APIRouter(prefix="/scan/reality", tags=["Scan"])
logger = logging.getLogger(__name__)


def _magic_audio(header: bytes) -> bool:
    return header.startswith(b"ID3") or header.startswith(b"RIFF")


@router.post("/audio")
async def scan_reality_audio(
    file: UploadFile = File(...),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_user),
):
    client_ip = request.client.host if request else "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))
    object_key = None

    try:
        file_bytes, size, mime, file_hash = process_upload(
            file,
            allowed_mimes={"audio/mpeg", "audio/wav"},
            allowed_extensions={".mp3", ".wav"},
            max_size=10 * 1024 * 1024,
            magic_check=_magic_audio,
        )

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/scan/reality/audio",
            client_ip=client_ip,
            user_namespace="scan:reality:audio:user",
            user_limit=20,
            ip_namespace="scan:reality:audio:ip",
            ip_limit=60,
            plan_limit_policy="plan_quota",
            scan_type="reality_audio",
        )

        object_key = upload_file(file_bytes, file.filename or "audio.bin")
        job = create_scan_job(
            db,
            user_id=current_user.id,
            file_path=object_key,
            scan_type="audio",
        )
        logger.info(
            "scan_job_enqueued",
            extra={
                "job_id": str(job.id),
                "user_id": str(current_user.id),
                "scan_type": "audio",
                "endpoint": "/scan/reality/audio",
                "plan": plan,
                "media_size": size,
                "mime": mime,
                "file_hash": file_hash[:12],
                "object_key": object_key,
            },
        )
        payload = {"job_id": str(job.id), "status": "processing", "risk_level": "UNKNOWN", "score": 0}
        return {**payload, "data": payload}
    except HTTPException:
        raise
    except Exception:
        if object_key:
            try:
                delete_file(object_key)
            except Exception:
                pass
        logger.exception(
            "scan_processing_failed",
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/reality/audio"},
        )
        raise_scan_error(500, "AI_DETECTION_FAILED", "Unable to analyze media")
