import logging
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request
from sqlalchemy.orm import Session

from app.core.features import normalize_plan
from app.db import get_db
from app.routes.scan_base import apply_scan_rate_limits, raise_scan_error, require_user
from app.services.scan_jobs import create_scan_job
from app.services.reality.media_pipeline import process_upload
from app.services.storage_service import delete_file, upload_file

router = APIRouter(prefix="/scan/reality", tags=["Scan"])
logger = logging.getLogger(__name__)


def _magic_image(header: bytes) -> bool:
    return header.startswith(b"\x89PNG") or header.startswith(b"\xff\xd8") or header.startswith(b"RIFF")


@router.post("/image")
async def scan_reality_image(
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
            allowed_mimes={"image/png", "image/jpeg", "image/webp"},
            allowed_extensions={".png", ".jpg", ".jpeg", ".webp"},
            max_size=10 * 1024 * 1024,
            magic_check=_magic_image,
        )

        apply_scan_rate_limits(
            current_user=current_user,
            endpoint="/scan/reality/image",
            client_ip=client_ip,
            user_namespace="scan:reality:image:user",
            user_limit=20,
            ip_namespace="scan:reality:image:ip",
            ip_limit=60,
            plan_limit_policy="plan_quota",
            scan_type="reality_image",
        )

        object_key = upload_file(file_bytes, file.filename or "image.bin")
        job = create_scan_job(
            db,
            user_id=current_user.id,
            file_path=object_key,
            scan_type="image",
        )
        logger.info(
            "scan_job_enqueued",
            extra={
                "job_id": str(job.id),
                "user_id": str(current_user.id),
                "scan_type": "image",
                "endpoint": "/scan/reality/image",
                "plan": plan,
                "media_size": size,
                "mime": mime,
                "file_hash": file_hash[:12],
                "object_key": object_key,
            },
        )
        return {"job_id": str(job.id), "status": "processing"}
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
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/reality/image"},
        )
        raise_scan_error(500, "AI_DETECTION_FAILED", "Unable to analyze media")
