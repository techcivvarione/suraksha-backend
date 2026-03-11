import os
import logging
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request

from app.core.features import normalize_plan
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.services.reality.media_pipeline import process_upload
from app.services.reality.image_ai_detector import ImageAIDetector
from app.services.reality.providers.base_provider import RealityDetectionError
from app.services.response_builder import build_scan_response
from app.services.risk_mapper import map_probability_to_risk
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan/reality", tags=["Scan"])
logger = logging.getLogger(__name__)

image_detector = ImageAIDetector()


def _magic_image(header: bytes) -> bool:
    return header.startswith(b"\x89PNG") or header.startswith(b"\xff\xd8") or header.startswith(b"RIFF")


@router.post("/image")
async def scan_reality_image(
    file: UploadFile = File(...),
    request: Request = None,
    current_user=Depends(require_user),
):
    scan_id = generate_scan_id()
    client_ip = request.client.host if request else "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    apply_scan_rate_limits(
        current_user=current_user,
        endpoint="/scan/reality/image",
        client_ip=client_ip,
        user_namespace="scan:reality:image:user",
        user_limit=20,
        ip_namespace="scan:reality:image:ip",
        ip_limit=60,
    )

    path = None
    try:
        path, size, mime, file_hash = process_upload(
            file,
            allowed_mimes={"image/png", "image/jpeg", "image/webp"},
            max_size=10 * 1024 * 1024,
            magic_check=_magic_image,
        )

        try:
            detection = await image_detector.detect(path, mime)
        except RealityDetectionError as exc:
            if exc.provider == "hive":
                raise HTTPException(
                    status_code=502,
                    detail={
                        "success": False,
                        "error": "AI_PROVIDER_ERROR",
                        "provider": "hive",
                        "message": "AI detection service returned an error",
                    },
                )
            raise_scan_error(500, "SCAN_PROCESSING_ERROR", "Scan could not be completed.")
        probability = detection.get("probability", 0.0)
        provider_used = detection.get("provider_used", "unknown")
        risk = map_probability_to_risk(probability)

        response = build_scan_response(
            analysis_type=ScanType.REALITY_IMAGE.value,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            reasons=[f"Synthetic probability {probability:.2f}"],
            recommendation="Treat with caution; verify source." if risk["risk_level"] != "LOW" else "No strong manipulation signs detected.",
            confidence=probability,
            scan_id=scan_id,
        )

        log_scan_event(
            scan_id=scan_id,
            user_id=str(current_user.id),
            scan_type=ScanType.REALITY_IMAGE.value,
            risk_score=risk["risk_score"],
            endpoint="/scan/reality/image",
            plan=plan,
            media_size=size,
            provider_used=provider_used,
        )
        return response
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "scan_processing_failed",
            extra={"user_id": str(current_user.id), "plan": plan, "endpoint": "/scan/reality/image"},
        )
        raise_scan_error(500, "SCAN_PROCESSING_ERROR", "Scan could not be completed.")
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
