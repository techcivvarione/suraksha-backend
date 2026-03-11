import os
import logging
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request

from app.core.features import normalize_plan
from app.routes.scan_base import apply_scan_rate_limits, generate_scan_id, raise_scan_error, require_user
from app.services.reality.media_pipeline import process_upload
from app.services.reality.image_ai_detector import ImageAIDetector
from app.services.reality_detection.engine import RealityDetectionBadRequest, RealityDetectionError
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
    fast_mode = plan == "GO_ULTRA"

    path = None
    try:
        path, size, mime, file_hash = process_upload(
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

        try:
            detection = await image_detector.detect(path, mime, filename=file.filename, fast_mode=fast_mode)
        except RealityDetectionBadRequest as exc:
            raise_scan_error(400, "SCAN_BAD_REQUEST", str(exc))
        except RealityDetectionError:
            raise HTTPException(
                status_code=500,
                detail={
                    "success": False,
                    "error": "AI_DETECTION_FAILED",
                    "message": "Unable to analyze media",
                },
            )
        probability = detection.get("probability", 0.0)
        provider_used = detection.get("provider_used", "unknown")
        signals = detection.get("signals") or [f"Synthetic probability {probability:.2f}"]
        risk = {
            "risk_score": detection.get("risk_score"),
            "risk_level": detection.get("risk_level"),
        }
        if risk["risk_score"] is None or risk["risk_level"] is None:
            risk = map_probability_to_risk(probability)

        logger.info(
            "reality_detection_result",
            extra={
                "user_id": str(current_user.id),
                "analysis_type": "image",
                "risk_score": risk["risk_score"],
                "signals": signals,
            },
        )

        response = build_scan_response(
            analysis_type=ScanType.REALITY_IMAGE.value,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            reasons=signals,
            recommendation="Treat with caution; verify source." if risk["risk_level"] != "LOW" else "No strong manipulation signs detected.",
            confidence=probability,
            scan_id=scan_id,
            success=True,
            ai_probability=probability,
            risk=risk["risk_level"],
            signals=signals,
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
        raise_scan_error(500, "AI_DETECTION_FAILED", "Unable to analyze media")
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
