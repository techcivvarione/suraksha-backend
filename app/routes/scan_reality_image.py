import os
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request

from app.routes.scan_base import require_user, apply_rate_limit, generate_scan_id
from app.services.reality.media_pipeline import process_upload
from app.services.reality.image_ai_detector import ImageAIDetector
from app.services.response_builder import build_scan_response
from app.services.risk_mapper import map_probability_to_risk
from app.services.scan_logger import log_scan_event
from app.enums.scan_type import ScanType

router = APIRouter(prefix="/scan/reality", tags=["Scan"])

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

    apply_rate_limit("scan:reality:image:user", 20, 3600, str(current_user.id))
    apply_rate_limit("scan:reality:image:ip", 60, 3600, client_ip)

    path = None
    try:
        path, size, mime, file_hash = process_upload(
            file,
            allowed_mimes={"image/png", "image/jpeg", "image/webp"},
            max_size=10 * 1024 * 1024,
            magic_check=_magic_image,
        )

        detection = await image_detector.detect(path, mime)
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
            media_size=size,
            provider_used=provider_used,
        )
        return response
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
