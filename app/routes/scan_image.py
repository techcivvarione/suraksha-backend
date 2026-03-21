"""POST /scan/image — synchronous, lightweight image authenticity scan.

Detection methods (pure Python + Pillow — no AI models, no external APIs):
  1. EXIF metadata analysis
     - Missing EXIF → suspicious
     - Software tag matches known AI generators → high signal
     - No camera make/model → suspicious
     - No capture timestamp → mildly suspicious
  2. Resolution pattern analysis
     - Square power-of-2 dimensions common to AI generators
  3. Pixel uniformity / noise analysis (via Pillow ImageStat)
     - Unusually low stddev → AI images are characteristically smooth
     - Atypical channel imbalance
  4. JPEG re-compression artifact check
     - AI images are over-smooth: re-encoding at Q92 produces ≥ original size

Response (exact structure, no null fields):
  {
    "risk_score":     int,         # 0–100
    "risk_level":     str,         # "LOW" | "MEDIUM" | "HIGH"
    "confidence":     float,       # 0.55–0.90
    "reasons":        [str],       # ≥1 entry always
    "recommendation": str
  }

The envelope middleware wraps this automatically in
{"status": "success", "data": {...}}.
"""
from __future__ import annotations

import io
import logging

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from PIL import Image, ImageStat

from app.routes.scan_base import apply_scan_rate_limits, require_user
from app.services.risk_mapper import derive_risk_level_from_score

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ALLOWED_MIMES: frozenset[str] = frozenset({"image/png", "image/jpeg", "image/webp"})
_MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Known AI / generative-tool software strings embedded in EXIF tag 305.
_AI_SOFTWARE_KEYWORDS: frozenset[str] = frozenset({
    "stable diffusion",
    "midjourney",
    "dall-e",
    "dall\u00b7e",
    "comfyui",
    "automatic1111",
    "novelai",
    "dreamstudio",
    "adobe firefly",
    "firefly",
    "leonardo",
    "invoke ai",
    "kandinsky",
    "imagen",
    "generative fill",
    "content credentials",
    "adobe photoshop generative",
})

# AI generators most commonly output square images at these exact pixel widths.
_AI_SQUARE_SIZES: frozenset[int] = frozenset({256, 512, 768, 1024, 1280, 1536, 2048})

# EXIF tag IDs (standard TIFF/JPEG tags understood by Pillow's getexif()).
_TAG_SOFTWARE = 305
_TAG_MAKE = 271
_TAG_MODEL = 272
_TAG_DATETIME_ORIGINAL = 36867

# Scoring component caps (total never exceeds 100).
_EXIF_MAX = 45   # AI software tag alone earns 45 pts
_RES_MAX = 22
_NOISE_MAX = 32
_ARTIFACT_MAX = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confidence_from_signal_count(n: int) -> float:
    """0 signals → 0.55 (uncertain-low), ≥4 signals → 0.90."""
    return round(min(0.90, 0.55 + n * 0.08), 2)


def _recommendations(risk_level: str) -> str:
    return {
        "HIGH": (
            "Strong indicators of AI generation or digital manipulation detected. "
            "Verify the source independently before trusting this image."
        ),
        "MEDIUM": (
            "Suspicious indicators found. Approach with caution and verify the "
            "image origin if the content is sensitive."
        ),
        "LOW": (
            "No significant manipulation indicators detected. "
            "Image appears consistent with a real photograph."
        ),
    }[risk_level]


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _analyze_image(image_bytes: bytes) -> dict:
    """Run all lightweight checks and return a complete, non-null result dict."""
    reasons: list[str] = []
    total_score = 0

    # ── Open and force-decode ────────────────────────────────────────────────
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()  # raises on truncated / corrupted files
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Cannot decode image: {exc}")

    # ── 1. EXIF metadata analysis ────────────────────────────────────────────
    exif_score = 0
    try:
        exif: dict = img.getexif() if hasattr(img, "getexif") else {}
        if not exif:
            exif_score += 18
            reasons.append("No EXIF metadata present")
        else:
            # Software tag (305)
            software_raw = str(exif.get(_TAG_SOFTWARE, "")).strip()
            if software_raw:
                sw_lower = software_raw.lower()
                for kw in _AI_SOFTWARE_KEYWORDS:
                    if kw in sw_lower:
                        exif_score += 45
                        reasons.append(
                            f'AI/generative software detected in EXIF: "{software_raw[:60]}"'
                        )
                        break

            # Camera make/model (271, 272)
            make = str(exif.get(_TAG_MAKE, "")).strip()
            model = str(exif.get(_TAG_MODEL, "")).strip()
            if not make and not model:
                exif_score += 12
                reasons.append("No camera make/model in EXIF")

            # Capture timestamp (36867 = DateTimeOriginal)
            date_taken = str(exif.get(_TAG_DATETIME_ORIGINAL, "")).strip()
            if not date_taken:
                exif_score += 8
                reasons.append("No capture timestamp in EXIF")

    except Exception:
        exif_score += 8
        reasons.append("EXIF metadata could not be read")

    total_score += min(exif_score, _EXIF_MAX)

    # ── 2. Resolution pattern analysis ──────────────────────────────────────
    res_score = 0
    w, h = img.size
    if w == h and w in _AI_SQUARE_SIZES:
        res_score += 22
        reasons.append(
            f"Square power-of-2 resolution ({w}\u00d7{h}) typical of AI generators"
        )
    elif w == h and w >= 512:
        res_score += 8
        reasons.append(f"Square resolution ({w}\u00d7{h}) common in AI-generated images")
    total_score += min(res_score, _RES_MAX)

    # ── 3. Pixel uniformity / noise analysis (Pillow only) ──────────────────
    noise_score = 0
    try:
        # Thumbnail to 128×128 so stat computation is always fast.
        thumb = img.convert("RGB").resize((128, 128), Image.LANCZOS)
        stat = ImageStat.Stat(thumb)
        stds: list[float] = stat.stddev  # [std_R, std_G, std_B]
        avg_std = sum(stds) / max(len(stds), 1)

        if avg_std < 15:
            noise_score += 20
            reasons.append("Unusually uniform pixel distribution (very low noise)")
        elif avg_std < 25:
            noise_score += 10
            reasons.append("Below-average pixel variance detected")

        # Atypical channel imbalance: synthetic images sometimes show this
        channel_range = max(stds) - min(stds)
        if channel_range > 40:
            noise_score += 12
            reasons.append("Atypical colour channel imbalance detected")

    except Exception:
        pass  # stat failure is non-fatal; skip this component

    total_score += min(noise_score, _NOISE_MAX)

    # ── 4. JPEG re-compression artifact check ────────────────────────────────
    artifact_score = 0
    try:
        if img.format == "JPEG":
            orig_size = len(image_bytes)
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=92, optimize=True)
            reencoded_size = buf.tell()
            # AI images are over-smooth: re-encoding yields ≥ original file size.
            if reencoded_size >= orig_size:
                artifact_score += 15
                reasons.append(
                    "Image appears over-smooth — minimal JPEG re-compression delta"
                )
    except Exception:
        pass  # artifact check failure is non-fatal

    total_score += min(artifact_score, _ARTIFACT_MAX)

    # ── Final scoring ────────────────────────────────────────────────────────
    risk_score = min(100, total_score)
    risk_level = derive_risk_level_from_score(risk_score)
    confidence = _confidence_from_signal_count(len(reasons))

    if not reasons:
        reasons = ["No manipulation or AI-generation indicators detected"]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "reasons": reasons,
        "recommendation": _recommendations(risk_level),
    }


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/image")
async def scan_image(
    file: UploadFile = File(...),
    request: Request = None,
    current_user=Depends(require_user),
):
    """Synchronous, lightweight image authenticity scan.

    Accepts PNG, JPEG, or WebP images up to 10 MB.
    Returns a complete risk assessment with no null fields.
    """
    client_ip = request.client.host if request and request.client else "unknown"

    # ── MIME-type guard ──────────────────────────────────────────────────────
    content_type = (file.content_type or "").lower().split(";")[0].strip()
    if content_type not in _ALLOWED_MIMES:
        raise HTTPException(
            status_code=400,
            detail="Only image files are supported (PNG, JPEG, WebP)",
        )

    # ── Read & size guard ────────────────────────────────────────────────────
    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(image_bytes) > _MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Image too large (max 10 MB)")

    # ── Rate limiting ────────────────────────────────────────────────────────
    apply_scan_rate_limits(
        current_user=current_user,
        endpoint="/scan/image",
        client_ip=client_ip,
        user_namespace="scan:image:user",
        user_limit=30,
        ip_namespace="scan:image:ip",
        ip_limit=90,
        plan_limit_policy="plan_quota",
        scan_type="image",
    )

    # ── Detection ────────────────────────────────────────────────────────────
    try:
        result = _analyze_image(image_bytes)
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "scan_image_detection_failed",
            extra={"user_id": str(current_user.id), "endpoint": "/scan/image"},
        )
        raise HTTPException(status_code=500, detail="Image analysis failed")

    logger.info(
        "scan_image_complete",
        extra={
            "user_id": str(current_user.id),
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "confidence": result["confidence"],
            "signal_count": len(result["reasons"]),
            "endpoint": "/scan/image",
        },
    )

    # Return the flat dict; the envelope middleware adds {"status":"success","data":{...}}
    return result
