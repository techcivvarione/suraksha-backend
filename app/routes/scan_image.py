"""POST /scan/image and POST /scan/image/explain — image authenticity scanner.

Detection methods (pure Python + Pillow — no AI models, no external APIs):
  1. EXIF metadata analysis
     - Missing EXIF         → weak signal  (10 pts)
     - AI software tag      → strong signal (65 pts, always HIGH alone)
     - No camera make/model → weak signal  (6 pts)
     - No capture timestamp → weak signal  (4 pts)
  2. Resolution pattern analysis
     - Square power-of-2 AI size  → medium signal (20 pts)
     - Generic large square       → weak signal   (6 pts)
     - Unusual aspect ratio       → weak signal   (8 pts)
  3. Pixel uniformity / noise analysis
     - Very low pixel stddev      → medium signal (25 pts)
     - Below-average pixel stddev → weak signal   (8 pts)
     - Channel imbalance          → medium signal (15 pts)
     - Noise distribution uniform → medium signal (15 pts)
  4. JPEG over-smoothness
     - Re-encoding at Q92 ≥ original → medium signal (20 pts)
  5. Edge sharpness variance
     - Unnaturally consistent edges  → medium signal (12 pts)
  6. Colour banding
     - Very few distinct colours     → weak signal  (10 pts)
  7. Shannon entropy variance (applied last, ±5 pts)

Scoring:
  - No per-component caps; only total is capped at 100.
  - Spread target: 10–30 for clean real photos, 40–65 for ambiguous,
    65–95 for clear AI indicators.

Response schema (POST /scan/image):
  {
    "risk_score":        int,    # 0–100
    "risk_level":        str,    # "LOW" | "MEDIUM" | "HIGH"
    "confidence":        float,  # 0.50–0.92 (detection_confidence internally)
    "confidence_label":  str,    # "Low" | "Moderate" | "High"
    "summary":           str,    # 1-line human explanation
    "highlights":        [str],  # human-friendly detection reasons
    "technical_signals": [str],  # raw signal codes
    "recommendation":    str     # clear action for the user
  }

Response schema (POST /scan/image/explain):
  { "explanation": str }         # 2-3 plain-English sentences via GPT-4o-mini

Both responses are wrapped in {"status":"success","data":{...}} by the envelope
middleware.
"""
from __future__ import annotations

import hashlib
import io
import logging
import math
import re

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from PIL import Image, ImageFilter, ImageStat
from pydantic import BaseModel

from app.db import get_db
from app.dependencies.access import require_feature
from app.core.features import Feature, TIER_ULTRA, normalize_plan
from app.routes.scan_base import apply_scan_rate_limits, require_user
from app.services.plan_limits import LimitType, enforce_limit
from app.services.redis_store import allow_daily_limit, get_redis
from app.services.risk_mapper import derive_risk_level_from_score
from app.services.safe_response import safe_scan_response
from app.services.security_alerts import try_create_scan_alert
from sqlalchemy.orm import Session

router = APIRouter(prefix="/scan", tags=["Scan"])
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ALLOWED_MIMES: frozenset[str] = frozenset({"image/png", "image/jpeg", "image/webp"})
_MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Known AI / generative-tool software strings (EXIF tag 305).
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

# Exact pixel widths most commonly produced by AI generators.
_AI_SQUARE_SIZES: frozenset[int] = frozenset({256, 512, 768, 1024, 1280, 1536, 2048})

# EXIF tag IDs understood by Pillow's getexif().
_TAG_SOFTWARE = 305
_TAG_MAKE = 271
_TAG_MODEL = 272
_TAG_DATETIME_ORIGINAL = 36867

# Standard camera / phone aspect ratios (long/short, value >= 1).
# Comparison uses 5 % tolerance.
_STD_RATIOS: tuple[float, ...] = (1.0, 4 / 3, 3 / 2, 16 / 9, 2.0, 5 / 4, 9 / 5)

# Signal codes that carry meaningful pixel-level evidence (not just absence data).
# Used to separate strong structural evidence from metadata gaps when computing
# detection_confidence.
_MEDIUM_SIGNAL_CODES: frozenset[str] = frozenset({
    "VERY_LOW_NOISE",
    "CHANNEL_IMBALANCE",
    "JPEG_OVERSMOOTH",
    "NOISE_UNIFORMITY",
    "EDGE_VARIANCE_LOW",
    "AI_SQUARE_RESOLUTION",
})


# ---------------------------------------------------------------------------
# Dynamic phrasing tables — 3 variants per signal key.
# Phrase selection is deterministic (driven by SHA-256 file seed).
# ---------------------------------------------------------------------------
_HIGHLIGHTS: dict[str, list[str]] = {
    "exif_missing": [
        "No camera metadata was found — most real photos carry this automatically.",
        "This image has no embedded origin data, which is unusual for genuine photos.",
        "Missing metadata fingerprint — authentic cameras always write EXIF information.",
    ],
    "ai_software": [
        "This image contains a digital fingerprint from an AI creation tool.",
        "A known AI generation tool left its signature in the image metadata.",
        "The file metadata directly identifies an AI image generator as its source.",
    ],
    "no_camera": [
        "No camera brand or model was recorded — real devices always embed this.",
        "Camera identity is absent, suggesting the image was not taken with a physical device.",
        "Missing camera manufacturer data is a common trait of AI-generated images.",
    ],
    "no_timestamp": [
        "No capture timestamp found — genuine camera shots are time-stamped automatically.",
        "The date of capture is absent, which may indicate a non-camera source.",
        "Real photographs record when they were taken; this one does not.",
    ],
    "exif_unreadable": [
        "Metadata could not be read — the file may have been processed or stripped.",
        "Embedded image data appears corrupted or has been deliberately removed.",
        "Unable to extract origin metadata from this file.",
    ],
    "ai_square_resolution": [
        "Exact square dimensions match standard AI generator output sizes.",
        "The image dimensions are a common AI canvas size, not a typical camera ratio.",
        "Resolution pattern is characteristic of images generated by AI tools.",
    ],
    "square_resolution": [
        "Square proportions are more common in AI-generated content than in real photos.",
        "Perfectly square dimensions suggest this may not be a camera photograph.",
        "This image's square format is atypical for photographs captured on a device.",
    ],
    "unusual_aspect": [
        "The image proportions don't match any standard camera or phone output format.",
        "An unusual aspect ratio was detected — this is rarely produced by real cameras.",
        "Non-standard image proportions suggest the file may have been generated, not photographed.",
    ],
    "very_low_noise": [
        "Pixel-level texture is unusually smooth — AI images often lack natural grain.",
        "Extremely low image noise suggests this was synthesised rather than photographed.",
        "The image has a hyper-smooth texture pattern consistent with AI generation.",
    ],
    "low_noise": [
        "Below-average grain detected — real photos have subtle, natural noise.",
        "Pixel variance is lower than expected for a photograph.",
        "Reduced texture irregularity hints at a non-photographic origin.",
    ],
    "channel_imbalance": [
        "Unusual colour channel distribution was detected in the pixel data.",
        "Atypical colour balance across channels can be a sign of synthetic generation.",
        "The red, green, and blue channels show an irregular variance pattern.",
    ],
    "jpeg_artifact": [
        "The image compresses like AI output — over-smooth files behave this way.",
        "JPEG re-compression analysis shows minimal quality loss, typical of AI imagery.",
        "Compression signature matches AI-generated content rather than a real photograph.",
    ],
    "edge_variance_low": [
        "Edge sharpness is unusually consistent — real photos have varied focus across regions.",
        "The image shows unnaturally even detail throughout, which cameras rarely produce.",
        "Sharpness uniformity across the frame is a subtle indicator of synthetic generation.",
    ],
    "color_banding": [
        "Limited colour variety was detected, which can indicate AI generation or heavy post-processing.",
        "The image uses a narrower colour palette than is typical for a natural photograph.",
        "Colour distribution patterns suggest this image may have been digitally synthesised.",
    ],
    "noise_uniformity": [
        "Image noise is distributed too evenly — real photos show more variation between regions.",
        "The texture pattern is suspiciously consistent across different areas of the image.",
        "Noise distribution analysis suggests this image may not have a photographic origin.",
    ],
    "no_signals": [
        "All standard checks passed — no manipulation or AI markers were detected.",
        "No suspicious patterns found; image appears consistent with a real photograph.",
        "Metadata and pixel analysis show no indicators of AI generation or editing.",
    ],
}

_SUMMARIES: dict[str, list[str]] = {
    "HIGH": [
        "Multiple strong indicators suggest this image was AI-generated or heavily manipulated.",
        "This image shows clear signs of synthetic generation or digital fabrication.",
        "Several signals point toward AI creation — this image is likely not a real photograph.",
    ],
    "MEDIUM": [
        "Some suspicious patterns were detected — treat this image with caution.",
        "Mixed signals found; this image may have been edited or generated by AI.",
        "Indicators of potential manipulation are present — verify the source if it matters.",
    ],
    "LOW": [
        "No significant manipulation or AI generation indicators were found.",
        "This image appears consistent with a genuine photograph.",
        "All checks passed — image shows characteristics typical of a real photo.",
    ],
}

_RECOMMENDATIONS: dict[str, list[str]] = {
    "HIGH": [
        "Verify the image source independently before sharing or trusting this content.",
        "Do not treat this as genuine without independent verification from the original source.",
        "Cross-check with original sources — this image is likely AI-created or digitally fabricated.",
    ],
    "MEDIUM": [
        "Approach with caution and verify the image origin if the content is sensitive.",
        "Check where this image came from before acting on it.",
        "Consider a reverse image search or source verification before trusting this content.",
    ],
    "LOW": [
        "Image appears authentic. No further action required.",
        "No manipulation detected — this image is consistent with a genuine photograph.",
        "No suspicious signals found. Image looks authentic.",
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_seed(image_bytes: bytes) -> int:
    """Deterministic seed from the first 8 hex chars of SHA-256 — drives phrase selection."""
    return int(hashlib.sha256(image_bytes).hexdigest()[:8], 16)


def _pick(options: list[str], seed: int, idx: int) -> str:
    """Pick one phrase deterministically — same file always produces the same variant."""
    return options[(seed + idx) % len(options)]


def _pixel_entropy(img: Image.Image) -> float:
    """Shannon entropy of the grayscale histogram (0.0 – 8.0 bits per pixel)."""
    grey = img.convert("L")
    hist = grey.histogram()  # 256 bins
    total = sum(hist)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in hist:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _confidence_label(detection_confidence: float) -> str:
    """Map a float detection confidence to a human-readable label."""
    if detection_confidence >= 0.80:
        return "High"
    if detection_confidence >= 0.62:
        return "Moderate"
    return "Low"


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _analyze_image(image_bytes: bytes) -> dict:
    """Run all lightweight checks and return a complete, non-null result dict."""
    seed = _file_seed(image_bytes)
    signal_keys: list[str] = []   # raw codes → technical_signals
    highlights: list[str] = []    # human-friendly reasons
    total_score = 0
    has_strong_signal = False     # AI software tag found

    # ── Open and force-decode ────────────────────────────────────────────────
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Cannot decode image: {exc}")

    # ── Shannon entropy variance (±5 pts, applied to final score) ───────────
    try:
        entropy = _pixel_entropy(img)
    except Exception:
        entropy = 6.0  # neutral fallback
    if entropy < 5.5:
        entropy_delta = 5     # suspiciously flat histogram
    elif entropy > 7.5:
        entropy_delta = -5    # rich, complex image — slight reduction
    else:
        entropy_delta = 0

    # ────────────────────────────────────────────────────────────────────────
    # 1. EXIF metadata analysis
    # ────────────────────────────────────────────────────────────────────────
    try:
        exif: dict = img.getexif() if hasattr(img, "getexif") else {}

        if not exif:
            # Weak signal: many real images (screenshots, web images) lack EXIF
            total_score += 10
            signal_keys.append("EXIF_MISSING")
            highlights.append(_pick(_HIGHLIGHTS["exif_missing"], seed, len(highlights)))
        else:
            # Software tag (305) — strong signal when AI keyword found
            software_raw = str(exif.get(_TAG_SOFTWARE, "")).strip()
            if software_raw:
                sw_lower = software_raw.lower()
                for kw in _AI_SOFTWARE_KEYWORDS:
                    if kw in sw_lower:
                        total_score += 65
                        has_strong_signal = True
                        signal_keys.append("AI_SOFTWARE_TAG")
                        highlights.append(
                            f'AI creation tool identified in file metadata: '
                            f'"{software_raw[:60]}"'
                        )
                        break

            # Camera make/model (271, 272) — weak absence signal
            make = str(exif.get(_TAG_MAKE, "")).strip()
            model = str(exif.get(_TAG_MODEL, "")).strip()
            if not make and not model:
                total_score += 6
                signal_keys.append("NO_CAMERA_ID")
                highlights.append(_pick(_HIGHLIGHTS["no_camera"], seed, len(highlights)))

            # Capture timestamp (36867 = DateTimeOriginal) — weak absence signal
            date_taken = str(exif.get(_TAG_DATETIME_ORIGINAL, "")).strip()
            if not date_taken:
                total_score += 4
                signal_keys.append("NO_TIMESTAMP")
                highlights.append(_pick(_HIGHLIGHTS["no_timestamp"], seed, len(highlights)))

    except Exception:
        total_score += 6
        signal_keys.append("EXIF_UNREADABLE")
        highlights.append(_pick(_HIGHLIGHTS["exif_unreadable"], seed, len(highlights)))

    # ────────────────────────────────────────────────────────────────────────
    # 2. Resolution / dimension analysis
    # ────────────────────────────────────────────────────────────────────────
    w, h = img.size

    if w == h and w in _AI_SQUARE_SIZES:
        # Medium signal: exact AI generator canvas size
        total_score += 20
        signal_keys.append("AI_SQUARE_RESOLUTION")
        highlights.append(_pick(_HIGHLIGHTS["ai_square_resolution"], seed, len(highlights)))
    elif w == h and w >= 512:
        # Weak signal: generic large square
        total_score += 6
        signal_keys.append("SQUARE_RESOLUTION")
        highlights.append(_pick(_HIGHLIGHTS["square_resolution"], seed, len(highlights)))
    elif w != h:
        # Check for unusual (non-standard) aspect ratio
        ratio = max(w, h) / max(min(w, h), 1)
        is_standard = any(abs(ratio - r) <= r * 0.05 for r in _STD_RATIOS)
        if not is_standard and 1.1 <= ratio <= 2.1:
            total_score += 8
            signal_keys.append("UNUSUAL_ASPECT_RATIO")
            highlights.append(_pick(_HIGHLIGHTS["unusual_aspect"], seed, len(highlights)))

    # ────────────────────────────────────────────────────────────────────────
    # 3. Pixel uniformity / noise analysis
    # ────────────────────────────────────────────────────────────────────────
    try:
        # Work on 128×128 thumbnail for consistent, fast computation.
        thumb128 = img.convert("RGB").resize((128, 128), Image.LANCZOS)
        stat = ImageStat.Stat(thumb128)
        stds: list[float] = stat.stddev   # [std_R, std_G, std_B]
        avg_std = sum(stds) / max(len(stds), 1)

        if avg_std < 15:
            # Medium signal: unnaturally smooth (AI over-synthesis)
            total_score += 25
            signal_keys.append("VERY_LOW_NOISE")
            highlights.append(_pick(_HIGHLIGHTS["very_low_noise"], seed, len(highlights)))
        elif avg_std < 25:
            # Weak signal: below-average variance
            total_score += 8
            signal_keys.append("LOW_NOISE")
            highlights.append(_pick(_HIGHLIGHTS["low_noise"], seed, len(highlights)))

        # Channel imbalance — medium signal
        channel_range = max(stds) - min(stds)
        if channel_range > 40:
            total_score += 15
            signal_keys.append("CHANNEL_IMBALANCE")
            highlights.append(_pick(_HIGHLIGHTS["channel_imbalance"], seed, len(highlights)))

    except Exception:
        pass  # non-fatal

    # ────────────────────────────────────────────────────────────────────────
    # 4. Noise distribution uniformity (patch-level analysis)
    #    16 patches on a greyscale thumbnail; low coefficient-of-variation of
    #    patch stds = AI images tend to have uniform noise everywhere.
    # ────────────────────────────────────────────────────────────────────────
    try:
        grey128 = img.convert("L").resize((128, 128), Image.LANCZOS)
        patch_stds: list[float] = []
        for row in range(4):
            for col in range(4):
                box = (col * 32, row * 32, (col + 1) * 32, (row + 1) * 32)
                ps = ImageStat.Stat(grey128.crop(box)).stddev[0]
                patch_stds.append(ps)

        mean_ps = sum(patch_stds) / len(patch_stds)
        if mean_ps > 3.0:   # image has some content, not a blank canvas
            cv = math.sqrt(
                sum((s - mean_ps) ** 2 for s in patch_stds) / len(patch_stds)
            ) / mean_ps
            if cv < 0.30:   # suspiciously uniform noise distribution
                total_score += 15
                signal_keys.append("NOISE_UNIFORMITY")
                highlights.append(_pick(_HIGHLIGHTS["noise_uniformity"], seed, len(highlights)))
    except Exception:
        pass

    # ────────────────────────────────────────────────────────────────────────
    # 5. JPEG re-compression artifact check
    #    AI images are over-smooth; re-encoding at Q92 yields ≥ original size.
    # ────────────────────────────────────────────────────────────────────────
    try:
        if img.format == "JPEG":
            orig_size = len(image_bytes)
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=92, optimize=True)
            if buf.tell() >= orig_size:
                total_score += 20
                signal_keys.append("JPEG_OVERSMOOTH")
                highlights.append(_pick(_HIGHLIGHTS["jpeg_artifact"], seed, len(highlights)))
    except Exception:
        pass

    # ────────────────────────────────────────────────────────────────────────
    # 6. Edge sharpness variance
    #    Real photos have varied sharpness (focused subjects, blurry backgrounds);
    #    AI images tend to have uniformly crisp edges everywhere.
    # ────────────────────────────────────────────────────────────────────────
    try:
        grey_edge = img.convert("L").resize((128, 128), Image.LANCZOS)
        edges = grey_edge.filter(ImageFilter.FIND_EDGES)
        es = ImageStat.Stat(edges)
        edge_mean = es.mean[0]
        edge_std = es.stddev[0]
        # Edges present (mean > threshold) but distribution too uniform (std/mean < 0.55)
        if edge_mean > 8 and edge_std < edge_mean * 0.55:
            total_score += 12
            signal_keys.append("EDGE_VARIANCE_LOW")
            highlights.append(_pick(_HIGHLIGHTS["edge_variance_low"], seed, len(highlights)))
    except Exception:
        pass

    # ────────────────────────────────────────────────────────────────────────
    # 7. Colour banding / limited palette
    #    Count distinct 4-bit quantised colours in a 32×32 thumbnail.
    #    Natural photos typically use 150+ distinct 4-bit colours;
    #    heavily banded / posterised images use far fewer.
    # ────────────────────────────────────────────────────────────────────────
    try:
        mini = img.convert("RGB").resize((32, 32), Image.LANCZOS)
        pixels = [(r >> 4, g >> 4, b >> 4) for r, g, b in mini.getdata()]
        distinct_colors = len(set(pixels))
        if distinct_colors < 60:
            total_score += 10
            signal_keys.append("COLOR_BANDING")
            highlights.append(_pick(_HIGHLIGHTS["color_banding"], seed, len(highlights)))
    except Exception:
        pass

    # ────────────────────────────────────────────────────────────────────────
    # Final scoring
    # ────────────────────────────────────────────────────────────────────────
    risk_score = min(100, max(0, total_score + entropy_delta))
    risk_level = derive_risk_level_from_score(risk_score)

    # Count medium-quality signals for confidence assessment.
    medium_count = sum(1 for k in signal_keys if k in _MEDIUM_SIGNAL_CODES)
    n_total = len(signal_keys)

    # detection_confidence reflects how reliable the result is,
    # NOT the probability of being AI-generated.
    if has_strong_signal:
        detection_confidence = 0.92
    elif medium_count >= 3:
        detection_confidence = 0.85
    elif medium_count >= 2:
        detection_confidence = 0.78
    elif medium_count >= 1:
        detection_confidence = 0.70
    elif n_total >= 3:
        detection_confidence = 0.68
    elif n_total == 2:
        detection_confidence = 0.62
    elif n_total == 1:
        detection_confidence = 0.56
    elif entropy < 5.5:
        detection_confidence = 0.55  # entropy anomaly without discrete signals
    else:
        detection_confidence = 0.50

    # ── Human-readable outputs ───────────────────────────────────────────────
    if not signal_keys:
        highlights = [_pick(_HIGHLIGHTS["no_signals"], seed, 0)]
        summary = _pick(_SUMMARIES["LOW"], seed, 0)
    elif has_strong_signal:
        summary = "This image contains a digital fingerprint from an AI creation tool."
    else:
        summary = _pick(_SUMMARIES[risk_level], seed, 1)

    recommendation = _pick(_RECOMMENDATIONS[risk_level], seed + 1, 0)

    return {
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "confidence":        round(detection_confidence, 2),
        "confidence_label":  _confidence_label(detection_confidence),
        "summary":           summary,
        "highlights":        highlights,
        "technical_signals": signal_keys,
        "recommendation":    recommendation,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/image")
async def scan_image(
    file: UploadFile = File(...),
    request: Request = None,
    current_user=Depends(require_user),
    db: Session = Depends(get_db),
):
    """Synchronous, lightweight image authenticity scan.

    Accepts PNG, JPEG, or WebP images up to 10 MB.
    Returns a complete risk assessment with no null fields.
    FREE users: 1 lifetime scan (enforced via DB counter).
    PRO/ULTRA: unlimited.
    """
    client_ip = request.client.host if request and request.client else "unknown"

    content_type = (file.content_type or "").lower().split(";")[0].strip()
    if content_type not in _ALLOWED_MIMES:
        raise HTTPException(
            status_code=400,
            detail="Only image files are supported (PNG, JPEG, WebP)",
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(image_bytes) > _MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Image too large (max 10 MB)")

    # Enforce per-plan rate limits; lifetime counter for FREE is below
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

    # FREE: enforce 1-lifetime DB counter (PRO/ULTRA skipped inside enforce_limit)
    enforce_limit(current_user, LimitType.AI_IMAGE_LIFETIME, db=db, endpoint="/scan/image")

    try:
        result = _analyze_image(image_bytes)
    except HTTPException:
        raise
    except Exception:
        # STEP 1 — Global fail-safe: NEVER return 500 to the user
        logger.exception(
            "scan_failed",
            extra={
                "endpoint": "/scan/image",
                "user_id": str(current_user.id),
                "input_size": len(image_bytes),
            },
        )
        return safe_scan_response(
            analysis_type="IMAGE",
            endpoint="/scan/image",
        )

    logger.info(
        "scan_image_complete",
        extra={
            "user_id":           str(current_user.id),
            "risk_score":        result["risk_score"],
            "risk_level":        result["risk_level"],
            "confidence":        result["confidence"],
            "confidence_label":  result["confidence_label"],
            "signal_count":      len(result["technical_signals"]),
            "endpoint":          "/scan/image",
        },
    )

    # Create alert for MEDIUM (≥40) or HIGH (≥70) risk — safe helper, never raises
    try_create_scan_alert(
        db,
        user=current_user,
        client_ip=client_ip,
        risk_score=int(result["risk_score"]),
        analysis_type="IMAGE",
        scan_id=None,
    )

    return result


# ---------------------------------------------------------------------------
# /scan/image/explain — LLM-powered plain-English explanation
# ---------------------------------------------------------------------------

_EXPLAIN_CACHE_TTL_SECONDS: int = 7 * 24 * 60 * 60  # 7 days

# ── System prompt ─────────────────────────────────────────────────────────────
# Tone + vocabulary rules are enforced here at the system level so they hold
# regardless of what the user prompt says.
_EXPLAIN_SYSTEM = (
    "You are a warm, helpful friend explaining things to people in India who are not good with technology. "
    "You just checked a photo for them and you are telling them what you found. "
    "Speak like a trusted neighbour — friendly, direct, and easy to understand. "
    "Never sound like a computer report or a formal letter. "
    "Use ONLY everyday words a 12-year-old would understand. "
    # ── Hard vocabulary ban ───────────────────────────────────────────────────
    "BANNED words — never use these: metadata, entropy, compression, artifact, heuristic, anomaly, "
    "algorithm, pixel, exif, JPEG, synthesis, forensic, luminance, coefficient, variance, "
    "distribution, spectrum, histogram, indicators, signals, analysis, detection, generated, "
    "'AI generation', pattern, texture, benchmark, threshold, correlation. "
    # ── Preferred vocabulary ──────────────────────────────────────────────────
    "INSTEAD use natural phrases like: 'looks real', 'looks fake', 'made by a computer', "
    "'not from a real camera', 'nothing unusual', 'something feels off', 'we noticed', 'seems real'. "
    # ── Tone rules based on score ─────────────────────────────────────────────
    "TONE RULES — the risk score is given in the user message, follow these exactly: "
    "  Score 0–30  → warm and reassuring. Start positively, put the person at ease. "
    "  Score 31–60 → gently cautious. Note something seems slightly unusual — calm but alert. "
    "  Score 61–100 → clear direct warning. Be honest that the photo looks fake, without being scary. "
    # ── Structure ─────────────────────────────────────────────────────────────
    "Write 2–3 short sentences only — no more. One plain paragraph. No bullet points or numbers. "
    "VARY your opening every time — never start the same way twice. "
    "Do NOT always start with 'This image' or 'This photo'. "
    # ── Anti-generic phrases ──────────────────────────────────────────────────
    "BANNED phrases: 'this is safe for now', 'exercise caution', 'for your information', "
    "'it is advisable', 'please note', 'based on our analysis', 'it appears that', "
    "'I would recommend', 'you should consider'. "
    "Be specific to the actual evidence — mention what was actually noticed."
)


class ImageExplainRequest(BaseModel):
    risk_level: str           # "LOW" | "MEDIUM" | "HIGH"
    risk_score: int           # 0–100
    highlights: list[str]     # human-readable detection reasons from /scan/image
    recommendation: str       # action text from /scan/image
    # kept for backwards-compat; not used in the new prompt
    summary: str | None = None


def _explain_cache_key(risk_level: str, risk_score: int, highlights: list[str]) -> str:
    """Stable SHA-256 cache key — same scan data always maps to the same key."""
    # Sort highlights so minor ordering differences don't break cache hits.
    h_norm = "|".join(sorted(h.strip().lower() for h in highlights[:5]))
    raw = f"v4|{risk_level.upper()}|{risk_score}|{h_norm}"
    return f"explain:image:{hashlib.sha256(raw.encode()).hexdigest()[:24]}"


def _clean_highlights(highlights: list[str]) -> list[str]:
    """Return only human-readable highlights — drop raw ALL_CAPS signal codes."""
    return [h for h in highlights if not re.match(r'^[A-Z0-9_]+$', h.strip()) and len(h.strip()) > 15]


# ── Opening-phrase pools for the fallback ────────────────────────────────────
# Four variants per tone level — selection is deterministic (driven by the
# first highlight text) so the same scan always returns the same variant,
# but different scans get different openings.

_FALLBACK_OPENERS: dict[str, list[str]] = {
    "LOW": [
        "This photo looks completely genuine to us.",
        "Nothing feels off about this image — it looks real.",
        "We had a close look and everything seems fine here.",
        "This looks like a normal photo taken with a real camera.",
    ],
    "MEDIUM": [
        "Something about this photo feels a little unusual.",
        "We are not fully sure about this one.",
        "A few things here look a bit odd to us.",
        "We noticed something slightly unusual about this photo.",
    ],
    "HIGH": [
        "This photo does not look real to us.",
        "We are quite sure this image was made by a computer, not a real camera.",
        "Something is clearly not right about this photo.",
        "This image has some clear signs that it was not taken with a real camera.",
    ],
}


def _fallback_seed(risk_level: str, highlights: list[str]) -> int:
    """Deterministic 0–3 seed so the same scan always picks the same opener."""
    seed_str = risk_level.upper() + (highlights[0][:30] if highlights else "empty")
    return int(hashlib.sha256(seed_str.encode()).hexdigest()[:4], 16)


def _build_prompt(
    risk_level: str,
    risk_score: int,
    highlights: list[str],
    recommendation: str,
) -> str:
    """Result-specific user prompt — all four scan fields injected, with tone instruction."""
    clean = _clean_highlights(highlights)[:4]
    findings = "; ".join(clean) if clean else "no single clear sign was found"

    verdict_hint = {
        "HIGH":   f"looks very likely fake — probably made by a computer (score: {risk_score}/100)",
        "MEDIUM": f"has some unusual things — hard to say for sure (score: {risk_score}/100)",
        "LOW":    f"looks like a genuine photo (score: {risk_score}/100)",
    }.get(risk_level.upper(), f"was checked (score: {risk_score}/100)")

    if risk_score <= 30:
        tone = "Tone: warm and reassuring. Start positively and put the person at ease."
    elif risk_score <= 60:
        tone = "Tone: gently cautious. Note something seems slightly unusual — keep them calm but alert."
    else:
        tone = "Tone: clear direct warning. Be honest that this photo looks fake without being scary."

    return (
        f"Photo check result: this photo {verdict_hint}. "
        f"What we noticed: {findings}. "
        f"What to do: {recommendation}. "
        f"{tone} "
        "Write 2–3 short sentences. "
        "Mention what was actually noticed — be specific, not generic. "
        "Vary your opening — do not start with 'This image' or repeat predictable phrases."
    )


def _build_fallback(
    risk_level: str,
    risk_score: int,
    highlights: list[str],
    recommendation: str,
) -> str:
    """Deterministic, result-specific fallback.

    Uses the first human-readable highlight as the 'reason' sentence so two
    different scans produce different text even without an LLM call.
    Opening line is chosen from a pool keyed by risk level + highlights hash.
    """
    clean = _clean_highlights(highlights)
    first_reason = clean[0].rstrip(". ") if clean else None
    rec = recommendation.strip().rstrip(".")

    rl = risk_level.upper() if risk_level.upper() in _FALLBACK_OPENERS else "MEDIUM"
    idx = _fallback_seed(risk_level, highlights) % len(_FALLBACK_OPENERS[rl])
    opener = _FALLBACK_OPENERS[rl][idx]

    # Reason clause — uses actual highlight when available
    if first_reason:
        why = f" We noticed that {first_reason.lower()}."
    elif rl == "HIGH":
        why = f" The score is {risk_score} out of 100, which is very high."
    elif rl == "MEDIUM":
        why = f" The score is {risk_score} out of 100, which means something may not be right."
    else:
        why = f" The score is only {risk_score} out of 100, which means it looks real."

    # Action clause — reassuring for LOW, recommendation for others
    if rl == "LOW":
        action = " There is nothing to worry about — this photo seems genuine."
    else:
        action = f" {rec}."

    return (opener + why + action).strip()


@router.post("/image/explain")
async def explain_image(
    body: ImageExplainRequest,
    request: Request,
    current_user=Depends(require_feature(Feature.AI_EXPLAIN)),  # blocks FREE users (403 + upgrade payload)
):
    """LLM-powered plain-English explanation of an image scan result.

    Requires AI_EXPLAIN feature (GO_PRO or GO_ULTRA).
    PRO: 20 explain calls/day. ULTRA: unlimited.

    Accepts the structured outputs from POST /scan/image and returns 3 plain-English
    sentences specific to THIS scan result. Results are cached in Redis (7 days) so
    the same scan never triggers a second OpenAI call.
    """
    client_ip = request.client.host or "unknown"
    plan = normalize_plan(getattr(current_user, "plan", None))

    # IP-level abuse guard — 20 unique explain calls/day per IP
    if not allow_daily_limit("scan:image:explain:ip", 20, client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many explain requests from this network. Try again tomorrow.",
        )

    # PRO: 20/day per user; ULTRA: unlimited
    if plan != TIER_ULTRA:
        if not allow_daily_limit("scan:image:explain:user", 20, str(current_user.id)):
            raise HTTPException(
                status_code=429,
                detail="Daily AI explain limit reached. Try again tomorrow.",
            )

    # ── Redis cache check ──────────────────────────────────────────────────────
    cache_key = _explain_cache_key(body.risk_level, body.risk_score, body.highlights)
    try:
        cached = get_redis().get(cache_key)
        if cached:
            logger.info("explain_image_cache_hit", extra={"cache_key": cache_key})
            return {"explanation": cached}
    except Exception:
        pass  # Redis unavailable — proceed to generate

    # ── Generate via GPT-4o-mini ───────────────────────────────────────────────
    prompt = _build_prompt(body.risk_level, body.risk_score, body.highlights, body.recommendation)

    try:
        import openai  # guarded import — keeps startup fast when unused

        ai_client = openai.OpenAI()  # reads OPENAI_API_KEY from environment
        response = ai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _EXPLAIN_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            max_tokens=120,
            temperature=0.7,
        )
        explanation = (response.choices[0].message.content or "").strip()
        if not explanation:
            raise ValueError("Empty LLM response")

    except Exception:
        logger.warning(
            "explain_image_llm_failed_using_fallback",
            extra={"risk_level": body.risk_level, "risk_score": body.risk_score},
        )
        explanation = _build_fallback(
            body.risk_level, body.risk_score, body.highlights, body.recommendation
        )

    # ── Cache the result ───────────────────────────────────────────────────────
    try:
        get_redis().set(cache_key, explanation, ex=_EXPLAIN_CACHE_TTL_SECONDS)
    except Exception:
        pass  # Redis unavailable — non-fatal

    return {"explanation": explanation}
