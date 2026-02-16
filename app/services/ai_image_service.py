import io
import json
import logging
import os
import base64
from typing import Dict

from PIL import Image, ImageStat
import piexif
from openai import OpenAI


# =========================================================
# CONFIG
# =========================================================

AI_SOFTWARE_KEYWORDS = [
    "stable diffusion", "midjourney", "dall-e",
    "firefly", "runway", "imagen", "comfyui",
    "invoke", "diffusion", "gan"
]

CAMERA_FIELDS = [
    piexif.ExifIFD.FocalLength,
    piexif.ExifIFD.ExposureTime,
    piexif.ExifIFD.FNumber,
    piexif.ExifIFD.ISOSpeedRatings,
]

COMMON_AI_SIZES = [512, 768, 1024, 1536, 2048]


# =========================================================
# EXIF ANALYSIS (WEAK SIGNAL)
# =========================================================

def analyze_exif(image_bytes: bytes) -> Dict:
    ai_score = 0
    real_score = 0
    signals = []

    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif_raw = img.info.get("exif")

        if not exif_raw:
            # DO NOT penalize — WhatsApp strips EXIF
            signals.append("Metadata stripped (common after social sharing)")
        else:
            exif_data = piexif.load(exif_raw)

            # Software tag check
            software = ""
            if piexif.ImageIFD.Software in exif_data.get("0th", {}):
                software = exif_data["0th"][piexif.ImageIFD.Software]
                software = (
                    software.decode("utf-8", errors="ignore").lower()
                    if isinstance(software, bytes)
                    else str(software).lower()
                )

                for kw in AI_SOFTWARE_KEYWORDS:
                    if kw in software:
                        signals.append(f"Software tag indicates AI tool")
                        ai_score += 30
                        break

            # Camera fields
            exif_ifd = exif_data.get("Exif", {})
            found = sum(1 for f in CAMERA_FIELDS if f in exif_ifd)

            if found >= 2:
                real_score += 25
                signals.append("Camera hardware metadata present")

        # Size heuristic (minor)
        w, h = img.size
        if w == h and w in COMMON_AI_SIZES:
            ai_score += 5
            signals.append("Resolution matches common AI output size")

    except Exception as e:
        logging.warning(f"EXIF analysis error: {e}")

    return {
        "ai_score": ai_score,
        "real_score": real_score,
        "signals": signals
    }


# =========================================================
# TAMPER DETECTION (NEW)
# =========================================================

def detect_basic_tampering(image_bytes: bytes) -> Dict:
    """
    Basic forensic indicators:
    - Extreme compression artifacts
    - Unnatural uniform smoothness
    """

    signals = []
    score_adjustment = 0

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        stat = ImageStat.Stat(img)

        variance = sum(stat.var) / len(stat.var)

        # Very low variance → over-smoothed (AI-like)
        if variance < 50:
            score_adjustment += 10
            signals.append("Unusually smooth texture detected")

        # Extremely high variance → heavy compression artifacts
        if variance > 5000:
            score_adjustment -= 5
            signals.append("High compression artifacts detected")

    except Exception:
        pass

    return {
        "score_adjustment": score_adjustment,
        "signals": signals
    }


# =========================================================
# VISION MODEL (PRIMARY SIGNAL)
# =========================================================

def analyze_with_ai_vision(image_bytes: bytes) -> Dict:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return {
            "confidence": 50,
            "signals": ["Vision model unavailable"]
        }

    try:
        client = OpenAI(api_key=api_key)
        b64 = base64.b64encode(image_bytes).decode()

        prompt = """
Determine probability (0-100) that this image is AI-generated.

Focus on:
- Texture realism
- Lighting consistency
- Background distortions
- Skin/hair artifacts
- Symmetry anomalies
- AI rendering artifacts

Return strict JSON:
{
  "ai_probability": <number>,
  "signals": [max 5 short reasons]
}
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.1,
            max_tokens=300,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{b64}",
                                "detail": "high"
                            }
                        },
                        {"type": "text", "text": prompt}
                    ]
                }
            ],
        )

        raw = response.choices[0].message.content
        parsed = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])

        confidence = int(parsed.get("ai_probability", 50))

        # Prevent extreme certainty
        confidence = max(5, min(95, confidence))

        return {
            "confidence": confidence,
            "signals": parsed.get("signals", [])
        }

    except Exception:
        logging.exception("Vision analysis failed")
        return {
            "confidence": 50,
            "signals": ["Vision analysis failed"]
        }


# =========================================================
# HYBRID DETECTION ENGINE
# =========================================================

def detect_ai_image(image_bytes: bytes) -> Dict:
    """
    Production hybrid engine:
    Vision = primary
    EXIF = weak modifier
    Tamper detection = minor modifier
    """

    vision = analyze_with_ai_vision(image_bytes)
    exif = analyze_exif(image_bytes)
    tamper = detect_basic_tampering(image_bytes)

    confidence = vision["confidence"]

    # Apply EXIF adjustments
    confidence += exif["ai_score"]
    confidence -= exif["real_score"]

    # Apply tamper adjustment
    confidence += tamper["score_adjustment"]

    confidence = max(0, min(100, confidence))

    result = _label(confidence)

    return {
        "result": result,
        "confidence": confidence,
        "method": "HYBRID_VISION_EXIF_TAMPER",
        "signals": vision["signals"] + exif["signals"] + tamper["signals"],
    }


# =========================================================
# SAFE LABELING
# =========================================================

def _label(confidence: int) -> str:
    if confidence >= 75:
        return "LIKELY_AI"
    if confidence <= 30:
        return "LIKELY_REAL"
    return "UNCERTAIN"
