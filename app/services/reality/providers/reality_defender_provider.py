import os

from .http_provider import HttpProbabilityProvider
from .base_provider import RealityDetectionError


def build_reality_defender_provider(kind: str, timeout: float = 15.0) -> HttpProbabilityProvider:
    if kind == "image":
        url = os.getenv("IMAGE_AI_DETECT_URL")
        key = os.getenv("IMAGE_AI_DETECT_KEY")
        if not url:
            raise RealityDetectionError("IMAGE_AI_DETECT_URL not configured")
    elif kind == "audio":
        url = os.getenv("VOICE_DEEPFAKE_URL")
        key = os.getenv("VOICE_DEEPFAKE_KEY")
        if not url:
            raise RealityDetectionError("VOICE_DEEPFAKE_URL not configured")
    else:
        raise RealityDetectionError("Unsupported kind")
    return HttpProbabilityProvider(api_url=url, api_key=key, timeout=timeout)
