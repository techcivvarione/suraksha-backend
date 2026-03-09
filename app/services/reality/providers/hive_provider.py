import os

from .http_provider import HttpProbabilityProvider
from .base_provider import RealityDetectionError


def build_hive_provider(timeout: float = 15.0) -> HttpProbabilityProvider:
    url = os.getenv("VIDEO_DEEPFAKE_URL")
    key = os.getenv("VIDEO_DEEPFAKE_KEY")
    if not url:
        raise RealityDetectionError("VIDEO_DEEPFAKE_URL not configured")
    return HttpProbabilityProvider(api_url=url, api_key=key, timeout=timeout)
