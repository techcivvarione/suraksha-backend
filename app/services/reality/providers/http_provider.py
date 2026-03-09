import asyncio
from typing import Dict, Optional

import httpx

from .base_provider import BaseRealityProvider, RealityDetectionError


class HttpProbabilityProvider(BaseRealityProvider):
    def __init__(self, api_url: str, api_key: Optional[str] = None, timeout: float = 15.0):
        if not api_url:
            raise RealityDetectionError("Detection provider URL not configured")
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout

    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        attempt = 0
        last_exc = None
        while attempt < 2:
            attempt += 1
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    with open(file_path, "rb") as fh:
                        files = {"file": ("upload", fh, mime_type)}
                        resp = await client.post(self.api_url, files=files, headers=headers)
                    resp.raise_for_status()
                    payload = resp.json()
                    prob = float(payload.get("synthetic_probability"))
                    if prob < 0 or prob > 1:
                        raise RealityDetectionError("Invalid probability range")
                    return {"probability": prob, "provider_used": self.api_url}
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
                last_exc = exc
                if attempt >= 2:
                    break
        raise RealityDetectionError(f"Provider failure: {last_exc}")
