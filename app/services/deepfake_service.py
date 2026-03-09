import asyncio
from typing import Dict

import httpx


class DeepfakeServiceError(Exception):
    pass


class DeepfakeService:
    def __init__(self, api_url: str, api_key: str | None, timeout: float = 15.0):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout

    async def analyze(self, file_path: str, mime_type: str) -> Dict[str, float]:
        """
        Proxy to external AI provider. Mocked deterministically if api_url is empty.
        """
        if not self.api_url:
            # deterministic mock
            return {
                "synthetic_probability": 0.82,
                "confidence": 0.91,
            }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                with open(file_path, "rb") as fh:
                    files = {"file": ("upload", fh, mime_type)}
                    headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                    resp = await client.post(self.api_url, files=files, headers=headers)
                    resp.raise_for_status()
                    payload = resp.json()
                    return {
                        "synthetic_probability": float(payload.get("synthetic_probability", 0.0)),
                        "confidence": float(payload.get("confidence", 0.0)),
                    }
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            raise DeepfakeServiceError(str(exc)) from exc
