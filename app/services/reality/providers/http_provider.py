import asyncio
import json
import logging
import os
from typing import Dict, Optional

import httpx

from .base_provider import BaseRealityProvider, RealityDetectionError

logger = logging.getLogger(__name__)


class HttpProbabilityProvider(BaseRealityProvider):
    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        *,
        provider_name: str | None = None,
    ):
        if not api_url:
            raise RealityDetectionError("Detection provider URL not configured")
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        self.provider_name = provider_name or self._detect_provider_name(api_url)

    @staticmethod
    def _detect_provider_name(api_url: str) -> str:
        lowered = api_url.lower()
        if "thehive.ai" in lowered:
            return "hive"
        return "generic"

    def _build_headers(self) -> dict[str, str]:
        if not self.api_key:
            return {}
        if self.provider_name == "hive":
            return {"Authorization": f"Token {self.api_key}"}
        return {"Authorization": f"Bearer {self.api_key}"}

    def _build_files(self, file_path: str, mime_type: str, fh) -> dict[str, tuple[str, object, str]]:
        filename = os.path.basename(file_path) or "upload.bin"
        field_name = "media" if self.provider_name == "hive" else "file"
        return {field_name: (filename, fh, mime_type)}

    @staticmethod
    def _extract_hive_probability(payload: dict) -> float:
        status = payload.get("status")
        if not isinstance(status, list):
            raise ValueError("Hive response missing status list")

        scores: list[float] = []
        for item in status:
            if not isinstance(item, dict):
                continue
            response = item.get("response") or {}
            output = response.get("output") or []
            if not isinstance(output, list):
                continue
            for output_item in output:
                classes = output_item.get("classes") or []
                if not isinstance(classes, list):
                    continue
                for klass in classes:
                    label = str(klass.get("class", "")).lower()
                    score = klass.get("score")
                    if score is None:
                        continue
                    try:
                        numeric_score = float(score)
                    except (TypeError, ValueError):
                        continue
                    if label in {"deepfake", "ai_generated"}:
                        scores.append(numeric_score)

        if not scores:
            raise ValueError("Hive response missing deepfake/ai_generated scores")
        return max(scores)

    def _extract_probability(self, payload: dict) -> float:
        if self.provider_name == "hive":
            return self._extract_hive_probability(payload)
        prob = payload.get("synthetic_probability")
        if prob is None:
            raise ValueError("Provider response missing synthetic_probability")
        return float(prob)

    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        headers = self._build_headers()
        attempt = 0
        last_exc = None
        while attempt < 2:
            attempt += 1
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    with open(file_path, "rb") as fh:
                        file_size = os.path.getsize(file_path)
                        files = self._build_files(file_path, mime_type, fh)
                        logger.info(
                            "hive_request endpoint=%s content_type=multipart/form-data mime=%s size=%s",
                            self.api_url,
                            mime_type,
                            file_size,
                            extra={
                                "provider": self.provider_name,
                                "endpoint": self.api_url,
                                "content_type": "multipart/form-data",
                                "file_size": file_size,
                                "mime_type": mime_type,
                            },
                        )
                        resp = await client.post(self.api_url, files=files, headers=headers)
                    if resp.status_code >= 400:
                        response_body = resp.text
                        logger.error(
                            "provider_error_response provider=%s status=%s body=%s",
                            self.provider_name,
                            resp.status_code,
                            response_body,
                            extra={
                                "provider": self.provider_name,
                                "status_code": resp.status_code,
                                "response_body": response_body,
                            },
                        )
                        raise RealityDetectionError(
                            "AI detection service returned an error",
                            provider=self.provider_name,
                            status_code=resp.status_code,
                            response_body=response_body,
                        )
                    payload = resp.json()
                    prob = self._extract_probability(payload)
                    if prob < 0 or prob > 1:
                        raise ValueError("Invalid probability range")
                    return {"probability": prob, "provider_used": self.provider_name}
            except RealityDetectionError as exc:
                last_exc = exc
                if attempt >= 2:
                    break
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError, json.JSONDecodeError) as exc:
                last_exc = exc
                if attempt >= 2:
                    break
        if isinstance(last_exc, RealityDetectionError):
            raise last_exc
        raise RealityDetectionError(
            f"Provider failure: {last_exc}",
            provider=self.provider_name,
        )
