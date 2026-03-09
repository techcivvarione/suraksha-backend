from typing import Dict

from app.services.reality.providers.hive_provider import build_hive_provider


class VideoDeepfakeDetector:
    def __init__(self, timeout: float = 15.0):
        self.provider = build_hive_provider(timeout=timeout)

    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        return await self.provider.detect(file_path, mime_type)
