from typing import Dict

from app.services.reality.providers.reality_defender_provider import build_reality_defender_provider


class VoiceDeepfakeDetector:
    def __init__(self, timeout: float = 15.0):
        self.provider = build_reality_defender_provider("audio", timeout=timeout)

    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        return await self.provider.detect(file_path, mime_type)
