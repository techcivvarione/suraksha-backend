from typing import Dict

from app.services.reality_detection import RealityDetectionEngine


class VideoDeepfakeDetector:
    def __init__(self, timeout: float = 15.0):
        self.engine = RealityDetectionEngine()

    async def detect(self, file_path: str, mime_type: str, filename: str | None = None, fast_mode: bool = False) -> Dict[str, float]:
        outcome = self.engine.analyze_video(file_path, mime_type, fast_mode=fast_mode)
        return {
            "probability": outcome.ai_probability,
            "provider_used": "internal-hybrid",
            "signals": outcome.signals,
            "risk_score": outcome.risk_score,
            "risk_level": outcome.risk_level,
        }
