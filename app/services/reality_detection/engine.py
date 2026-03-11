from __future__ import annotations

import importlib

from .risk_scoring import DetectionOutcome


class RealityDetectionError(Exception):
    pass


class RealityDetectionBadRequest(RealityDetectionError):
    pass


def validate_runtime_dependencies() -> None:
    required_modules = {
        "cv2": "opencv-python",
        "librosa": "librosa",
        "numpy": "numpy",
        "scipy": "scipy",
    }
    for module_name, package_name in required_modules.items():
        try:
            importlib.import_module(module_name)
        except ImportError as exc:  # pragma: no cover - depends on runtime environment
            raise RuntimeError(f"{package_name} required for AI detection") from exc


class RealityDetectionEngine:
    def __init__(self):
        from .audio_detector import AudioDetector
        from .image_detector import ImageDetector
        from .video_detector import VideoDetector

        self.image_detector = ImageDetector()
        self.video_detector = VideoDetector()
        self.audio_detector = AudioDetector()

    def analyze_image(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        try:
            return self.image_detector.analyze(path, mime_type, fast_mode=fast_mode)
        except RealityDetectionBadRequest:
            raise
        except Exception as exc:
            raise RealityDetectionError("Unable to analyze media") from exc

    def analyze_video(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        try:
            return self.video_detector.analyze(path, mime_type, fast_mode=fast_mode)
        except RealityDetectionBadRequest:
            raise
        except Exception as exc:
            raise RealityDetectionError("Unable to analyze media") from exc

    def analyze_audio(self, path: str, mime_type: str, *, fast_mode: bool = False) -> DetectionOutcome:
        try:
            return self.audio_detector.analyze(path, mime_type, fast_mode=fast_mode)
        except RealityDetectionBadRequest:
            raise
        except Exception as exc:
            raise RealityDetectionError("Unable to analyze media") from exc
