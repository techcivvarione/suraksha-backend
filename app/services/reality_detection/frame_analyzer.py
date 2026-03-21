from __future__ import annotations

from dataclasses import dataclass

from .risk_scoring import DetectionLayer

try:
    import cv2
except Exception:  # pragma: no cover - optional dependency
    cv2 = None


@dataclass
class FrameAnalysisResult:
    frames_sampled: int
    face_boundary: DetectionLayer
    temporal: DetectionLayer
    lighting: DetectionLayer
    texture: DetectionLayer


def analyze_video_frames(path: str, fast_mode: bool = False) -> FrameAnalysisResult:
    if cv2 is None:
        return FrameAnalysisResult(
            frames_sampled=0,
            face_boundary=DetectionLayer(0.15, ["Frame extraction fallback used"]),
            temporal=DetectionLayer(0.10, []),
            lighting=DetectionLayer(0.10, []),
            texture=DetectionLayer(0.10, []),
        )

    capture = cv2.VideoCapture(path)
    if not capture.isOpened():
        return FrameAnalysisResult(
            frames_sampled=0,
            face_boundary=DetectionLayer(0.20, ["Unable to decode video frames"]),
            temporal=DetectionLayer(0.20, []),
            lighting=DetectionLayer(0.20, []),
            texture=DetectionLayer(0.20, []),
        )

    max_frames = 7 if fast_mode else 18
    frame_stride = 15 if fast_mode else 10
    sampled = 0
    previous_gray = None
    boundary_scores: list[float] = []
    temporal_scores: list[float] = []
    lighting_scores: list[float] = []
    texture_scores: list[float] = []
    frame_index = 0

    try:
        while sampled < max_frames:
            ok, frame = capture.read()
            if not ok:
                break
            if frame_index % frame_stride != 0:
                frame_index += 1
                continue

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
            brightness = float(gray.mean())
            boundary_scores.append(1.0 if laplacian_var < 25 else 0.35 if laplacian_var < 45 else 0.05)
            lighting_scores.append(1.0 if brightness < 45 or brightness > 215 else 0.30 if brightness < 65 or brightness > 190 else 0.08)
            texture_scores.append(1.0 if gray.std() < 18 else 0.35 if gray.std() < 28 else 0.05)

            if previous_gray is not None:
                delta = float(cv2.absdiff(previous_gray, gray).mean())
                temporal_scores.append(1.0 if delta < 3 else 0.35 if delta < 7 else 0.08)
            previous_gray = gray
            sampled += 1
            frame_index += 1
    finally:
        capture.release()

    def _mean(values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    return FrameAnalysisResult(
        frames_sampled=sampled,
        face_boundary=DetectionLayer(_mean(boundary_scores), ["Face boundary blur detected"] if _mean(boundary_scores) > 0.4 else []),
        temporal=DetectionLayer(_mean(temporal_scores), ["Temporal inconsistency across frames"] if _mean(temporal_scores) > 0.4 else []),
        lighting=DetectionLayer(_mean(lighting_scores), ["Lighting mismatch across sampled frames"] if _mean(lighting_scores) > 0.4 else []),
        texture=DetectionLayer(_mean(texture_scores), ["Skin texture artifacts across frames"] if _mean(texture_scores) > 0.4 else []),
    )
