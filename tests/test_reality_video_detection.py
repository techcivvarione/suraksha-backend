from app.services.reality_detection.frame_analyzer import FrameAnalysisResult
from app.services.reality_detection.risk_scoring import DetectionLayer
from app.services.reality_detection.video_detector import VideoDetector


def test_video_detection_real_media_has_low_risk(monkeypatch):
    monkeypatch.setattr(
        "app.services.reality_detection.video_detector.analyze_video_frames",
        lambda path, fast_mode=False: FrameAnalysisResult(
            frames_sampled=12,
            face_boundary=DetectionLayer(0.08, []),
            temporal=DetectionLayer(0.10, []),
            lighting=DetectionLayer(0.10, []),
            texture=DetectionLayer(0.12, []),
        ),
    )

    outcome = VideoDetector().analyze("sample.mp4", "video/mp4")
    assert outcome.analysis_type == "video"
    assert outcome.risk_level == "LOW"


def test_video_detection_ai_like_media_flags_signals(monkeypatch):
    monkeypatch.setattr(
        "app.services.reality_detection.video_detector.analyze_video_frames",
        lambda path, fast_mode=False: FrameAnalysisResult(
            frames_sampled=24,
            face_boundary=DetectionLayer(0.72, ["Face boundary blur detected"]),
            temporal=DetectionLayer(0.75, ["Temporal inconsistency across frames"]),
            lighting=DetectionLayer(0.68, ["Lighting mismatch across sampled frames"]),
            texture=DetectionLayer(0.70, ["Skin texture artifacts across frames"]),
        ),
    )

    outcome = VideoDetector().analyze("sample.mp4", "video/mp4")
    assert outcome.risk_level == "HIGH"
    assert len(outcome.signals) >= 3


def test_video_detection_fast_mode_limits_work(monkeypatch):
    observed = {}

    def fake_analyze(path, fast_mode=False):
        observed["fast_mode"] = fast_mode
        return FrameAnalysisResult(
            frames_sampled=18,
            face_boundary=DetectionLayer(0.10, []),
            temporal=DetectionLayer(0.10, []),
            lighting=DetectionLayer(0.10, []),
            texture=DetectionLayer(0.10, []),
        )

    monkeypatch.setattr("app.services.reality_detection.video_detector.analyze_video_frames", fake_analyze)
    VideoDetector().analyze("sample.mp4", "video/mp4", fast_mode=True)
    assert observed["fast_mode"] is True
