import math
import wave

import pytest

from app.services.reality_detection.audio_detector import AudioDetector
from app.services.reality_detection.engine import RealityDetectionEngine, RealityDetectionError


def _write_wav(path, frequency=220.0, silence_every=0):
    sample_rate = 16000
    duration_seconds = 1
    frames = bytearray()
    for index in range(sample_rate * duration_seconds):
        if silence_every and index % silence_every == 0:
            sample = 0
        else:
            sample = int(12000 * math.sin(2 * math.pi * frequency * index / sample_rate))
        frames.extend(int(sample).to_bytes(2, byteorder="little", signed=True))

    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(bytes(frames))


def test_audio_detection_real_media_has_low_or_medium_risk(tmp_path):
    path = tmp_path / "speech.wav"
    _write_wav(path, frequency=220.0)

    outcome = AudioDetector().analyze(str(path), "audio/wav")
    assert outcome.analysis_type == "audio"
    assert outcome.risk_level in {"LOW", "MEDIUM"}


def test_audio_detection_synthetic_like_media_flags_signals(tmp_path):
    path = tmp_path / "clone.wav"
    _write_wav(path, frequency=300.0, silence_every=2)

    outcome = AudioDetector().analyze(str(path), "audio/wav")
    assert outcome.risk_level in {"MEDIUM", "HIGH"}
    assert outcome.signals


def test_audio_detection_rejects_corrupted_media(tmp_path):
    path = tmp_path / "broken.wav"
    path.write_bytes(b"broken-audio")

    with pytest.raises(RealityDetectionError):
        RealityDetectionEngine().analyze_audio(str(path), "audio/wav")
