from __future__ import annotations

import audioop
import wave

from .engine import RealityDetectionBadRequest
from .risk_scoring import DetectionLayer

try:
    import librosa
except Exception:  # pragma: no cover - optional dependency
    librosa = None


MAX_AUDIO_SECONDS = 60


def _load_wav_pcm(path: str) -> tuple[bytes, int]:
    with wave.open(path, "rb") as wav_file:
        frames = wav_file.readframes(wav_file.getnframes())
        rate = wav_file.getframerate()
        width = wav_file.getsampwidth()
        channels = wav_file.getnchannels()
        if channels > 1:
            frames = audioop.tomono(frames, width, 0.5, 0.5)
        if rate != 16000:
            frames, _ = audioop.ratecv(frames, width, 1, rate, 16000, None)
            rate = 16000
        return frames, rate


def analyze_audio_spectrum(path: str) -> tuple[DetectionLayer, DetectionLayer, DetectionLayer]:
    if librosa is not None:
        signal, sr = librosa.load(path, sr=16000, mono=True)
        duration = len(signal) / float(sr or 16000)
        if duration > MAX_AUDIO_SECONDS:
            raise RealityDetectionBadRequest("Audio duration exceeds 60 seconds")
        flatness = float(librosa.feature.spectral_flatness(y=signal).mean())
        pitches, magnitudes = librosa.piptrack(y=signal, sr=sr)
        pitch_track = pitches[magnitudes > magnitudes.mean()]
        pitch_std = float(pitch_track.std()) if pitch_track.size else 0.0
        silence_ratio = float((abs(signal) < 0.002).mean())
        spectral = DetectionLayer(0.75 if flatness > 0.35 else 0.35 if flatness > 0.22 else 0.10, ["Abnormal spectral flatness"] if flatness > 0.22 else [])
        pitch = DetectionLayer(0.70 if pitch_std < 12 else 0.30 if pitch_std < 24 else 0.10, ["Pitch stability too perfect"] if pitch_std < 24 else [])
        phase = DetectionLayer(0.70 if silence_ratio > 0.28 else 0.30 if silence_ratio > 0.18 else 0.10, ["Unnatural silence or phase artifacts"] if silence_ratio > 0.18 else [])
        return spectral, pitch, phase

    if path.lower().endswith(".wav"):
        frames, rate = _load_wav_pcm(path)
        duration = len(frames) / float(max(rate, 1) * 2)
        if duration > MAX_AUDIO_SECONDS:
            raise RealityDetectionBadRequest("Audio duration exceeds 60 seconds")
        rms = audioop.rms(frames, 2) if frames else 0
        zero_crossings = audioop.cross(frames, 2) if frames else 0
        silence_ratio = frames.count(b"\x00") / len(frames) if frames else 1.0
        spectral_score = 0.70 if rms < 450 else 0.30 if rms < 900 else 0.10
        pitch_score = 0.70 if zero_crossings < rate * 0.01 else 0.30 if zero_crossings < rate * 0.02 else 0.10
        if silence_ratio > 0.30:
            spectral_score = max(spectral_score, 0.45)
            pitch_score = max(pitch_score, 0.45)
        spectral = DetectionLayer(spectral_score, ["Low spectral energy"] if spectral_score >= 0.30 else [])
        pitch = DetectionLayer(pitch_score, ["Pitch contour unnaturally stable"] if pitch_score >= 0.30 else [])
        phase = DetectionLayer(0.70 if silence_ratio > 0.35 else 0.30 if silence_ratio > 0.20 else 0.10, ["Unnatural silence patterns"] if silence_ratio > 0.20 else [])
        return spectral, pitch, phase

    # MP3 and unsupported codecs fall back to conservative byte heuristics.
    with open(path, "rb") as handle:
        payload = handle.read()
    estimated_duration = len(payload) / float(16000 * 2)
    if estimated_duration > MAX_AUDIO_SECONDS:
        raise RealityDetectionBadRequest("Audio duration exceeds 60 seconds")
    unique_ratio = len(set(payload)) / max(len(payload), 1)
    spectral = DetectionLayer(0.60 if unique_ratio < 0.10 else 0.20, ["Spectral detail appears limited"] if unique_ratio < 0.10 else [])
    pitch = DetectionLayer(0.45 if payload.count(b"\x00") / max(len(payload), 1) > 0.30 else 0.15, ["Pitch stability anomaly"] if payload.count(b"\x00") / max(len(payload), 1) > 0.30 else [])
    phase = DetectionLayer(0.40 if payload[:3] == b"ID3" else 0.15, ["Compressed audio fallback analysis used"] if payload[:3] == b"ID3" else [])
    return spectral, pitch, phase
