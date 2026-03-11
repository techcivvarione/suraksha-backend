from __future__ import annotations

from dataclasses import dataclass, field


IMAGE_WEIGHTS = {
    "metadata": 0.20,
    "noise": 0.25,
    "texture": 0.25,
    "reflection": 0.15,
    "compression": 0.15,
}

VIDEO_WEIGHTS = {
    "face_boundary": 0.25,
    "temporal": 0.25,
    "lighting": 0.25,
    "texture": 0.25,
}

AUDIO_WEIGHTS = {
    "spectral": 0.40,
    "pitch": 0.30,
    "phase": 0.30,
}


@dataclass
class DetectionLayer:
    score: float = 0.0
    signals: list[str] = field(default_factory=list)


@dataclass
class DetectionOutcome:
    analysis_type: str
    ai_probability: float
    risk_score: int
    risk_level: str
    signals: list[str]
    details: dict[str, float] = field(default_factory=dict)


def clamp_score(value: float) -> float:
    return max(0.0, min(float(value or 0.0), 1.0))


def classify_risk(probability: float) -> tuple[int, str]:
    bounded = clamp_score(probability)
    score = int(round(bounded * 100))
    if score <= 30:
        return score, "LOW"
    if score <= 60:
        return score, "MEDIUM"
    return score, "HIGH"


def combine_weighted_scores(
    analysis_type: str,
    layers: dict[str, DetectionLayer],
    weights: dict[str, float],
) -> DetectionOutcome:
    bounded_details = {name: clamp_score(layer.score) for name, layer in layers.items()}
    probability = sum(bounded_details.get(name, 0.0) * weight for name, weight in weights.items())
    risk_score, risk_level = classify_risk(probability)

    signals: list[str] = []
    for layer in layers.values():
        for signal in layer.signals:
            if signal not in signals:
                signals.append(signal)

    return DetectionOutcome(
        analysis_type=analysis_type,
        ai_probability=probability,
        risk_score=risk_score,
        risk_level=risk_level,
        signals=signals,
        details=bounded_details,
    )
