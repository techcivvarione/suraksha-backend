from typing import Dict, Tuple


def map_risk(probability: float, confidence: float, analysis_type: str) -> Tuple[int, str, Dict]:
    p = max(0.0, min(probability, 1.0))
    score = int(round(p * 100))
    if p < 0.3:
        level = "LOW"
        recommendation = "Proceed but remain cautious."
    elif p < 0.7:
        level = "MEDIUM"
        recommendation = "Manually verify authenticity before acting."
    else:
        level = "HIGH"
        recommendation = "High likelihood of synthetic manipulation. Do not trust without independent verification."

    summary = f"{level} likelihood of synthetic manipulation with probability {p:.2f} and confidence {confidence:.2f}."

    return score, level, {
        "risk_score": score,
        "risk_level": level,
        "analysis_type": analysis_type,
        "synthetic_probability": p,
        "confidence": confidence,
        "summary": summary,
        "recommended_action": recommendation,
    }
