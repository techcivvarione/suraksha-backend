from __future__ import annotations

import json
import re
from collections.abc import Iterable


HIGH_VERDICT = "⚠️ This is dangerous. Do not trust this."
MEDIUM_VERDICT = "⚠️ This looks suspicious. Be careful."
LOW_VERDICT = "✅ This looks safe."

HIGH_ACTION = "Do not click, pay, reply, or share details."
MEDIUM_ACTION = "Check with the sender before taking action."
LOW_ACTION = "Still stay alert for anything unusual."

SIGNAL_MAPPINGS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("apk", "install app", "install anything", ".apk"), "It asks you to install an app from a link."),
    (("remote access", "anydesk", "teamviewer", "rustdesk"), "It asks for remote phone control."),
    (("rush", "urgent", "immediately", "blocked today", "deadline"), "It tries to rush you."),
    (("bank", "account warning", "card warning", "brand mismatch"), "It pretends to be a bank or trusted service."),
    (("otp", "upi pin", "sensitive information"), "It asks for private details like OTP or PIN."),
    (("kyc", "aadhaar", "aadhar", "pan"), "It uses a fake update request."),
    (("upi", "collect request", "approve payment", "refund pending"), "It tries to trick a payment approval."),
    (("payment panic", "money debited", "refund"), "It tries to scare you about money."),
    (("telegram", "whatsapp", "job"), "It looks like a fake job message."),
    (("delivery", "parcel", "courier"), "It uses a fake delivery story."),
    (("reward", "prize", "cashback", "lottery"), "It promises money or rewards."),
    (("link", "domain", "website"), "It pushes you to open a suspicious link."),
    (("generic greeting", "dear customer"), "It uses a mass message style."),
)

DEFAULT_HIGH_WHY = "It tries to trick you into losing money or data."
DEFAULT_MEDIUM_WHY = "Something does not look right in this message."
DEFAULT_LOW_WHY = "No major risk was found."


def generate_simple_explanation(
    risk_level: str,
    signals: list[str],
) -> str:
    normalized_level = _normalize_risk_level(risk_level)
    simple_reasons = _map_signals_to_simple_lines(signals)

    if normalized_level == "HIGH":
        verdict = HIGH_VERDICT
        why_lines = simple_reasons[:2] or [DEFAULT_HIGH_WHY]
        action = HIGH_ACTION
    elif normalized_level == "MEDIUM":
        verdict = MEDIUM_VERDICT
        why_lines = simple_reasons[:2] or [DEFAULT_MEDIUM_WHY]
        action = MEDIUM_ACTION
    else:
        verdict = LOW_VERDICT
        why_lines = simple_reasons[:1] or [DEFAULT_LOW_WHY]
        action = LOW_ACTION

    return "\n\n".join(
        [
            verdict,
            " ".join(why_lines),
            action,
        ]
    )


def generate_ai_explanation(
    scan_type: str,
    risk: str | None,
    score: int | None,
    reasons: list[str] | str | None,
    text: str | None = None,
) -> str:
    del scan_type, score, text
    return generate_simple_explanation(
        risk_level=risk or "LOW",
        signals=_coerce_signals(reasons),
    )


def _normalize_risk_level(risk_level: str | None) -> str:
    normalized = (risk_level or "").strip().upper()
    if normalized in {"HIGH", "VERY_HIGH", "CRITICAL"}:
        return "HIGH"
    if normalized in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    return "LOW"


def _coerce_signals(reasons: list[str] | str | None) -> list[str]:
    if reasons is None:
        return []
    if isinstance(reasons, list):
        return [str(item).strip() for item in reasons if str(item).strip()]
    if isinstance(reasons, str):
        raw = reasons.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
        return [raw]
    if isinstance(reasons, Iterable):
        return [str(item).strip() for item in reasons if str(item).strip()]
    return []


def _map_signals_to_simple_lines(signals: list[str]) -> list[str]:
    simple_lines: list[str] = []
    seen: set[str] = set()

    for signal in signals:
        lowered = signal.lower()
        mapped = None
        for keywords, sentence in SIGNAL_MAPPINGS:
            if any(_keyword_matches(lowered, keyword) for keyword in keywords):
                mapped = sentence
                break
        if mapped is None:
            mapped = _fallback_simple_line(lowered)
        if mapped and mapped not in seen:
            seen.add(mapped)
            simple_lines.append(mapped)

    return simple_lines


def _fallback_simple_line(lowered_signal: str) -> str:
    if "safe" in lowered_signal or "no major" in lowered_signal:
        return DEFAULT_LOW_WHY
    if "suspicious" in lowered_signal or "danger" in lowered_signal:
        return DEFAULT_MEDIUM_WHY
    return ""


def _keyword_matches(signal_text: str, keyword: str) -> bool:
    normalized_keyword = keyword.strip().lower()
    if " " in normalized_keyword or "." in normalized_keyword:
        return normalized_keyword in signal_text
    return re.search(rf"\b{re.escape(normalized_keyword)}\b", signal_text) is not None
