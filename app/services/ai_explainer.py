"""ai_explainer.py — Simple, human-friendly AI explanation generator.

Output style (MANDATORY for all scan types):
  Sentence 1: Clear verdict  (e.g. "This message looks like a scam.")
  Sentence 2: Simple reason  (e.g. "It is asking you to act quickly and share your details.")
  Sentence 3: Real-world meaning for the user  (e.g. "Messages like this are often used to steal money or passwords.")

Rules:
  • Max 3–4 short sentences total.
  • Zero jargon. No: metadata, entropy, compression, heuristic, anomaly, algorithm.
  • Always tell the user what to DO or NOT DO.
  • Fallback is plain-text, not bullet points or numbered lists.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ── Prompts ─────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a cybersecurity assistant for everyday users in India, including people in rural areas. "
    "Explain scan results in very simple language — like talking to a family member who does not know anything about technology. "
    "Never use technical words. Banned words: metadata, entropy, compression artifact, heuristic, anomaly, "
    "algorithm, payload, vector, indicator, signal, pattern. "
    "Write exactly 3 short sentences: "
    "1) A clear verdict (safe or not safe). "
    "2) One simple reason why. "
    "3) What the person should do next. "
    "Do not use bullet points, numbers, or headings. Write as a natural paragraph."
)

# Scan-type–aware user prompt templates
_PROMPT_TEMPLATES: dict[str, str] = {
    "THREAT": (
        "A message or link was checked. The result is: {risk}. "
        "Main findings: {signals}. "
        "Tell a non-technical person in 3 sentences: "
        "is this safe to trust, why, and what should they do?"
    ),
    "EMAIL": (
        "An email address was checked for data leaks. The result is: {risk}. "
        "Main findings: {signals}. "
        "Tell a non-technical person in 3 sentences: "
        "what does this mean for their account security, and what should they do?"
    ),
    "PASSWORD": (
        "A password was checked for strength. The result is: {risk}. "
        "Main findings: {signals}. "
        "Tell a non-technical person in 3 sentences: "
        "is this password safe, why, and what should they do?"
    ),
    "SECURITY_SCAN": (
        "A security scan was done. The result is: {risk}. "
        "Main findings: {signals}. "
        "Tell a non-technical person in 3 sentences: "
        "is this safe, why, and what should they do?"
    ),
}

_DEFAULT_PROMPT = _PROMPT_TEMPLATES["SECURITY_SCAN"]

# ── Fallback templates (no AI call needed) ───────────────────────────────────

_FALLBACK: dict[str, dict[str, str]] = {
    "THREAT": {
        "HIGH": (
            "This message looks like a scam. "
            "It contains signs that someone is trying to trick you into sharing your personal details or money. "
            "Do not click any links, do not share your bank details or OTP, and delete this message."
        ),
        "MEDIUM": (
            "This message looks a little suspicious. "
            "We are not fully sure, but it has some signs that it may not be safe. "
            "Be careful — check with someone you trust before clicking any links or sharing any information."
        ),
        "LOW": (
            "This message looks safe. "
            "We did not find any signs of a scam or dangerous content. "
            "You can proceed normally, but always stay alert."
        ),
    },
    "EMAIL": {
        "HIGH": (
            "Your email has appeared in known data leaks. "
            "This means someone may have access to your email and password from websites that were hacked. "
            "Change your password on all important websites right away."
        ),
        "MEDIUM": (
            "Your email may have appeared in some data leaks. "
            "This means there is a small chance someone could access your accounts. "
            "Change your passwords on important websites to stay safe."
        ),
        "LOW": (
            "Your email looks safe. "
            "We did not find it in any known data leaks. "
            "Keep using strong passwords and stay alert."
        ),
    },
    "PASSWORD": {
        "HIGH": (
            "This password is not safe. "
            "It is too simple or has been found in known hacked databases. "
            "Change it immediately to a longer password that mixes letters, numbers, and symbols."
        ),
        "MEDIUM": (
            "This password can be made stronger. "
            "It is okay for now but could be cracked with some effort. "
            "Make it longer and add a mix of numbers and symbols to stay safer."
        ),
        "LOW": (
            "This password looks strong. "
            "It has good length and variety, making it hard to guess. "
            "Keep using strong passwords like this on all your accounts."
        ),
    },
    "DEFAULT": {
        "HIGH": (
            "This looks risky. "
            "We found signs that this may not be safe to use or trust. "
            "Avoid using it and check with someone you trust before taking any action."
        ),
        "MEDIUM": (
            "This may not be completely safe. "
            "There are some warning signs, but nothing is certain yet. "
            "Be careful and double-check before proceeding."
        ),
        "LOW": (
            "This looks safe. "
            "We did not find any major problems. "
            "You can proceed normally, but always stay cautious."
        ),
    },
}


def _simple_fallback(risk: str, scan_type: str) -> str:
    """Return a plain-English fallback with zero jargon."""
    bucket = scan_type.upper()
    if bucket not in _FALLBACK:
        bucket = "DEFAULT"
    level = risk.upper()
    if level not in ("HIGH", "MEDIUM", "LOW"):
        level = "HIGH" if level in ("VERY_HIGH", "CRITICAL") else "LOW"
    return _FALLBACK[bucket].get(level, _FALLBACK["DEFAULT"]["MEDIUM"])


def _build_signals_text(reasons: list[str]) -> str:
    """Convert raw reason strings to a brief, human-friendly phrase."""
    if not reasons:
        return "no specific issues detected"
    # Take at most 3 reasons, keep them as-is (they're already somewhat readable)
    cleaned = [r.strip() for r in reasons[:3] if r.strip()]
    return "; ".join(cleaned) if cleaned else "no specific issues detected"


def _build_prompt(scan_type: str, risk: str, score: int | None, reasons: list[str], text: str | None) -> str:
    template = _PROMPT_TEMPLATES.get(scan_type.upper(), _DEFAULT_PROMPT)
    signals = _build_signals_text(reasons)
    return template.format(risk=risk or "UNKNOWN", signals=signals)


# ── Public API ───────────────────────────────────────────────────────────────

def generate_ai_explanation(
    scan_type: str,
    risk: str | None,
    score: int | None,
    reasons: list[str],
    text: str | None = None,
) -> str:
    """Generate a simple, human-friendly explanation for any scan type.

    Falls back to a deterministic template if the OpenAI call fails.
    Never raises — always returns a non-empty string.
    """
    normalized_risk = (risk or "UNKNOWN").upper()
    resolved_type = (scan_type or "SECURITY_SCAN").upper()

    prompt_text = _build_prompt(resolved_type, normalized_risk, score, reasons or [], text)

    try:
        from openai import OpenAI  # guarded import
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt_text},
            ],
            max_tokens=150,
            temperature=0.3,
        )
        result = (response.choices[0].message.content or "").strip()
        if result:
            return result
    except Exception:
        logger.exception("ai_explainer: OpenAI call failed for scan_type=%s", resolved_type)

    return _simple_fallback(normalized_risk, resolved_type)
