"""ai_explainer.py — Simple, human-friendly AI explanation generator.

Output style (MANDATORY for all scan types):
  2–3 short sentences, plain paragraph, no bullet points.
  Sentence 1: Clear verdict in everyday language.
  Sentence 2: ONE specific reason — what was found.
  Sentence 3 (optional): What the person should do.

Tone rules (enforced via system prompt AND user prompt tone hint):
  score 0–30  → warm and reassuring.
  score 31–60 → gently cautious.
  score 61–100 → clear direct warning.

Vocabulary rules:
  BANNED:  indicators, signals, analysis, AI generation, detection, metadata,
           entropy, compression artifact, heuristic, anomaly, algorithm,
           payload, vector, pattern, benchmark, threshold, correlation, forensic.
  ALLOWED: signs, looks, seems, feels, noticed, something feels off, looks normal,
           nothing unusual, seems real.
"""
from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a warm, helpful friend explaining security scan results to people in India "
    "who are not good with technology. "
    "Speak like a trusted neighbour — friendly, direct, and easy to understand. "
    "Never sound like a computer report or a formal letter. "
    "Use ONLY words a 12-year-old would know. "
    # ── Hard vocabulary ban ───────────────────────────────────────────────────
    "BANNED words (never use these): metadata, entropy, compression artifact, heuristic, anomaly, "
    "algorithm, payload, vector, indicators, signals, analysis, detection, generated, "
    "'AI generation', pattern, benchmark, threshold, correlation, forensic. "
    # ── Preferred vocabulary ──────────────────────────────────────────────────
    "INSTEAD use natural phrases like: 'looks safe', 'something feels off', 'we noticed', "
    "'nothing unusual', 'seems real', 'signs of', 'looks suspicious'. "
    # ── Tone based on score (provided in user message) ────────────────────────
    "TONE RULES — follow these based on the risk score in the message: "
    "  Score 0–30  → warm and reassuring. Start positively, put the person at ease. "
    "  Score 31–60 → gently cautious. Note something seems slightly unusual — keep them calm but alert. "
    "  Score 61–100 → clear direct warning. Be honest about the risk without being scary. "
    # ── Structure ─────────────────────────────────────────────────────────────
    "Write 2–3 short sentences only. One plain paragraph. No bullet points or numbers. "
    "VARY your opening — never start the same way twice. "
    "Do NOT always start with 'This message' or 'Your email'. "
    # ── Anti-generic phrases ──────────────────────────────────────────────────
    "BANNED phrases: 'this is safe for now', 'exercise caution', 'for your information', "
    "'it is advisable', 'please note', 'based on our analysis', 'it appears that', "
    "'I would recommend', 'you should consider'. "
    "Be specific to the actual findings — mention what was actually noticed."
)

# ── User prompt templates ─────────────────────────────────────────────────────
# {risk}, {signals}, {score}, {tone_hint} are injected by _build_prompt().

_PROMPT_TEMPLATES: dict[str, str] = {
    "THREAT": (
        "A message or link was checked. Risk: {risk} (score: {score}/100). "
        "What was found: {signals}. "
        "{tone_hint} "
        "In 2–3 sentences, explain to a non-technical person: "
        "is this safe to trust, what was noticed, and what should they do? "
        "Be specific. Vary your opening."
    ),
    "EMAIL": (
        "An email address was checked for data leaks. Risk: {risk} (score: {score}/100). "
        "What was found: {signals}. "
        "{tone_hint} "
        "In 2–3 sentences, explain: what does this mean for their account, and what should they do? "
        "Be specific. Vary your opening."
    ),
    "PASSWORD": (
        "A password was checked for safety. Risk: {risk} (score: {score}/100). "
        "What was found: {signals}. "
        "{tone_hint} "
        "In 2–3 sentences, explain: is this password safe, why, and what should they do? "
        "Be specific. Vary your opening."
    ),
    "SECURITY_SCAN": (
        "A security check was done. Risk: {risk} (score: {score}/100). "
        "What was found: {signals}. "
        "{tone_hint} "
        "In 2–3 sentences, explain: is this safe, why, and what should they do? "
        "Be specific. Vary your opening."
    ),
}

_DEFAULT_PROMPT = _PROMPT_TEMPLATES["SECURITY_SCAN"]

# ── Fallback pool ─────────────────────────────────────────────────────────────
# Each bucket has 3 variants so repeated scans of similar content produce
# different text.  Variant selection is deterministic (seed = scan_type+risk+
# first reason).

_FALLBACK: dict[str, dict[str, list[str]]] = {
    "THREAT": {
        "HIGH": [
            (
                "This message looks like a scam. "
                "It has signs that someone is trying to trick you into sharing your details or money. "
                "Do not click any links, do not share your OTP or bank details, and delete this message."
            ),
            (
                "Be very careful with this message — it does not look safe to us. "
                "We noticed signs that someone is trying to fool you into doing something harmful. "
                "Delete it and do not share any personal information."
            ),
            (
                "Something about this message feels very wrong. "
                "It looks like someone is pretending to be trustworthy to cheat you. "
                "Do not reply, do not click any links, and tell someone you trust about it."
            ),
        ],
        "MEDIUM": [
            (
                "This message looks a little suspicious. "
                "We are not fully sure, but something feels off — it may not be safe. "
                "Be careful and check with someone you trust before clicking links or sharing anything."
            ),
            (
                "Something about this message feels a little odd. "
                "It is not clearly a problem but it has a few unusual things worth noticing. "
                "Do not act on it right away — ask someone you trust to take a look first."
            ),
            (
                "We are not sure this message is completely safe. "
                "A few things do not seem quite right about it. "
                "Take your time and think before clicking anything or sharing your details."
            ),
        ],
        "LOW": [
            (
                "This message looks safe to us. "
                "We did not find any signs of a scam or dangerous content. "
                "You can proceed normally, but it is always good to stay alert."
            ),
            (
                "Nothing feels off about this message — it looks normal. "
                "We checked it and did not notice anything suspicious. "
                "Go ahead, but remember to always be careful with messages you did not expect."
            ),
            (
                "This looks like a genuine message. "
                "We went through it and nothing seemed unusual. "
                "There is nothing to worry about here."
            ),
        ],
    },
    "EMAIL": {
        "HIGH": [
            (
                "Your email has appeared in known data leaks. "
                "This means someone may already have your email and password from websites that were hacked. "
                "Change your password on all important websites right away."
            ),
            (
                "We found your email in places where stolen data is shared. "
                "Your account information may already be out there. "
                "Change your passwords right now — especially for your bank and important apps."
            ),
            (
                "Your email has been found in some data leaks. "
                "Someone may have gotten your old passwords from those leaks. "
                "Go and change your passwords now, starting with your bank and most important accounts."
            ),
        ],
        "MEDIUM": [
            (
                "Your email may have appeared in a small number of data leaks. "
                "There is some chance that someone could try to access your accounts. "
                "Change your passwords on important websites to be safe."
            ),
            (
                "We found your email in a couple of places it should not be. "
                "It is not very serious yet, but it is worth taking care of. "
                "Change your passwords soon, especially on important accounts."
            ),
            (
                "Your email shows up in a few leaks — nothing too serious right now. "
                "But updating your passwords is a smart thing to do just in case. "
                "Start with your bank account and any app you use for money."
            ),
        ],
        "LOW": [
            (
                "Your email looks safe. "
                "We did not find it in any known data leaks. "
                "Keep using strong passwords and stay alert."
            ),
            (
                "Nothing unusual — your email does not appear in any leaks we know of. "
                "That is good news. "
                "Just keep your passwords strong and do not share them with anyone."
            ),
            (
                "Your email seems fine to us. "
                "We checked it and found nothing to worry about. "
                "Keep using a different, strong password for each important account."
            ),
        ],
    },
    "PASSWORD": {
        "HIGH": [
            (
                "This password is not safe. "
                "It is too simple or has been found in lists of passwords that hackers already know. "
                "Change it right away to something longer that mixes letters, numbers, and symbols."
            ),
            (
                "We are quite worried about this password. "
                "It looks like the kind that someone could guess easily or may have been stolen before. "
                "Please change it now to something much longer and harder to guess."
            ),
            (
                "This password is easy to guess — it is not strong enough to protect you. "
                "Hackers use lists of common passwords and this one may already be on such a list. "
                "Create a new one using a mix of random words, numbers, and symbols."
            ),
        ],
        "MEDIUM": [
            (
                "This password could be made stronger. "
                "It is okay for now but someone with time could figure it out. "
                "Make it longer and add a mix of numbers and symbols to stay safer."
            ),
            (
                "Your password is not bad but it could be better. "
                "It might be a little too simple for important accounts. "
                "Adding more numbers and symbols will make it much harder to guess."
            ),
            (
                "We think this password needs a small improvement. "
                "It is not the worst but it is not the safest either. "
                "Try adding more random words or numbers to make it stronger."
            ),
        ],
        "LOW": [
            (
                "This password looks strong. "
                "It has good length and variety, making it hard to guess. "
                "Keep using passwords like this on all your accounts."
            ),
            (
                "Good news — this password looks solid. "
                "It is long and varied enough to be difficult for anyone to figure out. "
                "Use a different strong password like this on each of your accounts."
            ),
            (
                "This password seems very safe to us. "
                "It does not look like something easy to guess. "
                "You are doing well — just make sure you use a different strong password everywhere."
            ),
        ],
    },
    "DEFAULT": {
        "HIGH": [
            (
                "This looks risky. "
                "We found some signs that this may not be safe to use or trust. "
                "Avoid using it and check with someone you trust before taking any action."
            ),
            (
                "Something here does not feel right — be careful. "
                "We noticed a few things that suggest this may be harmful. "
                "Do not proceed and talk to someone you trust first."
            ),
            (
                "We are worried about this. "
                "It has some signs that suggest it is not safe. "
                "Stop and get advice before doing anything."
            ),
        ],
        "MEDIUM": [
            (
                "This may not be completely safe. "
                "There are a few unusual things, but nothing is certain yet. "
                "Be careful and double-check before proceeding."
            ),
            (
                "Something feels a little off here. "
                "We are not fully sure but it has a few unusual things worth noticing. "
                "Take your time and think before moving forward."
            ),
            (
                "We are not sure this is entirely safe. "
                "A few things seem slightly unusual. "
                "It is best to check with someone you trust before taking action."
            ),
        ],
        "LOW": [
            (
                "This looks safe to us. "
                "We did not find any major problems. "
                "You can proceed normally, but always stay cautious."
            ),
            (
                "Nothing unusual here — everything looks fine. "
                "We checked and did not find anything to worry about. "
                "Go ahead, but stay alert as always."
            ),
            (
                "This seems fine to us. "
                "We did not notice anything suspicious. "
                "There is nothing to worry about."
            ),
        ],
    },
}


def _fallback_idx(scan_type: str, risk: str, reasons: list[str]) -> int:
    """Deterministic 0–2 index — same scan always returns the same variant."""
    seed_str = scan_type + risk + (reasons[0][:20] if reasons else "none")
    return int(hashlib.sha256(seed_str.encode()).hexdigest()[:4], 16) % 3


def _simple_fallback(risk: str, scan_type: str, reasons: list[str] | None = None) -> str:
    """Return a plain-English fallback variant with zero jargon.

    Picks from a pool of 3 variants so repeated scans of similar content
    don't always produce identical text.
    """
    bucket = scan_type.upper()
    if bucket not in _FALLBACK:
        bucket = "DEFAULT"
    level = risk.upper()
    if level not in ("HIGH", "MEDIUM", "LOW"):
        level = "HIGH" if level in ("VERY_HIGH", "CRITICAL") else "LOW"
    variants: list[str] = _FALLBACK[bucket].get(level, _FALLBACK["DEFAULT"]["MEDIUM"])
    idx = _fallback_idx(scan_type, risk, reasons or [])
    return variants[idx]


def _build_signals_text(reasons: list[str]) -> str:
    """Convert raw reason strings to a brief, human-friendly phrase."""
    if not reasons:
        return "no specific issues found"
    cleaned = [r.strip() for r in reasons[:3] if r.strip()]
    return "; ".join(cleaned) if cleaned else "no specific issues found"


def _tone_hint(score: int | None) -> str:
    s = score if score is not None else 50
    if s <= 30:
        return "Tone: warm and reassuring."
    if s <= 60:
        return "Tone: gently cautious."
    return "Tone: clear direct warning."


def _build_prompt(
    scan_type: str,
    risk: str,
    score: int | None,
    reasons: list[str],
    text: str | None,
) -> str:
    template = _PROMPT_TEMPLATES.get(scan_type.upper(), _DEFAULT_PROMPT)
    return template.format(
        risk=risk or "UNKNOWN",
        score=score if score is not None else "?",
        signals=_build_signals_text(reasons),
        tone_hint=_tone_hint(score),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_ai_explanation(
    scan_type: str,
    risk: str | None,
    score: int | None,
    reasons: list[str],
    text: str | None = None,
) -> str:
    """Generate a simple, human-friendly explanation for any scan type.

    Falls back to a deterministic variant if the OpenAI call fails.
    Never raises — always returns a non-empty string.
    """
    normalized_risk = (risk or "UNKNOWN").upper()
    resolved_type = (scan_type or "SECURITY_SCAN").upper()

    prompt_text = _build_prompt(resolved_type, normalized_risk, score, reasons or [], text)

    try:
        from openai import OpenAI  # guarded import — keeps startup fast when unused
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt_text},
            ],
            max_tokens=130,
            temperature=0.7,
        )
        result = (response.choices[0].message.content or "").strip()
        if result:
            return result
    except Exception:
        logger.exception("ai_explainer: OpenAI call failed for scan_type=%s", resolved_type)

    return _simple_fallback(normalized_risk, resolved_type, reasons)
