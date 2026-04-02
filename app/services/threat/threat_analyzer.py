from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from app.enums.scan_type import ScanType
from app.services.risk_mapper import derive_risk_level_from_score

URL_REGEX = re.compile(r"(?:(?:https?://)|(?:www\.))[^\s<>()]+", re.IGNORECASE)
APK_REGEX = re.compile(r"(?:https?://[^\s]+\.apk\b)|(?:\b[\w.-]+\.apk\b)", re.IGNORECASE)

HARD_RULES: tuple[tuple[str, re.Pattern[str], int, str], ...] = (
    (
        "apk_install",
        re.compile(r"(?:\.apk\b)|(?:install\s+(?:the\s+)?(?:app|apk)\s+from\s+(?:this\s+)?link)|(?:download\s+(?:the\s+)?app\b)", re.IGNORECASE),
        96,
        "APK files can install malicious apps outside the official app store.",
    ),
    (
        "remote_access",
        re.compile(r"\b(?:anydesk|teamviewer|quicksupport|rustdesk)\b", re.IGNORECASE),
        94,
        "Remote access tools are frequently abused to take control of a victim's phone or bank session.",
    ),
    (
        "urgency_threat",
        re.compile(r"\b(?:blocked today|blocked tonight|suspended today|immediately update|update immediately|within\s+\d+\s*(?:minutes|hours))\b", re.IGNORECASE),
        88,
        "High-pressure deadlines are a classic scam tactic to stop users from verifying the request.",
    ),
    (
        "payment_panic",
        re.compile(r"\b(?:money debited|refund pending(?:\s+click\s+link)?|refund pending click link|refund.*click\s+link|wrong transfer.*refund)\b", re.IGNORECASE),
        90,
        "Payment panic is commonly used in UPI and refund scams to trigger rushed actions.",
    ),
    (
        "otp_request",
        re.compile(r"(?:\b(?:share|send|provide|tell|confirm|verify|submit)\b.{0,20}\botp\b)|(?:\botp\b.{0,20}\b(?:share|send|provide|tell|confirm|verify|submit)\b)", re.IGNORECASE),
        92,
        "Legitimate banks, apps, and support teams never ask you to share or verify OTPs in chat messages.",
    ),
)

PATTERN_RULES: tuple[tuple[str, re.Pattern[str], int, str], ...] = (
    (
        "bank_impersonation",
        re.compile(r"\b(?:sbi|state bank of india|hdfc|hdfc bank|icici|icici bank|axis bank|kotak|pnb|bank of baroda|bob|canara bank)\b.{0,40}\b(?:account|card|banking|kyc|verification|debit card)\b.{0,40}\b(?:blocked|suspended|freeze|restricted|verify|update|expired)\b", re.IGNORECASE),
        34,
        "The message imitates a bank warning about account access or verification.",
    ),
    (
        "kyc_scam",
        re.compile(r"\b(?:aadhaar|aadhar)\b.{0,25}\b(?:update|verify|link|re-?kyc)\b|\bkyc\b.{0,25}\b(?:pending|expired|update|complete|failed|suspend)\b", re.IGNORECASE),
        28,
        "KYC and Aadhaar updates are a common cover for credential theft and fake support scams.",
    ),
    (
        "upi_collect",
        re.compile(r"\b(?:collect request|approve payment|upi collect|approve collect|scan and pay to receive|receive money.*(?:pay|approve)|upi pin)\b", re.IGNORECASE),
        32,
        "UPI scams often trick users into approving a collect request instead of receiving money.",
    ),
    (
        "lottery_reward",
        re.compile(r"\b(?:won prize|claim reward|claim prize|lucky draw|cashback approved|gift voucher|free reward)\b", re.IGNORECASE),
        24,
        "Unexpected rewards and prize claims are common bait for phishing and advance-fee fraud.",
    ),
    (
        "job_scam",
        re.compile(r"\b(?:earn money daily|daily income|work from home|part[- ]?time job|telegram.*job|whatsapp.*job|salary per day)\b", re.IGNORECASE),
        24,
        "Telegram and WhatsApp job offers are frequently used for task scams and mule recruitment.",
    ),
    (
        "delivery_scam",
        re.compile(r"\b(?:parcel held|delivery failed.*click|courier.*pending|address update.*delivery|shipment on hold)\b", re.IGNORECASE),
        20,
        "Fake delivery failures are widely used to steal payment details or push malware links.",
    ),
    (
        "government_scheme_scam",
        re.compile(r"\b(?:pm kisan|e-?shram|subsidy released|government scheme|pan update|required)\b", re.IGNORECASE),
        18,
        "Fraudsters often impersonate government schemes or identity-update notices to exploit trust.",
    ),
)

URGENCY_WORDS = {
    "urgent",
    "immediately",
    "immediate",
    "today",
    "tonight",
    "now",
    "asap",
    "final",
    "last chance",
}

GENERIC_GREETINGS = (
    "dear customer",
    "dear user",
    "valued customer",
    "customer notice",
)

BRAND_DOMAINS = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com", "kotakbank.com"),
    "pnb": ("pnbindia.in",),
    "phonepe": ("phonepe.com",),
    "paytm": ("paytm.com", "paytm.in"),
    "gpay": ("google.com", "pay.google.com"),
    "google pay": ("google.com", "pay.google.com"),
    "aadhaar": ("uidai.gov.in",),
    "aadhar": ("uidai.gov.in",),
    "pan": ("incometax.gov.in", "protean-tinpan.com"),
    "upi": ("npci.org.in",),
}

SUSPICIOUS_SUFFIXES = (".top", ".xyz", ".click", ".live", ".shop", ".buzz", ".monster", ".loan")
SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "cutt.ly", "ow.ly", "rb.gy"}


@dataclass(frozen=True)
class ScanResult:
    riskScore: int
    riskLevel: str
    isScamLikely: bool
    detectedSignals: list[str]
    explanation: str
    recommendedAction: str
    confidence: float
    detectedType: str


@dataclass(frozen=True)
class _Signal:
    label: str
    weight: int
    dangerous_why: str
    category: str
    hard_floor: int = 0


def analyze_threat(text: str) -> dict:
    normalized_text = _normalize(text)
    lowered = normalized_text.lower()
    urls = _extract_urls(normalized_text)
    signals: list[_Signal] = []
    hard_floor = 0
    category_weights: dict[str, int] = {}

    for category, pattern, floor, why in HARD_RULES:
        if pattern.search(normalized_text):
            signal = _Signal(
                label=_signal_label(category),
                weight=max(20, floor - 60),
                dangerous_why=why,
                category=category,
                hard_floor=floor,
            )
            signals.append(signal)
            hard_floor = max(hard_floor, floor)
            category_weights[category] = category_weights.get(category, 0) + signal.weight

    for category, pattern, weight, why in PATTERN_RULES:
        if pattern.search(normalized_text):
            signal = _Signal(
                label=_signal_label(category),
                weight=weight,
                dangerous_why=why,
                category=category,
            )
            signals.append(signal)
            category_weights[category] = category_weights.get(category, 0) + weight

    context_signals = _context_signals(normalized_text, lowered, urls)
    for signal in context_signals:
        signals.append(signal)
        category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight

    score = _compute_score(signals, hard_floor)
    risk_level = derive_risk_level_from_score(score)
    is_scam_likely = score >= 70 or hard_floor >= 85
    detected_type = _top_detected_type(category_weights)
    explanation = _build_explanation(signals, urls, score, risk_level)
    recommended_action = _recommended_action(score, detected_type)
    confidence = _confidence(score, len(signals), hard_floor > 0)
    detected_signals = [signal.label for signal in signals] or ["No major scam indicators found"]

    result = ScanResult(
        riskScore=score,
        riskLevel=risk_level,
        isScamLikely=is_scam_likely,
        detectedSignals=detected_signals,
        explanation=explanation,
        recommendedAction=recommended_action,
        confidence=confidence,
        detectedType=detected_type,
    )

    return {
        "analysis_type": ScanType.THREAT.value,
        "risk_score": result.riskScore,
        "risk_level": result.riskLevel,
        "confidence": result.confidence,
        "reasons": result.detectedSignals,
        "signals": result.detectedSignals,
        "summary": result.explanation,
        "explanation": result.explanation,
        "recommendation": result.recommendedAction,
        "recommended_action": result.recommendedAction,
        "is_scam_likely": result.isScamLikely,
        "detected_type": result.detectedType,
        "structured_result": asdict(result),
    }


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.replace("\u200b", " ")
    return " ".join(text.split())


def _extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _context_signals(text: str, lowered: str, urls: list[str]) -> list[_Signal]:
    signals: list[_Signal] = []

    if any(greeting in lowered for greeting in GENERIC_GREETINGS):
        signals.append(
            _Signal(
                label="Generic greeting used instead of your name",
                weight=8,
                dangerous_why="Scam messages often use generic greetings because they are mass sent.",
                category="social_engineering",
            )
        )

    urgency_hits = sum(1 for word in URGENCY_WORDS if word in lowered)
    if urgency_hits >= 2:
        signals.append(
            _Signal(
                label="Multiple urgency words used to pressure immediate action",
                weight=14,
                dangerous_why="Pressure tactics are used to stop victims from pausing and verifying the message.",
                category="urgency",
            )
        )
    elif urgency_hits == 1:
        signals.append(
            _Signal(
                label="Urgency language detected",
                weight=6,
                dangerous_why="Urgency is a common social-engineering signal.",
                category="urgency",
            )
        )

    if re.search(r"\b(?:whatsapp|telegram)\b", text, re.IGNORECASE):
        signals.append(
            _Signal(
                label="Moves the conversation to WhatsApp or Telegram",
                weight=14,
                dangerous_why="Fraudsters prefer encrypted messaging apps where they are harder to trace and easier to pressure victims.",
                category="job_scam",
            )
        )

    if re.search(r"\b(?:pay now|click link|verify account|update account|claim reward|confirm payment)\b", text, re.IGNORECASE):
        signals.append(
            _Signal(
                label="Direct call to click, pay, or verify through the message",
                weight=14,
                dangerous_why="Direct financial or account-action instructions are common in phishing and payment scams.",
                category="social_engineering",
            )
        )

    if re.search(r"\bkindly\b.*\b(?:update|verify|click|install)\b", text, re.IGNORECASE):
        signals.append(
            _Signal(
                label="Awkward instruction pattern often seen in scam templates",
                weight=8,
                dangerous_why="Poorly localized language appears frequently in bulk phishing templates.",
                category="social_engineering",
            )
        )

    for url in urls:
        host = (_hostname(url) or "").lower()
        if not host:
            continue
        parsed = urlparse(url if "://" in url else f"https://{url}")
        path = (parsed.path or "").lower()

        if host in SHORTENERS:
            signals.append(
                _Signal(
                    label="Shortened link hides the real destination",
                    weight=18,
                    dangerous_why="Shortened links conceal the final website and are heavily used in phishing.",
                    category="suspicious_link",
                )
            )

        if host.endswith(SUSPICIOUS_SUFFIXES) or "xn--" in host:
            signals.append(
                _Signal(
                    label=f"Link uses a high-risk domain: {host}",
                    weight=20,
                    dangerous_why="Cheap or deceptive domains are commonly used for impersonation and malware delivery.",
                    category="suspicious_link",
                )
            )

        if any(keyword in path for keyword in ("pay", "login", "verify", "update", "kyc", "reward", ".apk")):
            signals.append(
                _Signal(
                    label=f"Link path suggests payment, verification, or app download: {host}{path}",
                    weight=18,
                    dangerous_why="Scam links often use payment, verification, or update paths to imitate legitimate flows.",
                    category="suspicious_link",
                )
            )

        if not _looks_official_domain(host):
            signals.append(
                _Signal(
                    label=f"Unknown or non-official link detected: {host}",
                    weight=14,
                    dangerous_why="Unknown domains increase the chance of phishing, fake support, or malware pages.",
                    category="suspicious_link",
                )
            )

        mismatch_signal = _brand_link_mismatch(lowered, host)
        if mismatch_signal is not None:
            signals.append(mismatch_signal)

    return _dedupe_signals(signals)


def _brand_link_mismatch(lowered: str, host: str) -> _Signal | None:
    for brand, trusted_domains in BRAND_DOMAINS.items():
        if brand not in lowered:
            continue
        if any(host == domain or host.endswith(f".{domain}") for domain in trusted_domains):
            return None
        return _Signal(
            label=f"Brand mismatch: message mentions {brand.upper()} but links to {host}",
            weight=24,
            dangerous_why="Impersonation scams frequently mention trusted brands while sending users to unrelated domains.",
            category="brand_mismatch",
        )
    return None


def _looks_official_domain(host: str) -> bool:
    return host.endswith((".gov.in", ".nic.in", ".bank", ".com", ".in", ".org")) and not host.endswith(SUSPICIOUS_SUFFIXES)


def _hostname(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname


def _compute_score(signals: list[_Signal], hard_floor: int) -> int:
    if not signals:
        return 18

    total = sum(signal.weight for signal in signals)
    distinct_categories = len({signal.category for signal in signals})
    score = total + (distinct_categories - 1) * 4

    if len(signals) >= 4:
        score += 6
    if len(signals) >= 6:
        score += 6

    score = max(score, hard_floor)
    return max(0, min(100, score))


def _top_detected_type(category_weights: dict[str, int]) -> str:
    if not category_weights:
        return "generic_risk"
    return max(category_weights.items(), key=lambda item: item[1])[0]


def _build_explanation(signals: list[_Signal], urls: list[str], score: int, risk_level: str) -> str:
    if not signals:
        return (
            "This message does not show strong scam indicators right now, but it should still be treated carefully. "
            "There was no clear request for money, OTP, app installation, or account verification. "
            "Do not click links or share sensitive details unless you independently trust the sender."
        )

    top_signals = signals[:3]
    detected = "; ".join(signal.label for signal in top_signals)
    danger = " ".join(signal.dangerous_why for signal in top_signals[:2])

    if risk_level == "HIGH":
        action = "Do not click, install, pay, or share OTP or PIN details. Contact the bank, app, or service through its official app or helpline only."
    elif risk_level == "MEDIUM":
        action = "Pause before taking action. Verify the sender through an official channel and avoid opening links until you confirm the request is legitimate."
    else:
        action = "Treat it cautiously and verify the sender if the message asks for any sensitive action."

    if urls:
        action += " If you already opened the link, do not enter credentials or approve any UPI request."

    return f"This message is {risk_level.lower()} risk because it shows {detected}. {danger} {action}"


def _recommended_action(score: int, detected_type: str) -> str:
    if score >= 90:
        return "Block the sender, avoid all links and attachments, and contact the institution through its official app or helpline immediately."
    if score >= 75:
        return "Do not click the link or share OTP, PIN, or bank details. Verify the request independently before doing anything."
    if score >= 45:
        if detected_type == "upi_collect":
            return "Do not approve the collect request. Open your UPI app directly and verify whether any payment request is genuine."
        return "Do not act yet. Verify the sender through an official number, website, or app before responding."
    return "No strong scam signal was found, but avoid sharing sensitive information unless you trust the sender and destination."


def _confidence(score: int, signal_count: int, has_hard_rule: bool) -> float:
    baseline = 0.35 + min(score, 100) / 150
    if signal_count >= 4:
        baseline += 0.1
    if has_hard_rule:
        baseline += 0.12
    return round(min(0.99, baseline), 2)


def _signal_label(category: str) -> str:
    labels = {
        "apk_install": "Requests APK installation or links to an APK file",
        "remote_access": "Mentions remote access tools such as AnyDesk or TeamViewer",
        "urgency_threat": "Creates a deadline like 'blocked today' or 'update immediately'",
        "payment_panic": "Uses payment panic such as 'money debited' or 'refund pending'",
        "otp_request": "Asks you to share or verify an OTP",
        "bank_impersonation": "Imitates a bank account or card warning",
        "kyc_scam": "Pushes a fake KYC or Aadhaar update",
        "upi_collect": "Uses a UPI collect or approval trick",
        "lottery_reward": "Promises a prize, cashback, or reward",
        "job_scam": "Looks like a WhatsApp or Telegram job scam",
        "delivery_scam": "Looks like a fake delivery or parcel notice",
        "government_scheme_scam": "Impersonates a government scheme or ID update notice",
    }
    return labels.get(category, category.replace("_", " ").title())


def _dedupe_signals(signals: list[_Signal]) -> list[_Signal]:
    deduped: list[_Signal] = []
    seen: set[str] = set()
    for signal in signals:
        if signal.label in seen:
            continue
        seen.add(signal.label)
        deduped.append(signal)
    return deduped
