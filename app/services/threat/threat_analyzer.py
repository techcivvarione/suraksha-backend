from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from math import log2
from urllib.parse import urljoin, urlparse

import requests
import whois

from app.enums.scan_type import ScanType
from app.services.risk_mapper import derive_risk_level_from_score

URL_REGEX = re.compile(r"(?:(?:https?://)|(?:www\.))[^\s<>()]+", re.IGNORECASE)

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
        re.compile(r"\b(?:sbi|hdfc|icici|paytm|phonepe|amazon|flipkart)\b.{0,40}\b(?:account|card|banking|kyc|verification|wallet|payment|refund|order)\b.{0,40}\b(?:blocked|suspended|freeze|restricted|verify|update|expired|failed)\b", re.IGNORECASE),
        34,
        "The message imitates a trusted brand warning about account access, payments, or verification.",
    ),
    (
        "kyc_scam",
        re.compile(r"\b(?:aadhaar|aadhar)\b.{0,25}\b(?:update|verify|link|re-?kyc)\b|\bkyc\b.{0,25}\b(?:pending|expired|update|complete|failed|suspend)\b", re.IGNORECASE),
        18,
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
)

GENERIC_GREETINGS = ("dear customer", "dear user", "valued customer", "customer notice")
URGENCY_WORDS = {"urgent", "immediately", "immediate", "today", "tonight", "now", "asap", "final", "last chance"}
INSTALL_INTENT = ("install", "download", "update app", "install app")
ACTION_INTENT = ("click", "open", "verify", "update", "confirm")
SENSITIVE_INTENT = ("otp", "pin", "password", "bank details")
FINANCIAL_KEYWORDS = ("bank", "upi", "otp")
SUSPICIOUS_SUFFIXES = (".xyz", ".top", ".click", ".shop", ".live", ".buzz", ".loan", ".monster")
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "tinyurl", "t.co", "goo.gl", "cutt.ly", "ow.ly", "rb.gy", "is.gd", "buff.ly"}
COMMON_SECOND_LEVEL_SUFFIXES = {"co.in", "org.in", "gov.in", "ac.in", "net.in", "co.uk", "com.au"}
NEW_DOMAIN_DAYS_THRESHOLD = 90
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

BRAND_DOMAINS = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "amazon": ("amazon.in", "amazon.com"),
    "flipkart": ("flipkart.com",),
    "facebook": ("facebook.com", "fb.com"),
}


@dataclass(frozen=True)
class ScanResult:
    riskScore: int
    riskLevel: str
    isScamLikely: bool
    detectedSignals: list[str]
    simpleExplanation: str
    detailedExplanation: str
    recommendedAction: str
    confidenceScore: int
    confidenceLabel: str
    detectedType: str
    originalUrl: str | None = None
    finalUrl: str | None = None
    domain: str | None = None
    redirectDetected: bool = False
    redirectChain: list[str] | None = None
    limitedAnalysis: bool = False


@dataclass(frozen=True)
class _Signal:
    label: str
    weight: int
    dangerous_why: str
    category: str
    severity: str = "medium"
    hard_floor: int = 0


@dataclass(frozen=True)
class _LinkAnalysis:
    original_url: str
    final_url: str
    domain: str | None
    final_domain: str | None
    redirect_detected: bool
    redirect_chain: list[str]
    limited_analysis: bool
    redirect_resolution_failed: bool
    signals: list[_Signal]


def analyze_threat(text: str) -> dict:
    normalized_text = _normalize(text)
    lowered = normalized_text.lower()
    urls = _extract_urls(normalized_text)
    signals: list[_Signal] = []
    category_weights: dict[str, int] = {}
    hard_floor = 0
    primary_link: _LinkAnalysis | None = None
    suspicious_link_present = False

    for category, pattern, floor, why in HARD_RULES:
        if pattern.search(normalized_text):
            signal = _Signal(
                label=_signal_label(category),
                weight=max(20, floor - 60),
                dangerous_why=why,
                category=category,
                severity="critical",
                hard_floor=floor,
            )
            signals.append(signal)
            category_weights[category] = category_weights.get(category, 0) + signal.weight
            hard_floor = max(hard_floor, floor)

    for category, pattern, weight, why in PATTERN_RULES:
        if pattern.search(normalized_text):
            signal = _Signal(
                label=_signal_label(category),
                weight=weight,
                dangerous_why=why,
                category=category,
                severity="high" if weight >= 25 else "medium",
            )
            signals.append(signal)
            category_weights[category] = category_weights.get(category, 0) + signal.weight

    for signal in _context_signals(normalized_text, lowered):
        signals.append(signal)
        category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight

    for signal in _intent_signals(lowered):
        signals.append(signal)
        category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight

    for signal in _india_specific_escalations(lowered):
        signals.append(signal)
        category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight
        hard_floor = max(hard_floor, signal.hard_floor)

    for url in urls:
        link_analysis = _analyze_link(url, lowered)
        if primary_link is None:
            primary_link = link_analysis
        suspicious_link_present = suspicious_link_present or any(
            signal.severity in {"critical", "high"} or signal.category in {"unknown_domain_pattern", "multiple_redirects", "tracking_parameters"}
            for signal in link_analysis.signals
        )
        for signal in link_analysis.signals:
            signals.append(signal)
            category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight
            hard_floor = max(hard_floor, signal.hard_floor)

    for signal in _intent_link_escalations(lowered, bool(urls), suspicious_link_present):
        signals.append(signal)
        category_weights[signal.category] = category_weights.get(signal.category, 0) + signal.weight
        hard_floor = max(hard_floor, signal.hard_floor)

    deduped_signals = _rank_signals(_dedupe_signals(signals))
    score = _compute_score(deduped_signals, hard_floor, lowered, primary_link)
    risk_level = derive_risk_level_from_score(score)
    confidence_score = _confidence_score(
        score,
        deduped_signals,
        hard_floor > 0,
        bool(primary_link and primary_link.limited_analysis),
        bool(primary_link and primary_link.redirect_resolution_failed),
    )
    confidence_label = _confidence_label(confidence_score)
    reasons = [signal.label for signal in deduped_signals] or ["No major threats detected, but stay cautious"]
    simple_explanation = _build_simple_explanation(risk_level, deduped_signals)
    detailed_explanation = _build_detailed_explanation(risk_level, deduped_signals)
    recommended_action = _recommended_action(score)
    detected_type = _top_detected_type(category_weights)
    limited_analysis = bool(primary_link and primary_link.limited_analysis)

    result = ScanResult(
        riskScore=score,
        riskLevel=risk_level,
        isScamLikely=score >= 71 or hard_floor >= 85,
        detectedSignals=reasons,
        simpleExplanation=simple_explanation,
        detailedExplanation=detailed_explanation,
        recommendedAction=recommended_action,
        confidenceScore=confidence_score,
        confidenceLabel=confidence_label,
        detectedType=detected_type,
        originalUrl=primary_link.original_url if primary_link else None,
        finalUrl=primary_link.final_url if primary_link else None,
        domain=(primary_link.final_domain or primary_link.domain) if primary_link else None,
        redirectDetected=primary_link.redirect_detected if primary_link else False,
        redirectChain=primary_link.redirect_chain if primary_link else [],
        limitedAnalysis=limited_analysis,
    )

    return {
        "analysis_type": ScanType.THREAT.value,
        "risk_score": result.riskScore,
        "score": result.riskScore,
        "risk_level": result.riskLevel,
        "risk": result.riskLevel,
        "confidence": round(result.confidenceScore / 100, 2),
        "confidence_score": result.confidenceScore,
        "confidence_label": result.confidenceLabel,
        "reasons": result.detectedSignals,
        "signals": result.detectedSignals,
        "risk_reason": result.detectedSignals,
        "summary": result.simpleExplanation,
        "simple_explanation": result.simpleExplanation,
        "detailed_explanation": result.detailedExplanation,
        "explanation": result.detailedExplanation,
        "recommendation": result.recommendedAction,
        "recommended_action": result.recommendedAction,
        "is_scam_likely": result.isScamLikely,
        "detected_type": result.detectedType,
        "original_url": result.originalUrl,
        "final_url": result.finalUrl,
        "domain": result.domain,
        "redirect_detected": result.redirectDetected,
        "redirect_chain": result.redirectChain,
        "limited_analysis": result.limitedAnalysis,
        "structured_result": asdict(result),
    }


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.replace("\u200b", " ")
    return " ".join(text.split())


def _extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _context_signals(text: str, lowered: str) -> list[_Signal]:
    signals: list[_Signal] = []

    if any(greeting in lowered for greeting in GENERIC_GREETINGS):
        signals.append(
            _Signal(
                label="Generic greeting used instead of your name",
                weight=8,
                dangerous_why="Scam messages often use generic greetings because they are mass sent.",
                category="social_engineering",
                severity="low",
            )
        )

    urgency_hits = sum(1 for word in URGENCY_WORDS if word in lowered)
    if urgency_hits >= 2:
        signals.append(
            _Signal(
                label="Multiple urgency words used to pressure immediate action",
                weight=14,
                dangerous_why="Pressure tactics are used to stop users from pausing and verifying the request.",
                category="urgency",
                severity="medium",
            )
        )
    elif urgency_hits == 1:
        signals.append(
            _Signal(
                label="Urgency language detected",
                weight=6,
                dangerous_why="Urgency is a common social-engineering signal.",
                category="urgency",
                severity="low",
            )
        )

    if re.search(r"\b(?:whatsapp|telegram)\b", text, re.IGNORECASE):
        signals.append(
            _Signal(
                label="Moves the conversation to WhatsApp or Telegram",
                weight=14,
                dangerous_why="Fraudsters prefer encrypted messaging apps where they are harder to trace and easier to pressure victims.",
                category="job_scam",
                severity="medium",
            )
        )

    if re.search(r"\b(?:pay now|click link|verify account|update account|claim reward|confirm payment)\b", text, re.IGNORECASE):
        signals.append(
            _Signal(
                label="Direct call to click, pay, or verify through the message",
                weight=14,
                dangerous_why="Direct financial or account-action instructions are common in phishing and payment scams.",
                category="social_engineering",
                severity="medium",
            )
        )

    return signals


def _intent_signals(lowered: str) -> list[_Signal]:
    signals: list[_Signal] = []

    if any(word in lowered for word in INSTALL_INTENT):
        signals.append(
            _Signal(
                label="App installation request",
                weight=30,
                dangerous_why="Scam messages often push app downloads or updates to install harmful software outside trusted channels.",
                category="install_intent",
                severity="high",
            )
        )

    if any(word in lowered for word in ACTION_INTENT):
        signals.append(
            _Signal(
                label="User action requested",
                weight=20,
                dangerous_why="Scammers push users to click, verify, update, or confirm before they stop to verify the sender.",
                category="action_intent",
                severity="medium",
            )
        )

    if any(word in lowered for word in SENSITIVE_INTENT):
        signals.append(
            _Signal(
                label="Sensitive data request",
                weight=35,
                dangerous_why="Requests for OTP, PIN, passwords, or bank details are a strong indicator of account takeover or payment fraud.",
                category="sensitive_intent",
                severity="high",
            )
        )

    if any(word in lowered for word in ("kyc", "bank", "aadhaar", "aadhar", "account blocked", "refund", "reward")):
        signals.append(
            _Signal(
                label="Financial or identity intent detected",
                weight=20,
                dangerous_why="Scam messages often combine money, KYC, Aadhaar, or account-blocked claims to pressure victims into unsafe actions.",
                category="financial_intent",
                severity="medium",
            )
        )

    return signals


def _india_specific_escalations(lowered: str) -> list[_Signal]:
    signals: list[_Signal] = []

    if "kyc" in lowered and ("install" in lowered or "download" in lowered):
        signals.append(
            _Signal(
                label="KYC + app install scam pattern",
                weight=35,
                dangerous_why="Fake KYC notices combined with app downloads are a common Indian fraud technique used to install malicious apps and steal data.",
                category="kyc_install_scam",
                severity="critical",
                hard_floor=85,
            )
        )

    if "account" in lowered and "blocked" in lowered:
        signals.append(
            _Signal(
                label="Account blocked warning",
                weight=30,
                dangerous_why="Account blocked threats are widely used to pressure victims into fast, unsafe actions.",
                category="account_blocked_scam",
                severity="high",
            )
        )

    return signals


def _intent_link_escalations(lowered: str, has_link: bool, suspicious_link_present: bool) -> list[_Signal]:
    if not has_link:
        return []

    signals: list[_Signal] = []
    action_present = any(word in lowered for word in ACTION_INTENT)
    financial_present = any(word in lowered for word in ("kyc", "bank", "aadhaar", "aadhar", "account blocked", "refund", "reward", "upi"))

    if action_present:
        signals.append(
            _Signal(
                label="Message asks you to act on a link",
                weight=20,
                dangerous_why="When a message pushes you to click or verify through a link, the risk of phishing rises sharply.",
                category="intent_link_escalation",
                severity="medium",
            )
        )

    if financial_present and suspicious_link_present:
        signals.append(
            _Signal(
                label="Financial claim paired with a link",
                weight=30,
                dangerous_why="Scam campaigns often combine KYC, refund, bank, or Aadhaar claims with a link to steal credentials or payments.",
                category="financial_link_escalation",
                severity="high",
            )
        )

    if action_present and financial_present and suspicious_link_present:
        signals.append(
            _Signal(
                label="Phishing-style keywords paired with a link",
                weight=45,
                dangerous_why="The message combines a risky action request, financial pressure, and a link, which is a strong phishing pattern.",
                category="phishing_link",
                severity="critical",
                hard_floor=70,
            )
        )

    return signals


def _analyze_link(url: str, lowered: str) -> _LinkAnalysis:
    normalized_url = url if "://" in url else f"https://{url}"
    host = (_hostname(normalized_url) or "").lower()
    parsed = urlparse(normalized_url)
    path = (parsed.path or "").lower()
    redirect_chain, loop_detected, redirect_resolution_failed = _resolve_redirect_chain(normalized_url)
    final_url = redirect_chain[-1] if redirect_chain else normalized_url
    final_host = (_hostname(final_url) or host).lower()
    redirect_detected = len(redirect_chain) > 1
    signals: list[_Signal] = []

    shortened_link = _is_shortened_domain(host)
    if shortened_link:
        signals.append(
            _Signal(
                label="Shortened link hides real destination",
                weight=30,
                dangerous_why="This link hides its real destination.",
                category="shortened_link",
                severity="high",
                hard_floor=41,
            )
        )

    if loop_detected:
        signals.append(
            _Signal(
                label="Redirect loop detected",
                weight=20,
                dangerous_why="Broken or looping redirects are unusual and can hide unsafe behavior.",
                category="redirect_loop",
                severity="medium",
            )
        )

    if len(redirect_chain) >= 3:
        signals.append(
            _Signal(
                label=f"Multiple redirects detected ({len(redirect_chain) - 1} hops)",
                weight=15,
                dangerous_why="Multiple redirect hops can be used to hide the final destination from the user.",
                category="multiple_redirects",
                severity="medium",
            )
        )

    domain_checks = [(host, "Link")]
    if final_host and final_host != host:
        domain_checks.append((final_host, "Final destination"))

    for domain_to_check, label_prefix in domain_checks:
        if not domain_to_check:
            continue
        if domain_to_check.endswith(SUSPICIOUS_SUFFIXES) or "xn--" in domain_to_check:
            signals.append(
                _Signal(
                    label=f"{label_prefix} uses a suspicious domain: {domain_to_check}",
                    weight=25,
                    dangerous_why="Suspicious or deceptive domains are common in phishing and credential theft.",
                    category="suspicious_tld",
                    severity="high",
                )
            )

        if not _looks_official_domain(domain_to_check):
            signals.append(
                _Signal(
                    label=f"{label_prefix} uses an unfamiliar domain pattern: {domain_to_check}",
                    weight=12,
                    dangerous_why="Unfamiliar or low-trust domain patterns deserve caution when a message asks for action.",
                    category="unknown_domain_pattern",
                    severity="medium",
                )
            )

    if any(keyword in path for keyword in ("pay", "login", "verify", "update", "kyc", "reward", ".apk")):
        signals.append(
            _Signal(
                label=f"Link path suggests payment, verification, or app download: {host}{path}",
                weight=45,
                dangerous_why="Scam links often mimic payment, login, or update flows to steal credentials.",
                category="phishing_link",
                severity="critical",
                hard_floor=70,
            )
        )

    if _has_excessive_tracking(parsed.query):
        signals.append(
            _Signal(
                label="Link carries excessive tracking parameters",
                weight=12,
                dangerous_why="Heavy tracking parameters are often used in bulk scam or affiliate-style campaigns.",
                category="tracking_parameters",
                severity="medium",
            )
        )

    brand_mismatch_signal = _brand_link_mismatch(lowered, final_host or host)
    if brand_mismatch_signal is not None:
        signals.append(brand_mismatch_signal)

    spoofed_domain_signal = _spoofed_brand_domain_signal(final_host or host)
    if spoofed_domain_signal is not None:
        signals.append(spoofed_domain_signal)

    if redirect_detected and _registrable_domain(host) != _registrable_domain(final_host):
        signals.append(
            _Signal(
                label=f"Redirect mismatch: {host} sends you to {final_host}",
                weight=45,
                dangerous_why="The shown domain and final destination do not match.",
                category="redirect_mismatch",
                severity="critical",
                hard_floor=70,
            )
        )

    safe_browsing_enabled = _safe_browsing_available()
    if safe_browsing_enabled and _matches_safe_browsing(final_url):
        signals.append(
            _Signal(
                label="Google Safe Browsing flagged this destination",
                weight=50,
                dangerous_why="Google Safe Browsing reported the destination as unsafe or deceptive.",
                category="unsafe_reputation",
                severity="critical",
                hard_floor=71,
            )
        )

    age_days = _get_domain_age_days(final_host or host)
    if age_days is not None and age_days < NEW_DOMAIN_DAYS_THRESHOLD:
        signals.append(
            _Signal(
                label=f"Domain is newly registered ({age_days} days old)",
                weight=25,
                dangerous_why="Newly registered domains are often used for short-lived scam campaigns.",
                category="new_domain",
                severity="high",
            )
        )

    return _LinkAnalysis(
        original_url=normalized_url,
        final_url=final_url,
        domain=host or None,
        final_domain=final_host or None,
        redirect_detected=redirect_detected,
        redirect_chain=redirect_chain or [normalized_url],
        limited_analysis=not safe_browsing_enabled,
        redirect_resolution_failed=redirect_resolution_failed,
        signals=_dedupe_signals(signals),
    )


def _brand_link_mismatch(lowered: str, host: str | None) -> _Signal | None:
    if not host:
        return None
    for brand, trusted_domains in BRAND_DOMAINS.items():
        if not _mentions_brand(lowered, brand):
            continue
        if any(host == domain or host.endswith(f".{domain}") for domain in trusted_domains):
            return None
        return _Signal(
            label=f"Brand mismatch: message mentions {brand.upper()} but links to {host}",
            weight=45,
            dangerous_why="The message mentions a trusted brand but the link does not use that brand's official domain.",
            category="brand_mismatch",
            severity="critical",
            hard_floor=71,
        )
    return None


def _spoofed_brand_domain_signal(host: str | None) -> _Signal | None:
    if not host:
        return None
    normalized = host.lower().strip(".")
    for brand, trusted_domains in BRAND_DOMAINS.items():
        if any(normalized == domain or normalized.endswith(f".{domain}") for domain in trusted_domains):
            continue
        for label in normalized.split("."):
            token = _normalize_brand_token(label)
            if not token:
                continue
            if token == brand or (token.startswith(brand) and len(token) - len(brand) <= 6) or _levenshtein_distance(token, brand) <= 1:
                return _Signal(
                    label=f"Domain imitates the trusted brand {brand.upper()}",
                    weight=45,
                    dangerous_why="The domain itself imitates a trusted brand while using an unofficial host.",
                    category="brand_mismatch",
                    severity="critical",
                    hard_floor=71,
                )
    return None


def _hostname(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def _compute_score(signals: list[_Signal], hard_floor: int, lowered: str, primary_link: _LinkAnalysis | None) -> int:
    if not signals:
        return 18

    grouped_weights: dict[str, list[int]] = {"critical": [], "high": [], "medium": [], "low": []}
    critical_present = any(signal.severity == "critical" for signal in signals)
    for signal in signals:
        weight = float(signal.weight)
        if critical_present and signal.severity == "medium":
            weight *= 0.5
        elif critical_present and signal.severity == "low":
            weight *= 0.3
        grouped_weights.setdefault(signal.severity, []).append(int(round(weight)))

    score = 0
    score += _group_weight_score(grouped_weights["critical"], cap=50, bonus_step=5)
    score += _group_weight_score(grouped_weights["high"], cap=35, bonus_step=4)
    score += _group_weight_score(grouped_weights["medium"], cap=20, bonus_step=3)
    score += _group_weight_score(grouped_weights["low"], cap=10, bonus_step=2)

    if grouped_weights["critical"]:
        score = max(score, 70)
    if any(signal.category == "shortened_link" for signal in signals):
        score = max(score, 41)
    if any(signal.category in {"financial_link_escalation", "phishing_link"} for signal in signals):
        score = max(score, 41)

    if primary_link and _is_trusted_domain(primary_link.final_domain or primary_link.domain) and not grouped_weights["critical"]:
        score -= 12

    score = max(score, hard_floor)
    return max(0, min(100, score))


def _confidence_score(
    score: int,
    signals: list[_Signal],
    has_hard_rule: bool,
    limited_analysis: bool,
    redirect_resolution_failed: bool,
) -> int:
    if not signals:
        return 20

    confidence = 0
    categories = {signal.category for signal in signals}
    critical_present = any(signal.severity == "critical" for signal in signals)

    if critical_present:
        confidence += 50

    confidence += len(signals) * 10

    if _signals_agree(categories) or has_hard_rule:
        confidence += 20

    if limited_analysis:
        confidence -= 20
    if redirect_resolution_failed:
        confidence -= 15

    return max(0, min(confidence, 100))


def _build_simple_explanation(risk_level: str, signals: list[_Signal]) -> str:
    if not signals:
        return "No major threats detected, but stay cautious"

    categories = {signal.category for signal in signals}
    if "shortened_link" in categories:
        return "This looks risky because this link hides its real destination."
    if "redirect_mismatch" in categories:
        return "This looks risky because the link redirects to a different destination."
    if "brand_mismatch" in categories:
        return "This looks risky because the link does not match the brand mentioned in the message."
    if "financial_link_escalation" in categories or "phishing_link" in categories:
        return "This looks risky because the message pushes you toward a money or verification link."
    if risk_level == "HIGH":
        return "This looks risky because multiple strong scam signals were detected."
    if risk_level == "MEDIUM":
        return "This needs caution because several suspicious signals were detected."
    return "We did not find a strong scam signal, but the message still deserves caution."


def _build_detailed_explanation(risk_level: str, signals: list[_Signal]) -> str:
    if not signals:
        return (
            f"Final risk: {risk_level}\n"
            "- No major scam indicators were detected\n"
            "- Analysis found no strong payment, OTP, or malware signals\n"
            "- Stay cautious before sharing sensitive details"
        )

    strongest = signals[0]
    lines = [f"Final risk: {risk_level}"]
    lines.append(f"We flagged this mainly because {strongest.dangerous_why.lower()}")
    for signal in signals[:3]:
        lines.append(f"- {signal.label}")
    return "\n".join(lines)


def _recommended_action(score: int) -> str:
    if score >= 71:
        return "Do not click the link or share any OTP, PIN, or bank details. Verify the request only through the official app or website."
    if score >= 41:
        return "Pause before taking action. Verify the sender and destination through an official channel."
    return "No major threats detected, but stay cautious"


def _top_detected_type(category_weights: dict[str, int]) -> str:
    if not category_weights:
        return "generic_risk"
    return max(category_weights.items(), key=lambda item: item[1])[0]


def _resolve_redirect_chain(url: str, max_redirects: int = 5) -> tuple[list[str], bool, bool]:
    chain = [url]
    seen = {url}
    current = url
    loop_detected = False
    redirect_resolution_failed = False
    headers = {"User-Agent": "GO-Suraksha-Link-Scanner/1.0"}

    for _ in range(max_redirects):
        try:
            response = requests.get(current, allow_redirects=False, timeout=4, headers=headers, stream=True)
        except Exception:
            redirect_resolution_failed = True
            break
        location = response.headers.get("Location")
        response.close()
        if response.status_code not in {301, 302, 303, 307, 308} or not location:
            break
        next_url = urljoin(current, location)
        if next_url in seen:
            loop_detected = True
            chain.append(next_url)
            break
        chain.append(next_url)
        seen.add(next_url)
        current = next_url

    return chain, loop_detected, redirect_resolution_failed


def _safe_browsing_available() -> bool:
    return bool((os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or "").strip())


def _matches_safe_browsing(url: str) -> bool:
    api_key = (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or "").strip()
    if not api_key:
        return False

    payload = {
        "client": {"clientId": "go-suraksha", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(f"{SAFE_BROWSING_API_URL}?key={api_key}", json=payload, timeout=4)
        response.raise_for_status()
        return bool(response.json().get("matches"))
    except Exception:
        return False


def _get_domain_age_days(domain: str | None) -> int | None:
    if not domain:
        return None
    try:
        details = whois.whois(domain)
        creation_date = details.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - creation_date).days
    except Exception:
        return None


def _registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return host.lower()
    suffix = ".".join(parts[-2:])
    if len(parts) >= 3 and suffix in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _looks_official_domain(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.lower().strip(".")
    if normalized.endswith(SUSPICIOUS_SUFFIXES):
        return False
    return any(
        normalized == domain or normalized.endswith(f".{domain}")
        for domains in BRAND_DOMAINS.values()
        for domain in domains
    ) or normalized.endswith((".gov.in", ".nic.in", ".org", ".com", ".in", ".bank"))


def _is_trusted_domain(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.lower().strip(".")
    if any(
        normalized == domain or normalized.endswith(f".{domain}")
        for domains in BRAND_DOMAINS.values()
        for domain in domains
    ):
        return True
    return normalized.endswith((".gov.in", ".nic.in", ".bank"))


def _is_shortened_domain(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.lower().strip(".")
    trusted_domains = {domain for domains in BRAND_DOMAINS.values() for domain in domains}
    if normalized in trusted_domains or any(normalized.endswith(f".{domain}") for domain in trusted_domains):
        return False
    if normalized in SHORTENER_HOSTS:
        return True
    parts = normalized.split(".")
    if len(parts) < 2:
        return False
    second_level = parts[-2]
    if len(second_level) <= 5:
        return True
    if "-" in second_level:
        return False
    return len(second_level) <= 6 and _looks_random_label(second_level)


def _has_excessive_tracking(query: str) -> bool:
    if not query:
        return False
    lowered = query.lower()
    tracking_hits = sum(
        1
        for marker in ("utm_", "gclid", "fbclid", "msclkid", "affid", "ref=", "source=")
        if marker in lowered
    )
    return tracking_hits >= 2 or len(query) > 80


def _mentions_brand(text: str, brand: str) -> bool:
    tokens = _extract_tokens(text)
    if brand in tokens:
        return True

    brand_variants = {_normalize_brand_token(brand)}
    if brand == "phonepe":
        brand_variants.add("phonepay")

    for token in tokens:
        normalized = _normalize_brand_token(token)
        if not normalized:
            continue
        if normalized in brand_variants:
            return True
        if normalized.startswith(brand) and len(normalized) - len(brand) <= 6:
            return True
        if _levenshtein_distance(normalized, brand) <= 1:
            return True
    return False


def _extract_tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9@._-]+", text.lower())


def _normalize_brand_token(token: str) -> str:
    replacements = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    normalized = token.lower().translate(replacements)
    normalized = normalized.replace("-", "").replace("_", "").replace(".", "")
    return re.sub(r"[^a-z]", "", normalized)


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _group_weight_score(weights: list[int], cap: int, bonus_step: int) -> int:
    if not weights:
        return 0
    ordered = sorted(weights, reverse=True)
    total = ordered[0]
    for weight in ordered[1:]:
        total += min(bonus_step, max(1, weight // 5))
    return min(cap, total)


def _confidence_label(confidence_score: int) -> str:
    if confidence_score >= 80:
        return "HIGH"
    if confidence_score >= 50:
        return "MEDIUM"
    return "LOW"


def _signals_agree(categories: set[str]) -> bool:
    agreeing_pairs = (
        {"brand_mismatch", "redirect_mismatch"},
        {"brand_mismatch", "phishing_link"},
        {"redirect_mismatch", "phishing_link"},
        {"financial_link_escalation", "phishing_link"},
        {"shortened_link", "phishing_link"},
    )
    return any(pair.issubset(categories) for pair in agreeing_pairs)


def _rank_signals(signals: list[_Signal]) -> list[_Signal]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(signals, key=lambda signal: (severity_rank.get(signal.severity, 9), -signal.weight, signal.label))


def _looks_random_label(label: str) -> bool:
    cleaned = re.sub(r"[^a-z0-9]", "", label.lower())
    if len(cleaned) < 4:
        return False
    unique_ratio = len(set(cleaned)) / len(cleaned)
    entropy = -sum((cleaned.count(ch) / len(cleaned)) * log2(cleaned.count(ch) / len(cleaned)) for ch in set(cleaned))
    return unique_ratio >= 0.75 and entropy >= 1.8


def _signal_label(category: str) -> str:
    labels = {
        "apk_install": "Requests APK installation or links to an APK file",
        "remote_access": "Mentions remote access tools such as AnyDesk or TeamViewer",
        "urgency_threat": "Creates a deadline like 'blocked today' or 'update immediately'",
        "payment_panic": "Uses payment panic such as 'money debited' or 'refund pending'",
        "otp_request": "Asks you to share or verify an OTP",
        "bank_impersonation": "Imitates a trusted brand warning",
        "kyc_scam": "Pushes a fake KYC or Aadhaar update",
        "upi_collect": "Uses a UPI collect or approval trick",
        "lottery_reward": "Promises a prize, cashback, or reward",
        "job_scam": "Looks like a WhatsApp or Telegram job scam",
        "delivery_scam": "Looks like a fake delivery or parcel notice",
        "install_intent": "Requests you to install or download an app",
        "action_intent": "Pushes you to click, open, verify, update, or confirm",
        "sensitive_intent": "Requests sensitive details such as OTP, PIN, password, or bank details",
        "financial_intent": "Mentions money, KYC, Aadhaar, or account pressure",
        "kyc_install_scam": "Combines KYC language with an app installation request",
        "account_blocked_scam": "Warns that your account is blocked to pressure you",
        "intent_link_escalation": "Message asks you to act on a link",
        "financial_link_escalation": "Financial claim paired with a link",
        "phishing_link": "Phishing-style keywords paired with a link",
        "multiple_redirects": "Multiple redirects were detected",
        "unknown_domain_pattern": "Link uses an unfamiliar domain pattern",
        "tracking_parameters": "Link carries excessive tracking parameters",
        "redirect_mismatch": "Redirect leads to a different domain",
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
