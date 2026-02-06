from urllib.parse import urlparse
from datetime import datetime, timezone
import re
import whois
import requests
from pathlib import Path
import os
import json
from openai import OpenAI

# =========================================================
# CONFIG
# =========================================================

NEW_DOMAIN_DAYS_THRESHOLD = 90
USE_HYBRID_FEEDS = True

BASE_DIR = Path(__file__).resolve().parent
FEEDS_DIR = BASE_DIR / "feeds"

OPENPHISH_FILE = FEEDS_DIR / "openphish.txt"
URLHAUS_FILE = FEEDS_DIR / "urlhaus.txt"


# =========================================================
# STATIC OFFLINE DATA
# =========================================================

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}

ABUSE_HOSTS = {
    "pastebin.com",
    "paste.ee",
    "raw.githubusercontent.com",
    "anonfiles.com",
    "transfer.sh"
}

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "verify", "update", "secure", "account",
    "bank", "confirm", "payment", "kyc", "auth"
}

SCAM_KEYWORDS = {
    "urgency": [
        "urgent", "immediately", "act now", "final warning",
        "within 24 hours", "account will be blocked"
    ],
    "authority": [
        "rbi", "income tax", "bank team", "kyc update",
        "customs", "police", "legal action"
    ],
    "reward": [
        "refund", "cashback", "won", "prize",
        "lottery", "gift", "free"
    ],
    "threat": [
        "blocked", "suspended", "terminated",
        "penalty", "fine", "arrest"
    ]
}

# =========================================================
# FEED LOADERS
# =========================================================

def load_feed(file_path: Path) -> set[str]:
    if not file_path.exists():
        return set()
    return {
        line.strip().lower()
        for line in file_path.read_text().splitlines()
        if line and not line.startswith("#")
    }

OPENPHISH_URLS = load_feed(OPENPHISH_FILE) if USE_HYBRID_FEEDS else set()
URLHAUS_URLS = load_feed(URLHAUS_FILE) if USE_HYBRID_FEEDS else set()

# =========================================================
# HELPERS
# =========================================================

def detect_scan_type(content: str) -> str:
    if content.strip().startswith(("http://", "https://")):
        return "link"
    if "subject:" in content.lower() or "from:" in content.lower():
        return "email"
    if len(content) < 300:
        return "sms"
    return "text"


def get_domain_age_days(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - creation_date).days
    except Exception:
        return None


def extract_url(text: str):
    match = re.search(r"(https?://[^\s]+)", text)
    return match.group(0) if match else None


# =========================================================
# TEXT ANALYSIS
# =========================================================

def analyze_text_message(text: str):
    reasons = []
    score = 0
    text_lower = text.lower()

    for keywords in SCAM_KEYWORDS.values():
        for word in keywords:
            if re.search(rf"\b{re.escape(word)}\b", text_lower):
                reasons.append(f"Scam keyword detected: '{word}'")
                score += 15

    return {"score": score, "reasons": reasons}


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return {"score": 60, "reasons": ["Malformed or invalid URL"]}

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if parsed.scheme != "https":
        reasons.append("URL is not using HTTPS")
        score += 20

    age_days = get_domain_age_days(domain)
    if age_days is not None and age_days < NEW_DOMAIN_DAYS_THRESHOLD:
        reasons.append(f"Domain registered {age_days} days ago")
        score += 30

    if domain in ABUSE_HOSTS:
        reasons.append("Domain frequently abused for malicious content")
        score += 40

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path:
            reasons.append(f"Suspicious URL path contains '{kw}'")
            score += 15

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if len(response.history) >= 3:
            reasons.append("Multiple URL redirects detected")
            score += 20

        if domain in SHORTENER_DOMAINS:
            reasons.append("URL uses known shortener service")
            score += 30
    except Exception:
        reasons.append("Could not safely resolve URL")
        score += 10

    if USE_HYBRID_FEEDS:
        if url.lower() in OPENPHISH_URLS:
            reasons.append("Matched OpenPhish feed")
            score += 80
        if url.lower() in URLHAUS_URLS:
            reasons.append("Matched URLHaus malware feed")
            score += 80

    return {"score": score, "reasons": reasons}


# =========================================================
# OPENAI DEEP SCAN
# =========================================================

def ai_deep_scan(content: str, scan_type: str):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {
            "risk_level": "SUSPICIOUS",
            "confidence": 50,
            "reasons": ["AI analysis unavailable (missing API key)"],
            "summary": "Heuristic scan completed without AI.",
            "recommended_action": "Proceed with caution."
        }

    client = OpenAI(api_key=api_key)

    prompt = f"""
You are a cybersecurity analyst for Indian users.

Analyze the following {scan_type} and return STRICT JSON.

Fields:
- risk_level: SAFE | SUSPICIOUS | DANGEROUS
- confidence: number 0-100
- reasons: list of strings
- summary: short explanation
- recommended_action: clear action

Content:
{content}
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Be factual. Do not exaggerate."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )

    raw = resp.choices[0].message.content
    start, end = raw.find("{"), raw.rfind("}") + 1
    return json.loads(raw[start:end])


# =========================================================
# MAIN ENTRY
# =========================================================

def analyze_input_full(content: str):
    scan_type = detect_scan_type(content)
    total_score = 0
    reasons = []

    if scan_type == "link":
        r = analyze_url(content)
        total_score += r["score"]
        reasons.extend(r["reasons"])
    else:
        t = analyze_text_message(content)
        total_score += t["score"]
        reasons.extend(t["reasons"])

        url = extract_url(content)
        if url:
            u = analyze_url(url)
            total_score += u["score"]
            reasons.extend(u["reasons"])

    if total_score < 30:
        return {
            "risk_level": "SAFE",
            "confidence": 85,
            "scan_type": scan_type,
            "reasons": reasons,
            "summary": "No strong scam indicators found.",
            "recommended_action": "No action needed. Stay alert."
        }

    ai = ai_deep_scan(content, scan_type)

    return {
        "risk_level": ai["risk_level"],
        "confidence": ai["confidence"],
        "scan_type": scan_type,
        "reasons": reasons + ai["reasons"],
        "summary": ai["summary"],
        "recommended_action": ai["recommended_action"]
    }
