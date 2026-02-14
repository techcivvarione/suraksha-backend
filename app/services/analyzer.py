from urllib.parse import urlparse
from datetime import datetime, timezone
import re
import whois
import requests
from pathlib import Path
import os
import json
from openai import OpenAI

from app.services.breach.manager import get_breach_provider

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
# BREACH CATEGORY INTELLIGENCE (NEW - ADDED)
# =========================================================

BREACH_CATEGORY_MAP = {
    "Instagram": "Social Media",
    "Facebook": "Social Media",
    "Twitter": "Social Media",
    "LinkedIn": "Professional",
    "Yahoo": "Email Services",
    "Gmail": "Email Services",
    "Adobe": "Tech Platforms",
    "Dropbox": "Cloud Services",
    "PayPal": "Finance",
    "WhatsApp": "Social Media",
    "Snapchat": "Social Media",
    "Telegram": "Social Media",
    "Amazon": "E-commerce",
    "Flipkart": "E-commerce",
}

def calculate_category_severity(count: int) -> str:
    if count >= 5:
        return "high"
    if count >= 2:
        return "medium"
    return "low"

def build_breach_analysis(sites: list[str]) -> dict:
    categories = {}

    for site in sites:
        category = BREACH_CATEGORY_MAP.get(site, "Other")

        if category not in categories:
            categories[category] = {
                "count": 0,
                "sites": []
            }

        categories[category]["count"] += 1
        categories[category]["sites"].append(site)

    highest_category = None
    highest_count = 0

    for category, data in categories.items():
        data["severity"] = calculate_category_severity(data["count"])

        if data["count"] > highest_count:
            highest_count = data["count"]
            highest_category = category

    return {
        "total_breaches": len(sites),
        "highest_risk_category": highest_category,
        "categories": categories
    }

# =========================================================
# STATIC DATA
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
# FEEDS
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
# THREAT ANALYSIS
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
# AI SCAN
# =========================================================

def ai_deep_scan(content: str):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {
            "risk_level": "SUSPICIOUS",
            "confidence": 50,
            "reasons": ["AI analysis unavailable"],
        }

    client = OpenAI(api_key=api_key)

    prompt = f"""
Analyze the following content and return STRICT JSON.

Fields:
- risk_level: SAFE | SUSPICIOUS | DANGEROUS
- confidence: number 0-100
- reasons: list of strings

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

def analyze_input_full(scan_type: str, content: str, user_plan: str):
    scan_type = scan_type.upper()
    is_paid = user_plan.upper() == "PAID"

    # ===================== THREAT =====================
    if scan_type == "THREAT":
        total_score = 0
        reasons = []

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
                "risk": "low",
                "score": 85,
                "reasons": ["No strong scam indicators found"]
            }

        ai = ai_deep_scan(content)

        return {
            "risk": ai["risk_level"].lower(),
            "score": ai["confidence"],
            "reasons": reasons + ai["reasons"]
        }

    # ===================== EMAIL =====================
    if scan_type == "EMAIL":
        provider = get_breach_provider(user_plan)
        raw = provider.check_email(content)

        response = {
            "risk": raw["risk"],
            "score": raw["score"],
            "count": raw.get("count", 0),
            "reasons": raw["reasons"]
        }

        if is_paid:
            sites = raw.get("sites", [])
            response["sites"] = sites
            response["domains"] = raw.get("domains", [])
            response["breach_analysis"] = build_breach_analysis(sites)
        else:
            response["upgrade"] = {
                "required": True,
                "message": "Upgrade to see breach category breakdown and exposure analytics",
            }

        return response

    # ===================== PASSWORD =====================
    if scan_type == "PASSWORD":
        provider = get_breach_provider(user_plan)
        raw = provider.check_password(content)

        response = {
            "risk": raw["risk"],
            "score": raw["score"],
            "count": raw.get("count", 0),
            "reasons": raw["reasons"]
        }

        if not is_paid:
            response["upgrade"] = {
                "required": True,
                "message": "Upgrade to see password breach details",
            }

        return response

    raise ValueError("Invalid scan type")
