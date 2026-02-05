from urllib.parse import urlparse
from datetime import datetime, timezone
import re
import whois
import requests
from pathlib import Path

# =========================================================
# CONFIG
# =========================================================

NEW_DOMAIN_DAYS_THRESHOLD = 90

USE_HYBRID_FEEDS = True   # 🔁 set False if you want PURE offline only

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
    "bopsecrets.org",
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
# HYBRID FEED LOADERS (LOCAL FILES)
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
# CORE URL ANALYSIS (OFFLINE + HYBRID)
# =========================================================

def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return {
            "score": 60,
            "reasons": ["Malformed or invalid URL"]
        }

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # ---- HTTPS ----
    if parsed.scheme != "https":
        reasons.append("URL is not using HTTPS")
        score += 20

    # ---- Domain age ----
    age_days = get_domain_age_days(domain)
    if age_days is not None and age_days < NEW_DOMAIN_DAYS_THRESHOLD:
        reasons.append(f"Domain registered {age_days} days ago")
        score += 30

    # ---- Known abuse hosts ----
    if domain in ABUSE_HOSTS:
        reasons.append("Domain frequently abused to host malicious content")
        score += 40

    # ---- Suspicious path ----
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path:
            reasons.append(f"Suspicious URL path contains '{kw}'")
            score += 15

    # ---- Redirects / shorteners ----
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        redirect_count = len(response.history)

        if redirect_count >= 3:
            reasons.append(f"URL redirects {redirect_count} times")
            score += 20

        if domain in SHORTENER_DOMAINS:
            reasons.append("URL uses a known shortener service")
            score += 30
    except Exception:
        reasons.append("Could not safely resolve URL")
        score += 10

    # ---- HYBRID FEEDS ----
    if USE_HYBRID_FEEDS:
        if url.lower() in OPENPHISH_URLS:
            reasons.append("Matched OpenPhish feed")
            score += 80

        if url.lower() in URLHAUS_URLS:
            reasons.append("Matched URLhaus malware feed")
            score += 80

    return {"score": score, "reasons": reasons}
