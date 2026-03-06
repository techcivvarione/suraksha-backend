import ipaddress
import re
import unicodedata
import urllib.parse
from typing import List, Tuple

from app.services.qr_classifier import SHORTENER_HOSTS

UPI_REGEX = re.compile(r"^[A-Za-z0-9.\-_]{3,256}@[A-Za-z0-9.\-]{2,64}$")
SUSPICIOUS_KEYWORDS = {
    "refund",
    "support",
    "cashback",
    "bonus",
    "reward",
    "gift",
    "lucky",
    "loan",
    "free",
    "kyc",
    "update",
    "verify",
    "urgent",
}

ALLOWED_PSP = {
    "oksbi",
    "okaxis",
    "okhdfcbank",
    "okicici",
    "ybl",
    "ibl",
    "axl",
    "hdfcbank",
    "paytm",
    "upi",
    "apl",
    "airtel",
}

NEW_TLDS = {
    "zip",
    "mov",
    "xyz",
    "click",
    "top",
    "online",
    "shop",
}


# SECURE QR START
def validate_upi(uri: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query)
    vpa = (params.get("pa") or [""])[0].strip()

    if not vpa:
        reasons.append("VPA missing")
        return False, reasons

    if not UPI_REGEX.fullmatch(vpa):
        reasons.append("Invalid VPA format")

    if len(vpa) > 256:
        reasons.append("VPA too long")

    handle = vpa.split("@")[-1].lower()
    if handle not in ALLOWED_PSP:
        reasons.append("Unrecognized PSP handle")

    if contains_zero_width(vpa):
        reasons.append("Zero-width character detected")

    if is_mixed_script(vpa):
        reasons.append("Mixed-script VPA")

    lower_vpa = vpa.lower()
    if any(keyword in lower_vpa for keyword in SUSPICIOUS_KEYWORDS):
        reasons.append("Suspicious keyword in VPA")

    return len(reasons) == 0, reasons


def validate_url(url: str) -> Tuple[bool, List[str], dict]:
    reasons: List[str] = []
    meta = {
        "is_shortener": False,
        "is_ip_host": False,
        "homograph": False,
        "domain_age_risk": False,
    }

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        reasons.append("Unsupported scheme")
        return False, reasons, meta

    host = parsed.hostname or ""
    if not host:
        reasons.append("Host missing")
        return False, reasons, meta

    try:
        ipaddress.ip_address(host)
        meta["is_ip_host"] = True
        reasons.append("IP address host")
    except ValueError:
        pass

    try:
        puny = host.encode("idna").decode("ascii")
        if host != puny and "xn--" in puny:
            meta["homograph"] = True
            reasons.append("IDN homograph risk")
        host_ascii = puny
    except Exception:
        host_ascii = host
        reasons.append("Invalid IDN encoding")

    tld = host_ascii.rsplit(".", 1)[-1].lower() if "." in host_ascii else ""
    if tld in NEW_TLDS:
        meta["domain_age_risk"] = True
        reasons.append("New/low-trust TLD")

    if host_ascii.lower() in SHORTENER_HOSTS:
        meta["is_shortener"] = True
        reasons.append("URL shortener detected")

    path = (parsed.path or "").lower()
    if any(p in path for p in ("/login", "/verify", "/update", "/bank", "/secure", "/support")):
        reasons.append("Phishing path pattern")

    return len(reasons) == 0, reasons, meta


def contains_zero_width(text: str) -> bool:
    return any(ch in text for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"))


def is_mixed_script(text: str) -> bool:
    scripts = set()
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if not name:
            continue
        script = name.split(" ")[0]
        scripts.add(script)
    return len(scripts) > 1
# SECURE QR END
