import re
import urllib.parse
from enum import Enum
from typing import Dict, Tuple


class QrType(str, Enum):
    UPI = "UPI"
    URL = "URL"
    TEL = "TEL"
    SMS = "SMS"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
}


SHORTENER_HOSTS = {
    "bit.ly",
    "goo.gl",
    "t.co",
    "tinyurl.com",
    "cutt.ly",
    "ow.ly",
    "is.gd",
    "v.gd",
    "buff.ly",
    "rebrand.ly",
}


# SECURE QR START
def classify_payload(payload: str) -> Tuple[QrType, Dict]:
    """
    Classify normalized payload into deterministic type and return metadata.
    """
    lower = payload.lower()

    if lower.startswith("upi://"):
        return QrType.UPI, {"uri": payload}

    parsed = urllib.parse.urlparse(payload)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        canonical = canonicalize_url(parsed)
        return QrType.URL, canonical

    if lower.startswith("tel:"):
        return QrType.TEL, {"value": payload[4:]}

    if lower.startswith(("sms:", "smsto:", "mmsto:")):
        return QrType.SMS, {"value": payload.split(":", 1)[1]}

    # plain text if printable and not empty
    if payload:
        return QrType.TEXT, {"value": payload}

    return QrType.UNKNOWN, {}


def canonicalize_url(parsed: urllib.parse.ParseResult) -> Dict:
    """
    Build canonical URL components and strip tracking params for hashing.
    """
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(k, v) for k, v in query if k.lower() not in TRACKING_PARAMS]
    query_str = urllib.parse.urlencode(filtered, doseq=True)
    canon = parsed._replace(query=query_str, fragment="")
    url = urllib.parse.urlunparse(canon)
    return {
        "url": url,
        "host": parsed.hostname or "",
        "path": parsed.path or "/",
        "scheme": parsed.scheme,
        "is_shortener": (parsed.hostname or "").lower() in SHORTENER_HOSTS,
    }
# SECURE QR END
