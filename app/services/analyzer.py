from urllib.parse import urlparse

def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)

    # Invalid URL
    if not parsed.scheme or not parsed.netloc:
        reasons.append("Invalid or malformed URL")
        score += 50
        return {
            "score": score,
            "reasons": reasons
        }

    # HTTPS check
    if parsed.scheme != "https":
        reasons.append("URL is not using HTTPS")
        score += 20

    return {
        "score": score,
        "reasons": reasons
    }
