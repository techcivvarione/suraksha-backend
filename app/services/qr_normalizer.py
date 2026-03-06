import re
import unicodedata

ZERO_WIDTH_PATTERN = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff]", flags=re.UNICODE
)

CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# SECURE QR START
def normalize_payload(raw: str) -> str:
    """
    Normalize QR payload safely.
    - Ensure text (raises UnicodeError if not UTF-8 decodable)
    - Unicode NFKC
    - Strip zero-width chars
    - Remove control chars (except tab/newline)
    - Trim whitespace
    """
    if raw is None:
        raise ValueError("Payload missing")

    # force str
    if not isinstance(raw, str):
        raise ValueError("Payload must be text")

    # normalize unicode
    normalized = unicodedata.normalize("NFKC", raw)
    normalized = ZERO_WIDTH_PATTERN.sub("", normalized)
    normalized = CONTROL_PATTERN.sub("", normalized)
    normalized = normalized.strip()

    if not normalized:
        raise ValueError("Payload empty after normalization")

    if len(normalized) > 512:
        raise ValueError("Payload exceeds maximum length")

    return normalized
# SECURE QR END
