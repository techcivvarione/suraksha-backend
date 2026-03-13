from __future__ import annotations

from urllib.parse import urlparse


def normalize_phone_number(phone_number: str | None) -> tuple[str | None, str | None]:
    if not phone_number:
        return None, None
    digits = ''.join(ch for ch in phone_number if ch.isdigit())
    if not digits:
        return None, None
    if digits.startswith('00'):
        digits = digits[2:]
    if len(digits) == 10:
        normalized = f'+91{digits}'
    elif digits.startswith('91') and len(digits) == 12:
        normalized = f'+{digits}'
    elif phone_number.strip().startswith('+'):
        normalized = f'+{digits}'
    else:
        normalized = f'+{digits}'
    display = normalized[:3] + ('*' * max(0, len(normalized) - 7)) + normalized[-4:]
    return normalized, display


def normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if '://' not in candidate:
        candidate = f'https://{candidate}'
    parsed = urlparse(candidate)
    domain = parsed.netloc.lower().strip()
    path = parsed.path.rstrip('/')
    if not domain:
        return None
    return f'{parsed.scheme.lower()}://{domain}{path}'


def normalize_domain(url: str | None) -> str | None:
    normalized = normalize_url(url)
    if not normalized:
        return None
    return urlparse(normalized).netloc.lower()


def normalize_payment_handle(payment_handle: str | None) -> str | None:
    if not payment_handle:
        return None
    return payment_handle.strip().lower().replace(' ', '')


def geohash_bucket(lat: float | None, lng: float | None, precision: int = 2) -> str | None:
    if lat is None or lng is None:
        return None
    return f'{round(lat, precision)}:{round(lng, precision)}'
