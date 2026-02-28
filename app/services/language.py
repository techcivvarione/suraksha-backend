from __future__ import annotations

from typing import Any

ALLOWED_LANGUAGES = {"en", "hi", "te"}


def normalize_language(value: str | None, supported: set[str] | None = None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if supported is not None and normalized not in supported:
        return None
    return normalized


def parse_accept_language(header_value: str | None, supported: set[str] | None = None) -> str | None:
    if not header_value:
        return None
    for chunk in header_value.split(","):
        token = chunk.split(";", 1)[0].strip().lower()
        if not token:
            continue
        base = token.split("-", 1)[0]
        chosen = normalize_language(base, supported=supported)
        if chosen:
            return chosen
    return None


def resolve_language_value(
    query_lang: str | None = None,
    user: Any | None = None,
    accept_language: str | None = None,
    fallback: str = "en",
    supported: set[str] | None = None,
) -> str:
    chosen = normalize_language(query_lang, supported=supported)
    if chosen:
        return chosen

    chosen = normalize_language(getattr(user, "preferred_language", None) if user is not None else None, supported=supported)
    if chosen:
        return chosen

    chosen = parse_accept_language(accept_language, supported=supported)
    if chosen:
        return chosen

    fallback_norm = normalize_language(fallback, supported=supported)
    return fallback_norm or "en"
