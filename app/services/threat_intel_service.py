from __future__ import annotations

import io
import logging
import os
import random
import re
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import text

from app.db import SessionLocal
from app.services.supabase_client import get_supabase

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
SPAMHAUS_LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
SPAMHAUS_DOWNLOAD_URL = "https://api.spamhaus.org/api/intel/v1/download/ext/{dataset}"
IP_GEO_URL = "http://ip-api.com/json/{ip}"
MAX_EVENTS_PER_RUN = 200
MIN_EVENTS_PER_RUN = 10
REQUEST_TIMEOUT = 15
_BATCH_SIZE = 100
_DATASET_CONFIG = (
    ("bcl", "botnet", 4),
    ("xbl", "malicious_infrastructure", 5),
)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GEO_CACHE: dict[str, tuple[float, float] | None] = {}
_COUNTRY_CENTROIDS = {
    "US": (37.0902, -95.7129),
    "IN": (20.5937, 78.9629),
    "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515),
    "FR": (46.2276, 2.2137),
    "BR": (-14.2350, -51.9253),
    "RU": (61.5240, 105.3188),
    "CN": (35.8617, 104.1954),
    "JP": (36.2048, 138.2529),
    "SG": (1.3521, 103.8198),
    "AU": (-25.2744, 133.7751),
    "CA": (56.1304, -106.3468),
    "NL": (52.1326, 5.2913),
}


@dataclass
class ThreatIngestionResult:
    inserted: int
    abuseipdb_count: int
    spamhaus_count: int
    fallback_count: int


def ingest_threat_events(*, max_events: int = MAX_EVENTS_PER_RUN) -> ThreatIngestionResult:
    max_events = max(1, min(max_events, MAX_EVENTS_PER_RUN))
    abuse_events = _fetch_abuseipdb_events(limit=min(100, max_events))
    spam_events = _fetch_spamhaus_events(limit=max_events - len(abuse_events))

    normalized = _dedupe_events(abuse_events + spam_events)
    fallback_events: list[dict[str, Any]] = []
    if len(normalized) < MIN_EVENTS_PER_RUN:
        fallback_events = _build_fallback_events(MIN_EVENTS_PER_RUN - len(normalized))
        normalized.extend(fallback_events)

    normalized = normalized[:max_events]
    _cleanup_old_external_events()
    inserted = _insert_events(normalized)
    return ThreatIngestionResult(
        inserted=inserted,
        abuseipdb_count=len(abuse_events),
        spamhaus_count=len(spam_events),
        fallback_count=len(fallback_events),
    )


def _fetch_abuseipdb_events(*, limit: int) -> list[dict[str, Any]]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or limit <= 0:
        return []

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"confidenceMinimum": 75, "limit": min(limit, 100)},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:
        logger.exception("abuseipdb_fetch_failed")
        return []

    events: list[dict[str, Any]] = []
    for item in payload.get("data", [])[:limit]:
        ip_address = item.get("ipAddress")
        if not ip_address:
            continue
        coords = _resolve_ip(ip_address, country_code=item.get("countryCode"))
        if not coords:
            continue
        events.append(
            _normalize_event(
                latitude=coords[0],
                longitude=coords[1],
                category="botnet",
                severity=_scale_abuse_confidence(item.get("abuseConfidenceScore")),
                reports=int(item.get("abuseConfidenceScore") or 1),
                source="abuseipdb",
            )
        )
    return events


def _fetch_spamhaus_events(*, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    headers = _get_spamhaus_headers()
    if not headers:
        return []

    events: list[dict[str, Any]] = []
    for dataset, category, severity in _DATASET_CONFIG:
        if len(events) >= limit:
            break
        try:
            response = requests.get(
                SPAMHAUS_DOWNLOAD_URL.format(dataset=dataset),
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except Exception:
            logger.exception("spamhaus_fetch_failed dataset=%s", dataset)
            continue

        for ip_address in _extract_ip_addresses(response.content):
            if len(events) >= limit:
                break
            coords = _resolve_ip(ip_address)
            if not coords:
                continue
            events.append(
                _normalize_event(
                    latitude=coords[0],
                    longitude=coords[1],
                    category=category,
                    severity=severity,
                    reports=1,
                    source="spamhaus",
                )
            )
    return events


def _get_spamhaus_headers() -> dict[str, str] | None:
    username = os.getenv("SPAMHAUS_USERNAME")
    password = os.getenv("SPAMHAUS_PASSWORD")
    if username and password:
        try:
            response = requests.post(
                SPAMHAUS_LOGIN_URL,
                json={"username": username, "password": password, "realm": "intel"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
            token = payload.get("token") or payload.get("jwt")
            if token:
                return {"Authorization": f"Bearer {token}"}
        except Exception:
            logger.exception("spamhaus_login_failed")
            return None

    api_key = os.getenv("SPAMHAUS_API_KEY")
    if not api_key:
        return None
    return {"Authorization": f"Bearer {api_key}"}


def _extract_ip_addresses(content: bytes) -> list[str]:
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            text_blobs: list[str] = []
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                text_blobs.append(extracted.read().decode("utf-8", errors="ignore"))
            matches = _IP_PATTERN.findall("\n".join(text_blobs))
            return matches
    except tarfile.TarError:
        decoded = content.decode("utf-8", errors="ignore")
        return _IP_PATTERN.findall(decoded)


def _resolve_ip(ip_address: str, *, country_code: str | None = None) -> tuple[float, float] | None:
    if ip_address in _GEO_CACHE:
        return _GEO_CACHE[ip_address]

    coords: tuple[float, float] | None = None
    try:
        response = requests.get(
            IP_GEO_URL.format(ip=ip_address),
            params={"fields": "status,lat,lon,countryCode"},
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") == "success" and payload.get("lat") is not None and payload.get("lon") is not None:
            coords = (float(payload["lat"]), float(payload["lon"]))
            country_code = payload.get("countryCode") or country_code
    except Exception:
        logger.warning("threat_geo_lookup_failed ip=%s", ip_address, exc_info=True)

    if coords is None and country_code:
        centroid = _COUNTRY_CENTROIDS.get(str(country_code).upper())
        if centroid:
            coords = centroid

    _GEO_CACHE[ip_address] = coords
    return coords


def _normalize_event(*, latitude: float, longitude: float, category: str, severity: int, reports: int, source: str) -> dict[str, Any]:
    return {
        "latitude": round(float(latitude), 4),
        "longitude": round(float(longitude), 4),
        "category": category,
        "severity": max(1, min(int(severity), 5)),
        "reports": max(1, int(reports)),
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _insert_events(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    supabase = get_supabase()
    inserted = 0
    for index in range(0, len(events), _BATCH_SIZE):
        batch = events[index:index + _BATCH_SIZE]
        try:
            supabase.table("scam_events").insert(batch).execute()
            inserted += len(batch)
        except Exception:
            logger.exception("threat_events_insert_failed batch_start=%s", index)
    return inserted


def _cleanup_old_external_events() -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    try:
        get_supabase().table("scam_events").delete().lt("created_at", cutoff).execute()
    except Exception:
        logger.warning("threat_events_cleanup_failed", exc_info=True)


def _build_fallback_events(missing_count: int) -> list[dict[str, Any]]:
    if missing_count <= 0:
        return []
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT latitude, longitude, category, COUNT(*) AS reports
                FROM scam_reports
                WHERE latitude IS NOT NULL
                  AND longitude IS NOT NULL
                  AND created_at >= now() - interval '30 days'
                GROUP BY latitude, longitude, category
                ORDER BY reports DESC, latitude, longitude
                LIMIT 20
                """
            )
        ).mappings().all()
    finally:
        db.close()

    if not rows:
        rows = [
            {"latitude": 20.5937, "longitude": 78.9629, "category": "botnet", "reports": 1},
            {"latitude": 28.6139, "longitude": 77.2090, "category": "spam_network", "reports": 1},
            {"latitude": 19.0760, "longitude": 72.8777, "category": "malicious_infrastructure", "reports": 1},
        ]

    fallback_events: list[dict[str, Any]] = []
    randomizer = random.Random(42)
    while len(fallback_events) < missing_count:
        base = rows[len(fallback_events) % len(rows)]
        jitter_lat = randomizer.uniform(-0.15, 0.15)
        jitter_lng = randomizer.uniform(-0.15, 0.15)
        fallback_events.append(
            _normalize_event(
                latitude=float(base["latitude"]) + jitter_lat,
                longitude=float(base["longitude"]) + jitter_lng,
                category=str(base.get("category") or "malicious_infrastructure"),
                severity=2,
                reports=int(base.get("reports") or 1),
                source="fallback",
            )
        )
    return fallback_events


def _dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for event in events:
        key = (
            event["latitude"],
            event["longitude"],
            event["category"],
            event["source"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _scale_abuse_confidence(score: Any) -> int:
    try:
        value = int(score or 0)
    except (TypeError, ValueError):
        return 1
    if value >= 90:
        return 5
    if value >= 80:
        return 4
    if value >= 70:
        return 3
    if value >= 50:
        return 2
    return 1

