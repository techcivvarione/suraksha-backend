from __future__ import annotations

import hashlib
import io
import logging
import os
import random
import re
import tarfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import text

from app.db import SessionLocal

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
SPAMHAUS_LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
SPAMHAUS_DOWNLOAD_URL = "https://api.spamhaus.org/api/intel/v1/download/ext/{dataset}"
IP_GEO_URL = "https://ipinfo.io/{ip}/json"
MAX_EVENTS_PER_RUN = 200
MIN_EVENTS_PER_RUN = 10
REQUEST_TIMEOUT = 15
_BATCH_SIZE = 100
_DATASET_CONFIG = (("bcl", "botnet", 4), ("xbl", "malicious_infrastructure", 5))
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


@dataclass
class NormalizedThreatEvent:
    id: str
    latitude: float
    longitude: float
    category: str
    severity: int
    reports: int
    source: str
    created_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "category": self.category,
            "severity": self.severity,
            "reports": self.reports,
            "source": self.source,
            "created_at": self.created_at,
        }


def ingest_threat_events(*, max_events: int = MAX_EVENTS_PER_RUN) -> ThreatIngestionResult:
    max_events = max(1, min(max_events, MAX_EVENTS_PER_RUN))
    abuse_events = _fetch_abuseipdb_events(limit=min(100, max_events))
    spam_events = _fetch_spamhaus_events(limit=max_events - len(abuse_events))
    normalized = _dedupe_events(abuse_events + spam_events)

    fallback_events: list[NormalizedThreatEvent] = []
    if len(normalized) < MIN_EVENTS_PER_RUN:
        fallback_events = _build_fallback_events(MIN_EVENTS_PER_RUN - len(normalized))
        normalized.extend(fallback_events)

    normalized = normalized[:max_events]
    _cleanup_old_external_events()
    inserted = _upsert_events(normalized)
    return ThreatIngestionResult(inserted=inserted, abuseipdb_count=len(abuse_events), spamhaus_count=len(spam_events), fallback_count=len(fallback_events))


def _fetch_abuseipdb_events(*, limit: int) -> list[NormalizedThreatEvent]:
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

    events: list[NormalizedThreatEvent] = []
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
                identity=ip_address,
            )
        )
    return events


def _fetch_spamhaus_events(*, limit: int) -> list[NormalizedThreatEvent]:
    if limit <= 0:
        return []
    headers = _get_spamhaus_headers()
    if not headers:
        return []

    events: list[NormalizedThreatEvent] = []
    for dataset, category, severity in _DATASET_CONFIG:
        if len(events) >= limit:
            break
        try:
            response = requests.get(SPAMHAUS_DOWNLOAD_URL.format(dataset=dataset), headers=headers, timeout=REQUEST_TIMEOUT)
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
                    identity=f"{dataset}:{ip_address}",
                )
            )
    return events


def _get_spamhaus_headers() -> dict[str, str] | None:
    username = os.getenv("SPAMHAUS_USERNAME")
    password = os.getenv("SPAMHAUS_PASSWORD")
    if username and password:
        try:
            response = requests.post(SPAMHAUS_LOGIN_URL, json={"username": username, "password": password, "realm": "intel"}, timeout=REQUEST_TIMEOUT)
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
            return _IP_PATTERN.findall("\n".join(text_blobs))
    except tarfile.TarError:
        return _IP_PATTERN.findall(content.decode("utf-8", errors="ignore"))


def _resolve_ip(ip_address: str, *, country_code: str | None = None) -> tuple[float, float] | None:
    if ip_address in _GEO_CACHE:
        return _GEO_CACHE[ip_address]

    coords: tuple[float, float] | None = None
    try:
        response = requests.get(IP_GEO_URL.format(ip=ip_address), timeout=5)
        response.raise_for_status()
        payload = response.json()
        loc = payload.get("loc")
        if isinstance(loc, str) and "," in loc:
            lat_str, lon_str = loc.split(",", 1)
            coords = (float(lat_str), float(lon_str))
        country_code = payload.get("country") or country_code
    except Exception:
        logger.warning("threat_geo_lookup_failed", extra={"provider": "ipinfo"}, exc_info=True)

    if coords is None and country_code:
        coords = _COUNTRY_CENTROIDS.get(str(country_code).upper())

    _GEO_CACHE[ip_address] = coords
    return coords


def _normalize_event(*, latitude: float, longitude: float, category: str, severity: int, reports: int, source: str, identity: str) -> NormalizedThreatEvent:
    rounded_lat = round(float(latitude), 4)
    rounded_lng = round(float(longitude), 4)
    digest = hashlib.sha256(f"{source}|{identity}|{category}|{rounded_lat}|{rounded_lng}".encode("utf-8")).hexdigest()
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, digest))
    return NormalizedThreatEvent(
        id=event_id,
        latitude=rounded_lat,
        longitude=rounded_lng,
        category=category,
        severity=max(1, min(int(severity), 5)),
        reports=max(1, int(reports)),
        source=source,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _upsert_events(events: list[NormalizedThreatEvent]) -> int:
    if not events:
        return 0
    db = SessionLocal()
    try:
        inserted = 0
        statement = text(
            """
            INSERT INTO scam_events (id, latitude, longitude, category, severity, reports, source, created_at)
            VALUES (CAST(:id AS uuid), :latitude, :longitude, :category, :severity, :reports, :source, :created_at)
            ON CONFLICT (id) DO UPDATE SET
                severity = EXCLUDED.severity,
                reports = EXCLUDED.reports,
                created_at = EXCLUDED.created_at
            """
        )
        for index in range(0, len(events), _BATCH_SIZE):
            batch = [event.as_dict() for event in events[index:index + _BATCH_SIZE]]
            db.execute(statement, batch)
            inserted += len(batch)
        db.commit()
        return inserted
    finally:
        db.close()


def _cleanup_old_external_events() -> None:
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM scam_events WHERE created_at < now() - interval '24 hours'"))
        db.commit()
    finally:
        db.close()


def _build_fallback_events(missing_count: int) -> list[NormalizedThreatEvent]:
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

    fallback_events: list[NormalizedThreatEvent] = []
    randomizer = random.Random(42)
    while len(fallback_events) < missing_count:
        base = rows[len(fallback_events) % len(rows)]
        fallback_events.append(
            _normalize_event(
                latitude=float(base["latitude"]) + randomizer.uniform(-0.15, 0.15),
                longitude=float(base["longitude"]) + randomizer.uniform(-0.15, 0.15),
                category=str(base.get("category") or "malicious_infrastructure"),
                severity=2,
                reports=int(base.get("reports") or 1),
                source="fallback",
                identity=f"fallback:{len(fallback_events)}:{base['latitude']}:{base['longitude']}",
            )
        )
    return fallback_events


def _dedupe_events(events: list[NormalizedThreatEvent]) -> list[NormalizedThreatEvent]:
    deduped: list[NormalizedThreatEvent] = []
    seen: set[str] = set()
    for event in events:
        if event.id in seen:
            continue
        seen.add(event.id)
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
