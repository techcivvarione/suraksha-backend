from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def get_heatmap_points(
    db: Session,
    *,
    window: str,
    scope: str,
    state: str | None,
    country: str | None,
    lat: float | None,
    lng: float | None,
) -> list[dict]:
    rows = db.execute(
        text(
            '''
            SELECT
                latitude_center,
                longitude_center,
                report_count,
                city,
                state,
                country
            FROM attack_locations
            WHERE time_window = :window
              AND (:state IS NULL OR state = :state)
              AND (:country IS NULL OR country = :country)
            ORDER BY report_count DESC
            LIMIT 200
            '''
        ),
        {'window': window, 'state': state, 'country': country},
    ).mappings().all()
    if scope == 'nearby' and lat is not None and lng is not None:
        rows = [row for row in rows if abs(float(row['latitude_center']) - lat) <= 2 and abs(float(row['longitude_center']) - lng) <= 2]
    return [
        {
            'lat': float(row['latitude_center']),
            'lng': float(row['longitude_center']),
            'count': int(row['report_count'] or 0),
            'severity': _severity(int(row['report_count'] or 0)),
            'city': row['city'],
            'state': row['state'],
            'country': row['country'],
        }
        for row in rows
    ]


def _severity(count: int) -> str:
    if count >= 15:
        return 'high'
    if count >= 5:
        return 'medium'
    return 'low'
