from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session


def update_scan_reputation(db: Session, hash_value: str, hash_type: str) -> Tuple[int, int, bool]:
    """
    Upsert reputation row, increment scan_count, return (scan_count, report_count, is_flagged).
    """
    now = datetime.now(timezone.utc)
    db.execute(
        text(
            """
            INSERT INTO scan_reputation (hash_value, hash_type, first_seen, last_seen, scan_count, report_count, is_flagged, created_at, updated_at)
            VALUES (:hv, :ht, :now, :now, 1, 0, false, :now, :now)
            ON CONFLICT (hash_value, hash_type)
            DO UPDATE SET
                scan_count = scan_reputation.scan_count + 1,
                last_seen = :now,
                updated_at = :now
            """
        ),
        {"hv": hash_value, "ht": hash_type, "now": now},
    )
    row = db.execute(
        text(
            """
            SELECT scan_count, report_count, is_flagged
            FROM scan_reputation
            WHERE hash_value = :hv AND hash_type = :ht
            """
        ),
        {"hv": hash_value, "ht": hash_type},
    ).mappings().first()
    db.commit()
    return int(row["scan_count"]), int(row["report_count"]), bool(row["is_flagged"])


def record_scan_report(db: Session, user_id: str, hash_value: str, hash_type: str, reason: str | None = None) -> Tuple[int, int, bool]:
    now = datetime.now(timezone.utc)
    db.execute(
        text(
            """
            INSERT INTO scan_reports (user_id, hash_value, hash_type, reason, created_at)
            VALUES (CAST(:uid AS uuid), :hv, :ht, :reason, :now)
            """
        ),
        {"uid": user_id, "hv": hash_value, "ht": hash_type, "reason": reason, "now": now},
    )
    db.execute(
        text(
            """
            INSERT INTO scan_reputation (hash_value, hash_type, first_seen, last_seen, scan_count, report_count, is_flagged, created_at, updated_at)
            VALUES (:hv, :ht, :now, :now, 0, 1, false, :now, :now)
            ON CONFLICT (hash_value, hash_type)
            DO UPDATE SET
                report_count = scan_reputation.report_count + 1,
                last_seen = :now,
                updated_at = :now,
                is_flagged = CASE WHEN scan_reputation.report_count + 1 >= 5 THEN true ELSE scan_reputation.is_flagged END
            """
        ),
        {"hv": hash_value, "ht": hash_type, "now": now},
    )
    row = db.execute(
        text(
            """
            SELECT scan_count, report_count, is_flagged
            FROM scan_reputation
            WHERE hash_value = :hv AND hash_type = :ht
            """
        ),
        {"hv": hash_value, "ht": hash_type},
    ).mappings().first()
    db.commit()
    return int(row["scan_count"]), int(row["report_count"]), bool(row["is_flagged"])
