from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.db import Base, SessionLocal, engine
from app.models.scam import Scam

SCAMS_JSON_PATH = ROOT_DIR / "scripts" / "scams.json"
REQUIRED_FIELDS = (
    "id",
    "title_en",
    "title_hi",
    "title_te",
    "description_en",
    "description_hi",
    "description_te",
    "category",
    "read_time",
    "content_en",
    "content_hi",
    "content_te",
)


def _load_scams(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("scripts/scams.json must contain a JSON array")
    return payload


def _validate_record(record: dict, index: int) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise ValueError(f"Record at index {index} missing required fields: {', '.join(missing)}")
    if not str(record.get("id") or "").strip():
        raise ValueError(f"Record at index {index} has empty id")


def seed_scams() -> None:
    if not SCAMS_JSON_PATH.exists():
        raise FileNotFoundError(f"Missing seed file: {SCAMS_JSON_PATH}")

    Base.metadata.create_all(bind=engine, tables=[Scam.__table__])

    records = _load_scams(SCAMS_JSON_PATH)
    inserted = 0
    updated = 0
    errors: list[str] = []

    db = SessionLocal()
    try:
        for index, record in enumerate(records):
            try:
                _validate_record(record, index)
                scam_id = str(record["id"]).strip()
                existing = db.query(Scam).filter(Scam.id == scam_id).first()
                payload = {
                    "id": scam_id,
                    "title_en": record["title_en"],
                    "title_hi": record["title_hi"],
                    "title_te": record["title_te"],
                    "description_en": record["description_en"],
                    "description_hi": record["description_hi"],
                    "description_te": record["description_te"],
                    "category": record["category"],
                    "risk_level": record.get("risk_level"),
                    "read_time": int(record["read_time"]),
                    "content_en": record["content_en"],
                    "content_hi": record["content_hi"],
                    "content_te": record["content_te"],
                    "related": record.get("related"),
                    "quick_tips": record.get("quick_tips"),
                }
                if existing is None:
                    db.add(Scam(**payload))
                    inserted += 1
                else:
                    for key, value in payload.items():
                        setattr(existing, key, value)
                    updated += 1
                db.commit()
            except Exception as exc:
                db.rollback()
                errors.append(f"index={index} id={record.get('id')!r}: {exc}")
                continue
    finally:
        db.close()

    print(f"Total records processed: {len(records)}")
    print(f"Inserted: {inserted}")
    print(f"Updated: {updated}")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Errors: 0")
    print("Seeding completed successfully")


if __name__ == "__main__":
    seed_scams()
