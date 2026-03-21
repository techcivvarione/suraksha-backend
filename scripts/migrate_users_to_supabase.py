#!/usr/bin/env python3
"""
One-time migration: creates Supabase auth.users entries for every existing
backend user and stores the resulting Supabase UUID in users.supabase_user_id.

Safe to run multiple times — users that already have a supabase_user_id are
skipped instantly (no network call made).

Usage
-----
    cd gosuraksha-backend
    python -m scripts.migrate_users_to_supabase

    # or directly:
    python scripts/migrate_users_to_supabase.py

Environment
-----------
Requires the same .env as the main application (DATABASE_URL, SUPABASE_URL,
SUPABASE_SERVICE_ROLE_KEY).
"""
from __future__ import annotations

import logging
import os
import sys
import time

# Ensure the project root is importable when run as a standalone script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from app.db import SessionLocal
from app.models.user import User
from app.services.supabase_sync import ensure_supabase_user

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

BATCH_SIZE = 50
# Pause between batches to avoid hammering the Supabase Admin API rate limits
BATCH_SLEEP_SECONDS = 0.5


def run() -> None:
    db = SessionLocal()
    try:
        total: int = db.query(User).count()
        logger.info("migrate_users_to_supabase.start  total_users=%d", total)

        already_synced = 0
        newly_synced = 0
        failed = 0
        offset = 0

        while True:
            batch: list[User] = (
                db.query(User)
                .order_by(User.created_at)
                .offset(offset)
                .limit(BATCH_SIZE)
                .all()
            )
            if not batch:
                break

            for user in batch:
                had_id = bool(getattr(user, "supabase_user_id", None))

                if had_id:
                    already_synced += 1
                    continue

                try:
                    ensure_supabase_user(db, user)
                    db.refresh(user)

                    if getattr(user, "supabase_user_id", None):
                        newly_synced += 1
                        logger.info(
                            "synced  backend_id=%s  supabase_id=%s  email=%s  phone=%s",
                            user.id,
                            user.supabase_user_id,
                            # Mask email — log domain only
                            (user.email or "").split("@")[-1] or "—",
                            ("*" + (user.phone or "")[-4:]) if user.phone else "—",
                        )
                    else:
                        failed += 1
                        logger.warning(
                            "failed  backend_id=%s  email_domain=%s  has_phone=%s",
                            user.id,
                            (user.email or "").split("@")[-1] or "—",
                            bool(user.phone),
                        )

                except Exception:
                    failed += 1
                    logger.exception("unexpected_error  backend_id=%s", user.id)

            offset += BATCH_SIZE
            processed = min(offset, total)
            logger.info(
                "progress  %d/%d  already_synced=%d  newly_synced=%d  failed=%d",
                processed,
                total,
                already_synced,
                newly_synced,
                failed,
            )

            if offset < total:
                time.sleep(BATCH_SLEEP_SECONDS)

        logger.info(
            "migrate_users_to_supabase.done  "
            "total=%d  already_synced=%d  newly_synced=%d  failed=%d",
            total,
            already_synced,
            newly_synced,
            failed,
        )

        if failed:
            logger.warning(
                "%d user(s) could not be synced — check logs above for details. "
                "Re-run this script after fixing any Supabase issues; it is idempotent.",
                failed,
            )
            sys.exit(1)

    finally:
        db.close()


if __name__ == "__main__":
    run()
