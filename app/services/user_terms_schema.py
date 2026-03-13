import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import engine

logger = logging.getLogger(__name__)


def ensure_user_terms_columns() -> None:
    statements = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS accepted_terms BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS accepted_terms_at TIMESTAMP NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_version TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_version TEXT",
        "UPDATE users SET accepted_terms = FALSE WHERE accepted_terms IS NULL",
        "UPDATE users SET terms_version = 'v1' WHERE terms_version IS NULL",
        "UPDATE users SET privacy_version = 'v1' WHERE privacy_version IS NULL",
        "ALTER TABLE users ALTER COLUMN accepted_terms SET DEFAULT FALSE",
    ]
    try:
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
    except SQLAlchemyError:
        logger.exception("user_terms_schema_ensure_failed")
