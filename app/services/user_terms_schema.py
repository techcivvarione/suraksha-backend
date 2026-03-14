from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def ensure_user_terms_columns() -> None:
    logger.info("user_terms_schema_managed_by_migrations")
