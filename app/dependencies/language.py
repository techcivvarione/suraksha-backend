from __future__ import annotations

from fastapi import Depends, Query, Request

from app.models.user import User
from app.routes.auth import get_current_user_optional
from app.services.language import ALLOWED_LANGUAGES, resolve_language_value


def resolve_language(
    request: Request,
    lang: str | None = Query(None),
    current_user: User | None = Depends(get_current_user_optional),
) -> str:
    return resolve_language_value(
        query_lang=lang,
        user=current_user,
        accept_language=request.headers.get("accept-language"),
        fallback="en",
        supported=ALLOWED_LANGUAGES,
    )
