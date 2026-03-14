from __future__ import annotations

from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


DOCS_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
STRICT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
DOCS_PATH_PREFIXES = ("/docs", "/openapi.json", "/redoc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        csp_value = DOCS_CSP if request.url.path.startswith(DOCS_PATH_PREFIXES) else STRICT_CSP
        response.headers.setdefault("Content-Security-Policy", csp_value)
        return response
