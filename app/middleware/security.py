import time
import uuid
import logging
from typing import Callable

from fastapi import HTTPException
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.routes.scan_base import build_scan_error
from app.services.safe_response import safe_middleware_response

logger = logging.getLogger(__name__)


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """
    Global security + audit middleware.

    - Adds request_id
    - Logs method, path, status, latency
    - Extracts user_id safely (if authenticated)
    - Captures IP & User-Agent
    - NEVER crashes the app — always returns a usable JSON response
    """

    # Paths where a structured JSON error body is preferred over an HTML 500
    _HANDLED_PREFIXES = ("/scan", "/qr", "/alerts", "/trusted", "/search")

    @classmethod
    def _is_handled_path(cls, path: str) -> bool:
        return any(path.startswith(p) for p in cls._HANDLED_PREFIXES)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Attach request_id to request state
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            status_code = getattr(exc, "status_code", 500)
            logger.exception(
                "request_failed",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            if isinstance(exc, HTTPException) and isinstance(exc.detail, dict):
                # Route already built a structured error payload — pass it through.
                # Use the original status code so 400/429 are preserved for clients
                # that inspect HTTP status; 500s are clamped to 200 for scan paths.
                raw_status = exc.status_code
                out_status = (
                    200
                    if raw_status >= 500 and self._is_handled_path(request.url.path)
                    else raw_status
                )
                response = JSONResponse(status_code=out_status, content=exc.detail)
            elif self._is_handled_path(request.url.path):
                # Unhandled exception on a known API path — return a safe 200 JSON
                payload = build_scan_error(
                    "SCAN_PROCESSING_ERROR",
                    "Scan could not be completed.",
                )
                response = JSONResponse(status_code=200, content=payload)
            else:
                # Unknown path — still return JSON 200 rather than crashing the server
                logger.exception(
                    "middleware_failure",
                    extra={"request_id": request_id, "path": request.url.path},
                )
                response = JSONResponse(
                    status_code=200,
                    content=safe_middleware_response(),
                )

        duration_ms = int((time.time() - start_time) * 1000)

        # Extract user_id safely (never assume)
        user_id = None
        try:
            user = getattr(request.state, "user", None)
            if user and hasattr(user, "id"):
                user_id = str(user.id)
        except Exception:
            user_id = None

        # Client info
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "user_id": user_id,
                "ip": client_ip,
                "user_agent": user_agent,
            },
        )

        # Expose request id to client (VERY useful for support/debug)
        response.headers["X-Request-ID"] = request_id
        return response
